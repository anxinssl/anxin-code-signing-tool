using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using System.IO;

namespace CodeSigner.App.Tests;

internal abstract class StagedIntakeAdapterFake : IIntakeAdapter
{
    private string[] admittedInputs = [];
    private bool recurseDirectories;

    public Task<QueuedSourceAdmissionResult> AdmitAsync(
        IReadOnlyCollection<string> inputs,
        bool recurse,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        admittedInputs = inputs.ToArray();
        recurseDirectories = recurse;
        QueuedSource[] sources = admittedInputs
            .Select((path, index) => new QueuedSource(
                path,
                Path.GetFileName(path),
                new StableFileIdentity((ulong)(index + 1), path)))
            .ToArray();
        return Task.FromResult(new QueuedSourceAdmissionResult(sources, []));
    }

    public Task<QueuedSourceDetectionResult> DetectAsync(
        QueuedSource source,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SigningSubject subject = SigningSubject.TryCreateForExtension(Path.GetExtension(source.CanonicalPath)).Value
            ?? SigningSubject.TryCreateForExtension(".exe").Value
            ?? throw new InvalidOperationException("The test signing policy is unavailable.");
        var detected = new DetectedQueuedSource(
            source,
            new SignableSubject(subject, Guid.NewGuid(), null),
            new SourceFingerprint(source.Identity, 0, DateTime.UnixEpoch, new string('A', 64)));
        return Task.FromResult(new QueuedSourceDetectionResult(
            QueuedSourceDetectionStatus.Supported,
            detected,
            Error: null));
    }

    public async Task<IntakeFile> PlanOutputAsync(
        DetectedQueuedSource detectedSource,
        string outputRoot,
        CancellationToken cancellationToken)
    {
        IReadOnlyCollection<string> inputs = [detectedSource.Source.CanonicalPath];
        IntakePlan plan = await BuildPlanAsync(
            inputs,
            recurseDirectories,
            outputRoot,
            cancellationToken);

        IntakeFile planned = plan.Files.FirstOrDefault(file => string.Equals(
                file.OriginalPath,
                detectedSource.Source.CanonicalPath,
                StringComparison.OrdinalIgnoreCase))
            ?? (plan.Files.Count == 1
                ? plan.Files[0]
                : throw new InvalidOperationException("The fake intake plan does not contain the detected source."));
        return planned with
        {
            Identity = detectedSource.Source.Identity,
            Subject = detectedSource.Subject
        };
    }

    public Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
        DetectedQueuedSource detectedSource,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new QueuedSourceDetectionResult(
            QueuedSourceDetectionStatus.Supported,
            detectedSource,
            Error: null));
    }

    protected abstract Task<IntakePlan> BuildPlanAsync(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        string? outputRoot,
        CancellationToken cancellationToken);
}

public sealed class StagedIntakeAdapterFakeContractTests
{
    [Fact]
    public async Task PlanOutputAsyncReevaluatesMutableConfigurationForSameOutputRoot()
    {
        var adapter = new MutablePlanAdapter();
        string sourcePath = Path.Combine(Path.GetTempPath(), "codesigner-same-root-mutable.exe");
        string outputRoot = Path.Combine(Path.GetTempPath(), "codesigner-same-root-output");
        QueuedSource source = Assert.Single((await adapter.AdmitAsync(
            [sourcePath],
            recurse: false,
            CancellationToken.None)).Sources);
        DetectedQueuedSource detected = Assert.IsType<DetectedQueuedSource>(
            (await adapter.DetectAsync(source, CancellationToken.None)).DetectedSource);

        IntakeFile planned = await adapter.PlanOutputAsync(detected, outputRoot, CancellationToken.None);

        Assert.Equal(detected.Source.Identity, planned.Identity);
        Assert.Equal(detected.Subject, planned.Subject);
        Assert.Equal(1, adapter.PlanCalls);

        adapter.Error = new IntakeValidationException(
            IntakeError.DestinationExists,
            "mutable error",
            sourcePath);
        await Assert.ThrowsAsync<IntakeValidationException>(() =>
            adapter.PlanOutputAsync(detected, outputRoot, CancellationToken.None));

        adapter.Error = null;
        adapter.Fault = new InvalidOperationException("mutable fault");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            adapter.PlanOutputAsync(detected, outputRoot, CancellationToken.None));

        adapter.Fault = null;
        adapter.BlockPath = sourcePath;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            adapter.PlanOutputAsync(detected, outputRoot, CancellationToken.None));

        Assert.Equal(4, adapter.PlanCalls);
    }

    private sealed class MutablePlanAdapter : StagedIntakeAdapterFake
    {
        public IntakeValidationException? Error { get; set; }

        public Exception? Fault { get; set; }

        public string? BlockPath { get; set; }

        public int PlanCalls { get; private set; }

        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            PlanCalls++;
            if (Fault is not null)
            {
                throw Fault;
            }

            if (Error is not null)
            {
                throw Error;
            }

            if (BlockPath is not null && inputs.Contains(BlockPath, StringComparer.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("mutable block");
            }

            string root = outputRoot ?? "default-output-root";
            IntakeFile[] files = inputs.Select(path => new IntakeFile(
                path,
                Path.GetFileName(path),
                Path.Combine(root, Path.GetFileName(path)),
                root,
                new StableFileIdentity(11, path),
                new SignableSubject(
                    SigningSubject.TryCreateForExtension(Path.GetExtension(path)).Value!,
                    Guid.NewGuid(),
                    scriptProfile: null))).ToArray();
            return Task.FromResult(new IntakePlan(root, files));
        }
    }
}
