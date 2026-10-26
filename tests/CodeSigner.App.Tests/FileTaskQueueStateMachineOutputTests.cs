using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class FileTaskQueueStateMachineOutputTests
{
    [Fact]
    public async Task DistinctCanonicalOutputRootIncrementsGenerationAndPlansOnlyCurrentRow()
    {
        using var fixture = new SourceFixture("first.exe", "second.exe");
        var intake = new RecordingIntakeAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];
        long initialGeneration = first.OutputGeneration;

        await viewModel.ReplanOutputRootAsync(fixture.Output("generation-one"));

        Assert.Equal(initialGeneration + 1, first.OutputGeneration);
        Assert.Equal(QueueItemPreflightState.Stale, second.PreflightState);
        Assert.NotEqual(first.OutputGeneration, second.OutputGeneration);
        Assert.False(viewModel.CanSign);
        Assert.Equal(viewModel.CanSignQueue, viewModel.SignCommand.CanExecute(null));
        IntakeCall[] generationCalls = intake.Calls
            .Where(call => string.Equals(call.OutputRoot, fixture.Output("generation-one"), StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert.Single(generationCalls);
        Assert.Equal([first.FullPath], generationCalls[0].Inputs);
        Assert.Equal(2, intake.DetectionCalls);
        int callsBeforeEquivalentRoot = intake.Calls.Count;

        await viewModel.ReplanOutputRootAsync(fixture.Output("GENERATION-ONE") + Path.DirectorySeparatorChar);

        Assert.Equal(initialGeneration + 1, first.OutputGeneration);
        Assert.Equal(callsBeforeEquivalentRoot, intake.Calls.Count);
        Assert.Equal(2, intake.DetectionCalls);
    }

    [Fact]
    public async Task SelectingStalePendingRowPlansOnlyThatRowAtCurrentGeneration()
    {
        using var fixture = new SourceFixture("first.exe", "second.exe");
        var intake = new RecordingIntakeAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];
        await viewModel.ReplanOutputRootAsync(fixture.Output("selected"));
        Assert.Single(intake.Calls, call => string.Equals(
            call.OutputRoot,
            fixture.Output("selected"),
            StringComparison.OrdinalIgnoreCase));

        await viewModel.SetCurrentItemAsync(second.ItemId);

        Assert.Same(second, viewModel.CurrentItem);
        Assert.Equal(first.OutputGeneration, second.OutputGeneration);
        Assert.Equal(Path.Combine(fixture.Output("selected"), "second.exe"), second.DestinationPath);
        Assert.Equal(first.OutputGeneration, second.OutputGeneration);
        Assert.Collection(
            intake.Calls.Where(call => string.Equals(
                call.OutputRoot,
                fixture.Output("selected"),
                StringComparison.OrdinalIgnoreCase)),
            call => Assert.Equal([first.FullPath], call.Inputs),
            call => Assert.Equal([second.FullPath], call.Inputs));
        Assert.Equal(2, intake.DetectionCalls);
    }

    [Fact]
    public async Task LowestItemIdOwnsNormalizedDestinationAndRemovalReleasesReservation()
    {
        using var fixture = new SourceFixture("first/shared.exe", "second/shared.exe");
        var intake = new RecordingIntakeAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.RefreshReadinessAsync();
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);
        QueueItemViewModel owner = viewModel.Rows[0];
        QueueItemViewModel loser = viewModel.Rows[1];
        await viewModel.SetCurrentItemAsync(loser.ItemId);

        await viewModel.ReplanOutputRootAsync(fixture.Output("collision"));

        Assert.Equal(QueueItemPreflightState.Blocked, loser.PreflightState);
        Assert.Equal(QueueAuditReasons.DestinationUnsafe, loser.PreflightIssue?.DetailCode);
        Assert.Equal(QueueItemPreflightState.Stale, owner.PreflightState);
        owner.IsSelected = true;
        viewModel.RemoveSelected();
        await WaitForPreflightAsync(loser, QueueItemPreflightState.Ready);
        Assert.Same(loser, viewModel.CurrentItem);
        Assert.True(viewModel.CanSign);
        Assert.Equal(2, intake.DetectionCalls);
    }

    [Fact]
    public void BlockedPlanDoesNotRollbackOtherRowsSuccessfulPlan()
    {
        using var fixture = new SourceFixture("first.exe", "second.exe");
        QueuedSourceAdmissionResult admission = QueuedSourceAdmission.Admit(
            fixture.Paths,
            recurseDirectories: false,
            CancellationToken.None);
        QueueItemViewModel first = CreateDetectedRow("1", admission.Sources[0]);
        QueueItemViewModel second = CreateDetectedRow("2", admission.Sources[1]);
        first.BeginPlan(configGeneration: 1, outputGeneration: 2);
        first.CommitOutputPlan(
            FileFor(first.Source, fixture.Output("collision")),
            outputGeneration: 2);
        first.SetPreflightReady();
        string committedDestination = first.DestinationPath;
        long generation = first.OutputGeneration;

        second.BeginPlan(configGeneration: 1, outputGeneration: 2);
        second.SetPreflightBlocked(new QueueItemPreflightIssue(
            QueueItemPreflightIssueCode.OutputUnavailable,
            IntakeError.DestinationCollision.ToString()));

        Assert.Equal(committedDestination, first.DestinationPath);
        Assert.Equal(generation, first.OutputGeneration);
        Assert.Equal(QueueItemPreflightState.Blocked, second.PreflightState);
        Assert.Equal(QueueItemPreflightIssueCode.OutputUnavailable, second.PreflightIssue?.Code);
    }

    [Fact]
    public async Task LatePlanFromOldRootCannotMutateCurrentGenerationOrReaddedRow()
    {
        using var fixture = new SourceFixture("payload.exe");
        var intake = new BlockingIntakeAdapter(fixture.Output("stale"));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);
        string removedItemId = viewModel.Rows[0].ItemId;
        Task stale = viewModel.ReplanOutputRootAsync(fixture.Output("stale"));
        await intake.BlockedCallStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        viewModel.Rows[0].IsSelected = true;
        viewModel.RemoveSelected();
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);
        QueueItemViewModel replacement = Assert.Single(viewModel.Rows);
        await viewModel.ReplanOutputRootAsync(fixture.Output("current"));
        long currentGeneration = replacement.OutputGeneration;
        string currentDestination = replacement.DestinationPath;

        intake.ReleaseBlockedPlan(fixture.Output("stale"));
        await stale;

        Assert.NotEqual(removedItemId, replacement.ItemId);
        Assert.True(viewModel.IsRemovedItemTombstoned(removedItemId));
        Assert.Equal(currentGeneration, replacement.OutputGeneration);
        Assert.Equal(currentDestination, replacement.DestinationPath);
        Assert.Equal(Path.Combine(fixture.Output("current"), "payload.exe"), replacement.DestinationPath);
    }

    [Theory]
    [InlineData(BatchItemState.Failed)]
    [InlineData(BatchItemState.PausedProvider)]
    [InlineData(BatchItemState.PausedTimestamp)]
    public async Task OutputRootChangePreservesHistoricalDestinationAndRetainedRequest(BatchItemState state)
    {
        using var fixture = new SourceFixture("history.exe", "pending.exe");
        var intake = new RecordingIntakeAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);
        await viewModel.ReplanOutputRootAsync(fixture.Output("initial"));
        QueueItemViewModel history = viewModel.Rows[0];
        IntakeFile retainedFile = history.File;
        var retainedRequest = new BatchItemRequest(history.ItemId, retainedFile, "{}");
        history.RetainRequest(retainedRequest);
        history.Apply(state, receipt: null);
        await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);

        await viewModel.ReplanOutputRootAsync(fixture.Output("new-root"));

        Assert.Same(retainedRequest, history.RetainedRequest);
        Assert.Same(retainedFile, history.RetainedRequest?.File);
        Assert.Equal(retainedFile.DestinationPath, history.DestinationPath);
        Assert.Equal(state, history.State);

        history.IsSelected = true;
        string removedItemId = history.ItemId;
        viewModel.RemoveSelected();
        await viewModel.QueueFilesAsync([fixture.Paths[0]]);
        await WaitForDetectionAsync(viewModel);
        QueueItemViewModel replacement = Assert.Single(
            viewModel.Rows,
            row => string.Equals(row.FullPath, fixture.Paths[0], StringComparison.OrdinalIgnoreCase));
        Assert.NotEqual(removedItemId, replacement.ItemId);
        Assert.Equal(QueueItemPreflightState.Unplanned, replacement.PreflightState);
        await viewModel.SetCurrentItemAsync(replacement.ItemId);
        Assert.Equal(Path.Combine(fixture.Output("new-root"), "history.exe"), replacement.DestinationPath);
    }

    [Fact]
    public async Task OutputPlanningNeverChangesSourceBytes()
    {
        using var fixture = new SourceFixture("hash.exe");
        byte[] before = SHA256.HashData(File.ReadAllBytes(fixture.Paths[0]));
        var intake = new RecordingIntakeAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(fixture.Paths);
        await WaitForDetectionAsync(viewModel);

        await viewModel.ReplanOutputRootAsync(fixture.Output("hash-output"));
        viewModel.Rows[0].IsSelected = true;
        viewModel.RemoveSelected();

        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(fixture.Paths[0])));
    }

    private static SigningWorkbenchViewModel CreateViewModel(IIntakeAdapter intake)
    {
        var viewModel = new SigningWorkbenchViewModel(
            new FixedReadinessAdapter(),
            intake,
            new NoopBatchAdapter(),
            new NoopOperatorShell(),
            new HealthyWorkerHealthService(),
            new NoopWorkerRepairService(),
            static _ => ValueTask.FromResult(true),
            queueAuditSink: new AcceptingQueueAuditSink());
        viewModel.PrimaryCertificate = new CertificateOptionViewModel(FixedReadinessAdapter.Certificate);
        return viewModel;
    }

    private class RecordingIntakeAdapter : IIntakeAdapter
    {
        public List<IntakeCall> Calls { get; } = [];

        public int DetectionCalls { get; private set; }

        public string? FailurePath { get; init; }

        public IntakeError? Failure { get; init; }

        public Task<QueuedSourceAdmissionResult> AdmitAsync(
            IReadOnlyCollection<string> inputs,
            bool recurse,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(QueuedSourceAdmission.Admit(inputs, recurse, cancellationToken));
        }

        public Task<QueuedSourceDetectionResult> DetectAsync(
            QueuedSource source,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DetectionCalls++;
            DetectedQueuedSource detected = DetectedFor(source);
            return Task.FromResult(new QueuedSourceDetectionResult(
                QueuedSourceDetectionStatus.Supported,
                detected,
                Error: null));
        }

        public virtual Task<IntakeFile> PlanOutputAsync(
            DetectedQueuedSource detectedSource,
            string outputRoot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = detectedSource.Source.CanonicalPath;
            Calls.Add(new IntakeCall([path], RecurseDirectories: false, outputRoot));
            if (Failure is IntakeError error &&
                string.Equals(path, FailurePath, StringComparison.OrdinalIgnoreCase))
            {
                throw new IntakeValidationException(error, error.ToString(), FailurePath);
            }

            return Task.FromResult(FileFor(detectedSource.Source, outputRoot));
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
    }

    private sealed class BlockingIntakeAdapter(string blockedOutputRoot) : RecordingIntakeAdapter
    {
        private readonly TaskCompletionSource<string> release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int blocked;

        public TaskCompletionSource BlockedCallStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override Task<IntakeFile> PlanOutputAsync(
            DetectedQueuedSource detectedSource,
            string outputRoot,
            CancellationToken cancellationToken)
        {
            if (string.Equals(outputRoot, blockedOutputRoot, StringComparison.OrdinalIgnoreCase) &&
                Interlocked.CompareExchange(ref blocked, 1, 0) == 0)
            {
                BlockedCallStarted.TrySetResult();
                return AwaitReleaseAsync(detectedSource.Source);
            }

            return base.PlanOutputAsync(detectedSource, outputRoot, cancellationToken);
        }

        public void ReleaseBlockedPlan(string outputRoot) => release.TrySetResult(outputRoot);

        private async Task<IntakeFile> AwaitReleaseAsync(QueuedSource source) =>
            FileFor(source, await release.Task);
    }

    private sealed record IntakeCall(
        IReadOnlyCollection<string> Inputs,
        bool RecurseDirectories,
        string? OutputRoot);

    private static QueueItemViewModel CreateDetectedRow(string itemId, QueuedSource source)
    {
        var row = new QueueItemViewModel(itemId, source);
        long generation = row.BeginDetection();
        row.CompleteDetection(DetectedFor(source), generation);
        return row;
    }

    private static DetectedQueuedSource DetectedFor(QueuedSource source) => new(
        source,
        new SignableSubject(
            SignableFileType.PortableExecutable,
            Guid.Parse("11111111-1111-1111-1111-111111111111")),
        new SourceFingerprint(source.Identity, 6, DateTime.UnixEpoch, new string('A', 64)));

    private static IntakeFile FileFor(QueuedSource source, string outputRoot) => new(
        source.CanonicalPath,
        source.RelativePath,
        Path.Combine(outputRoot, source.RelativePath),
        outputRoot,
        source.Identity,
        DetectedFor(source).Subject);

    private sealed class SourceFixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), $"codesigner-task6-{Guid.NewGuid():N}");

        public SourceFixture(params string[] names)
        {
            Directory.CreateDirectory(root);
            Paths = names.Select(name => Path.Combine(root, name)).ToArray();
            foreach (string path in Paths)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, [0x4D, 0x5A, 0x06, 0x00, 0x00, 0x00]);
            }
        }

        public string[] Paths { get; }

        public string Output(string name) => Path.Combine(root, name);

        public void Dispose() => Directory.Delete(root, recursive: true);
    }

    private sealed class FixedReadinessAdapter : IReadinessAdapter
    {
        public static EligibleCertificate Certificate { get; } = new(
            StoreLocation.CurrentUser,
            "My",
            new string('A', 40),
            "CN=Queue",
            "CN=Issuer",
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            true,
            [CertificateCatalogProbe.CodeSigningEkuOid]);

        public ReadinessSnapshot Probe(Uri timestampUri) => new(
            new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
            NativeApiAvailability.Available,
            new SimplySignInstallation(
                SimplySignInstallationStatus.Installed,
                "{A}",
                "{B}",
                "SimplySign Desktop",
                "Certum",
                "1.0"),
            new CertificateCatalog(
                CertificateAvailabilityStatus.CertificateAvailable,
                [Certificate],
                []),
            new TimestampConfiguration(TimestampConfigurationStatus.Configured, timestampUri),
            ProviderAuthorizationStatus.AuthorizationUnknown);
    }

    private sealed class AcceptingQueueAuditSink : IQueueAuditSink
    {
        public bool WriteAdmissionEvent(
            string eventName,
            string operationId,
            string? outcome = null,
            string? reason = null) => true;

        public bool WriteQueueEvent(
            string eventName,
            string itemId,
            string operationId,
            string phase,
            string? check = null,
            string? action = null,
            string? outcome = null,
            string? reason = null) => true;
    }

    private static async Task WaitForDetectionAsync(SigningWorkbenchViewModel viewModel)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (viewModel.Rows.Any(row => row.DetectionState is
                   QueueItemDetectionState.Pending or QueueItemDetectionState.Running))
        {
            await Task.Delay(10, cancellation.Token);
        }
    }

    private static async Task WaitForPreflightAsync(
        QueueItemViewModel row,
        QueueItemPreflightState expected)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (row.PreflightState != expected)
        {
            await Task.Delay(10, cancellation.Token);
        }
    }

    private sealed class NoopBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }

        public Task<BatchProgressUpdate> RunAsync(BatchItemRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Production batch execution is prohibited in Task 6 tests.");

        public Task<BatchProgressUpdate> ResumeAsync(
            string itemId,
            bool retryFailed,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Production batch execution is prohibited in Task 6 tests.");

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Production batch execution is prohibited in Task 6 tests.");

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoopOperatorShell : IOperatorShell
    {
        public void OpenFolder(string path)
        {
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken) => Task.FromResult(string.Empty);
    }

    private sealed class HealthyWorkerHealthService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
    }

    private sealed class NoopWorkerRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Worker repair is not available in this fake.");

        public void Dispose()
        {
        }
    }
}
