using System.Security.Cryptography;
using System.Diagnostics;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class TransactionalFilePipelineTests
{
    [Fact]
    public async Task Todo7CharacterizationPublishPreservesOriginalHashAndCommitsVerifiedStage()
    {
        using TestTree tree = new();
        string original = tree.Write("todo7-characterization.exe", "pristine-source");
        IntakePlan plan = await Planner().CreateAsync(
            [original],
            recurseDirectories: false,
            tree.PathOf("out"),
            CancellationToken.None);
        byte[] originalBytes = await File.ReadAllBytesAsync(original);
        string originalHash = Convert.ToHexString(SHA256.HashData(originalBytes));

        PublishReceipt receipt = await TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new MarkerVerifier()).PublishAsync(plan.Files[0], CancellationToken.None);

        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(original));
        Assert.Equal(originalHash, receipt.OriginalSha256);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(receipt.DestinationPath))),
            receipt.PublishedSha256);
        Assert.Equal("pristine-source|signed", await File.ReadAllTextAsync(receipt.DestinationPath));
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    [Fact]
    public async Task RuntimeEventsBracketStagingHashCopySignerAndPublishInOrder()
    {
        using TestTree tree = new();
        string original = tree.Write("runtime-events.exe", "source");
        IntakePlan plan = await Planner().CreateAsync(
            [original],
            recurseDirectories: false,
            tree.PathOf("out"),
            CancellationToken.None);
        var events = new List<string>();
        TransactionalFilePublisher publisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new MarkerVerifier(),
            hooks: null,
            runtimeEventSink: events.Add);

        await publisher.PublishAsync(plan.Files[0], CancellationToken.None);

        Assert.Equal(
            [
                "staging-create-start",
                "staging-create-done",
                "source-hash-start",
                "source-hash-done",
                "copy-to-staging-start",
                "copy-to-staging-done",
                "signer-enter",
                "publish-start",
                "publish-done"
            ],
            events);
    }

    [Fact]
    public async Task FileInputPublishesVerifiedCopyWithoutChangingOriginal()
    {
        using TestTree tree = new();
        string original = tree.Write("input/app.exe", "original");
        IntakePlan plan = await Planner().CreateAsync([original], recurseDirectories: false, outputRoot: null, CancellationToken.None);
        byte[] before = SHA256.HashData(File.ReadAllBytes(original));
        RecordingSigner signer = new();
        TransactionalFilePublisher publisher = TestTransactionalFilePublishers.Create(signer, new MarkerVerifier());

        PublishReceipt receipt = await publisher.PublishAsync(plan.Files[0], CancellationToken.None);

        Assert.Equal(PublishStatus.Published, receipt.Status);
        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(original)));
        Assert.Equal("original|signed", File.ReadAllText(receipt.DestinationPath));
        Assert.Equal(["original"], signer.ObservedInputs);
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task FailureAndCancellationLeaveNoDestinationOrStagingResidue()
    {
        using TestTree tree = new();
        string failureInput = tree.Write("failure.exe", "failure-original");
        string cancelInput = tree.Write("cancel.exe", "cancel-original");
        IntakePlan plan = await Planner().CreateAsync([failureInput, cancelInput], false, tree.PathOf("out"), CancellationToken.None);
        byte[] failureHash = SHA256.HashData(File.ReadAllBytes(failureInput));
        byte[] cancelHash = SHA256.HashData(File.ReadAllBytes(cancelInput));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestTransactionalFilePublishers.Create(new ThrowingSigner(), new MarkerVerifier())
                .PublishAsync(plan.Files[0], CancellationToken.None));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            TestTransactionalFilePublishers.Create(new CancellingSigner(), new MarkerVerifier())
                .PublishAsync(plan.Files[1], CancellationToken.None));

        Assert.Equal(failureHash, SHA256.HashData(File.ReadAllBytes(failureInput)));
        Assert.Equal(cancelHash, SHA256.HashData(File.ReadAllBytes(cancelInput)));
        Assert.False(File.Exists(plan.Files[0].DestinationPath));
        Assert.False(File.Exists(plan.Files[1].DestinationPath));
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    [Fact]
    public async Task RetryAlwaysCopiesTheOriginalAgain()
    {
        using TestTree tree = new();
        string original = tree.Write("retry.exe", "pristine");
        IntakePlan plan = await Planner().CreateAsync([original], false, tree.PathOf("out"), CancellationToken.None);
        FailOnceSigner signer = new();
        TransactionalFilePublisher publisher = TestTransactionalFilePublishers.Create(signer, new MarkerVerifier());

        await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.PublishAsync(plan.Files[0], CancellationToken.None));
        PublishReceipt receipt = await publisher.PublishAsync(plan.Files[0], CancellationToken.None);

        Assert.Equal(["pristine", "pristine"], signer.ObservedInputs);
        Assert.Equal("pristine|signed", File.ReadAllText(receipt.DestinationPath));
        Assert.Equal("pristine", File.ReadAllText(original));
    }

    [Fact]
    public async Task VerificationFailureAndPublishRaceNeverOverwriteDestination()
    {
        using TestTree tree = new();
        string original = tree.Write("app.exe", "source");
        IntakePlan plan = await Planner().CreateAsync([original], false, tree.PathOf("out"), CancellationToken.None);
        TransactionalFilePublisher invalidPublisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new RejectingVerifier());

        await Assert.ThrowsAsync<InvalidDataException>(() => invalidPublisher.PublishAsync(plan.Files[0], CancellationToken.None));
        Assert.False(File.Exists(plan.Files[0].DestinationPath));

        TransactionalFilePublisher racedPublisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new CallbackVerifier(() => tree.WriteRelative(plan.Files[0].DestinationPath, "winner")));
        FilePipelineException race = await Assert.ThrowsAsync<FilePipelineException>(() =>
            racedPublisher.PublishAsync(plan.Files[0], CancellationToken.None));
        Assert.Equal(FilePipelineError.DestinationCollision, race.Error);
        Assert.Equal("winner", File.ReadAllText(plan.Files[0].DestinationPath));
        Assert.Equal("source", File.ReadAllText(original));
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    [Fact]
    public async Task VerifiedStagePathReplacementBeforeCommitFailsClosedWithoutSignerOrPublication()
    {
        using TestTree tree = new();
        string original = tree.Write("verified-stage-aba.exe", "verified-source");
        IntakePlan plan = await Planner().CreateAsync(
            [original],
            recurseDirectories: false,
            tree.PathOf("out"),
            CancellationToken.None);
        var signer = new RecordingSigner();
        string? heldStagePath = null;
        string? replacedStagePath = null;
        TransactionalFilePublisher publisher = new(
            signer,
            new MarkerVerifier(),
            new TransactionalFilePipelineHooks(
                AfterCommit: static () => { },
                BeforeCommit: stagedPath =>
                {
                    replacedStagePath = stagedPath;
                    heldStagePath = stagedPath + ".verified";
                    using (Microsoft.Win32.SafeHandles.SafeFileHandle attacker = WindowsFileIdentity.OpenForMove(stagedPath))
                    {
                        WindowsFileIdentity.MoveByHandleNoReplace(
                            attacker,
                            heldStagePath,
                            usePosixSemantics: true);
                    }

                    File.WriteAllText(stagedPath, "attacker-replacement");
                }));

        Exception? observedFailure = await Record.ExceptionAsync(
            () => publisher.PublishAsync(plan.Files[0], CancellationToken.None));
        FilePipelineException? failure = observedFailure as FilePipelineException;

        string observed = File.Exists(plan.Files[0].DestinationPath)
            ? $"destination={File.ReadAllText(plan.Files[0].DestinationPath)}"
            : "destination=absent";
        Assert.True(
            failure?.Error == FilePipelineError.InvalidPlan,
            $"Expected invalid-plan after staged identity replacement; observed {observed}; " +
            $"failure={observedFailure?.GetType().FullName}: {observedFailure}; " +
            $"held-exists={heldStagePath is not null && File.Exists(heldStagePath)}; " +
            $"replacement-exists={replacedStagePath is not null && File.Exists(replacedStagePath)}.");
        Assert.Equal(["verified-source"], signer.ObservedInputs);
        Assert.False(File.Exists(plan.Files[0].DestinationPath));
        Assert.Equal("verified-source", File.ReadAllText(original));
        Assert.NotNull(heldStagePath);
        Assert.False(File.Exists(heldStagePath));
        Assert.NotNull(replacedStagePath);
        Assert.Equal("attacker-replacement", File.ReadAllText(replacedStagePath));
        Assert.Single(FindStaging(plan.OutputRoot));
    }

    [Fact]
    public async Task PublicationFailureDeletesOwnedOutputByHandleWithoutDeletingDestinationReplacement()
    {
        using TestTree tree = new();
        string original = tree.Write("cleanup-identity.exe", "original-source");
        string unrelatedStagingDirectory = tree.PathOf("out/.codesigner-staging-unrelated");
        string unrelated = tree.Write("out/.codesigner-staging-unrelated/keep.txt", "unrelated");
        IntakePlan plan = await Planner().CreateAsync(
            [original],
            recurseDirectories: false,
            tree.PathOf("out"),
            CancellationToken.None);
        string relocatedOwnedOutput = tree.PathOf("relocated-owned-output.exe");
        TransactionalFilePublisher publisher = new(
            new RecordingSigner(),
            new MarkerVerifier(),
            hooks: null,
            runtimeEventSink: null,
            afterPublishedVerification: _ => File.AppendAllText(original, "|changed-at-publication-boundary"),
            beforePublishedOutputDelete: destinationPath =>
            {
                using Microsoft.Win32.SafeHandles.SafeFileHandle ownedOutput =
                    WindowsFileIdentity.OpenForMove(destinationPath);
                WindowsFileIdentity.MoveByHandleNoReplace(
                    ownedOutput,
                    relocatedOwnedOutput,
                    usePosixSemantics: true);
                File.WriteAllText(destinationPath, "replacement-output");
            });

        FilePipelineException failure = await Assert.ThrowsAsync<FilePipelineException>(
            () => publisher.PublishAsync(plan.Files[0], CancellationToken.None));

        Assert.Equal(FilePipelineError.OriginalChanged, failure.Error);
        Assert.Equal("original-source|changed-at-publication-boundary", File.ReadAllText(original));
        Assert.False(File.Exists(relocatedOwnedOutput));
        Assert.Equal("replacement-output", File.ReadAllText(plan.Files[0].DestinationPath));
        Assert.Equal("unrelated", File.ReadAllText(unrelated));
        Assert.Equal([unrelatedStagingDirectory], FindStaging(plan.OutputRoot));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RecoveryDeletesOnlyRecognizedStaleAttemptsAndAllowsRetry()
    {
        using TestTree tree = new();
        string original = tree.Write("app.exe", "source");
        string outputRoot = tree.PathOf("out");
        string stale = TransactionalStaging.CreateAttemptDirectory(
            outputRoot,
            ownerProcessId: int.MaxValue,
            ownerProcessStartUtc: DateTimeOffset.UnixEpoch);
        File.WriteAllText(Path.Combine(stale, "partial.exe"), "partial");
        string unrelated = tree.Write("out/.keep/data.txt", "keep");

        StagingRecoveryReceipt recovery = TransactionalStaging.Recover(outputRoot);
        IntakePlan plan = await Planner().CreateAsync([original], false, outputRoot, CancellationToken.None);
        PublishReceipt receipt = await TestTransactionalFilePublishers.Create(new RecordingSigner(), new MarkerVerifier())
            .PublishAsync(plan.Files[0], CancellationToken.None);

        Assert.Equal(1, recovery.RemovedAttemptCount);
        Assert.False(Directory.Exists(stale));
        Assert.Equal("keep", File.ReadAllText(unrelated));
        Assert.Equal(PublishStatus.Published, receipt.Status);
    }

    [RequiresSymbolicLinksFact]
    public void RecoveryPreservesActiveForeignMalformedAndReparseAttempts()
    {
        using TestTree tree = new();
        string outputRoot = tree.PathOf("out");
        using Process current = Process.GetCurrentProcess();
        string active = TransactionalStaging.CreateAttemptDirectory(
            outputRoot,
            current.Id,
            current.StartTime.ToUniversalTime());
        string foreign = tree.Write("out/.codesigner-staging-foreign/payload.exe", "foreign");
        string malformedDirectory = tree.PathOf($"out/.codesigner-staging-{Guid.NewGuid():N}");
        Directory.CreateDirectory(malformedDirectory);
        File.WriteAllText(Path.Combine(malformedDirectory, TransactionalStaging.ManifestFileName), "not-json");

        string ownedTarget = TransactionalStaging.CreateAttemptDirectory(
            tree.PathOf("other-output"),
            int.MaxValue,
            DateTimeOffset.UnixEpoch);
        string reparseAttempt = tree.PathOf($"out/.codesigner-staging-{Guid.NewGuid():N}");
        Directory.CreateDirectory(outputRoot);
        Directory.CreateSymbolicLink(reparseAttempt, ownedTarget);

        StagingRecoveryReceipt receipt = TransactionalStaging.Recover(outputRoot);

        Assert.Equal(0, receipt.RemovedAttemptCount);
        Assert.True(receipt.SkippedAttemptCount >= 3);
        Assert.True(Directory.Exists(active));
        Assert.Equal("foreign", File.ReadAllText(foreign));
        Assert.True(Directory.Exists(malformedDirectory));
        Assert.True(Directory.Exists(reparseAttempt));
        Assert.True(Directory.Exists(ownedTarget));
    }

    [Fact]
    public async Task SourcePathReplacementAndHardLinkMutationCannotPublish()
    {
        using TestTree tree = new();
        string original = tree.Write("source.exe", "pristine");
        string alias = tree.CreateHardLink("alias.exe", original);
        IntakePlan plan = await Planner().CreateAsync([original], false, tree.PathOf("out"), CancellationToken.None);
        byte[] before = SHA256.HashData(File.ReadAllBytes(original));
        string moved = tree.PathOf("moved.exe");

        TransactionalFilePublisher hardLinkPublisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new CallbackVerifier(() => File.AppendAllText(alias, "|attacker")));
        await Assert.ThrowsAsync<IOException>(() => hardLinkPublisher.PublishAsync(plan.Files[0], CancellationToken.None));

        TransactionalFilePublisher replacementPublisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new CallbackVerifier(() => File.Move(original, moved)));
        await Assert.ThrowsAsync<IOException>(() => replacementPublisher.PublishAsync(plan.Files[0], CancellationToken.None));

        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(original)));
        Assert.False(File.Exists(moved));
        Assert.False(File.Exists(plan.Files[0].DestinationPath));
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    [Fact]
    public async Task ConcurrentPublishHasOneWinnerOneTypedCollisionAndNoResidue()
    {
        using TestTree tree = new();
        string original = tree.Write("app.exe", "source");
        IntakePlan plan = await Planner().CreateAsync([original], false, tree.PathOf("out"), CancellationToken.None);
        using Barrier barrier = new(2);

        Task<PublishReceipt> first = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new BarrierVerifier(barrier)).PublishAsync(plan.Files[0], CancellationToken.None);
        Task<PublishReceipt> second = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new BarrierVerifier(barrier)).PublishAsync(plan.Files[0], CancellationToken.None);

        Exception? firstError = await Record.ExceptionAsync(() => first);
        Exception? secondError = await Record.ExceptionAsync(() => second);

        Assert.Single(new[] { firstError, secondError }, error => error is null);
        FilePipelineException collision = Assert.IsType<FilePipelineException>(
            new[] { firstError, secondError }.Single(error => error is not null));
        Assert.Equal(FilePipelineError.DestinationCollision, collision.Error);
        Assert.Equal("source|signed", File.ReadAllText(plan.Files[0].DestinationPath));
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task CancellationBeforeCommitLeavesNoOutputButCancellationAfterCommitReturnsPublished()
    {
        using TestTree tree = new();
        string original = tree.Write("app.exe", "source");
        IntakePlan plan = await Planner().CreateAsync([original], false, tree.PathOf("out"), CancellationToken.None);
        using CancellationTokenSource beforeCommit = new();
        TransactionalFilePublisher cancelledPublisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new CallbackVerifier(beforeCommit.Cancel));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            cancelledPublisher.PublishAsync(plan.Files[0], beforeCommit.Token));
        Assert.False(File.Exists(plan.Files[0].DestinationPath));

        using CancellationTokenSource afterCommit = new();
        TransactionalFilePublisher committedPublisher = TestTransactionalFilePublishers.Create(
            new RecordingSigner(),
            new MarkerVerifier(),
            new TransactionalFilePipelineHooks(afterCommit.Cancel));
        PublishReceipt receipt = await committedPublisher.PublishAsync(plan.Files[0], afterCommit.Token);

        Assert.True(afterCommit.IsCancellationRequested);
        Assert.Equal(PublishStatus.Published, receipt.Status);
        Assert.True(File.Exists(receipt.DestinationPath));
        Assert.Empty(FindStaging(plan.OutputRoot));
    }

    private static IntakePlanner Planner() => new(new AcceptingSubjectProbe());

    private static string[] FindStaging(string outputRoot) => Directory.Exists(outputRoot)
        ? Directory.GetDirectories(outputRoot, ".codesigner-staging-*", SearchOption.TopDirectoryOnly)
        : [];

    private sealed class AcceptingSubjectProbe : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => new(SignableFileType.PortableExecutable, Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee"));
    }

    private sealed class RecordingSigner : IStagedFileSigner
    {
        public List<string> ObservedInputs { get; } = [];

        public async Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            ObservedInputs.Add(await File.ReadAllTextAsync(stagedPath, cancellationToken));
            await File.AppendAllTextAsync(stagedPath, "|signed", cancellationToken);
        }
    }

    private sealed class ThrowingSigner : IStagedFileSigner
    {
        public Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            File.AppendAllText(stagedPath, "|partial");
            throw new InvalidOperationException("injected failure");
        }
    }

    private sealed class CancellingSigner : IStagedFileSigner
    {
        public Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            File.AppendAllText(stagedPath, "|partial");
            throw new OperationCanceledException(cancellationToken);
        }
    }

    private sealed class FailOnceSigner : IStagedFileSigner
    {
        private int attempt;
        public List<string> ObservedInputs { get; } = [];

        public async Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            ObservedInputs.Add(await File.ReadAllTextAsync(stagedPath, cancellationToken));
            await File.AppendAllTextAsync(stagedPath, "|signed", cancellationToken);
            if (Interlocked.Increment(ref attempt) == 1)
            {
                throw new InvalidOperationException("first attempt failed");
            }
        }
    }

    private sealed class MarkerVerifier : IStagedFileVerifier
    {
        public Task VerifyAsync(string stagedPath, CancellationToken cancellationToken)
        {
            Assert.EndsWith("|signed", File.ReadAllText(stagedPath), StringComparison.Ordinal);
            return Task.CompletedTask;
        }
    }

    private sealed class RejectingVerifier : IStagedFileVerifier
    {
        public Task VerifyAsync(string stagedPath, CancellationToken cancellationToken) =>
            throw new InvalidDataException("injected verification failure");
    }

    private sealed class CallbackVerifier(Action callback) : IStagedFileVerifier
    {
        public Task VerifyAsync(string stagedPath, CancellationToken cancellationToken)
        {
            callback();
            return Task.CompletedTask;
        }
    }

    private sealed class BarrierVerifier(Barrier barrier) : IStagedFileVerifier
    {
        public Task VerifyAsync(string stagedPath, CancellationToken cancellationToken)
        {
            Assert.True(barrier.SignalAndWait(TimeSpan.FromSeconds(10), cancellationToken));
            return Task.CompletedTask;
        }
    }
}
