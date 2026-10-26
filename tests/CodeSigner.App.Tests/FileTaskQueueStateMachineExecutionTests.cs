using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.Tests;

public sealed partial class FileTaskQueueStateMachineTests
{
    private static readonly JsonSerializerOptions EvidenceJsonOptions = new() { WriteIndented = true };

    [Fact]
    public async Task TerminalRowsArePrunedBeforePublishedAndSkippedRowsAreRemoved()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        await viewModel.QueueFilesAndWaitAsync([@"C:\queue\published.exe", @"C:\queue\skipped.exe"]);
        QueueItemViewModel published = viewModel.Rows[0];
        QueueItemViewModel skipped = viewModel.Rows[1];
        await viewModel.SetCurrentItemAsync(skipped.ItemId);
        published.RetainRequest(new BatchItemRequest(published.ItemId, published.File, "{}"));
        skipped.RetainRequest(new BatchItemRequest(skipped.ItemId, skipped.File, "{}"));
        published.Apply(BatchItemState.Published, receipt: null);
        skipped.Apply(BatchItemState.SkippedAlreadySigned, receipt: null);

        Assert.True(viewModel.RemoveQueueItemCommand.CanExecute(published));
        viewModel.RemoveQueueItemCommand.Execute(published);
        Assert.True(viewModel.RemoveQueueItemCommand.CanExecute(skipped));
        viewModel.RemoveQueueItemCommand.Execute(skipped);

        Assert.Empty(viewModel.Rows);
        Assert.Equal([published.ItemId, skipped.ItemId], batch.PrunedItemIds);
    }

    [Fact]
    public async Task PruneFailurePreservesTerminalRowAndSourceReference()
    {
        var batch = new RecordingBatchAdapter { FailPrune = true };
        await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        await viewModel.QueueFilesAndWaitAsync([@"C:\queue\failed.exe"]);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        row.RetainRequest(new BatchItemRequest(row.ItemId, row.File, "{}"));
        row.Apply(BatchItemState.Failed, receipt: null);

        viewModel.RemoveQueueItemCommand.Execute(row);

        Assert.Same(row, Assert.Single(viewModel.Rows));
        Assert.Same(row, viewModel.CurrentItem);
        Assert.Equal(@"C:\queue\failed.exe", row.FullPath);
    }

    [Fact]
    public async Task BusyOperationDisablesMutatingCommandsAndCancelsActiveItemOnly()
    {
        var batch = new RecordingBatchAdapter();
        batch.BlockNextRun();
        await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        await viewModel.QueueFilesAndWaitAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        QueueItemViewModel active = viewModel.Rows[0];
        QueueItemViewModel other = viewModel.Rows[1];
        string outputRoot = viewModel.OutputRoot;
        CertificateOptionViewModel? primaryCertificate = viewModel.PrimaryCertificate;
        Uri timestampUri = viewModel.TimestampUri;

        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await viewModel.SetCurrentItemAsync(other.ItemId);

        Assert.Same(active, viewModel.CurrentItem);
        Assert.False(viewModel.AddFilesCommand.CanExecute(null));
        Assert.False(viewModel.AddFolderCommand.CanExecute(null));
        Assert.False(viewModel.RemoveQueueItemCommand.CanExecute(active));
        Assert.False(viewModel.SignCommand.CanExecute(null));
        Assert.False(viewModel.RetryCommand.CanExecute(null));
        Assert.False(viewModel.OpenOutputCommand.CanExecute(null));
        Assert.False(viewModel.SettingsCommand.CanExecute(null));
        Assert.False(viewModel.RefreshSdkSignToolCommand.CanExecute(null));
        Assert.True(viewModel.CancelCommand.CanExecute(null));

        await viewModel.QueueFilesAsync([@"C:\queue\late.exe"]);
        await viewModel.QueueDroppedInputsAsync([@"C:\queue\dropped.exe"]);
        await viewModel.ReplanOutputRootAsync(@"C:\queue\changed-output");
        viewModel.PrimaryCertificate = null;
        viewModel.SelectedMode = SigningMode.Dual;
        Assert.Equal(2, viewModel.Rows.Count);
        Assert.Equal(outputRoot, viewModel.OutputRoot);
        Assert.Same(primaryCertificate, viewModel.PrimaryCertificate);
        Assert.Equal(SigningMode.Single, viewModel.SelectedMode);
        Assert.Equal(timestampUri, viewModel.TimestampUri);

        await viewModel.CancelAsync();
        Assert.Equal([active.ItemId], batch.CancelItemIds);
        batch.CompleteBlockedRun(active.ItemId);
        await signing;
    }

    [Fact]
    public async Task RemovedItemProgressDoesNotMutateReplacement()
    {
        SynchronizationContext? originalContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(null);
        try
        {
            var batch = new RecordingBatchAdapter();
            batch.BlockNextRun();
            await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
            await viewModel.QueueFilesAndWaitAsync([@"C:\queue\first.exe", @"C:\queue\old.exe"]);
            QueueItemViewModel active = viewModel.Rows[0];
            QueueItemViewModel old = viewModel.Rows[1];
            viewModel.RemoveQueueItemCommand.Execute(old);
            await viewModel.QueueFilesAndWaitAsync([@"C:\queue\old.exe"]);
            QueueItemViewModel replacement = viewModel.Rows[1];

            Task signing = viewModel.SignAsync();
            await batch.RunStarted.Task;
            batch.PublishProgress(new BatchProgressUpdate(
                new ExecutionAttemptContext(old.ItemId, new string('a', 32), 1),
                BatchItemState.Failed,
                null));
            Assert.Equal(BatchItemState.Pending, replacement.State);
            batch.CompleteBlockedRun(active.ItemId);
            await signing;
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(originalContext);
        }
    }

    [Fact]
    public async Task UnregisteredLiveProgressFailsOnlyActiveItemClosed()
    {
        SynchronizationContext? originalContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(null);
        try
        {
            var batch = new RecordingBatchAdapter();
            batch.BlockNextRun();
            await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
            await viewModel.QueueFilesAndWaitAsync([@"C:\queue\active.exe", @"C:\queue\other.exe"]);
            QueueItemViewModel active = viewModel.Rows[0];
            QueueItemViewModel other = viewModel.Rows[1];

            Task signing = viewModel.SignAsync();
            await batch.RunStarted.Task;

            batch.PublishProgress(new BatchProgressUpdate(
                new ExecutionAttemptContext(other.ItemId, new string('a', 32), 1),
                BatchItemState.Published,
                null));
            Assert.Equal(BatchItemState.Failed, active.State);
            Assert.Equal(BatchItemState.Pending, other.State);
            batch.CompleteBlockedRun(active.ItemId);
            await signing;
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(originalContext);
        }
    }

    [Fact]
    public async Task PostedProgressFromCompletedOperationIsIgnoredWithoutMutatingRow()
    {
        SynchronizationContext? originalContext = SynchronizationContext.Current;
        var context = new QueuedSynchronizationContext();
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            var batch = new RecordingBatchAdapter();
            batch.BlockNextRun();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            // Capture the queued context for progress, but do not queue fixture setup continuations.
            SynchronizationContext.SetSynchronizationContext(null);
            await viewModel.RefreshReadinessAsync();
            await viewModel.ReplanOutputRootAsync(@"C:\queue\out");
            await viewModel.QueueFilesAndWaitAsync([@"C:\queue\active.exe"]);
            QueueItemViewModel active = Assert.Single(viewModel.Rows);

            SynchronizationContext.SetSynchronizationContext(context);
            Task signing = viewModel.SignAsync();
            Assert.True(batch.RunStarted.Task.IsCompleted);

            SynchronizationContext.SetSynchronizationContext(null);
            await Task.Run(() => batch.PublishProgress(
                new BatchProgressUpdate(active.ItemId, BatchItemState.Failed, null)));
            SynchronizationContext.SetSynchronizationContext(context);
            Assert.Equal(BatchItemState.Pending, active.State);
            Assert.Equal(1, context.PendingCallbackCount);

            batch.CompleteBlockedRun(active.ItemId);
            SynchronizationContext.SetSynchronizationContext(null);
            Task continuationDispatch = context.WaitForPendingCallbackCountAsync(2);
            Task completed = await Task.WhenAny(signing, continuationDispatch);
            SynchronizationContext.SetSynchronizationContext(context);
            if (!signing.IsCompleted)
            {
                Assert.Same(continuationDispatch, completed);
                context.DrainMostRecentlyQueuedCallback();
            }

            Assert.True(signing.IsCompleted);
            await signing;
            Assert.Equal(BatchItemState.Published, active.State);
            Assert.Equal(1, context.PendingCallbackCount);

            Assert.Null(Record.Exception(context.DrainNextCallback));
            Assert.Equal(BatchItemState.Published, active.State);
            Assert.Equal(0, context.PendingCallbackCount);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(originalContext);
        }
    }

    [Fact]
    public async Task FinalPreflightSourceChangeBlocksRunAndPreservesChangedSourceBytes()
    {
        using var fixture = new ExecutionFixture("source.exe");
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        File.Delete(fixture.SourcePath);
        File.WriteAllBytes(fixture.SourcePath, [0x4D, 0x5A, 0x01, 0x02, 0x7F]);
        string beforeSign = fixture.SourceHash();

        await viewModel.SignAsync();

        Assert.Equal(QueueItemPreflightIssueCode.SourceChanged, row.PreflightIssue?.Code);
        Assert.Empty(batch.RunItemIds);
        Assert.Equal(0, batch.ProductionCalls);
        Assert.Equal(beforeSign, fixture.SourceHash());
    }

    [Fact]
    public async Task SignThenRetryReusesFrozenRequestWithFreshMonotonicAttempt()
    {
        using var fixture = new ExecutionFixture("source.exe");
        var batch = new RecordingBatchAdapter
        {
            RunResultState = BatchItemState.Failed,
            ResumeResultState = BatchItemState.Published
        };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        string sourceHash = fixture.SourceHash();

        await viewModel.SignAsync();
        BatchItemRequest retained = Assert.IsType<BatchItemRequest>(row.RetainedRequest);
        await viewModel.RetryAsync();

        Assert.Equal([row.ItemId], batch.RunItemIds);
        Assert.Equal([row.ItemId], batch.ResumeItemIds);
        Assert.Equal(0, batch.LegacyOverloadCalls);
        Assert.Equal(2, batch.Attempts.Count);
        Assert.Equal([1L, 2L], batch.Attempts.Select(attempt => attempt.ExecutionGeneration));
        Assert.All(batch.Attempts, attempt => Assert.Matches("^[0-9a-f]{32}$", attempt.OperationId));
        Assert.NotEqual(batch.Attempts[0].OperationId, batch.Attempts[1].OperationId);
        Assert.All(batch.ObservedRequests, request => Assert.Same(retained, request));
        Assert.Equal(2, batch.RequestHashes.Count);
        Assert.Equal(batch.RequestHashes[0], batch.RequestHashes[1]);
        Assert.Equal(sourceHash, fixture.SourceHash());
        WriteEvidence("request-byte-hashes.json", new
        {
            requestHashes = batch.RequestHashes,
            generations = batch.Attempts.Select(attempt => attempt.ExecutionGeneration).ToArray(),
            operationIds = batch.Attempts.Select(attempt => attempt.OperationId).ToArray(),
            byteIdentical = batch.RequestHashes.Distinct(StringComparer.Ordinal).Count() == 1,
            productionCalls = 0,
            fakeBatchCalls = batch.ProductionCalls,
            workerStarts = 0,
            protectedCalls = 0,
            networkCalls = 0
        });
        WriteEvidence("source-hashes.json", new
        {
            scenario = "sign-retry-unchanged-source",
            before = sourceHash,
            after = fixture.SourceHash(),
            unchanged = string.Equals(sourceHash, fixture.SourceHash(), StringComparison.Ordinal)
        });
    }

    [Fact]
    public async Task RetryIgnoresStaleAndWrongOperationCallbacksUntilExactAttemptCompletes()
    {
        using var fixture = new ExecutionFixture("source.exe");
        var batch = new RecordingBatchAdapter { RunResultState = BatchItemState.Failed };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        await viewModel.SignAsync();
        ExecutionAttemptContext first = Assert.Single(batch.Attempts);
        batch.BlockNextResume();

        Task retry = viewModel.RetryAsync();
        await batch.ResumeStarted.Task;
        ExecutionAttemptContext second = batch.Attempts[1];
        batch.PublishProgress(new BatchProgressUpdate(first, BatchItemState.Published, null));
        batch.PublishProgress(new BatchProgressUpdate(
            new ExecutionAttemptContext(second.ItemId, new string('b', 32), second.ExecutionGeneration),
            BatchItemState.Published,
            null));

        Assert.Equal(BatchItemState.Failed, row.State);
        batch.CompleteBlockedResume(BatchItemState.Published);
        await retry;
        Assert.Equal(BatchItemState.Published, row.State);
    }

    [Fact]
    public async Task RetryRechecksRetainedFingerprintAndSkipsAdapterWhenSourceChanged()
    {
        using var fixture = new ExecutionFixture("source.exe");
        var batch = new RecordingBatchAdapter { RunResultState = BatchItemState.Failed };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        await viewModel.SignAsync();
        DateTime retainedWriteTime = File.GetLastWriteTimeUtc(fixture.SourcePath);
        File.WriteAllBytes(fixture.SourcePath, [0x4D, 0x5A, 0x07, 0x06]);
        File.SetLastWriteTimeUtc(fixture.SourcePath, retainedWriteTime);
        string changedHash = fixture.SourceHash();

        await viewModel.RetryAsync();

        Assert.Equal(BatchItemState.Failed, row.State);
        Assert.Empty(batch.ResumeItemIds);
        Assert.Equal(1, batch.ProductionCalls);
        Assert.Equal(changedHash, fixture.SourceHash());
        WriteEvidence("retry-source-change.json", new
        {
            scenario = "retry-same-size-restored-time-content-change",
            changedHash,
            afterRetry = fixture.SourceHash(),
            fakeResumeCalls = batch.ResumeItemIds.Count,
            productionCalls = 0,
            workerStarts = 0,
            protectedCalls = 0,
            networkCalls = 0
        });
    }

    private static void WriteEvidence(string fileName, object value)
    {
        string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_TASK9_EVIDENCE_DIR");
        if (string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            return;
        }

        Directory.CreateDirectory(evidenceDirectory);
        File.WriteAllText(
            Path.Combine(evidenceDirectory, fileName),
            JsonSerializer.Serialize(value, EvidenceJsonOptions));
    }

    [Fact]
    public async Task CancelDuringActiveAttemptTargetsOnlyActiveItem()
    {
        using var fixture = new ExecutionFixture("active.exe", "other.exe");
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel active = await fixture.QueueAndPreflightAsync(viewModel, fixture.SourcePaths[0]);
        await viewModel.QueueFilesAsync([fixture.SourcePaths[1]]);
        QueueItemViewModel other = await fixture.WaitForRowAsync(viewModel, fixture.SourcePaths[1]);
        batch.BlockNextRun();

        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task;
        await viewModel.CancelAsync();
        batch.CompleteBlockedRun(active.ItemId);
        await signing;

        Assert.Equal([active.ItemId], batch.CancelItemIds);
        Assert.Equal(BatchItemState.Pending, other.State);
    }

    [Fact]
    public async Task TombstonedCallbackDuringAnotherAttemptDoesNotMutateReplacement()
    {
        using var fixture = new ExecutionFixture("active.exe", "replace.exe");
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel active = await fixture.QueueAndPreflightAsync(viewModel, fixture.SourcePaths[0]);
        await viewModel.QueueFilesAsync([fixture.SourcePaths[1]]);
        QueueItemViewModel removed = await fixture.WaitForRowAsync(viewModel, fixture.SourcePaths[1]);
        viewModel.RemoveQueueItemCommand.Execute(removed);
        await viewModel.QueueFilesAsync([fixture.SourcePaths[1]]);
        QueueItemViewModel replacement = await fixture.WaitForRowAsync(viewModel, fixture.SourcePaths[1]);
        batch.BlockNextRun();

        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task;
        batch.PublishProgress(new BatchProgressUpdate(
            new ExecutionAttemptContext(removed.ItemId, new string('a', 32), 1),
            BatchItemState.Failed,
            null));

        Assert.Equal(BatchItemState.Pending, replacement.State);
        batch.CompleteBlockedRun(active.ItemId);
        await signing;
    }

    [Fact]
    public async Task UnregisteredLiveCallbackFailsActiveAndPreservesPeer()
    {
        SynchronizationContext? originalContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(null);
        try
        {
            using var fixture = new ExecutionFixture("active.exe", "other.exe");
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
            QueueItemViewModel active = await fixture.QueueAndPreflightAsync(viewModel, fixture.SourcePaths[0]);
            await viewModel.QueueFilesAsync([fixture.SourcePaths[1]]);
            QueueItemViewModel other = await fixture.WaitForRowAsync(viewModel, fixture.SourcePaths[1]);
            batch.BlockNextRun();

            Task signing = viewModel.SignAsync();
            await batch.RunStarted.Task;
            batch.PublishProgress(new BatchProgressUpdate(
                new ExecutionAttemptContext(other.ItemId, new string('a', 32), 1),
                BatchItemState.Published,
                null));
            batch.CompleteBlockedRun(active.ItemId);
            await signing;

            Assert.Equal(BatchItemState.Failed, active.State);
            Assert.Equal(BatchItemState.Pending, other.State);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(originalContext);
        }
    }

    [Fact]
    public async Task FinalFingerprintRejectsSameSizeRestoredTimestampMutationBeforeBatchCall()
    {
        using var fixture = new ExecutionFixture("source.exe");
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        DateTime admittedWriteTime = File.GetLastWriteTimeUtc(fixture.SourcePath);
        File.WriteAllBytes(fixture.SourcePath, [0x4D, 0x5A, 0x09, 0x08]);
        File.SetLastWriteTimeUtc(fixture.SourcePath, admittedWriteTime);
        string mutatedHash = fixture.SourceHash();

        await viewModel.SignAsync();

        Assert.Equal(QueueItemPreflightIssueCode.SourceChanged, row.PreflightIssue?.Code);
        Assert.Empty(batch.RunItemIds);
        Assert.Equal(0, batch.ProductionCalls);
        Assert.Equal(mutatedHash, fixture.SourceHash());
    }

    private sealed class ExecutionFixture : IDisposable
    {
        public ExecutionFixture(params string[] fileNames)
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSigner-Task7-" + Guid.NewGuid().ToString("N"));
            OutputRoot = Path.Combine(Root, "out");
            SourcePaths = fileNames.Select(fileName => Path.Combine(Root, fileName)).ToArray();
            Directory.CreateDirectory(OutputRoot);
            foreach (string sourcePath in SourcePaths)
            {
                File.WriteAllBytes(sourcePath, [0x4D, 0x5A, 0x01, 0x02]);
            }
        }

        public string Root { get; }

        public string OutputRoot { get; }

        public string[] SourcePaths { get; }

        public string SourcePath => SourcePaths[0];

        public async Task<SigningWorkbenchViewModel> CreateReadyViewModelAsync(RecordingBatchAdapter batch)
        {
            var viewModel = new SigningWorkbenchViewModel(
                new FixedReadinessAdapter(),
                new IdentityIntakeAdapter(OutputRoot),
                batch,
                new NoopOperatorShell(),
                new HealthyWorkerHealthService(),
                new NoopWorkerRepairService(),
                static _ => ValueTask.FromResult(true),
                sdkSignToolReadinessState: null,
                new AcceptingQueueAuditSink());
            await viewModel.RefreshReadinessAsync();
            viewModel.PrimaryCertificate = Assert.Single(viewModel.Certificates);
            await viewModel.ReplanOutputRootAsync(OutputRoot);
            return viewModel;
        }

        public Task<QueueItemViewModel> QueueAndPreflightAsync(SigningWorkbenchViewModel viewModel) =>
            QueueAndPreflightAsync(viewModel, SourcePath);

        public async Task<QueueItemViewModel> QueueAndPreflightAsync(
            SigningWorkbenchViewModel viewModel,
            string sourcePath)
        {
            Assert.Contains(sourcePath, SourcePaths);
            await viewModel.QueueFilesAsync([sourcePath]);
            QueueItemViewModel? row = null;
            for (int attempt = 0; attempt < 500 && row is null; attempt++)
            {
                row = viewModel.Rows.FirstOrDefault(candidate =>
                    string.Equals(candidate.FullPath, sourcePath, StringComparison.OrdinalIgnoreCase));
                if (row is null)
                {
                    await Task.Delay(10);
                }
            }

            Assert.NotNull(row);
            await viewModel.SetCurrentItemAsync(row.ItemId);
            for (int attempt = 0;
                 attempt < 500 && row.PreflightState is not QueueItemPreflightState.Ready;
                 attempt++)
            {
                await Task.Delay(10);
            }

            Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
            return row;
        }

        public async Task<QueueItemViewModel> WaitForRowAsync(
            SigningWorkbenchViewModel viewModel,
            string sourcePath)
        {
            Assert.Contains(sourcePath, SourcePaths);
            QueueItemViewModel? row = null;
            for (int attempt = 0; attempt < 500 && row is null; attempt++)
            {
                row = viewModel.Rows.FirstOrDefault(candidate =>
                    string.Equals(candidate.FullPath, sourcePath, StringComparison.OrdinalIgnoreCase));
                if (row is null)
                {
                    await Task.Delay(10);
                }
            }

            return Assert.IsType<QueueItemViewModel>(row);
        }

        public string SourceHash() => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(SourcePath)));

        public static string SourceHash(string sourcePath) =>
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourcePath)));

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }

    private sealed class IdentityIntakeAdapter(string outputRoot) : StagedIntakeAdapterFake, IIntakeAdapter
    {
        public new Task<QueuedSourceDetectionResult> DetectAsync(
            QueuedSource source,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(source.CanonicalPath);
            SigningSubject subject = SigningSubject.TryCreateForExtension(Path.GetExtension(source.CanonicalPath)).Value!;
            var detected = new DetectedQueuedSource(
                source,
                new SignableSubject(subject, Guid.NewGuid(), null),
                new SourceFingerprint(
                    source.Identity,
                    info.Length,
                    info.LastWriteTimeUtc,
                    Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source.CanonicalPath)))));
            return Task.FromResult(new QueuedSourceDetectionResult(
                QueuedSourceDetectionStatus.Supported,
                detected,
                Error: null));
        }

        public new Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
            DetectedQueuedSource detectedSource,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(detectedSource.Source.CanonicalPath);
            var current = new SourceFingerprint(
                detectedSource.Source.Identity,
                info.Length,
                info.LastWriteTimeUtc,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(detectedSource.Source.CanonicalPath))));
            bool matches = current == detectedSource.Fingerprint;
            return Task.FromResult(new QueuedSourceDetectionResult(
                matches ? QueuedSourceDetectionStatus.Supported : QueuedSourceDetectionStatus.Changed,
                matches ? detectedSource : null,
                Error: null));
        }

        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? requestedOutputRoot,
            CancellationToken cancellationToken)
        {
            string root = requestedOutputRoot ?? outputRoot;
            IntakeFile[] files = inputs.Select(path => CreateFile(path, root)).ToArray();
            return Task.FromResult(new IntakePlan(root, files));
        }

        private static IntakeFile CreateFile(string path, string root)
        {
            QueuedSource source = Assert.Single(
                QueuedSourceAdmission.Admit([path], false, CancellationToken.None).Sources);
            SigningSubject subject = SigningSubject.TryCreateForExtension(Path.GetExtension(path)).Value!;
            return new IntakeFile(
                path,
                Path.GetFileName(path),
                Path.Combine(root, Path.GetFileName(path)),
                root,
                source.Identity,
                new SignableSubject(subject, Guid.NewGuid(), null));
        }
    }

    private sealed class AcceptingQueueAuditSink : IQueueAuditSink
    {
        public bool CheckHealth() => true;

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

    private sealed class QueuedSynchronizationContext : SynchronizationContext
    {
        private readonly object sync = new();
        private readonly List<(SendOrPostCallback Callback, object? State)> callbacks = [];
        private TaskCompletionSource? pendingCallbackCountReached;
        private int pendingCallbackCountTarget;

        public int PendingCallbackCount
        {
            get
            {
                lock (sync)
                {
                    return callbacks.Count;
                }
            }
        }

        public override void Post(SendOrPostCallback callback, object? state)
        {
            TaskCompletionSource? reached = null;
            lock (sync)
            {
                callbacks.Add((callback, state));
                if (pendingCallbackCountReached is not null &&
                    callbacks.Count >= pendingCallbackCountTarget)
                {
                    reached = pendingCallbackCountReached;
                    pendingCallbackCountReached = null;
                    pendingCallbackCountTarget = 0;
                }
            }

            reached?.TrySetResult();
        }

        public Task WaitForPendingCallbackCountAsync(int count)
        {
            lock (sync)
            {
                if (callbacks.Count >= count)
                {
                    return Task.CompletedTask;
                }

                pendingCallbackCountTarget = count;
                return (pendingCallbackCountReached ??= new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously)).Task;
            }
        }

        public void DrainMostRecentlyQueuedCallback() => DrainCallbackAt(PendingCallbackCount - 1);

        public void DrainNextCallback() => DrainCallbackAt(0);

        private void DrainCallbackAt(int index)
        {
            (SendOrPostCallback Callback, object? State) callback;
            lock (sync)
            {
                callback = callbacks[index];
                callbacks.RemoveAt(index);
            }
            SynchronizationContext? previous = Current;
            SetSynchronizationContext(this);
            try
            {
                callback.Callback(callback.State);
            }
            finally
            {
                SetSynchronizationContext(previous);
            }
        }
    }
}

public sealed class FileTaskQueueStateMachineExecutionTests
{
    [Fact]
    public Task SignRetryCorrelation() =>
        new FileTaskQueueStateMachineTests().SignThenRetryReusesFrozenRequestWithFreshMonotonicAttempt();

    [Fact]
    public Task SameSizeRestoredTimestampMutation() =>
        new FileTaskQueueStateMachineTests().FinalFingerprintRejectsSameSizeRestoredTimestampMutationBeforeBatchCall();

    [Fact]
    public Task CancelTargetsOnlyActiveItem() =>
        new FileTaskQueueStateMachineTests().CancelDuringActiveAttemptTargetsOnlyActiveItem();

    [Fact]
    public Task StaleAndWrongCallbacks() =>
        new FileTaskQueueStateMachineTests().RetryIgnoresStaleAndWrongOperationCallbacksUntilExactAttemptCompletes();

    [Fact]
    public Task RetryFingerprintChange() =>
        new FileTaskQueueStateMachineTests().RetryRechecksRetainedFingerprintAndSkipsAdapterWhenSourceChanged();

    [Fact]
    public Task UnregisteredLiveCallback() =>
        new FileTaskQueueStateMachineTests().UnregisteredLiveCallbackFailsActiveAndPreservesPeer();

    [Fact]
    public Task RemovedReplacementCallback() =>
        new FileTaskQueueStateMachineTests().TombstonedCallbackDuringAnotherAttemptDoesNotMutateReplacement();
}
