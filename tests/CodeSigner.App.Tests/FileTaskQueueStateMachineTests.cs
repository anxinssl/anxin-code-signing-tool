using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed partial class FileTaskQueueStateMachineTests
{
    [Fact]
    public void RowWithoutIntakeFileRendersQueuedSourceSafely()
    {
        QueueItemViewModel row = CreatePendingRow();

        Assert.Equal(@"C:\queue\pending.exe", row.FullPath);
        Assert.Equal("pending.exe", row.DisplayName);
        Assert.Empty(row.DestinationPath);
        Assert.Equal(QueueItemDetectionState.Pending, row.DetectionState);
        Assert.Equal(QueueItemSourceIntegrityState.Current, row.SourceIntegrityState);
        Assert.Equal(QueueItemPreflightState.Unplanned, row.PreflightState);
        Assert.Equal("等待检测", row.FormatText);
        Assert.Equal("等待检测", row.EngineText);
        Assert.Equal("等待检测", row.EffectivePolicyText);
        Assert.Contains("源文件 当前", row.AutomationName, StringComparison.Ordinal);
    }

    [Fact]
    public void PublishedResultStatesTheEffectiveSingleOrDualSigningMode()
    {
        QueueItemViewModel pe = CreatePendingRow();
        long peGeneration = pe.BeginDetection();
        pe.CompleteDetection(CreateDetectedSource(pe.Source), peGeneration);
        pe.UpdateSigningMode(SigningMode.Dual);
        pe.Apply(BatchItemState.Published, receipt: null);

        var installerSource = new QueuedSource(
            @"C:\queue\package.msi",
            "package.msi",
            new StableFileIdentity(18, "installer-file-id"));
        var installer = new QueueItemViewModel("row-2", installerSource);
        long installerGeneration = installer.BeginDetection();
        installer.CompleteDetection(new DetectedQueuedSource(
            installerSource,
            new SignableSubject(
                SignableFileType.WindowsInstaller,
                Guid.Parse("22222222-2222-2222-2222-222222222222")),
            new SourceFingerprint(installerSource.Identity, 128, DateTime.UnixEpoch, new string('B', 64))), installerGeneration);
        installer.UpdateSigningMode(SigningMode.Dual);
        installer.Apply(BatchItemState.Published, receipt: null);

        Assert.Equal("双签完成，签名已验证并发布", pe.ResultText);
        Assert.Equal("单签完成，签名已验证并发布", installer.ResultText);
    }

    [Fact]
    public void DetectionTerminalIsImmutableAndIntegrityRequiresRemoveAndReadd()
    {
        QueueItemViewModel row = CreatePendingRow();
        long generation = row.BeginDetection();

        row.CompleteDetection(CreateDetectedSource(row.Source), generation);

        Assert.Equal(QueueItemDetectionState.Supported, row.DetectionState);
        Assert.Throws<InvalidOperationException>(() => row.BeginDetection());
        Assert.Throws<InvalidOperationException>(() => row.CancelDetection(generation));

        row.MarkSourceChanged();

        Assert.Equal(QueueItemDetectionState.Supported, row.DetectionState);
        Assert.Equal(QueueItemSourceIntegrityState.Changed, row.SourceIntegrityState);
        Assert.Equal("源文件已更改，请移除后重新添加", row.SourceStateText);
        Assert.Throws<InvalidOperationException>(row.MarkSourceCurrent);
        Assert.Throws<InvalidOperationException>(row.MarkSourceUnavailable);
    }

    [Theory]
    [InlineData(QueueItemDetectionState.Blocked)]
    [InlineData(QueueItemDetectionState.Faulted)]
    [InlineData(QueueItemDetectionState.Cancelled)]
    public void NonSupportedDetectionTerminalIsImmutable(QueueItemDetectionState terminal)
    {
        QueueItemViewModel row = CreatePendingRow();
        long generation = row.BeginDetection();

        switch (terminal)
        {
            case QueueItemDetectionState.Blocked:
                row.BlockDetection(generation);
                break;
            case QueueItemDetectionState.Faulted:
                row.FaultDetection(generation);
                break;
            case QueueItemDetectionState.Cancelled:
                row.CancelDetection(generation);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(terminal), terminal, null);
        }

        Assert.Equal(terminal, row.DetectionState);
        Assert.Throws<InvalidOperationException>(() => row.BeginDetection());
        Assert.Throws<InvalidOperationException>(() => row.BlockDetection(generation));
        Assert.Empty(row.DestinationPath);
        Assert.False(string.IsNullOrWhiteSpace(row.AutomationName));
    }

    [Fact]
    public void DetectionAndPlanningGenerationsAdvanceOnlyTheirOwningAxes()
    {
        QueueItemViewModel row = CreatePendingRow();
        long detectionGeneration = row.BeginDetection();
        long initialPlanGeneration = row.PlanGeneration;
        long initialExecutionGeneration = row.ExecutionGeneration;
        row.CompleteDetection(CreateDetectedSource(row.Source), detectionGeneration);

        long planGeneration = row.BeginPlan(configGeneration: 7, outputGeneration: 11);

        Assert.Equal(detectionGeneration, row.DetectionGeneration);
        Assert.Equal(initialPlanGeneration + 1, planGeneration);
        Assert.Equal(planGeneration, row.PlanGeneration);
        Assert.Equal(initialExecutionGeneration, row.ExecutionGeneration);
        Assert.Equal(QueueItemPreflightState.Planning, row.PreflightState);

        long executionGeneration = row.BeginExecutionAttempt();

        Assert.Equal(initialExecutionGeneration + 1, executionGeneration);
        Assert.Equal(planGeneration, row.PlanGeneration);
        Assert.Equal(detectionGeneration, row.DetectionGeneration);
    }

    [Fact]
    public void PlanningTransitionsRejectRegressionsAndHistoricalRewrites()
    {
        QueueItemViewModel row = CreatePendingRow();
        long detectionGeneration = row.BeginDetection();
        row.CompleteDetection(CreateDetectedSource(row.Source), detectionGeneration);
        row.BeginPlan(configGeneration: 1, outputGeneration: 2);
        IntakeFile planned = CreatePlannedFile(row.Source, @"C:\queue\out-one\pending.exe");
        row.CommitOutputPlan(planned, outputGeneration: 2);
        row.SetPreflightReady();
        var retained = new BatchItemRequest(row.ItemId, planned, "{}");
        row.RetainRequest(retained);
        row.Apply(BatchItemState.Failed, receipt: null);

        Assert.Throws<InvalidOperationException>(() => row.InvalidateOutputPlan());
        Assert.Throws<InvalidOperationException>(() => row.BeginPlan(3, 4));
        Assert.Throws<InvalidOperationException>(() => row.MarkSourceChanged());
        Assert.Throws<InvalidOperationException>(() => row.CommitOutputPlan(
            CreatePlannedFile(row.Source, @"C:\queue\out-two\pending.exe"),
            outputGeneration: 4));
        Assert.Throws<InvalidOperationException>(() => row.RetainRequest(new BatchItemRequest(
            row.ItemId,
            planned,
            "{\"changed\":true}")));
        row.UpdateSigningMode(SigningMode.Dual);
        Assert.Same(retained, row.RetainedRequest);
        Assert.Equal(@"C:\queue\out-one\pending.exe", row.DestinationPath);
        Assert.Equal(SigningMode.Single, row.RequestedMode);
        Assert.Equal(QueueItemDetectionState.Supported, row.DetectionState);
        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        Assert.Equal(BatchItemState.Failed, row.State);
    }

    [Fact]
    public void ReadyPlanRejectsCommitWithoutMutatingRowStateOrDestination()
    {
        QueueItemViewModel row = CreatePendingRow();
        long detectionGeneration = row.BeginDetection();
        row.CompleteDetection(CreateDetectedSource(row.Source), detectionGeneration);
        row.BeginPlan(configGeneration: 1, outputGeneration: 2);
        IntakeFile initialPlan = CreatePlannedFile(row.Source, @"C:\queue\out-one\pending.exe");
        row.CommitOutputPlan(initialPlan, outputGeneration: 2);
        row.SetPreflightReady();

        IntakeFile? retainedFile = row.CurrentIntakeFile;
        string destinationBefore = row.DestinationPath;
        long planGenerationBefore = row.PlanGeneration;
        long outputGenerationBefore = row.OutputGeneration;
        QueueItemPreflightState preflightStateBefore = row.PreflightState;

        Assert.Throws<InvalidOperationException>(() => row.CommitOutputPlan(
            CreatePlannedFile(row.Source, @"C:\queue\out-two\pending.exe"),
            outputGeneration: 3));

        Assert.Same(retainedFile, row.CurrentIntakeFile);
        Assert.Equal(destinationBefore, row.DestinationPath);
        Assert.Equal(planGenerationBefore, row.PlanGeneration);
        Assert.Equal(outputGenerationBefore, row.OutputGeneration);
        Assert.Equal(preflightStateBefore, row.PreflightState);
    }

    [Theory]
    [InlineData(QueueItemPreflightState.Unplanned)]
    [InlineData(QueueItemPreflightState.Stale)]
    [InlineData(QueueItemPreflightState.Blocked)]
    public void MutablePlanStatesCanReenterPlanning(QueueItemPreflightState initialState)
    {
        QueueItemViewModel row = CreatePendingRow();
        long detectionGeneration = row.BeginDetection();
        row.CompleteDetection(CreateDetectedSource(row.Source), detectionGeneration);

        if (initialState is QueueItemPreflightState.Stale or QueueItemPreflightState.Blocked)
        {
            row.BeginPlan(configGeneration: 1, outputGeneration: 2);
            if (initialState == QueueItemPreflightState.Stale)
            {
                row.InvalidateOutputPlan();
            }
            else
            {
                row.SetPreflightBlocked(new QueueItemPreflightIssue(
                    QueueItemPreflightIssueCode.OutputUnavailable,
                    "output-unavailable"));
            }
        }

        Assert.Equal(initialState, row.PreflightState);
        row.BeginPlan(configGeneration: 3, outputGeneration: 4);

        Assert.Equal(QueueItemPreflightState.Planning, row.PreflightState);
        Assert.Equal(3, row.ConfigGeneration);
        Assert.Equal(4, row.OutputGeneration);
    }

    [Fact]
    public async Task SelectionMultipleSelectedRowsRemainRemoveSelection()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        await viewModel.QueueFilesAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);

        viewModel.Rows[0].IsSelected = true;
        viewModel.Rows[1].IsSelected = true;

        Assert.True(viewModel.RemoveCommand.CanExecute(null));
        viewModel.RemoveSelected();
        Assert.Empty(viewModel.Rows);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionFirstAddBecomesCurrentAndLaterAddDoesNotStealFocus()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);

        await viewModel.QueueFilesAsync([@"C:\queue\first.exe"]);
        QueueItemViewModel first = Assert.Single(viewModel.Rows);
        Assert.Same(first, viewModel.CurrentItem);

        await viewModel.QueueFilesAsync([@"C:\queue\second.exe"]);

        Assert.Equal(2, viewModel.Rows.Count);
        Assert.Same(first, viewModel.CurrentItem);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionRemovingCurrentChoosesNextThenPreviousThenNull()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        await viewModel.QueueFilesAsync(
            [@"C:\queue\first.exe", @"C:\queue\second.exe", @"C:\queue\third.exe"]);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];
        QueueItemViewModel third = viewModel.Rows[2];

        await viewModel.SetCurrentItemAsync(second.ItemId);
        viewModel.RemoveQueueItemCommand.Execute(second);
        Assert.Same(third, viewModel.CurrentItem);

        viewModel.RemoveQueueItemCommand.Execute(third);
        Assert.Same(first, viewModel.CurrentItem);

        viewModel.RemoveQueueItemCommand.Execute(first);
        Assert.Null(viewModel.CurrentItem);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionRemovingNonCurrentPreservesCurrent()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        await viewModel.QueueFilesAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        QueueItemViewModel current = viewModel.Rows[0];

        viewModel.RemoveQueueItemCommand.Execute(viewModel.Rows[1]);

        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionCtrlShiftMultiSelectChangesOnlyRemoveSelection()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        await viewModel.QueueFilesAsync(
            [@"C:\queue\first.exe", @"C:\queue\second.exe", @"C:\queue\third.exe"]);
        QueueItemViewModel current = viewModel.Rows[0];

        viewModel.Rows[1].IsSelected = true;
        viewModel.Rows[2].IsSelected = true;

        Assert.Same(current, viewModel.CurrentItem);
        Assert.True(viewModel.RemoveCommand.CanExecute(null));
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task SignCommandSubmitsPendingRowsSequentially()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);

        Assert.Equal(
            CurrentItemExecutionCapability.ItemTargetedExecution,
            viewModel.CurrentItemExecutionCapability);
        Assert.True(viewModel.SignCommand.CanExecute(null));

        await viewModel.SignCommand.ExecuteAsync(null);

        Assert.Equal(BatchItemState.Published, viewModel.Rows[0].State);
        Assert.Equal(BatchItemState.Published, viewModel.Rows[1].State);
        Assert.Equal([viewModel.Rows[0].ItemId, viewModel.Rows[1].ItemId], batch.RunItemIds);
        Assert.Equal(2, batch.ProductionCalls);
    }

    [Fact]
    public async Task RetryCommandResumesOnlyCurrentFailedRow()
    {
        using var fixture = new ExecutionFixture("first.exe", "second.exe");
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyViewModelAsync(batch);
        string[] sourceHashes = fixture.SourcePaths.Select(ExecutionFixture.SourceHash).ToArray();
        QueueItemViewModel first = await fixture.QueueAndPreflightAsync(viewModel, fixture.SourcePaths[0]);
        var retained = new BatchItemRequest(
            first.ItemId,
            first.File,
            SigningPlanJson.Serialize(viewModel.BuildSigningPlan(first.File)));
        first.RetainRequest(retained);
        batch.SeedRetainedRequest(retained);
        first.Apply(BatchItemState.Failed, receipt: null);

        await viewModel.QueueFilesAndWaitAsync([fixture.SourcePaths[1]]);
        QueueItemViewModel second = viewModel.Rows[1];
        await viewModel.SetCurrentItemAsync(second.ItemId);
        await viewModel.SignAsync();
        await viewModel.SetCurrentItemAsync(first.ItemId);
        await viewModel.RetryAsync();

        Assert.Equal([second.ItemId], batch.RunItemIds);
        Assert.Equal([first.ItemId], batch.ResumeItemIds);
        Assert.Equal(2, batch.ProductionCalls);
        Assert.Equal(sourceHashes, fixture.SourcePaths.Select(ExecutionFixture.SourceHash));
    }

    [Fact]
    public async Task SelectionNoCurrentHasDeterministicDisabledReason()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        await viewModel.QueueFilesAsync([@"C:\queue\first.exe"]);

        await viewModel.SetCurrentItemAsync(null);

        Assert.Null(viewModel.CurrentItem);
        Assert.False(viewModel.CanSign);
        Assert.False(viewModel.RetryCommand.CanExecute(null));
        Assert.Equal("请选择一个签名文件项目", viewModel.SignDisabledReason);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionUnselectedTerminalAndBlockedRowsDoNotChangeCurrentActions()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        await viewModel.QueueFilesAndWaitAsync(
            [@"C:\queue\current.exe", @"C:\queue\failed.exe", @"C:\queue\blocked.exe",
             @"C:\queue\published.exe", @"C:\queue\skipped.exe"]);
        QueueItemViewModel current = viewModel.Rows[0];
        viewModel.Rows[1].Apply(BatchItemState.Failed, receipt: null);
        viewModel.Rows[2].SetPreflightBlocked(
            new QueueItemPreflightIssue(QueueItemPreflightIssueCode.SourceUnavailable, "source-unavailable"));
        viewModel.Rows[3].Apply(BatchItemState.Published, receipt: null);
        viewModel.Rows[4].Apply(BatchItemState.SkippedAlreadySigned, receipt: null);
        await viewModel.QueueFilesAsync([]);

        Assert.Same(current, viewModel.CurrentItem);
        Assert.True(viewModel.CanSign);
        Assert.False(viewModel.RetryCommand.CanExecute(null));
        Assert.Empty(viewModel.SignDisabledReason);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionRapidUnknownAndStaleTransitionsDoNotStartAdaptersOrMutateWrongRow()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        await viewModel.QueueFilesAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];

        await Task.WhenAll(
            viewModel.SetCurrentItemAsync(second.ItemId),
            viewModel.SetCurrentItemAsync(first.ItemId),
            viewModel.SetCurrentItemAsync(second.ItemId));
        await viewModel.SetCurrentItemAsync("unknown-item");
        second.IsSelected = true;
        viewModel.RemoveSelected();
        await viewModel.QueueFilesAsync([@"C:\queue\second.exe"]);
        QueueItemViewModel replacement = viewModel.Rows.Single(row => row.FullPath.EndsWith("second.exe", StringComparison.Ordinal));
        await viewModel.SetCurrentItemAsync(second.ItemId);

        Assert.NotEqual(second.ItemId, replacement.ItemId);
        Assert.Same(first, viewModel.CurrentItem);
        Assert.Equal(BatchItemState.Pending, replacement.State);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task SelectionQueueItemRetainsIndependentDualAxisAndGenerationState()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        await viewModel.QueueFilesAndWaitAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];
        IntakeFile originalFile = first.File;
        var retained = new BatchItemRequest(first.ItemId, originalFile, "{}");

        first.SetPreflightChecking(configGeneration: 3, outputGeneration: 4);
        first.SetPreflightBlocked(
            new QueueItemPreflightIssue(QueueItemPreflightIssueCode.SourceUnavailable, "source-unavailable"));
        first.RetainRequest(retained);
        first.Apply(BatchItemState.Failed, receipt: null);

        Assert.Equal(new QueuedSource(originalFile.OriginalPath, originalFile.Identity), first.Source);
        Assert.Same(originalFile, first.CurrentIntakeFile);
        Assert.Equal(BatchItemState.Failed, first.State);
        Assert.Equal(QueueItemPreflightState.Blocked, first.PreflightState);
        Assert.Equal(QueueItemPreflightIssueCode.SourceUnavailable, first.PreflightIssue?.Code);
        Assert.Equal(3, first.ConfigGeneration);
        Assert.Equal(4, first.OutputGeneration);
        Assert.True(first.ValidationGeneration > 0);
        Assert.Same(retained, first.RetainedRequest);
        Assert.Equal(BatchItemState.Pending, second.State);
        Assert.NotEqual(first.ValidationGeneration, second.ValidationGeneration);
        Assert.Equal(0, batch.ProductionCalls);
    }

    private static SigningWorkbenchViewModel CreateViewModel(IBatchAdapter batch, IIntakeAdapter? intake = null) => new(
        new FixedReadinessAdapter(),
        intake ?? new FixedIntakeAdapter(),
        batch,
        new NoopOperatorShell(),
        new HealthyWorkerHealthService(),
        new NoopWorkerRepairService(),
        static _ => ValueTask.FromResult(true));

    private static QueueItemViewModel CreatePendingRow()
    {
        var identity = new StableFileIdentity(17, "pending-file-id");
        return new QueueItemViewModel(
            "row-1",
            new QueuedSource(@"C:\queue\pending.exe", "pending.exe", identity));
    }

    private static DetectedQueuedSource CreateDetectedSource(QueuedSource source) => new(
        source,
        new SignableSubject(
            SignableFileType.PortableExecutable,
            Guid.Parse("11111111-1111-1111-1111-111111111111")),
        new SourceFingerprint(source.Identity, 128, DateTime.UnixEpoch, new string('A', 64)));

    private static IntakeFile CreatePlannedFile(QueuedSource source, string destinationPath) => new(
        source.CanonicalPath,
        source.RelativePath,
        destinationPath,
        Path.GetDirectoryName(destinationPath)!,
        source.Identity,
        CreateDetectedSource(source).Subject);

    private static async Task<SigningWorkbenchViewModel> CreateReadyViewModelAsync(RecordingBatchAdapter batch)
    {
        SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = Assert.Single(viewModel.Certificates);
        await viewModel.ReplanOutputRootAsync(@"C:\queue\out");
        return viewModel;
    }

    private sealed class FixedReadinessAdapter : IReadinessAdapter
    {
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
                [new EligibleCertificate(
                    System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                    "My",
                    new string('A', 40),
                    "CN=Queue",
                    "CN=Issuer",
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddDays(1),
                    true,
                    [CertificateCatalogProbe.CodeSigningEkuOid])],
                []),
            new TimestampConfiguration(TimestampConfigurationStatus.Configured, timestampUri),
            ProviderAuthorizationStatus.AuthorizationUnknown,
            new WindowsPowerShellBridgeReadiness(
                WindowsPowerShellBridgeStatus.Available,
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "5.1",
                "None"));
    }

    private sealed class FixedIntakeAdapter : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            string root = outputRoot ?? @"C:\queue\out";
            IntakeFile[] files = inputs.Select((path, index) => FileFor(path, root, index)).ToArray();
            return Task.FromResult(new IntakePlan(root, files));
        }

        private static IntakeFile FileFor(string path, string outputRoot, int index)
        {
            PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(Path.GetExtension(path));
            Assert.True(subject.IsSuccess);
            return new IntakeFile(
                path,
                Path.GetFileName(path),
                Path.Combine(outputRoot, Path.GetFileName(path)),
                outputRoot,
                new StableFileIdentity((ulong)(index + 1), path),
                new SignableSubject(subject.Value!, Guid.NewGuid(), null));
        }
    }

    private sealed class RecordingBatchAdapter : IBatchAdapter
    {
        private TaskCompletionSource<BatchProgressUpdate>? blockedRun;
        private ExecutionAttemptContext? blockedAttempt;
        private TaskCompletionSource<BatchProgressUpdate>? blockedResume;
        private ExecutionAttemptContext? blockedResumeAttempt;
        private readonly Dictionary<string, BatchItemRequest> retainedRequests = new(StringComparer.Ordinal);

        public int ProductionCalls { get; private set; }

        public int LegacyOverloadCalls { get; private set; }

        public BatchItemState RunResultState { get; set; } = BatchItemState.Published;

        public BatchResultCode? RunResultCode { get; set; }

        public Exception? RunFailure { get; set; }

        public BatchItemState ResumeResultState { get; set; } = BatchItemState.Published;

        public List<string> RunItemIds { get; } = [];

        public List<string> ResumeItemIds { get; } = [];

        public List<string> CancelItemIds { get; } = [];

        public List<string> PrunedItemIds { get; } = [];

        public List<ExecutionAttemptContext> Attempts { get; } = [];

        public List<BatchItemRequest> ObservedRequests { get; } = [];

        public List<string> RequestHashes { get; } = [];

        public bool FailPrune { get; set; }

        public TaskCompletionSource RunStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ResumeStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

        public void SeedRetainedRequest(BatchItemRequest request) =>
            retainedRequests.Add(request.ItemId, request);

        public Task<BatchProgressUpdate> RunAsync(BatchItemRequest request, CancellationToken cancellationToken)
        {
            LegacyOverloadCalls++;
            throw new InvalidOperationException("Production execution must supply an attempt context.");
        }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            ExecutionAttemptContext attempt,
            CancellationToken cancellationToken)
        {
            ProductionCalls++;
            RunItemIds.Add(request.ItemId);
            Attempts.Add(attempt);
            retainedRequests.Add(request.ItemId, request);
            ObserveRequest(request);
            blockedAttempt = attempt;
            RunStarted.TrySetResult();
            if (RunFailure is not null)
            {
                throw RunFailure;
            }
            BatchItemReceipt? receipt = RunResultCode is { } code
                ? new BatchItemReceipt(request.ItemId, RunResultState, code,
                    request.File.OriginalPath, request.File.DestinationPath,
                    null, null, null, null, unchecked((int)0x80131620))
                : null;
            return blockedRun?.Task.WaitAsync(cancellationToken) ??
                Task.FromResult(new BatchProgressUpdate(attempt, RunResultState, receipt));
        }

        public Task<BatchProgressUpdate> ResumeAsync(
            string itemId,
            bool retryFailed,
            CancellationToken cancellationToken)
        {
            LegacyOverloadCalls++;
            throw new InvalidOperationException("Production retry must supply an attempt context.");
        }

        public Task<BatchProgressUpdate> ResumeAsync(
            ExecutionAttemptContext attempt,
            bool retryFailed,
            CancellationToken cancellationToken)
        {
            ProductionCalls++;
            ResumeItemIds.Add(attempt.ItemId);
            Attempts.Add(attempt);
            ObserveRequest(retainedRequests[attempt.ItemId]);
            blockedResumeAttempt = attempt;
            ResumeStarted.TrySetResult();
            return blockedResume?.Task.WaitAsync(cancellationToken) ??
                Task.FromResult(new BatchProgressUpdate(attempt, ResumeResultState, null));
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken)
        {
            ProductionCalls++;
            CancelItemIds.Add(itemId);
            return Task.CompletedTask;
        }

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
            if (FailPrune)
            {
                throw new BatchAdapterItemContextException(
                    BatchAdapterItemContextError.UnknownItem,
                    "The fake retained context could not be pruned.");
            }

            PrunedItemIds.AddRange(itemIds);
        }

        public void BlockNextRun() => blockedRun = new TaskCompletionSource<BatchProgressUpdate>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public void BlockNextResume() => blockedResume = new TaskCompletionSource<BatchProgressUpdate>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public void CompleteBlockedRun(string itemId)
        {
            ExecutionAttemptContext attempt = blockedAttempt ??
                throw new InvalidOperationException("No attempt is blocked.");
            Assert.Equal(itemId, attempt.ItemId);
            blockedRun?.TrySetResult(new BatchProgressUpdate(attempt, BatchItemState.Published, null));
            blockedRun = null;
            blockedAttempt = null;
        }

        public void CompleteBlockedResume(BatchItemState state)
        {
            ExecutionAttemptContext attempt = blockedResumeAttempt ??
                throw new InvalidOperationException("No retry attempt is blocked.");
            blockedResume?.TrySetResult(new BatchProgressUpdate(attempt, state, null));
            blockedResume = null;
            blockedResumeAttempt = null;
        }

        public void PublishProgress(BatchProgressUpdate update) =>
            ProgressChanged?.Invoke(this, new BatchProgressChangedEventArgs(update));

        private void ObserveRequest(BatchItemRequest request)
        {
            ObservedRequests.Add(request);
            RequestHashes.Add(Convert.ToHexString(SHA256.HashData(
                JsonSerializer.SerializeToUtf8Bytes(request))));
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
