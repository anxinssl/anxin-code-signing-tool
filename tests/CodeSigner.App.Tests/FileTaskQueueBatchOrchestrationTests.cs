using System.IO;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.Tests;

public sealed partial class FileTaskQueueStateMachineTests
{
    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueSaveFailureExplainsChangingOutputAndReaddingWithoutRetargetingRetry()
    {
        var batch = new RecordingBatchAdapter
        {
            RunResultState = BatchItemState.Failed,
            RunResultCode = BatchResultCode.OutputSaveFailed
        };
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        QueueItemViewModel first = viewModel.Rows[0];

        await viewModel.SignQueueAsync();

        Assert.Equal(BatchResultCode.OutputSaveFailed, first.Receipt?.Code);
        Assert.Contains("更改输出位置", first.ResultText, StringComparison.Ordinal);
        Assert.Contains("更改文件输出位置", first.DetailText, StringComparison.Ordinal);
        Assert.Contains("移除并重新添加", first.DetailText, StringComparison.Ordinal);
        Assert.Contains("更改输出位置", viewModel.QueueStatusText, StringComparison.Ordinal);
        Assert.Contains("更改输出位置", viewModel.StatusMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("工作程序意外停止", first.ResultText, StringComparison.Ordinal);
        Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
        Assert.Single(batch.RunItemIds);
        Assert.False(viewModel.CanSignQueue);

        BatchItemRequest retained = first.RetainedRequest!;
        await viewModel.ReplanOutputRootAsync(Path.Combine(Path.GetTempPath(), $"codesigner-new-output-{Guid.NewGuid():N}"));
        Assert.Same(retained, first.RetainedRequest);
        Assert.NotEqual(viewModel.OutputRoot, retained.File.OutputRoot);
        Assert.False(viewModel.CanSignQueue);
    }

    [Fact]
    public void BatchQueueTrueWorkerCrashDoesNotSuggestOutputDirectoryFailure()
    {
        QueueItemViewModel row = CreatePendingRow();
        row.Apply(BatchItemState.Failed, new BatchItemReceipt(
            row.ItemId, BatchItemState.Failed, BatchResultCode.WorkerCrashed,
            row.FullPath, @"C:\queue\out\pending.exe", null, null, null, 123, null));
        Assert.Equal("签名工作程序意外停止", row.ResultText);
        Assert.DoesNotContain("更改文件输出位置", row.DetailText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BatchQueueGuardRequiresPendingItemsAndOutputWithoutCallingAdapters()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        Assert.False(viewModel.CanSignQueue);
        viewModel.Rows.Add(CreatePendingRow());
        Assert.False(viewModel.CanSignQueue);
        viewModel.OutputRoot = Path.Combine(Path.GetTempPath(), "codesigner-queue-guard");
        Assert.True(viewModel.CanSignQueue);
        Assert.True(viewModel.SignCommand.CanExecute(null));
        Assert.Equal("签名", viewModel.SignButtonText);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Theory]
    [InlineData(BatchItemState.Failed)]
    [InlineData(BatchItemState.PausedProvider)]
    [InlineData(BatchItemState.PausedTimestamp)]
    [InlineData(BatchItemState.Cancelled)]
    public async Task BatchQueueGuardRetainedProblemsBlockNewBatchWithoutCallingAdapters(BatchItemState state)
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
        QueueItemViewModel row = CreatePendingRow();
        row.Apply(state, receipt: null);
        viewModel.Rows.Add(row);
        viewModel.OutputRoot = Path.Combine(Path.GetTempPath(), "codesigner-queue-guard");
        Assert.False(viewModel.CanSignQueue);
        Assert.Contains("重试", viewModel.QueueSignDisabledReason, StringComparison.Ordinal);
        Assert.Equal(0, batch.ProductionCalls);
    }

    // Mock execution tests require the separate approval recorded in the queue plan.
    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunUsesQueueOrderRegardlessOfSelectionAndDoesNotRepeatCompletedRows()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.msi", @"C:\queue\third.exe"]);
        viewModel.Rows[0].Apply(BatchItemState.Published, receipt: null);
        await viewModel.SetCurrentItemAsync(viewModel.Rows[2].ItemId);
        Assert.Equal("批量签名", viewModel.SignButtonText);

        await viewModel.SignCommand.ExecuteAsync(null).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal([viewModel.Rows[1].ItemId, viewModel.Rows[2].ItemId], batch.RunItemIds);
        Assert.All(viewModel.Rows, row => Assert.Equal(BatchItemState.Published, row.State));
        Assert.Equal(0, batch.LegacyOverloadCalls);
        Assert.False(viewModel.IsBusy);
        Assert.False(viewModel.CanSignQueue);
        await viewModel.SignQueueAsync();
        Assert.Equal(2, batch.RunItemIds.Count);
    }

    [Theory]
    [InlineData(BatchItemState.Failed)]
    [InlineData(BatchItemState.PausedProvider)]
    [InlineData(BatchItemState.PausedTimestamp)]
    [InlineData(BatchItemState.Cancelled)]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunStopsOnProblemAndPreservesLaterRows(BatchItemState state)
    {
        var batch = new RecordingBatchAdapter { RunResultState = state };
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);

        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal([viewModel.Rows[0].ItemId], batch.RunItemIds);
        Assert.Equal(state, viewModel.Rows[0].State);
        Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
        Assert.Null(viewModel.Rows[1].RetainedRequest);
        Assert.False(viewModel.IsBusy);
        Assert.Contains("已停止", viewModel.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunWaitsForActiveItemLocksConfigurationAndRejectsDuplicateStart()
    {
        var batch = new RecordingBatchAdapter();
        batch.BlockNextRun();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        string output = viewModel.OutputRoot;
        CertificateOptionViewModel? certificate = viewModel.PrimaryCertificate;
        Task running = viewModel.SignQueueAsync();
        try
        {
            await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Single(batch.RunItemIds);
            Assert.True(viewModel.IsBusy);
            Assert.False(viewModel.SettingsCommand.CanExecute(null));
            Assert.False(viewModel.SignCommand.CanExecute(null));
            Assert.False(viewModel.AddFilesCommand.CanExecute(null));
            await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);
            await viewModel.SignQueueAsync();
            await viewModel.SignAsync();
            viewModel.PrimaryCertificate = null;
            viewModel.SelectedMode = SigningMode.Dual;
            viewModel.OutputRoot = @"C:\queue\changed-output";
            Assert.Same(viewModel.Rows[0], viewModel.CurrentItem);
            Assert.Same(certificate, viewModel.PrimaryCertificate);
            Assert.Equal(SigningMode.Single, viewModel.SelectedMode);
            Assert.Equal(output, viewModel.OutputRoot);
            Assert.Single(batch.RunItemIds);
            batch.CompleteBlockedRun(viewModel.Rows[0].ItemId);
            await running.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal([viewModel.Rows[0].ItemId, viewModel.Rows[1].ItemId], batch.RunItemIds);
        }
        finally
        {
            await viewModel.CancelAsync();
            await running.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunCancellationDoesNotStartNextFile()
    {
        var batch = new RecordingBatchAdapter();
        batch.BlockNextRun();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        Task running = viewModel.SignQueueAsync();
        try
        {
            await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await viewModel.CancelAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await running.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal([viewModel.Rows[0].ItemId], batch.RunItemIds);
            Assert.Equal([viewModel.Rows[0].ItemId], batch.CancelItemIds);
            Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
            Assert.Null(viewModel.Rows[1].RetainedRequest);
            Assert.Contains("已取消", viewModel.StatusMessage, StringComparison.Ordinal);
            Assert.False(viewModel.IsBusy);
        }
        finally
        {
            await viewModel.CancelAsync();
            await running.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunRechecksEachFilesPolicyBeforeSubmission()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.msi", @"C:\queue\second.exe", @"C:\queue\third.msi"]);
        viewModel.SelectedMode = SigningMode.Dual;
        viewModel.SecondaryCertificate = null;

        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal([viewModel.Rows[0].ItemId], batch.RunItemIds);
        Assert.Equal(BatchItemState.Published, viewModel.Rows[0].State);
        Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
        Assert.Equal(QueueItemPreflightState.Blocked, viewModel.Rows[1].PreflightState);
        Assert.Null(viewModel.Rows[1].RetainedRequest);
        Assert.Null(viewModel.Rows[2].RetainedRequest);
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunMixedFormatsPreservePerFileSingleAndDualPlans()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.msi", @"C:\queue\third.exe"]);
        viewModel.SecondaryCertificate = viewModel.PrimaryCertificate;
        viewModel.SelectedMode = SigningMode.Dual;
        SigningPlan[] expected = viewModel.Rows.Select(row => viewModel.BuildSigningPlan(
            CreatePlannedFile(row.Source, Path.Combine(viewModel.OutputRoot, row.Source.RelativePath)) with
            {
                Subject = row.DetectedSource!.Subject
            })).ToArray();

        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, batch.ObservedRequests.Count);
        Assert.Equal(expected.Select(SigningPlanJson.Serialize), batch.ObservedRequests.Select(request => request.SigningPlanJson));
        SigningPlan[] actual = batch.ObservedRequests.Select(request =>
            SigningPlanJson.Parse(request.SigningPlanJson).Value!).ToArray();
        Assert.Equal([SigningMode.Dual, SigningMode.Single, SigningMode.Dual], actual.Select(plan => plan.EffectiveMode));
        Assert.All(viewModel.Rows, row => Assert.Equal(BatchItemState.Published, row.State));
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunFiftyFilesCompletesEachItemExactlyOnce()
    {
        var batch = new RecordingBatchAdapter();
        string[] paths = Enumerable.Range(1, 50).Select(index => $@"C:\queue\item-{index}.exe").ToArray();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(batch, paths);

        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(viewModel.Rows.Select(row => row.ItemId), batch.RunItemIds);
        Assert.Equal(50, batch.Attempts.Select(attempt => attempt.OperationId).Distinct().Count());
        Assert.All(viewModel.Rows, row => Assert.Equal(BatchItemState.Published, row.State));
        Assert.False(viewModel.IsBusy);
        Assert.Contains("50 / 50", viewModel.StatusMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunCancellationWhilePreparingNeverSubmitsAFile(bool pauseDetection)
    {
        var batch = new RecordingBatchAdapter();
        var intake = new BlockingQueueIntakeAdapter(new FixedIntakeAdapter()) { PauseDetection = pauseDetection };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch, intake);
        await viewModel.RefreshReadinessAsync();
        await viewModel.ReplanOutputRootAsync(Path.Combine(Path.GetTempPath(), $"codesigner-prepare-{Guid.NewGuid():N}"));
        await viewModel.QueueFilesAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        if (!pauseDetection)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (viewModel.Rows.Any(row => row.DetectionState != QueueItemDetectionState.Supported))
            {
                await Task.Delay(10, timeout.Token);
            }
            await viewModel.InvalidateCurrentPreflightAsync();
            intake.PauseIntegrity = true;
        }
        Task running = viewModel.SignQueueAsync();
        try
        {
            await intake.Paused.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(viewModel.IsBusy);
            await viewModel.CancelAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await running.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Empty(batch.RunItemIds);
            Assert.Empty(batch.CancelItemIds);
            Assert.All(viewModel.Rows, row => Assert.Null(row.RetainedRequest));
            Assert.False(viewModel.IsBusy);
        }
        finally
        {
            intake.Release.TrySetResult();
            await viewModel.CancelAsync();
            await running.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    private sealed class BlockingQueueIntakeAdapter(IIntakeAdapter inner) : IIntakeAdapter
    {
        public bool PauseDetection { get; init; }
        public bool PauseIntegrity { get; set; }
        public TaskCompletionSource Paused { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<QueuedSourceAdmissionResult> AdmitAsync(
            IReadOnlyCollection<string> inputs, bool recurseDirectories, CancellationToken cancellationToken) =>
            inner.AdmitAsync(inputs, recurseDirectories, cancellationToken);

        public async Task<QueuedSourceDetectionResult> DetectAsync(QueuedSource source, CancellationToken cancellationToken)
        {
            if (PauseDetection) await PauseAsync(cancellationToken);
            return await inner.DetectAsync(source, cancellationToken);
        }

        public Task<IntakeFile> PlanOutputAsync(
            DetectedQueuedSource detectedSource, string outputRoot, CancellationToken cancellationToken) =>
            inner.PlanOutputAsync(detectedSource, outputRoot, cancellationToken);

        public async Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
            DetectedQueuedSource detectedSource, CancellationToken cancellationToken)
        {
            if (PauseIntegrity) await PauseAsync(cancellationToken);
            return await inner.VerifyIntegrityAsync(detectedSource, cancellationToken);
        }

        private async Task PauseAsync(CancellationToken cancellationToken)
        {
            Paused.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
        }
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunAdapterExceptionFailsCurrentItemAndPreservesLaterRows()
    {
        var batch = new RecordingBatchAdapter { RunFailure = new InvalidOperationException("mock failure") };
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);

        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Single(batch.RunItemIds);
        Assert.Equal(BatchItemState.Failed, viewModel.Rows[0].State);
        Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
        Assert.Null(viewModel.Rows[1].RetainedRequest);
        Assert.False(viewModel.IsBusy);
        Assert.False(viewModel.CanSignQueue);
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunCanContinuePendingFilesAfterCurrentItemRetry()
    {
        var batch = new RecordingBatchAdapter { RunResultState = BatchItemState.Failed };
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(viewModel.CanSignQueue);

        await viewModel.RetryAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(BatchItemState.Published, viewModel.Rows[0].State);
        Assert.True(viewModel.CanSignQueue);
        batch.RunResultState = BatchItemState.Published;
        await viewModel.SignCommand.ExecuteAsync(null).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal([viewModel.Rows[0].ItemId, viewModel.Rows[1].ItemId], batch.RunItemIds);
        Assert.Equal([viewModel.Rows[0].ItemId], batch.ResumeItemIds);
        Assert.All(viewModel.Rows, row => Assert.Equal(BatchItemState.Published, row.State));
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunCancellationBetweenFilesDoesNotRequireActiveWorker()
    {
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        Task cancellation = Task.CompletedTask;
        viewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(SigningWorkbenchViewModel.CurrentItem) &&
                ReferenceEquals(viewModel.CurrentItem, viewModel.Rows[1]))
            {
                cancellation = viewModel.CancelAsync();
            }
        };

        await viewModel.SignQueueAsync().WaitAsync(TimeSpan.FromSeconds(5));
        await cancellation.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal([viewModel.Rows[0].ItemId], batch.RunItemIds);
        Assert.Empty(batch.CancelItemIds);
        Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
        Assert.Null(viewModel.Rows[1].RetainedRequest);
        Assert.Contains("已取消", viewModel.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "MockSigningFlow")]
    public async Task BatchQueueRunDisposeCancelsAndWaitsWithoutStartingNextFile()
    {
        var batch = new RecordingBatchAdapter();
        batch.BlockNextRun();
        await using SigningWorkbenchViewModel viewModel = await CreateBatchQueueReadyAsync(
            batch, [@"C:\queue\first.exe", @"C:\queue\second.exe"]);
        Task running = viewModel.SignQueueAsync();
        try
        {
            await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await viewModel.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            await running.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Single(batch.RunItemIds);
            Assert.Equal(BatchItemState.Pending, viewModel.Rows[1].State);
            Assert.False(viewModel.CanSignQueue);
        }
        finally
        {
            await viewModel.CancelAsync();
            await running.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    private static async Task<SigningWorkbenchViewModel> CreateBatchQueueReadyAsync(
        RecordingBatchAdapter batch, string[] paths)
    {
        SigningWorkbenchViewModel viewModel = await CreateReadyViewModelAsync(batch);
        try
        {
            await viewModel.QueueFilesAsync(paths);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (viewModel.Rows.Any(row => row.DetectionState is
                       QueueItemDetectionState.Pending or QueueItemDetectionState.Running))
            {
                await Task.Delay(10, timeout.Token);
            }
            await viewModel.ReplanOutputRootAsync(
                Path.Combine(Path.GetTempPath(), $"codesigner-batch-{Guid.NewGuid():N}"));
            return viewModel;
        }
        catch
        {
            await viewModel.DisposeAsync();
            throw;
        }
    }
}
