using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Windows.Files;
using System.Reflection;

namespace CodeSigner.App.Tests;

public sealed partial class FileTaskQueueAdmissionDetectionTests
{
    [Fact]
    public async Task LateDetectionCannotRewriteTerminalRowOrStopPeers()
    {
        var intake = new ControlledIntakeAdapter();
        intake.BlockDetection("first.exe");
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(["first.exe", "second.exe"]);
        await intake.WaitForDetectionAsync("first.exe");
        QueueItemViewModel first = viewModel.Rows[0];
        try
        {
            first.Apply(CodeSigner.Windows.Batch.BatchItemState.Failed, receipt: null);
        }
        finally
        {
            intake.ReleaseDetection("first.exe");
        }
        await intake.WaitForAllDetectionsAsync(2);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (viewModel.Rows[1].DetectionState != QueueItemDetectionState.Supported)
        {
            await Task.Delay(10, timeout.Token);
        }
        Assert.Equal(CodeSigner.Windows.Batch.BatchItemState.Failed, first.State);
        Assert.Null(first.DetectedSource);
        Assert.Equal(0, intake.PlanOutputCalls);
    }

    [Fact]
    public async Task AcceptedRowsAppearBeforeDetectionAndCurrentItemOnlyChangesPendingPriority()
    {
        var intake = new ControlledIntakeAdapter();
        intake.BlockDetection("first.exe");
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);

        Task queue = viewModel.QueueFilesAsync(["first.exe", "second.exe", "third.exe"]);
        await intake.WaitForDetectionAsync("first.exe");
        try
        {
            Assert.Equal(3, viewModel.Rows.Count);
            Assert.All(viewModel.Rows, row => Assert.NotEqual(QueueItemDetectionState.Supported, row.DetectionState));
            string thirdId = viewModel.Rows.Single(row => row.DisplayName == "third.exe").ItemId;
            await viewModel.SetCurrentItemAsync(thirdId);
            await viewModel.SetCurrentItemAsync(thirdId);
        }
        finally
        {
            intake.ReleaseDetection("first.exe");
        }

        await queue;
        await intake.WaitForDetectionAsync("third.exe");
        await intake.WaitForAllDetectionsAsync(3);

        Assert.Equal(["first.exe", "third.exe", "second.exe"], intake.DetectionOrder);
        Assert.All(intake.DetectionCounts.Values, count => Assert.Equal(1, count));
        Assert.Equal(0, intake.PlanOutputCalls);
    }

    [Fact]
    public async Task MixedDetectionTerminalsAreRowLocalAndPeersContinue()
    {
        var intake = new ControlledIntakeAdapter();
        intake.SetResult("blocked.exe", QueuedSourceDetectionStatus.Blocked);
        intake.SetFault("faulted.exe");
        intake.SetResult("changed.exe", QueuedSourceDetectionStatus.Changed);
        intake.SetMalformedSupported("malformed.exe");
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);

        await viewModel.QueueFilesAsync(["good.exe", "blocked.exe", "faulted.exe", "changed.exe", "malformed.exe"]);
        await intake.WaitForAllDetectionsAsync(5);

        Assert.Equal(QueueItemDetectionState.Supported, Row("good.exe").DetectionState);
        Assert.Equal(QueueItemDetectionState.Blocked, Row("blocked.exe").DetectionState);
        Assert.Equal(QueueItemDetectionState.Faulted, Row("faulted.exe").DetectionState);
        Assert.Equal(QueueItemDetectionState.Faulted, Row("changed.exe").DetectionState);
        Assert.Equal(QueueItemDetectionState.Faulted, Row("malformed.exe").DetectionState);
        Assert.Equal(5, intake.DetectionCounts.Count);
        Assert.Equal(0, intake.PlanOutputCalls);

        QueueItemViewModel Row(string name) => viewModel.Rows.Single(row => row.DisplayName == name);
    }

    [Fact]
    public async Task OverlappingAdmissionsSerializeAndSeparateAddsDedupePathAndIdentity()
    {
        var intake = new ControlledIntakeAdapter();
        intake.BlockNextAdmission();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);

        Task first = viewModel.QueueFilesAsync(["first.exe"]);
        await intake.FirstAdmissionStarted.Task;
        Task second = viewModel.QueueFilesAsync(["second.exe"]);
        await Task.Delay(50);
        Assert.Equal(1, intake.AdmissionCalls);

        intake.ReleaseAdmission();
        await Task.WhenAll(first, second);
        await intake.WaitForAllDetectionsAsync(2);
        await viewModel.QueueFilesAsync(["first.exe", "first-alias.exe"]);

        Assert.Equal(1, intake.MaxConcurrentAdmissions);
        Assert.Equal(2, viewModel.Rows.Count);
        Assert.Equal(1, intake.DetectionCounts["first.exe"]);
        Assert.DoesNotContain("first-alias.exe", intake.DetectionCounts.Keys);
    }

    [Fact]
    public async Task RemoveCancelsOldGenerationAndLateResultCannotMutateReaddedRow()
    {
        var intake = new ControlledIntakeAdapter { IgnoreDetectionCancellation = true };
        intake.BlockDetection("same.exe");
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);

        Task firstAdd = viewModel.QueueFilesAsync(["same.exe"]);
        await intake.WaitForDetectionAsync("same.exe");
        QueueItemViewModel removed;
        Task readd;
        try
        {
            removed = Assert.Single(viewModel.Rows);
            removed.IsSelected = true;
            viewModel.RemoveSelected();
            readd = viewModel.QueueFilesAsync(["same.exe"]);
        }
        finally
        {
            intake.ReleaseDetection("same.exe");
        }

        await firstAdd;
        await readd;
        await intake.WaitForDetectionCountAsync("same.exe", 2);

        QueueItemViewModel replacement = Assert.Single(viewModel.Rows);
        Assert.NotEqual(removed.ItemId, replacement.ItemId);
        Assert.Equal(QueueItemDetectionState.Supported, replacement.DetectionState);
        Assert.Equal(2, intake.DetectionCounts["same.exe"]);
    }

    [Fact]
    public async Task RemovingQueuedRowPreventsItsProbeAndAllowsActivePeerToFinish()
    {
        var intake = new ControlledIntakeAdapter();
        intake.BlockDetection("active.exe");
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(["active.exe", "queued.exe"]);
        await intake.WaitForDetectionAsync("active.exe");
        QueueItemViewModel queued = viewModel.Rows.Single(row => row.DisplayName == "queued.exe");

        queued.IsSelected = true;
        viewModel.RemoveSelected();
        intake.ReleaseDetection("active.exe");
        await intake.WaitForAllDetectionsAsync(1);

        Assert.Single(viewModel.Rows);
        Assert.DoesNotContain("queued.exe", intake.DetectionCounts.Keys);
        Assert.Equal(QueueItemDetectionState.Supported, viewModel.Rows[0].DetectionState);
    }

    [Fact]
    public async Task RemovingQueuedRowDisposesItsUnstartedDetectionCancellationSource()
    {
        var intake = new ControlledIntakeAdapter();
        intake.BlockDetection("active.exe");
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(["active.exe", "queued.exe"]);
        await intake.WaitForDetectionAsync("active.exe");
        QueueItemViewModel queued = viewModel.Rows.Single(row => row.DisplayName == "queued.exe");
        CancellationTokenSource cancellation = QueuedDetectionCancellation(viewModel, queued.ItemId);

        queued.IsSelected = true;
        viewModel.RemoveSelected();

        Assert.Throws<ObjectDisposedException>(cancellation.Cancel);
        intake.ReleaseDetection("active.exe");
        await intake.WaitForAllDetectionsAsync(1);
        Assert.DoesNotContain("queued.exe", intake.DetectionCounts.Keys);
    }

    [Fact]
    public async Task DisposeCancelsInFlightDetectionWithoutProtectedCalls()
    {
        var intake = new ControlledIntakeAdapter();
        intake.BlockDetection("dispose.exe");
        SigningWorkbenchViewModel viewModel = CreateViewModel(intake);

        Task queue = viewModel.QueueFilesAsync(["dispose.exe"]);
        await intake.WaitForDetectionAsync("dispose.exe");
        await viewModel.DisposeAsync();
        intake.ReleaseDetection("dispose.exe");
        await queue;

        Assert.True(intake.DetectionCancellationObserved);
        Assert.Equal(0, intake.PlanOutputCalls);
    }

    [Fact]
    public async Task AdmissionFailureDoesNotGateOrRefocusExistingReadyCurrentItem()
    {
        var intake = new ControlledIntakeAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake);
        await viewModel.QueueFilesAsync(["ready.exe"]);
        await intake.WaitForAllDetectionsAsync(1);
        QueueItemViewModel current = Assert.Single(viewModel.Rows);
        DetectedQueuedSource detected = Assert.IsType<DetectedQueuedSource>(current.DetectedSource);
        current.BeginPlan(0, 0);
        current.CommitOutputPlan(new IntakeFile(
            current.FullPath,
            current.DisplayName,
            "out/ready.exe",
            "out",
            current.Source.Identity,
            detected.Subject), 0);
        current.SetPreflightReady();
        string focusBefore = viewModel.FocusTargetAutomationId;
        intake.SetAdmissionFailure("missing.exe", QueuedSourceAdmissionError.InputNotFound);

        await viewModel.QueueFilesAsync(["missing.exe"]);

        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal(QueueItemPreflightState.Ready, current.PreflightState);
        Assert.Equal(focusBefore, viewModel.FocusTargetAutomationId);
        Assert.NotEmpty(viewModel.InputError);
        Assert.Equal(1, intake.DetectionCounts["ready.exe"]);
    }

    [Fact]
    public async Task PersistedAdmissionAndDetectionEachHaveStartThenOneTerminal()
    {
        var intake = new ControlledIntakeAdapter();
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, audit);

        await viewModel.QueueFilesAsync(["audit.exe"]);
        await intake.WaitForAllDetectionsAsync(1);

        string[] lifecycleEvents = audit.EventNames.Where(eventName => eventName is
            SigningRuntimeEventNames.AdmissionStarted or
            SigningRuntimeEventNames.AdmissionCompleted or
            SigningRuntimeEventNames.DetectionStarted or
            SigningRuntimeEventNames.DetectionCompleted).ToArray();
        Assert.Equal(
            [
                SigningRuntimeEventNames.AdmissionStarted,
                SigningRuntimeEventNames.AdmissionCompleted,
                SigningRuntimeEventNames.DetectionStarted,
                SigningRuntimeEventNames.DetectionCompleted
            ],
            lifecycleEvents);
        Assert.Equal(3, audit.OperationIds.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(SigningRuntimeEventNames.ItemSelected, audit.EventNames);
        Assert.DoesNotContain(audit.ItemIds, itemId => itemId?.Contains("audit.exe", StringComparison.Ordinal) == true);
    }

    private static CancellationTokenSource QueuedDetectionCancellation(
        SigningWorkbenchViewModel viewModel,
        string itemId)
    {
        FieldInfo workByItemField = typeof(SigningWorkbenchViewModel).GetField(
            "detectionWorkByItem",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object workByItem = workByItemField.GetValue(viewModel)!;
        PropertyInfo itemProperty = workByItem.GetType().GetProperty("Item")!;
        object work = itemProperty.GetValue(workByItem, [itemId])!;
        PropertyInfo cancellationProperty = work.GetType().GetProperty("Cancellation")!;
        return Assert.IsAssignableFrom<CancellationTokenSource>(cancellationProperty.GetValue(work));
    }

}
