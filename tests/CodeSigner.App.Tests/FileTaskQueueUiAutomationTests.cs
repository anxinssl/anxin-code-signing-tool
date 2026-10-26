using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Diagnostics;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class FileTaskQueueUiSerialGroup
{
    public const string Name = "FileTaskQueueUi";
}

[Collection(FileTaskQueueUiSerialGroup.Name)]
public sealed class FileTaskQueueUiAutomationTests
{
    private static readonly KeyboardRouteStep[] Ui10KeyboardRoute =
    [
        new(Key.Down, ModifierKeys.None),
        new(Key.Up, ModifierKeys.Control),
        new(Key.Down, ModifierKeys.Shift),
        new(Key.Down, ModifierKeys.Shift),
        new(Key.Delete, ModifierKeys.None)
    ];

    private enum KeyDownReceiptKind
    {
        BubblingKeyDown,
        PreviewKeyDown
    }

    private readonly record struct KeyboardRouteStep(Key Key, ModifierKeys Modifiers);

    private sealed record ObservedRoutedKeyEventTrace(
        string EventName,
        string Key,
        string SystemKey,
        string ImeProcessedKey,
        string DeadCharProcessedKey,
        string NormalizedKey,
        string Modifiers,
        bool Handled,
        string? SourceType,
        string? OriginalSourceType);

    private sealed record ViewportSpec(
        string Label,
        double WidthDip,
        double HeightDip,
        int? ScalePercent);

    private sealed record ViewportEvidence(
        string Label,
        double RequestedWidthDip,
        double RequestedHeightDip,
        int ScalePercent,
        double ActualWidthDip,
        double ActualHeightDip,
        int BitmapWidthPixels,
        int BitmapHeightPixels,
        double RenderDpi,
        string Screenshot,
        string ScreenshotSha256,
        object WindowBounds,
        object RootBounds,
        IReadOnlyDictionary<string, object> RegionBounds,
        string StatusText,
        string AutomationName,
        string? AutomationHelpText,
        string TooltipText,
        string TextTrimming,
        bool FullTextAccessible,
        bool RegionsInsideViewport,
        bool RegionsDoNotOverlap);

    [Fact]
    [Trait("ScenarioId", "UI-10-viewport-evidence")]
    [Trait("Visibility", "NonVisible")]
    public void FakeHostViewportEvidencePlanUsesOnlyTheFrozenThreeEntryMatrix()
    {
        Assert.Equal(
        [
            new ViewportSpec("normal", 992, 736, null),
            new ViewportSpec("compact", 650.67, 480, 150),
            new ViewportSpec("ultra-compact", 480, 352, 200)
        ],
        VisibleFakeHost.ViewportEvidencePlan);
    }

    [Fact]
    [Trait("ScenarioId", "UI-10-viewport-dpi-quantization")]
    [Trait("Visibility", "NonVisible")]
    public void CapturedCompactViewportWidthIsWithinOneRenderDevicePixel()
    {
        const double requestedWidthDip = 650.67;
        const double observedWidthDip = 650.40;
        const double renderDpi = 144;
        double quantumDip = DevicePixelQuantumDip(renderDpi);

        Assert.Equal(96d / renderDpi, quantumDip, precision: 12);
        Assert.InRange(
            observedWidthDip,
            requestedWidthDip - quantumDip,
            requestedWidthDip + quantumDip);
    }

    [Fact]
    [Trait("ScenarioId", "UI-10-viewport-summary-status")]
    [Trait("Visibility", "NonVisible")]
    public void ViewportCaptureSelectsSummaryStatusByLayoutMode()
    {
        const string expectedFullStatus = "审计记录已完成，已移除敏感字段。";
        const string expectedCompactStatus = "当前文件尚未检查";

        Assert.Equal(
            expectedFullStatus,
            ExpectedViewportSummaryStatus(
                isCompactLayout: false,
                expectedFullStatus,
                expectedCompactStatus));
        Assert.Equal(
            expectedCompactStatus,
            ExpectedViewportSummaryStatus(
                isCompactLayout: true,
                expectedFullStatus,
                expectedCompactStatus));
    }

    private static string ExpectedViewportSummaryStatus(
        bool isCompactLayout,
        string expectedFullStatus,
        string expectedCompactStatus) => isCompactLayout
            ? expectedCompactStatus
            : expectedFullStatus;

    [Fact]
    [Trait("ScenarioId", "UI-10-telemetry")]
    [Trait("Visibility", "NonVisible")]
    public void PersistedInputTelemetryUsesStableScalarHandleValues()
    {
        NativeInputDeliveryTrace telemetry = FileTaskQueueTelemetrySerializationContract.CreateRepresentativeTelemetry();

        FileTaskQueueTelemetrySerializationContract.AssertPersistedTelemetryTypes([telemetry]);
        string json = FileTaskQueueEvidenceSerializer.Serialize(new { inputTelemetry = new[] { telemetry } });
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement serialized = document.RootElement
            .GetProperty("inputTelemetry")
            .EnumerateArray()
            .Single();

        Assert.Equal(JsonValueKind.Number, serialized.GetProperty("ForegroundHwnd").ValueKind);
        Assert.Equal(0x1234L, serialized.GetProperty("ForegroundHwnd").GetInt64());
        Assert.Equal(JsonValueKind.Number, serialized.GetProperty("TargetWindowHwnd").ValueKind);
        Assert.Equal(0x5678L, serialized.GetProperty("TargetWindowHwnd").GetInt64());
        Assert.Equal(JsonValueKind.Number, serialized.GetProperty("NativeFocusHwndBeforeInput").ValueKind);
        Assert.Equal(0x9ABCL, serialized.GetProperty("NativeFocusHwndBeforeInput").GetInt64());
        Assert.Equal("DataGridCell", serialized.GetProperty("BeforeInput").GetProperty("FocusedElementType").GetString());
        Assert.True(serialized.GetProperty("BeforeInput").GetProperty("CurrentCellIsValid").GetBoolean());
        Assert.Equal(0, serialized.GetProperty("BeforeInput").GetProperty("CurrentCellColumnDisplayIndex").GetInt32());
        Assert.True(serialized.GetProperty("RoutedEvents").GetProperty("KeyDownHandledAtGridAfterClassHandler").GetBoolean());
        Assert.True(serialized.GetProperty("RoutedEvents").GetProperty("KeyUpReceived").GetBoolean());
        Assert.Equal(0xDEF0L, serialized.GetProperty("ForegroundThreadId").GetInt64());
        Assert.Equal(0x1357L, serialized.GetProperty("TargetWindowThreadId").GetInt64());
        Assert.Equal(0x2468L, serialized.GetProperty("TargetDispatcherThreadId").GetInt64());
    }

    [Fact]
    [Trait("ScenarioId", "UI-10-focus-timeline")]
    [Trait("Visibility", "NonVisible")]
    public void PersistedFocusTimelineUsesStableScalarValues()
    {
        UiEventTimelineTrace telemetry = FileTaskQueueTelemetrySerializationContract.CreateRepresentativeTimelineEntry();

        FileTaskQueueTelemetrySerializationContract.AssertPersistedTimelineTypes([telemetry]);
        string json = FileTaskQueueEvidenceSerializer.Serialize(new { uiEventTimeline = new[] { telemetry } });
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement serialized = document.RootElement.GetProperty("uiEventTimeline").EnumerateArray().Single();

        Assert.Equal("GotKeyboardFocus", serialized.GetProperty("EventName").GetString());
        Assert.Equal("QueueRow_2", serialized.GetProperty("NewFocusAutomationId").GetString());
        Assert.Equal(
            serialized.GetProperty("NewFocusAutomationId").GetString(),
            serialized.GetProperty("FocusedAutomationId").GetString());
        Assert.Equal(JsonValueKind.String, serialized.GetProperty("FocusTargetAutomationId").ValueKind);
        Assert.Equal(JsonValueKind.Number, serialized.GetProperty("StopwatchTimestamp").ValueKind);
        Assert.DoesNotContain(nameof(DependencyObject), json, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(RoutedEventArgs), json, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("ScenarioId", "UI-10-route-contract")]
    [Trait("Visibility", "NonVisible")]
    public void Ui10RouteContractUsesNativeCtrlMovementShiftRangeAndDeleteReceipts()
    {
        Assert.Equal(
            [
                new KeyboardRouteStep(Key.Down, ModifierKeys.None),
                new KeyboardRouteStep(Key.Up, ModifierKeys.Control),
                new KeyboardRouteStep(Key.Down, ModifierKeys.Shift),
                new KeyboardRouteStep(Key.Down, ModifierKeys.Shift),
                new KeyboardRouteStep(Key.Delete, ModifierKeys.None)
            ],
            Ui10KeyboardRoute);
        Assert.DoesNotContain(
            Ui10KeyboardRoute,
            static step => step.Key == Key.Space && step.Modifiers == ModifierKeys.Control);
        Assert.All(
            Ui10KeyboardRoute[..^1],
            static step => Assert.Equal(KeyDownReceiptKind.BubblingKeyDown, ReceiptKindFor(step.Key)));
        Assert.Equal(KeyDownReceiptKind.PreviewKeyDown, ReceiptKindFor(Key.Delete));
        Assert.Equal(Key.Up, NormalizeObservedKey(Key.System, Key.Up, Key.None, Key.None));
        Assert.Equal(Key.Down, NormalizeObservedKey(Key.ImeProcessed, Key.None, Key.Down, Key.None));
        Assert.Equal(Key.Delete, NormalizeObservedKey(Key.DeadCharProcessed, Key.None, Key.None, Key.Delete));

        var observed = new ObservedRoutedKeyEventTrace(
            "Window.PreviewKeyDown",
            Key.ImeProcessed.ToString(),
            Key.None.ToString(),
            Key.Down.ToString(),
            Key.None.ToString(),
            Key.Down.ToString(),
            ModifierKeys.Shift.ToString(),
            Handled: true,
            nameof(System.Windows.Controls.DataGrid),
            nameof(System.Windows.Controls.DataGridCell));
        using JsonDocument document = JsonDocument.Parse(FileTaskQueueEvidenceSerializer.Serialize(observed));
        Assert.Equal("ImeProcessed", document.RootElement.GetProperty("Key").GetString());
        Assert.Equal("Down", document.RootElement.GetProperty("ImeProcessedKey").GetString());
        Assert.Equal("Down", document.RootElement.GetProperty("NormalizedKey").GetString());
        Assert.Equal("Shift", document.RootElement.GetProperty("Modifiers").GetString());
        Assert.True(document.RootElement.GetProperty("Handled").GetBoolean());
        Assert.Equal("DataGrid", document.RootElement.GetProperty("SourceType").GetString());
        Assert.Equal("DataGridCell", document.RootElement.GetProperty("OriginalSourceType").GetString());
    }

    [Fact]
    [Trait("ScenarioId", "UI-01")]
    public async Task Ui01PersistentDirectAddAddsTwoDistinctRowsWithOneDetectionEach()
    {
        FakeHostProtectedCounters rejectedCounters = FakeHostProtectedCounters.Zero with { VerificationCalls = 1 };
        Assert.Equal(1, rejectedCounters.VerificationCalls);
        Assert.Throws<InvalidDataException>(() => ValidateFakeHostProtectedCounters(rejectedCounters));

        await RunScenarioAsync(
            "UI-01",
            async context =>
            {
                string firstSource = context.CreateSource("supported.exe");
                string secondSource = context.CreateSource("supported-second.msi");
                context.ConfigureTwoDirectAddSelections(firstSource, secondSource);

                await context.InvokeQueueDirectAddButtonAsync(firstSource);
                QueueItemViewModel firstRow = Assert.Single(context.ViewModel.Rows);
                Assert.Equal(QueueItemDetectionState.Supported, firstRow.DetectionState);
                Assert.Equal(1, context.Intake.DetectionCount(firstSource));

                await context.InvokeQueueDirectAddButtonAsync(secondSource);
                Assert.Equal(2, context.ViewModel.Rows.Count);
                QueueItemViewModel secondRow = context.Row("supported-second.msi");
                Assert.NotEqual(firstRow.ItemId, secondRow.ItemId);
                Assert.Equal(QueueItemDetectionState.Supported, secondRow.DetectionState);
                Assert.Equal(1, context.Intake.DetectionCount(firstSource));
                Assert.Equal(1, context.Intake.DetectionCount(secondSource));
                Assert.Equal(2, context.DirectAddPickerCallCount);
                context.AssertAutomationIds(
                    "QueueDirectAddButton",
                    "SigningQueueGrid",
                    firstRow.AutomationId,
                    secondRow.AutomationId,
                    "SignButton");
            });
    }

    [Fact]
    [Trait("ScenarioId", "UI-02")]
    public Task Ui02MixedDetectionIsRowLocal() => RunScenarioAsync(
        "UI-02",
        async context =>
        {
            string supported = context.CreateSource("supported.exe");
            string blocked = context.CreateSource("unsupported.bin");
            context.Intake.DetectionResults[blocked] = QueuedSourceDetectionStatus.Blocked;
            await context.QueueAsync([supported, blocked]);
            Assert.Equal(2, context.ViewModel.Rows.Count);
            QueueItemViewModel good = context.Row("supported.exe");
            QueueItemViewModel bad = context.Row("unsupported.bin");
            Assert.Equal(QueueItemDetectionState.Supported, good.DetectionState);
            Assert.Equal(QueueItemDetectionState.Blocked, bad.DetectionState);
            await context.SelectAsync(good.ItemId);
            Assert.Same(good, context.ViewModel.CurrentItem);
            Assert.Equal(1, context.Intake.DetectionCount(supported));
            context.AssertAutomationIds(good.AutomationId, bad.AutomationId);
        });

    [Fact]
    [Trait("ScenarioId", "UI-03")]
    public Task Ui03CurrentSwitchingKeepsRowStateIsolated() => RunScenarioAsync(
        "UI-03",
        async context =>
        {
            await context.QueueAsync([
                context.CreateSource("first.exe"),
                context.CreateSource("second.msi")]);
            QueueItemViewModel first = context.Row("first.exe");
            QueueItemViewModel second = context.Row("second.msi");
            QueueItemDetectionState secondState = second.DetectionState;
            await context.SelectAsync(second.ItemId);
            Assert.Same(second, context.ViewModel.CurrentItem);
            await context.SelectAsync(first.ItemId);
            Assert.Same(first, context.ViewModel.CurrentItem);
            Assert.Equal(secondState, second.DetectionState);
            context.AssertAutomationIds(first.AutomationId, second.AutomationId, "SelectedFileDisabledReason");
        });

    [Fact]
    [Trait("ScenarioId", "UI-04")]
    public Task Ui04InvalidOutputRecoversWithoutReadding() => RunScenarioAsync(
        "UI-04",
        async context =>
        {
            string source = context.CreateSource("output-recovery.exe");
            context.Intake.FailingOutputRoots.Add("invalid-output");
            await context.QueueAsync([source]);
            QueueItemViewModel row = Assert.Single(context.ViewModel.Rows);
            await context.SelectAsync(row.ItemId);
            await context.InvokeAsync(viewModel => viewModel.ReplanOutputRootAsync("invalid-output"));
            Assert.NotEqual(QueueItemPreflightState.Ready, row.PreflightState);
            await context.InvokeAsync(viewModel => viewModel.ReplanOutputRootAsync(context.OutputRoot));
            Assert.NotEqual("invalid-output", context.ViewModel.OutputRoot);
            Assert.Single(context.ViewModel.Rows);
            Assert.Equal(1, context.Intake.DetectionCount(source));
            Assert.True(context.Intake.PlanCount(source) >= 1);
            context.AssertAutomationIds("OutputRootTextBox", "BrowseOutputButton", row.AutomationId);
        });

    [Fact]
    [Trait("ScenarioId", "UI-05")]
    public Task Ui05FailedHistoryDoesNotGateNewRow() => RunScenarioAsync(
        "UI-05",
        async context =>
        {
            string failedSource = context.CreateSource("failed-history.exe");
            await context.QueueAsync([failedSource]);
            QueueItemViewModel failed = Assert.Single(context.ViewModel.Rows);
            ScenarioContext.Invoke(() => failed.Apply(BatchItemState.Failed, receipt: null));
            string newSource = context.CreateSource("new-row.exe");
            await context.QueueAsync([newSource]);
            QueueItemViewModel added = context.Row("new-row.exe");
            await context.SelectAsync(added.ItemId);
            Assert.Equal(BatchItemState.Failed, failed.State);
            Assert.Same(added, context.ViewModel.CurrentItem);
            Assert.Equal(QueueItemDetectionState.Supported, added.DetectionState);
            Assert.Equal(0, context.Batch.RunCount);
            context.AssertAutomationIds(failed.AutomationId, added.AutomationId);
        });

    [Fact]
    [Trait("ScenarioId", "UI-06")]
    public Task Ui06RemoveReaddUsesFreshIdentityAndRejectsLateEvent() => RunScenarioAsync(
        "UI-06",
        async context =>
        {
            string source = context.CreateSource("remove-readd.exe");
            string peerSource = context.CreateSource("peer.exe");
            await context.QueueAsync([source, peerSource]);
            QueueItemViewModel removed = context.Row("remove-readd.exe");
            string removedId = removed.ItemId;
            ScenarioContext.Invoke(() =>
            {
                removed.IsSelected = true;
                context.ViewModel.RemoveSelected();
            });
            context.Batch.EmitLate(removedId);
            await context.QueueAsync([source]);
            QueueItemViewModel replacement = context.Row("remove-readd.exe");
            Assert.NotEqual(removedId, replacement.ItemId);
            Assert.Equal(2, context.Intake.DetectionCount(source));
            Assert.DoesNotContain(context.ViewModel.Rows, row => row.ItemId == removedId);
            Assert.Equal(context.SourceHashes[source], ScenarioContext.HashSource(source));
            context.AssertAutomationIds(replacement.AutomationId, context.Row("peer.exe").AutomationId);
        });

    [Fact]
    [Trait("ScenarioId", "UI-07")]
    public Task Ui07PathAndPhysicalIdentityDedupePreservesExistingRow() => RunScenarioAsync(
        "UI-07",
        async context =>
        {
            string source = context.CreateSource("dedupe.exe");
            string alias = context.CreateSource("dedupe-alias.exe");
            context.Intake.IdentityAliases[alias] = source;
            await context.QueueAsync([source]);
            string itemId = Assert.Single(context.ViewModel.Rows).ItemId;
            await context.QueueAsync([source]);
            await context.QueueAsync([alias]);
            Assert.Single(context.ViewModel.Rows);
            Assert.Equal(itemId, context.ViewModel.Rows[0].ItemId);
            Assert.Equal(1, context.Intake.DetectionCount(source));
            Assert.Equal(0, context.Intake.DetectionCount(alias));
            context.AssertAutomationIds(context.ViewModel.Rows[0].AutomationId, "InputError");
        });

    [Fact]
    [Trait("ScenarioId", "UI-08")]
    public Task Ui08SourceChangedBlocksOnlyChangedRow() => RunScenarioAsync(
        "UI-08",
        async context =>
        {
            string changedSource = context.CreateSource("changed.exe");
            string peerSource = context.CreateSource("ready-peer.exe");
            await context.QueueAsync([changedSource, peerSource]);
            QueueItemViewModel changed = context.Row("changed.exe");
            QueueItemViewModel peer = context.Row("ready-peer.exe");
            await context.SelectAsync(peer.ItemId);
            Assert.Same(peer, context.ViewModel.CurrentItem);
            await context.InvokeAsync(viewModel => viewModel.ReplanOutputRootAsync(context.OutputRoot));
            context.Intake.IntegrityResults[changedSource] = QueuedSourceDetectionStatus.Changed;
            File.AppendAllText(changedSource, "changed");
            await context.SelectAsync(changed.ItemId);
            Assert.Equal(QueueItemSourceIntegrityState.Changed, changed.SourceIntegrityState);
            Assert.Equal(QueueItemSourceIntegrityState.Current, peer.SourceIntegrityState);
            Assert.Equal(0, context.Batch.RunCount);
            context.SourceHashes[changedSource] = ScenarioContext.HashSource(changedSource);
            context.AssertAutomationIds(changed.AutomationId, peer.AutomationId, "SignButton");
        });

    [Fact]
    [Trait("ScenarioId", "UI-09")]
    public Task Ui09OutputPlanningIsCurrentRowLazy() => RunScenarioAsync(
        "UI-09",
        async context =>
        {
            string firstSource = context.CreateSource("current.exe");
            string secondSource = context.CreateSource("pending.exe");
            await context.QueueAsync([firstSource, secondSource]);
            QueueItemViewModel first = context.Row("current.exe");
            QueueItemViewModel second = context.Row("pending.exe");
            await context.SelectAsync(first.ItemId);
            Assert.Same(first, context.ViewModel.CurrentItem);
            await context.InvokeAsync(viewModel => viewModel.ReplanOutputRootAsync(context.OutputRoot));
            int secondBefore = context.Intake.PlanCount(secondSource);
            string revised = Path.Combine(context.FixtureRoot, "revised-output");
            Directory.CreateDirectory(revised);
            await context.InvokeAsync(viewModel => viewModel.ReplanOutputRootAsync(revised));
            Assert.True(context.Intake.PlanCount(firstSource) >= 2);
            Assert.Equal(secondBefore, context.Intake.PlanCount(secondSource));
            await context.SelectAsync(second.ItemId);
            Assert.True(context.Intake.PlanCount(secondSource) > secondBefore);
            Assert.Equal(1, context.Intake.DetectionCount(firstSource));
            Assert.Equal(1, context.Intake.DetectionCount(secondSource));
            context.AssertAutomationIds(first.AutomationId, second.AutomationId, "OutputRootTextBox");
        });

    [Fact]
    [Trait("ScenarioId", "UI-10")]
    public Task Ui10KeyboardFocusMultiSelectionChineseAndRedactedAuditRemainScoped() => RunScenarioAsync(
        "UI-10",
        async context =>
        {
            string firstSource = context.CreateSource("focus-first.exe");
            string secondSource = context.CreateSource("focus-second.exe");
            string thirdSource = context.CreateSource("focus-third.exe");
            string retainedSource = context.CreateSource("focus-retained.exe");
            await context.QueueAsync([firstSource, secondSource, thirdSource, retainedSource]);
            QueueItemViewModel first = context.Row("focus-first.exe");
            QueueItemViewModel second = context.Row("focus-second.exe");
            QueueItemViewModel third = context.Row("focus-third.exe");
            QueueItemViewModel retained = context.Row("focus-retained.exe");
            await context.FocusAsync(first.AutomationId);
            await context.RouteKeyAsync(Ui10KeyboardRoute[0].Key, Ui10KeyboardRoute[0].Modifiers);
            await ScenarioContext.WaitUntilAsync(() => ReferenceEquals(context.ViewModel.CurrentItem, second));
            Assert.Same(second, context.ViewModel.CurrentItem);
            context.RecordObservable("keyboardSelection", context.SelectionObservation());

            await context.RouteKeyAsync(Ui10KeyboardRoute[1].Key, Ui10KeyboardRoute[1].Modifiers);
            context.RecordObservable("ctrlSelectionAfterInput", context.SelectionObservation());
            context.RecordObservable("ctrlInputCleanup", context.LastInputCleanup);
            await ScenarioContext.WaitUntilAsync(() => first.IsSelected && !second.IsSelected);
            SelectionTrace ctrlSelection = context.SelectionObservation();
            Assert.Equal([first.ItemId], ctrlSelection.SelectedItemIds);
            Assert.Equal(first.AutomationId, ctrlSelection.FocusedAutomationId);
            Assert.Equal(first.ItemId, ctrlSelection.CurrentCellItemId);
            Assert.Same(second, context.ViewModel.CurrentItem);
            context.RecordObservable("ctrlSelection", ctrlSelection);

            await context.RouteKeyAsync(Ui10KeyboardRoute[2].Key, Ui10KeyboardRoute[2].Modifiers);
            await ScenarioContext.WaitUntilAsync(() => first.IsSelected && second.IsSelected);
            SelectionTrace twoRowRange = context.SelectionObservation();
            Assert.True(twoRowRange.SelectedItemIds.ToHashSet(StringComparer.Ordinal).SetEquals([first.ItemId, second.ItemId]));
            Assert.Equal(second.AutomationId, twoRowRange.FocusedAutomationId);
            Assert.Equal(second.ItemId, twoRowRange.CurrentCellItemId);
            Assert.Same(second, context.ViewModel.CurrentItem);
            context.RecordObservable("shiftTwoRowRange", twoRowRange);

            await context.RouteKeyAsync(Ui10KeyboardRoute[3].Key, Ui10KeyboardRoute[3].Modifiers);
            context.RecordObservable("shiftSelectionAfterInput", context.SelectionObservation());
            context.RecordObservable("shiftInputCleanup", context.LastInputCleanup);
            await ScenarioContext.WaitUntilAsync(() => first.IsSelected && second.IsSelected && third.IsSelected);
            Assert.Equal(3, context.ViewModel.Rows.Count(row => row.IsSelected));
            Assert.Same(second, context.ViewModel.CurrentItem);
            context.RecordObservable("shiftSelection", context.SelectionObservation());

            await context.RouteKeyAsync(Ui10KeyboardRoute[4].Key, Ui10KeyboardRoute[4].Modifiers);
            context.RecordObservable("deleteInputCleanup", context.LastInputCleanup);
            await ScenarioContext.WaitUntilAsync(() => context.ViewModel.Rows.Count == 1);
            Assert.Same(retained, Assert.Single(context.ViewModel.Rows));
            Assert.Same(retained, context.ViewModel.CurrentItem);
            SelectionTrace retainedSelection = context.SelectionObservation();
            Assert.Equal([retained.ItemId], retainedSelection.SelectedItemIds);
            Assert.Equal("SummaryRegion", retainedSelection.FocusedAutomationId);
            Assert.Equal(retained.ItemId, retainedSelection.CurrentCellItemId);
            Assert.Equal("SummaryRegion", context.ViewModel.FocusTargetAutomationId);
            List<UiEventTimelineTrace> deleteTimeline = context.TimelineObservation();
            UiEventTimelineTrace retainedRowFocus = Assert.Single(deleteTimeline, entry =>
                entry.Phase.StartsWith("RouteKey:Delete:None:", StringComparison.Ordinal) &&
                entry.EventName == "GotKeyboardFocus" &&
                entry.NewFocusAutomationId == retained.AutomationId &&
                entry.FocusedAutomationId == retained.AutomationId &&
                entry.CurrentCellItemId == retained.ItemId);
            UiEventTimelineTrace summaryFocus = Assert.Single(deleteTimeline, entry =>
                entry.Phase.StartsWith("RouteKey:Delete:None:", StringComparison.Ordinal) &&
                entry.EventName == "GotKeyboardFocus" &&
                entry.OldFocusAutomationId == retained.AutomationId &&
                entry.NewFocusAutomationId == "SummaryRegion" &&
                entry.FocusedAutomationId == "SummaryRegion" &&
                entry.CurrentCellItemId == retained.ItemId);
            Assert.True(retainedRowFocus.Order < summaryFocus.Order);
            Assert.DoesNotContain(
                deleteTimeline.Where(entry => entry.Order > retainedRowFocus.Order),
                entry => entry.Phase.StartsWith("Focus:", StringComparison.Ordinal));
            context.RecordObservable("removeMembership", retainedSelection);

            const string sensitiveSentinel = "UI10-SENSITIVE-SENTINEL";
            string longStatus = string.Concat(
                "审计记录已完成，当前文件任务队列的键盘选择、范围选择和移除成员关系均已更新；",
                "此状态用于验证较长中文内容在可见区域中保持清晰且不会遮挡相邻的队列与操作区域；",
                "password=", sensitiveSentinel);
            string visibleStatus = context.PresentRedactedAuditStatus(longStatus);
            Assert.True(visibleStatus.Length >= 70);
            Assert.Contains("审计记录已完成", visibleStatus, StringComparison.Ordinal);
            Assert.DoesNotContain(sensitiveSentinel, visibleStatus, StringComparison.Ordinal);
            Assert.Equal(visibleStatus, context.VisibleText("SummaryRegion"));
            context.RecordObservable("visibleRedactedAuditStatus", visibleStatus);

            IReadOnlyDictionary<string, object> geometry = context.AssertQueueLayoutDoesNotOverlap();
            context.RecordObservable("layoutGeometry", geometry);
            context.RecordObservable(
                "viewportEvidence",
                context.CaptureViewportEvidenceMatrix(
                    visibleStatus,
                    context.ViewModel.CurrentFileStatusText));
            Assert.All(context.Audit.Entries, entry =>
            {
                Assert.DoesNotContain(context.FixtureRoot, entry, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(sensitiveSentinel, entry, StringComparison.Ordinal);
            });
            Assert.Contains(context.Audit.Entries, entry =>
                AuditEntryMatches(entry, first.ItemId, QueueAuditActions.Remove));
            Assert.Contains(context.Audit.Entries, entry =>
                AuditEntryMatches(entry, second.ItemId, QueueAuditActions.Remove));
            Assert.Contains(context.Audit.Entries, entry =>
                AuditEntryMatches(entry, third.ItemId, QueueAuditActions.Remove));
            Assert.DoesNotContain(context.Audit.Entries, entry =>
                AuditEntryMatches(entry, retained.ItemId, QueueAuditActions.Remove));
            Assert.Equal(context.SourceHashes[firstSource], ScenarioContext.HashSource(firstSource));
            Assert.Equal(context.SourceHashes[secondSource], ScenarioContext.HashSource(secondSource));
            Assert.Equal(context.SourceHashes[thirdSource], ScenarioContext.HashSource(thirdSource));
            Assert.Equal(context.SourceHashes[retainedSource], ScenarioContext.HashSource(retainedSource));
            context.AssertAutomationIds("SigningQueueGrid", retained.AutomationId, "RemoveButton", "SummaryRegion");
        });

    private static KeyDownReceiptKind ReceiptKindFor(Key key) =>
        key == Key.Delete ? KeyDownReceiptKind.PreviewKeyDown : KeyDownReceiptKind.BubblingKeyDown;

    private static double DevicePixelQuantumDip(double renderDpi) => 96d / renderDpi;

    private static Key NormalizeObservedKey(
        Key key,
        Key systemKey,
        Key imeProcessedKey,
        Key deadCharProcessedKey) => key switch
        {
            Key.System => systemKey,
            Key.ImeProcessed => imeProcessedKey,
            Key.DeadCharProcessed => deadCharProcessedKey,
            _ => key
        };

    private static bool AuditEntryMatches(string entry, string itemId, string action)
    {
        string[] fields = entry.Split('|');
        return fields.Length > 5 &&
            string.Equals(fields[1], itemId, StringComparison.Ordinal) &&
            string.Equals(fields[5], action, StringComparison.Ordinal);
    }

    internal static async Task RunManualHostAsync(string completionFile, CancellationToken cancellationToken)
    {
        await using var context = await ScenarioContext.CreateAsync("manual");
        await context.QueueAsync([
            context.CreateSource("manual-supported.exe"),
            context.CreateSource("manual-second.msi")]);
        while (!File.Exists(completionFile))
        {
            await Task.Delay(250, cancellationToken);
        }
    }

    private static async Task RunScenarioAsync(string scenarioId, Func<ScenarioContext, Task> action)
    {
        var context = await ScenarioContext.CreateAsync(scenarioId);
        Exception? failure = null;
        try
        {
            await action(context);
        }
        catch (Exception exception)
        {
            failure = exception;
            throw;
        }
        finally
        {
            try
            {
                await context.CompleteAsync(failure);
            }
            finally
            {
                await context.DisposeAsync();
            }
        }
    }

    private sealed class ScenarioContext : IAsyncDisposable
    {
        private readonly VisibleFakeHost host;
        private readonly string taskRoot;
        private bool completed;

        private ScenarioContext(
            string scenarioId,
            string taskRoot,
            string evidenceDirectory,
            string fixtureRoot,
            FakeIntakeAdapter intake,
            FakeBatchAdapter batch,
            RecordingAuditSink audit,
            VisibleFakeHost host)
        {
            ScenarioId = scenarioId;
            this.taskRoot = taskRoot;
            EvidenceDirectory = evidenceDirectory;
            FixtureRoot = fixtureRoot;
            Intake = intake;
            Batch = batch;
            Audit = audit;
            this.host = host;
        }

        public string ScenarioId { get; }
        public string EvidenceDirectory { get; }
        public string FixtureRoot { get; }
        public string OutputRoot { get; private set; } = string.Empty;
        public FakeIntakeAdapter Intake { get; }
        public FakeBatchAdapter Batch { get; }
        public RecordingAuditSink Audit { get; }
        public SigningWorkbenchViewModel ViewModel => host.ViewModel;
        public Dictionary<string, string> SourceHashes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, object?> Observables { get; } = new(StringComparer.Ordinal);

        public static async Task<ScenarioContext> CreateAsync(string scenarioId)
        {
            string taskRoot = Path.Combine(
                Path.GetTempPath(),
                "CodeSigner.FileTaskQueueUi",
                $"{scenarioId}-{Guid.NewGuid():N}");
            string? configuredEvidence = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
            string? routedScenario = Environment.GetEnvironmentVariable("CODESIGNER_UI_QA_SCENARIO");
            bool routeMatches = string.IsNullOrWhiteSpace(routedScenario) ||
                string.Equals(routedScenario, scenarioId, StringComparison.Ordinal);
            bool persistEvidence = !string.IsNullOrWhiteSpace(configuredEvidence) && routeMatches;
            string evidenceDirectory = persistEvidence
                ? string.IsNullOrWhiteSpace(routedScenario)
                    ? Path.Combine(Path.GetFullPath(configuredEvidence!), scenarioId)
                    : Path.GetFullPath(configuredEvidence!)
                : Path.Combine(taskRoot, "evidence");
            string fixtureRoot = Path.Combine(taskRoot, "fixtures");
            Directory.CreateDirectory(evidenceDirectory);
            Directory.CreateDirectory(fixtureRoot);

            var protectedOperations = new FakeHostProtectedOperationTracker();
            var intake = new FakeIntakeAdapter();
            var batch = new FakeBatchAdapter(protectedOperations);
            var audit = new RecordingAuditSink();
            var host = new VisibleFakeHost(intake, batch, audit, protectedOperations);
            host.Start();
            var context = new ScenarioContext(
                scenarioId,
                taskRoot,
                evidenceDirectory,
                fixtureRoot,
                intake,
                batch,
                audit,
                host)
            {
                OutputRoot = Path.Combine(fixtureRoot, "output")
            };
            Directory.CreateDirectory(context.OutputRoot);
            host.RefreshFakeReadiness();
            await Task.CompletedTask;
            return context;
        }

        public string CreateSource(string name)
        {
            string path = Path.Combine(FixtureRoot, name);
            File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00]);
            SourceHashes[path] = HashSource(path);
            return path;
        }

        public async Task QueueAsync(IReadOnlyCollection<string> paths)
        {
            await host.InvokeAsync(viewModel =>
            {
                viewModel.OutputRoot = OutputRoot;
                return viewModel.QueueFilesAsync(paths);
            });
            await WaitForConditionAsync(() => paths.All(path =>
            {
                QueueItemViewModel? row = ViewModel.Rows.FirstOrDefault(candidate =>
                    string.Equals(candidate.FullPath, path, StringComparison.OrdinalIgnoreCase));
                return row is null || row.DetectionState is
                    QueueItemDetectionState.Supported or
                    QueueItemDetectionState.Blocked or
                    QueueItemDetectionState.Faulted;
            }));
        }

        public void ConfigureTwoDirectAddSelections(string firstSource, string secondSource)
        {
            Assert.NotEqual(firstSource, secondSource);
            AssertTaskOwnedSource(firstSource);
            AssertTaskOwnedSource(secondSource);
            host.ConfigureTwoDirectAddSelections(firstSource, secondSource);
        }

        public async Task InvokeQueueDirectAddButtonAsync(string expectedSource)
        {
            AssertTaskOwnedSource(expectedSource);
            await host.InvokeAsync(viewModel =>
            {
                viewModel.OutputRoot = OutputRoot;
                return Task.CompletedTask;
            });
            host.InvokeQueueDirectAddButton();
            await WaitForConditionAsync(() =>
            {
                QueueItemViewModel? row = ViewModel.Rows.FirstOrDefault(candidate =>
                    string.Equals(candidate.FullPath, expectedSource, StringComparison.OrdinalIgnoreCase));
                return row?.DetectionState is
                    QueueItemDetectionState.Supported or
                    QueueItemDetectionState.Blocked or
                    QueueItemDetectionState.Faulted;
            });
        }

        public int DirectAddPickerCallCount => host.DirectAddPickerCallCount;

        public Task SelectAsync(string itemId) => host.InvokeAsync(viewModel => viewModel.SetCurrentItemAsync(itemId));

        public Task InvokeAsync(Func<SigningWorkbenchViewModel, Task> action) => host.InvokeAsync(action);

        public static void Invoke(Action action) => VisibleFakeHost.Invoke(action);

        public QueueItemViewModel Row(string name) =>
            ViewModel.Rows.Single(row => string.Equals(row.DisplayName, name, StringComparison.OrdinalIgnoreCase));

        public void AssertAutomationIds(params string[] automationIds) =>
            host.AssertAutomationIds(automationIds);

        public Task FocusAsync(string automationId) => host.FocusAsync(automationId);

        public NativeInputCleanupTrace? LastInputCleanup => host.LastInputCleanup;

        public Task RouteKeyAsync(Key key, ModifierKeys modifiers = ModifierKeys.None) =>
            host.RouteKeyAsync(key, modifiers);

        public static Task WaitUntilAsync(Func<bool> condition) => WaitForConditionAsync(condition);

        public void RecordObservable(string name, object? value) => Observables[name] = value;

        public SelectionTrace SelectionObservation() => host.SelectionObservation();

        public List<UiEventTimelineTrace> TimelineObservation() => host.UiEventTimeline;

        public string PresentRedactedAuditStatus(string message) => host.PresentRedactedAuditStatus(message);

        public string VisibleText(string elementName) => host.VisibleText(elementName);

        public Dictionary<string, object> AssertQueueLayoutDoesNotOverlap() =>
            host.AssertQueueLayoutDoesNotOverlap();

        public List<ViewportEvidence> CaptureViewportEvidenceMatrix(
            string expectedFullStatus,
            string expectedCompactStatus) =>
            host.CaptureViewportEvidenceMatrix(
                EvidenceDirectory,
                expectedFullStatus,
                expectedCompactStatus);

        public static string HashSource(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

        public async Task CompleteAsync(Exception? failure)
        {
            if (completed)
            {
                return;
            }

            string screenshot = Path.Combine(EvidenceDirectory, "screenshot.png");
            host.CaptureScreenshot(screenshot);
            bool sourcePreserved = SourceHashes.All(pair =>
                File.Exists(pair.Key) && string.Equals(pair.Value, HashSource(pair.Key), StringComparison.Ordinal));
            FakeHostProtectedCounters counters = host.ProtectedCounters;
            ValidateFakeHostProtectedCounters(counters);
            await host.DisposeAsync();
            if (Directory.Exists(FixtureRoot))
            {
                Directory.Delete(FixtureRoot, recursive: true);
            }
            Assert.False(Directory.Exists(FixtureRoot));

            string productPath = typeof(CodeSigner.App.MainWindow).Assembly.Location;
            string testPath = typeof(FileTaskQueueUiAutomationTests).Assembly.Location;
            var trace = new
            {
                schemaVersion = 1,
                scenarioId = ScenarioId,
                outcome = failure is null ? "passed" : "failed",
                failureType = failure?.GetType().FullName,
                productSha256 = FileHash(productPath),
                testSha256 = FileHash(testPath),
                screenshotSha256 = FileHash(screenshot),
                rows = ViewModel.Rows.Select(row => new
                {
                    row.ItemId,
                    row.AutomationId,
                    row.DetectionState,
                    row.SourceIntegrityState,
                    row.PreflightState,
                    row.State,
                    row.IsSelected
                }).ToArray(),
                currentItemId = ViewModel.CurrentItem?.ItemId,
                ViewModel.OutputRoot,
                ViewModel.OutputError,
                ViewModel.InputError,
                ViewModel.SignDisabledReason,
                auditEntries = Audit.Entries,
                observables = Observables,
                inputTelemetry = host.InputTelemetry,
                observedKeyEvents = host.ObservedKeyEvents,
                uiEventTimeline = host.UiEventTimeline,
                counters = new
                {
                    productionCalls = counters.ProductionCalls,
                    workerStarts = counters.WorkerStarts,
                    protectedLaunches = counters.ProtectedLaunches,
                    networkAttempts = counters.NetworkAttempts,
                    verificationCalls = counters.VerificationCalls,
                    fakeAdmissionCalls = Intake.AdmissionCalls,
                    fakeDetectionCalls = Intake.TotalDetectionCalls,
                    fakePlanCalls = Intake.TotalPlanCalls,
                    fakeIntegrityCalls = Intake.IntegrityCalls,
                    fakeBatchRuns = Batch.RunCount
                },
                sourcePreserved,
                fixtureRoot = FixtureRoot,
                fixtureCleaned = !Directory.Exists(FixtureRoot)
            };
            File.WriteAllText(
                Path.Combine(EvidenceDirectory, "trace.json"),
                FileTaskQueueEvidenceSerializer.Serialize(trace));
            WriteRouterEvidence(screenshot, counters, failure, sourcePreserved);
            completed = true;
            if (Directory.Exists(taskRoot))
            {
                Directory.Delete(taskRoot, recursive: true);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (!completed)
            {
                await host.DisposeAsync();
                if (Directory.Exists(taskRoot))
                {
                    Directory.Delete(taskRoot, recursive: true);
                }
            }
        }

        private static async Task WaitForConditionAsync(Func<bool> condition)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!condition())
            {
                await Task.Delay(10, timeout.Token);
            }
        }

        private static string FileHash(string path) =>
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

        private void AssertTaskOwnedSource(string source)
        {
            string relativePath = Path.GetRelativePath(FixtureRoot, source);
            Assert.False(Path.IsPathRooted(relativePath));
            Assert.False(relativePath.StartsWith("..", StringComparison.Ordinal));
            Assert.True(File.Exists(source));
        }

        private void WriteRouterEvidence(
            string screenshot,
            FakeHostProtectedCounters counters,
            Exception? failure,
            bool sourcePreserved)
        {
            string? routedScenario = Environment.GetEnvironmentVariable("CODESIGNER_UI_QA_SCENARIO");
            string? externalDirectory = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
            if (string.IsNullOrWhiteSpace(externalDirectory) ||
                (!string.IsNullOrWhiteSpace(routedScenario) &&
                 !string.Equals(routedScenario, ScenarioId, StringComparison.Ordinal)))
            {
                return;
            }

            string externalScreenshot = Path.GetFullPath(screenshot);
            string externalTrace = Path.GetFullPath(Path.Combine(EvidenceDirectory, "trace.json"));
            var evidence = new
            {
                visibleFakeHost = true,
                classFilter = "FullyQualifiedName~FileTaskQueueUiAutomationTests",
                scenario = ScenarioId,
                outcome = failure is null ? "passed" : "failed",
                failureType = failure?.GetType().FullName,
                sourcePreserved,
                fixtureCleaned = !Directory.Exists(FixtureRoot),
                manifestSha256 = Environment.GetEnvironmentVariable("CODESIGNER_UI_QA_ASSEMBLY_MANIFEST_SHA256"),
                attemptNonce = Environment.GetEnvironmentVariable("CODESIGNER_UI_QA_ATTEMPT_NONCE"),
                attemptStartedAt = Environment.GetEnvironmentVariable("CODESIGNER_UI_QA_ATTEMPT_STARTED_AT"),
                artifactPaths = new
                {
                    screenshot = externalScreenshot,
                    trace = externalTrace
                },
                counters = new
                {
                    productionCalls = counters.ProductionCalls,
                    productionAppLaunches = counters.ProductionAppLaunches,
                    installedAppLaunches = counters.InstalledAppLaunches,
                    workerStarts = counters.WorkerStarts,
                    protectedLaunches = counters.ProtectedLaunches,
                    signingCalls = counters.SigningCalls,
                    verificationCalls = counters.VerificationCalls,
                    providerCalls = counters.ProviderCalls,
                    certificateCalls = counters.CertificateCalls,
                    tsaCalls = counters.TsaCalls,
                    networkAttempts = counters.NetworkAttempts,
                    msiOperations = counters.MsiOperations,
                    scmOperations = counters.ScmOperations,
                    uacPrompts = counters.UacPrompts,
                    pinPrompts = counters.PinPrompts,
                    installOperations = counters.InstallOperations,
                    upgradeOperations = counters.UpgradeOperations
                }
            };
            File.WriteAllText(
                Path.Combine(EvidenceDirectory, "fake-host-evidence.json"),
                FileTaskQueueEvidenceSerializer.Serialize(evidence));
        }
    }

    private sealed record FakeHostProtectedCounters(
        int ProductionCalls,
        int ProductionAppLaunches,
        int InstalledAppLaunches,
        int WorkerStarts,
        int ProtectedLaunches,
        int SigningCalls,
        int VerificationCalls,
        int ProviderCalls,
        int CertificateCalls,
        int TsaCalls,
        int NetworkAttempts,
        int MsiOperations,
        int ScmOperations,
        int UacPrompts,
        int PinPrompts,
        int InstallOperations,
        int UpgradeOperations)
    {
        public static FakeHostProtectedCounters Zero { get; } = new(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    private static void ValidateFakeHostProtectedCounters(FakeHostProtectedCounters counters)
    {
        if (counters.ProductionCalls != 0 ||
            counters.ProductionAppLaunches != 0 ||
            counters.InstalledAppLaunches != 0 ||
            counters.WorkerStarts != 0 ||
            counters.ProtectedLaunches != 0 ||
            counters.SigningCalls != 0 ||
            counters.VerificationCalls != 0 ||
            counters.ProviderCalls != 0 ||
            counters.CertificateCalls != 0 ||
            counters.TsaCalls != 0 ||
            counters.NetworkAttempts != 0 ||
            counters.MsiOperations != 0 ||
            counters.ScmOperations != 0 ||
            counters.UacPrompts != 0 ||
            counters.PinPrompts != 0 ||
            counters.InstallOperations != 0 ||
            counters.UpgradeOperations != 0)
        {
            throw new InvalidDataException(
                $"The fake-host receipt contains a protected-operation counter greater than zero: {JsonSerializer.Serialize(counters)}");
        }
    }

    private sealed class FakeHostProtectedOperationTracker
    {
        public int ProductionCalls { get; private set; }
        public int WorkerStarts { get; private set; }
        public int ProtectedLaunches { get; private set; }
        public int SigningCalls { get; private set; }

        public FakeHostProtectedCounters Snapshot => new(
            ProductionCalls,
            ProductionAppLaunches: 0,
            InstalledAppLaunches: 0,
            WorkerStarts,
            ProtectedLaunches,
            SigningCalls,
            VerificationCalls: 0,
            ProviderCalls: 0,
            CertificateCalls: 0,
            TsaCalls: 0,
            NetworkAttempts: 0,
            MsiOperations: 0,
            ScmOperations: 0,
            UacPrompts: 0,
            PinPrompts: 0,
            InstallOperations: 0,
            UpgradeOperations: 0);

        public void RecordWorkerStart()
        {
            ProductionCalls++;
            WorkerStarts++;
            ProtectedLaunches++;
        }

        public void RecordProtectedLaunch()
        {
            ProductionCalls++;
            ProtectedLaunches++;
        }

        public void RecordSigningCall()
        {
            ProductionCalls++;
            ProtectedLaunches++;
            SigningCalls++;
        }
    }

    private sealed class VisibleFakeHost : IAsyncDisposable
    {
        private static readonly Lazy<WpfDispatcherHost> Shared = new(() => new WpfDispatcherHost());
        internal static IReadOnlyList<ViewportSpec> ViewportEvidencePlan { get; } =
        [
            new("normal", 992, 736, null),
            new("compact", 650.67, 480, 150),
            new("ultra-compact", 480, 352, 200)
        ];
        private readonly FakeIntakeAdapter intake;
        private readonly FakeBatchAdapter batch;
        private readonly RecordingAuditSink audit;
        private readonly FakeHostProtectedOperationTracker protectedOperations;
        private readonly ScriptedDialogs dialogs = new();
        private MainWindow? window;
        private bool disposed;
        private long timelineOrder;
        private string timelinePhase = "host-start";

        public VisibleFakeHost(
            FakeIntakeAdapter intake,
            FakeBatchAdapter batch,
            RecordingAuditSink audit,
            FakeHostProtectedOperationTracker protectedOperations)
        {
            this.intake = intake;
            this.batch = batch;
            this.audit = audit;
            this.protectedOperations = protectedOperations;
        }

        public SigningWorkbenchViewModel ViewModel { get; private set; } = null!;
        public FakeHostProtectedCounters ProtectedCounters => protectedOperations.Snapshot;
        public int DirectAddPickerCallCount => dialogs.PickExeFilesCallCount;
        public NativeInputCleanupTrace? LastInputCleanup { get; private set; }
        public List<NativeInputDeliveryTrace> InputTelemetry { get; } = [];
        public List<ObservedRoutedKeyEventTrace> ObservedKeyEvents { get; } = [];
        public List<UiEventTimelineTrace> UiEventTimeline { get; } = [];

        public void Start() => Shared.Value.Dispatcher.Invoke(() =>
        {
            ViewModel = new SigningWorkbenchViewModel(
                new FakeReadinessAdapter(),
                intake,
                batch,
                new ThrowingShell(protectedOperations),
                new ThrowingWorkerHealthService(protectedOperations),
                new NoopWorkerRepairService(protectedOperations),
                static _ => ValueTask.FromResult(false),
                queueAuditSink: audit);
            window = new MainWindow(ViewModel, dialogs);
            window.AddHandler(
                Keyboard.GotKeyboardFocusEvent,
                new KeyboardFocusChangedEventHandler((_, eventArgs) => RecordTimelineOnDispatcher(
                    "GotKeyboardFocus",
                    eventArgs,
                    eventArgs.OldFocus,
                    eventArgs.NewFocus)),
                handledEventsToo: true);
            window.AddHandler(
                Keyboard.LostKeyboardFocusEvent,
                new KeyboardFocusChangedEventHandler((_, eventArgs) => RecordTimelineOnDispatcher(
                    "LostKeyboardFocus",
                    eventArgs,
                    eventArgs.OldFocus,
                    eventArgs.NewFocus)),
                handledEventsToo: true);
            var queueGrid = (System.Windows.Controls.DataGrid)window.FindName("QueueGrid");
            queueGrid.SelectionChanged += (_, eventArgs) =>
                RecordTimelineOnDispatcher("HarnessObserved.SelectionChanged", eventArgs);
            queueGrid.CurrentCellChanged += (_, _) =>
                RecordTimelineOnDispatcher("HarnessObserved.CurrentCellChanged");
            ViewModel.PropertyChanged += (_, eventArgs) =>
            {
                if (string.Equals(
                    eventArgs.PropertyName,
                    nameof(SigningWorkbenchViewModel.FocusTargetAutomationId),
                    StringComparison.Ordinal))
                {
                    RecordTimelineOnDispatcher("ViewModel.FocusTargetAutomationIdChanged");
                }
            };
            MethodInfo loaded = typeof(MainWindow).GetMethod(
                "OnLoaded",
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                [typeof(object), typeof(RoutedEventArgs)],
                modifiers: null)!;
            var handler = loaded.CreateDelegate<RoutedEventHandler>(window);
            window.Loaded -= handler;
            window.Width = 1100;
            window.Height = 760;
            window.Show();
            window.Activate();
            window.UpdateLayout();
            RecordTimelineOnDispatcher("Harness.StartCompleted");
        });

        public Task InvokeAsync(Func<SigningWorkbenchViewModel, Task> action) =>
            Shared.Value.Dispatcher.Invoke(() => action(ViewModel));

        public void ConfigureTwoDirectAddSelections(string firstSource, string secondSource) =>
            Shared.Value.Dispatcher.Invoke(() => dialogs.ConfigureTwoFileSelections(firstSource, secondSource));

        public void InvokeQueueDirectAddButton() => Shared.Value.Dispatcher.Invoke(() =>
        {
            var button = Assert.IsType<System.Windows.Controls.Button>(window!.FindName("QueueDirectAddButton"));
            window.UpdateLayout();
            Assert.True(button.IsVisible);
            Assert.True(button.IsEnabled);
            Assert.True(button.Focusable);
            Assert.True(button.Focus());
            Assert.Same(button, Keyboard.FocusedElement);
            button.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent, button));
        });

        public void RefreshFakeReadiness() => Shared.Value.Dispatcher.Invoke(() =>
        {
            MethodInfo refresh = typeof(SigningWorkbenchViewModel).GetMethod(
                "RefreshEnvironmentReadiness",
                BindingFlags.Instance | BindingFlags.NonPublic) ??
                throw new MissingMethodException(
                    typeof(SigningWorkbenchViewModel).FullName,
                    "RefreshEnvironmentReadiness");
            refresh.Invoke(ViewModel, null);
        });

        public static void Invoke(Action action) => Shared.Value.Dispatcher.Invoke(action);

        public void AssertAutomationIds(IEnumerable<string> automationIds) => Shared.Value.Dispatcher.Invoke(() =>
        {
            HashSet<string> present = Enumerate(window!)
                .OfType<FrameworkElement>()
                .Select(AutomationProperties.GetAutomationId)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .ToHashSet(StringComparer.Ordinal);
            foreach (string automationId in automationIds)
            {
                if (ViewModel.Rows.Any(row => string.Equals(row.AutomationId, automationId, StringComparison.Ordinal)))
                {
                    continue;
                }

                Assert.Contains(automationId, present);
            }
        });

        public async Task FocusAsync(string automationId)
        {
            await Shared.Value.Dispatcher.InvokeAsync(() =>
            {
                timelinePhase = $"Focus:{automationId}:host-settling-input";
                RecordTimelineOnDispatcher("Harness.HostSettledBegin");
            }, DispatcherPriority.Input);
            await Shared.Value.Dispatcher.InvokeAsync(() =>
            {
                timelinePhase = $"Focus:{automationId}:host-settling-idle";
                window!.UpdateLayout();
                Assert.Equal(ViewModel.FocusTargetAutomationId, FocusedAutomationId());
                RecordTimelineOnDispatcher("Harness.HostSettledEnd");
            }, DispatcherPriority.ApplicationIdle);

            IntPtr handle = await Shared.Value.Dispatcher.InvokeAsync(() =>
            {
                timelinePhase = $"Focus:{automationId}:final-cell-focus";
                RecordTimelineOnDispatcher("Harness.FinalCellFocusBegin");
                QueueItemViewModel? row = ViewModel.Rows.FirstOrDefault(candidate =>
                    string.Equals(candidate.AutomationId, automationId, StringComparison.Ordinal));
                if (row is not null)
                {
                    var grid = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
                    grid.ScrollIntoView(row);
                    window.UpdateLayout();
                    DataGridRow rowContainer = Assert.IsType<DataGridRow>(
                        grid.ItemContainerGenerator.ContainerFromItem(row));
                    DataGridColumn column = grid.Columns[0];
                    FrameworkElement content = column.GetCellContent(rowContainer) ??
                        throw new InvalidOperationException("The first generated queue cell has no content.");
                    System.Windows.Controls.DataGridCell cell =
                        FindVisualAncestor<System.Windows.Controls.DataGridCell>(content) ??
                        throw new InvalidOperationException("The first generated queue cell was not found.");
                    Assert.True(cell.Focus());
                    Assert.Same(cell, Keyboard.FocusedElement);
                    Assert.True(grid.CurrentCell.IsValid);
                    Assert.Same(row, grid.CurrentCell.Item);
                    Assert.Same(column, grid.CurrentCell.Column);
                    RecordTimelineOnDispatcher("Harness.FinalCellFocusEstablished");
                }

                return new WindowInteropHelper(window).Handle;
            }, DispatcherPriority.Send);
            await Shared.Value.Dispatcher.InvokeAsync(() =>
            {
                var grid = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
                Assert.True(grid.IsKeyboardFocusWithin);
                Assert.IsType<System.Windows.Controls.DataGridCell>(Keyboard.FocusedElement);
                Assert.Equal(handle, GetForegroundWindow());
                timelinePhase = $"Focus:{automationId}:final-cell-focus-complete";
                RecordTimelineOnDispatcher("Harness.FinalCellFocusCompleted");
            }, DispatcherPriority.Send);
        }

        public async Task RouteKeyAsync(Key key, ModifierKeys modifiers)
        {
            ushort virtualKey = checked((ushort)KeyInterop.VirtualKeyFromKey(key));
            if (virtualKey == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(key), key, "The WPF key has no Win32 virtual-key mapping.");
            }

            ushort[] modifierKeys = ModifierVirtualKeys(modifiers);
            NativeInput[] chord = BuildKeyboardChord(virtualKey, key, modifierKeys);
            uint inserted = 0;
            int sendInputLastError = 0;
            uint cleanupInserted = 0;
            int cleanupLastError = 0;
            IntPtr foregroundHandle = IntPtr.Zero;
            uint foregroundThreadId = 0;
            IntPtr targetHandle = IntPtr.Zero;
            uint targetWindowThreadId = 0;
            uint targetDispatcherThreadId = 0;
            int targetDispatcherManagedThreadId = 0;
            bool setForegroundAccepted = false;
            IntPtr nativeFocusHandle = IntPtr.Zero;
            string? focusedAutomationIdBeforeInput = null;
            bool queueHadKeyboardFocusBeforeInput = false;
            bool previewReceived = false;
            string? previewModifiers = null;
            bool keyDownReceived = false;
            string? keyDownModifiers = null;
            SelectionTrace beforeInput = null!;
            SelectionTrace? afterProcessing = null;
            string? previewSourceType = null;
            string? previewOriginalSourceType = null;
            bool previewHandledAtWindow = false;
            bool previewHandledAtGrid = false;
            string? keyDownSourceType = null;
            string? keyDownOriginalSourceType = null;
            bool keyDownHandledAtGrid = false;
            bool keyDownHandledAtWindow = false;
            bool keyUpReceived = false;
            string? keyUpModifiers = null;
            bool keyUpHandledAtWindow = false;
            KeyDownReceiptKind receiptKind = ReceiptKindFor(key);
            System.Windows.Input.KeyEventHandler? previewHandler = null;
            System.Windows.Input.KeyEventHandler? gridPreviewHandler = null;
            System.Windows.Input.KeyEventHandler? keyDownHandler = null;
            System.Windows.Input.KeyEventHandler? gridKeyDownHandler = null;
            System.Windows.Input.KeyEventHandler? keyUpHandler = null;
            var keyDownReceipt = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var keyUpReceipt = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            try
            {
                await Shared.Value.Dispatcher.InvokeAsync(() =>
                {
                    var grid = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
                    timelinePhase = $"RouteKey:{key}:{modifiers}:precondition";
                    RecordTimelineOnDispatcher("Harness.RouteKeyPrecondition");
                    targetHandle = new WindowInteropHelper(window).Handle;
                    targetWindowThreadId = GetWindowThreadProcessId(targetHandle, out _);
                    targetDispatcherThreadId = GetCurrentThreadId();
                    targetDispatcherManagedThreadId = Environment.CurrentManagedThreadId;
                    Assert.Equal(Shared.Value.NativeThreadId, targetDispatcherThreadId);
                    Assert.Equal(Shared.Value.ManagedThreadId, targetDispatcherManagedThreadId);
                    Assert.Equal(targetWindowThreadId, targetDispatcherThreadId);

                    window.Activate();
                    setForegroundAccepted = SetForegroundWindow(targetHandle);
                    foregroundHandle = GetForegroundWindow();
                    foregroundThreadId = GetWindowThreadProcessId(foregroundHandle, out _);
                    nativeFocusHandle = GetFocus();
                    focusedAutomationIdBeforeInput = FocusedAutomationId();
                    queueHadKeyboardFocusBeforeInput = grid.IsKeyboardFocusWithin;
                    beforeInput = SelectionObservationOnDispatcher(grid);
                    Assert.Equal(targetHandle, foregroundHandle);
                    Assert.Equal(targetWindowThreadId, foregroundThreadId);
                    Assert.True(queueHadKeyboardFocusBeforeInput);
                    Assert.Equal(targetHandle, nativeFocusHandle);

                    previewHandler = (_, eventArgs) =>
                    {
                        RecordObservedKeyEventOnDispatcher("Window.PreviewKeyDown", eventArgs);
                        if (NormalizeObservedKey(eventArgs) != key)
                        {
                            return;
                        }

                        previewReceived = true;
                        previewModifiers = Keyboard.Modifiers.ToString();
                        previewSourceType = eventArgs.Source?.GetType().Name;
                        previewOriginalSourceType = eventArgs.OriginalSource?.GetType().Name;
                        previewHandledAtWindow = eventArgs.Handled;
                        RecordTimelineOnDispatcher("Window.PreviewKeyDown", eventArgs);
                        if (receiptKind == KeyDownReceiptKind.PreviewKeyDown)
                        {
                            keyDownReceipt.TrySetResult();
                        }
                    };
                    gridPreviewHandler = (_, eventArgs) =>
                    {
                        RecordObservedKeyEventOnDispatcher("QueueGrid.PreviewKeyDownAfterClassHandler", eventArgs);
                        if (NormalizeObservedKey(eventArgs) == key)
                        {
                            previewHandledAtGrid = eventArgs.Handled;
                            RecordTimelineOnDispatcher("QueueGrid.PreviewKeyDownAfterClassHandler", eventArgs);
                        }
                    };
                    keyDownHandler = (_, eventArgs) =>
                    {
                        RecordObservedKeyEventOnDispatcher("Window.KeyDownAfterClassHandler", eventArgs);
                        if (NormalizeObservedKey(eventArgs) != key)
                        {
                            return;
                        }

                        keyDownReceived = true;
                        keyDownModifiers = Keyboard.Modifiers.ToString();
                        keyDownSourceType = eventArgs.Source?.GetType().Name;
                        keyDownOriginalSourceType = eventArgs.OriginalSource?.GetType().Name;
                        keyDownHandledAtWindow = eventArgs.Handled;
                        RecordTimelineOnDispatcher("Window.KeyDownAfterClassHandler", eventArgs);
                        if (receiptKind == KeyDownReceiptKind.BubblingKeyDown)
                        {
                            keyDownReceipt.TrySetResult();
                        }
                    };
                    gridKeyDownHandler = (_, eventArgs) =>
                    {
                        RecordObservedKeyEventOnDispatcher("QueueGrid.KeyDownAfterClassHandler", eventArgs);
                        if (NormalizeObservedKey(eventArgs) == key)
                        {
                            keyDownHandledAtGrid = eventArgs.Handled;
                            RecordTimelineOnDispatcher("QueueGrid.KeyDownAfterClassHandler", eventArgs);
                        }
                    };
                    keyUpHandler = (_, eventArgs) =>
                    {
                        if (NormalizeObservedKey(eventArgs) != key)
                        {
                            return;
                        }

                        keyUpReceived = true;
                        keyUpModifiers = Keyboard.Modifiers.ToString();
                        keyUpHandledAtWindow = eventArgs.Handled;
                        RecordTimelineOnDispatcher("Window.KeyUp", eventArgs);
                        keyUpReceipt.TrySetResult();
                    };
                    window.AddHandler(Keyboard.PreviewKeyDownEvent, previewHandler, handledEventsToo: true);
                    grid.AddHandler(Keyboard.PreviewKeyDownEvent, gridPreviewHandler, handledEventsToo: true);
                    window.AddHandler(Keyboard.KeyDownEvent, keyDownHandler, handledEventsToo: true);
                    grid.AddHandler(Keyboard.KeyDownEvent, gridKeyDownHandler, handledEventsToo: true);
                    window.AddHandler(Keyboard.KeyUpEvent, keyUpHandler, handledEventsToo: true);

                    timelinePhase = $"RouteKey:{key}:{modifiers}:send-input";
                    RecordTimelineOnDispatcher("Harness.BeforeSendInput");
                    Marshal.SetLastPInvokeError(0);
                    inserted = SendInput((uint)chord.Length, chord, Marshal.SizeOf<NativeInput>());
                    sendInputLastError = Marshal.GetLastPInvokeError();
                    if (inserted != chord.Length)
                    {
                        throw new Win32Exception(
                            sendInputLastError,
                            $"SendInput inserted {inserted} of {chord.Length} keyboard events.");
                    }
                }, DispatcherPriority.Send);

                await keyDownReceipt.Task.WaitAsync(TimeSpan.FromSeconds(2));
                await Shared.Value.Dispatcher.InvokeAsync(
                    () => RecordTimelineOnDispatcher("Harness.KeyDownReceiptCompleted"),
                    DispatcherPriority.Send);
                await keyUpReceipt.Task.WaitAsync(TimeSpan.FromSeconds(2));
                await Shared.Value.Dispatcher.InvokeAsync(() =>
                {
                    timelinePhase = $"RouteKey:{key}:{modifiers}:application-idle";
                    RecordTimelineOnDispatcher("Harness.KeyUpReceiptCompleted");
                }, DispatcherPriority.Send);
                await Shared.Value.Dispatcher.InvokeAsync(
                    () =>
                    {
                        RecordTimelineOnDispatcher("Harness.ApplicationIdleBegin");
                        window!.UpdateLayout();
                        RecordTimelineOnDispatcher("Harness.ApplicationIdleEnd");
                    },
                    DispatcherPriority.ApplicationIdle);
                afterProcessing = SelectionObservation();
            }
            finally
            {
                NativeInput[] releases = BuildKeyReleases(virtualKey, key, modifierKeys);
                await Shared.Value.Dispatcher.InvokeAsync(
                    () =>
                    {
                        timelinePhase = $"RouteKey:{key}:{modifiers}:cleanup";
                        RecordTimelineOnDispatcher("Harness.CleanupBegin");
                        Marshal.SetLastPInvokeError(0);
                        cleanupInserted = SendInput((uint)releases.Length, releases, Marshal.SizeOf<NativeInput>());
                        cleanupLastError = Marshal.GetLastPInvokeError();
                        if (previewHandler is not null)
                        {
                            window!.RemoveHandler(Keyboard.PreviewKeyDownEvent, previewHandler);
                        }

                        if (gridPreviewHandler is not null)
                        {
                            var grid = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
                            grid.RemoveHandler(Keyboard.PreviewKeyDownEvent, gridPreviewHandler);
                        }

                        if (keyDownHandler is not null)
                        {
                            window!.RemoveHandler(Keyboard.KeyDownEvent, keyDownHandler);
                        }

                        if (gridKeyDownHandler is not null)
                        {
                            var grid = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
                            grid.RemoveHandler(Keyboard.KeyDownEvent, gridKeyDownHandler);
                        }

                        if (keyUpHandler is not null)
                        {
                            window!.RemoveHandler(Keyboard.KeyUpEvent, keyUpHandler);
                        }

                        window!.UpdateLayout();
                        RecordTimelineOnDispatcher("Harness.CleanupEnd");
                    },
                    DispatcherPriority.ApplicationIdle);
                bool modifiersReleased = modifierKeys.All(static keyCode => !IsKeyDown(keyCode));
                bool primaryKeyReleased = !IsKeyDown(virtualKey);
                LastInputCleanup = new NativeInputCleanupTrace(
                    key.ToString(),
                    modifiers.ToString(),
                    inserted,
                    cleanupInserted,
                    cleanupLastError,
                    primaryKeyReleased,
                    modifiersReleased);
                InputTelemetry.Add(new NativeInputDeliveryTrace(
                    key.ToString(),
                    modifiers.ToString(),
                    "SendInputOnTargetDispatcherThread",
                    foregroundHandle.ToInt64(),
                    foregroundThreadId,
                    targetHandle.ToInt64(),
                    targetWindowThreadId,
                    targetDispatcherThreadId,
                    targetDispatcherManagedThreadId,
                    InputThreadsAttached: false,
                    InputThreadAttachmentApplicable: false,
                    setForegroundAccepted,
                    nativeFocusHandle.ToInt64(),
                    focusedAutomationIdBeforeInput,
                    queueHadKeyboardFocusBeforeInput,
                    (uint)chord.Length,
                    inserted,
                    sendInputLastError,
                    previewReceived,
                    previewModifiers,
                    keyDownReceived,
                    keyDownModifiers,
                    beforeInput,
                    new RoutedKeyEventTrace(
                        previewSourceType,
                        previewOriginalSourceType,
                        previewHandledAtWindow,
                        previewHandledAtGrid,
                        keyDownSourceType,
                        keyDownOriginalSourceType,
                        keyDownHandledAtGrid,
                        keyDownHandledAtWindow,
                        keyUpReceived,
                        keyUpModifiers,
                        keyUpHandledAtWindow),
                    afterProcessing,
                    LastInputCleanup));
                Assert.Equal((uint)releases.Length, cleanupInserted);
                Assert.Equal(0, cleanupLastError);
                Assert.True(primaryKeyReleased);
                Assert.True(modifiersReleased);
            }
        }

        public SelectionTrace SelectionObservation() => Shared.Value.Dispatcher.Invoke(() =>
        {
            var grid = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
            return SelectionObservationOnDispatcher(grid);
        });

        private SelectionTrace SelectionObservationOnDispatcher(System.Windows.Controls.DataGrid grid)
        {
            string? focusedAutomationId = FocusedAutomationId();
            QueueItemViewModel? currentCellItem = grid.CurrentCell.Item as QueueItemViewModel;
            return new SelectionTrace(
                ViewModel.CurrentItem?.ItemId,
                grid.SelectedItems
                    .OfType<QueueItemViewModel>()
                    .Select(static row => row.ItemId)
                    .ToArray(),
                focusedAutomationId,
                Keyboard.FocusedElement?.GetType().Name,
                grid.IsKeyboardFocusWithin,
                currentCellItem?.ItemId,
                grid.CurrentCell.Column?.DisplayIndex,
                grid.CurrentCell.IsValid);
        }

        public string PresentRedactedAuditStatus(string message) => Shared.Value.Dispatcher.Invoke(() =>
        {
            string safe = audit.RecordPresentedStatus(message);
            PropertyInfo statusProperty = typeof(SigningWorkbenchViewModel).GetProperty(
                nameof(SigningWorkbenchViewModel.StatusMessage),
                BindingFlags.Instance | BindingFlags.Public)!;
            statusProperty.SetValue(ViewModel, safe);
            window!.UpdateLayout();
            return safe;
        });

        public string VisibleText(string elementName) => Shared.Value.Dispatcher.Invoke(() =>
        {
            var text = (TextBlock)(window!.FindName(elementName) ??
                throw new InvalidOperationException($"Visible text element '{elementName}' was not found."));
            Assert.True(text.IsVisible);
            Assert.False(Bounds(text).IsEmpty);
            return text.Text;
        });

        public Dictionary<string, object> AssertQueueLayoutDoesNotOverlap() =>
            Shared.Value.Dispatcher.Invoke(() =>
            {
                FrameworkElement command = Element("CommandBand");
                FrameworkElement queue = Element("QueueRegion");
                FrameworkElement actions = Element("ActionBand");
                FrameworkElement status = Element("SummaryRegion");
                Rect commandBounds = Bounds(command);
                Rect queueBounds = Bounds(queue);
                Rect actionBounds = Bounds(actions);
                Rect statusBounds = Bounds(status);
                Assert.False(commandBounds.IsEmpty);
                Assert.False(queueBounds.IsEmpty);
                Assert.False(actionBounds.IsEmpty);
                Assert.False(statusBounds.IsEmpty);
                Assert.False(commandBounds.IntersectsWith(queueBounds));
                Assert.False(queueBounds.IntersectsWith(actionBounds));
                Assert.False(actionBounds.IntersectsWith(statusBounds));
                return new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["command"] = SerializableBounds(commandBounds),
                    ["queue"] = SerializableBounds(queueBounds),
                    ["actions"] = SerializableBounds(actionBounds),
                    ["status"] = SerializableBounds(statusBounds)
                };
            });

        public List<ViewportEvidence> CaptureViewportEvidenceMatrix(
            string evidenceDirectory,
            string expectedFullStatus,
            string expectedCompactStatus) => Shared.Value.Dispatcher.Invoke(() =>
        {
            var evidence = new List<ViewportEvidence>(ViewportEvidencePlan.Count);
            double originalWidth = window!.Width;
            double originalHeight = window.Height;
            try
            {
                foreach (ViewportSpec viewport in ViewportEvidencePlan)
                {
                    window.Width = viewport.WidthDip;
                    window.Height = viewport.HeightDip;
                    window.UpdateLayout();

                    FrameworkElement root = Element("RootGrid");
                    FrameworkElement command = Element("CommandBand");
                    FrameworkElement queue = Element("QueueRegion");
                    FrameworkElement actions = Element("ActionBand");
                    var status = (TextBlock)Element("SummaryRegion");
                    Rect windowBounds = new(0, 0, window.ActualWidth, window.ActualHeight);
                    Rect rootBounds = Bounds(root);
                    Rect commandBounds = Bounds(command);
                    Rect queueBounds = Bounds(queue);
                    Rect actionBounds = Bounds(actions);
                    Rect statusBounds = Bounds(status);
                    bool regionsInsideViewport =
                        Contains(windowBounds, rootBounds) &&
                        Contains(windowBounds, commandBounds) &&
                        Contains(windowBounds, queueBounds) &&
                        Contains(windowBounds, actionBounds) &&
                        Contains(windowBounds, statusBounds);
                    bool regionsDoNotOverlap =
                        !commandBounds.IntersectsWith(queueBounds) &&
                        !queueBounds.IntersectsWith(actionBounds) &&
                        !actionBounds.IntersectsWith(statusBounds);
                    AutomationPeer automationPeer =
                        FrameworkElementAutomationPeer.CreatePeerForElement(status) ??
                        new FrameworkElementAutomationPeer(status);
                    string automationName = automationPeer.GetName();
                    string? automationHelpText = automationPeer.GetHelpText();
                    string tooltipText = Assert.IsType<string>(status.ToolTip);
                    string expectedVisibleStatus = ExpectedViewportSummaryStatus(
                        window.IsCompactLayout,
                        expectedFullStatus,
                        expectedCompactStatus);
                    bool fullTextAccessible =
                        string.Equals(automationName, expectedVisibleStatus, StringComparison.Ordinal) &&
                        string.Equals(tooltipText, expectedVisibleStatus, StringComparison.Ordinal);

                    int scalePercent = viewport.ScalePercent ?? 100;
                    double renderDpi = 96d * scalePercent / 100d;
                    double widthToleranceDip = DevicePixelQuantumDip(renderDpi);
                    Assert.InRange(
                        window.ActualWidth,
                        viewport.WidthDip - widthToleranceDip,
                        viewport.WidthDip + widthToleranceDip);
                    Assert.Equal(viewport.HeightDip, window.ActualHeight, precision: 2);
                    Assert.Equal(expectedVisibleStatus, status.Text);
                    Assert.True(fullTextAccessible);
                    Assert.True(regionsInsideViewport);
                    Assert.True(regionsDoNotOverlap);

                    int bitmapWidth = Math.Max(1, (int)Math.Ceiling(window.ActualWidth * scalePercent / 100d));
                    int bitmapHeight = Math.Max(1, (int)Math.Ceiling(window.ActualHeight * scalePercent / 100d));
                    string screenshot = Path.Combine(evidenceDirectory, $"viewport-{viewport.Label}.png");
                    CaptureScreenshotOnDispatcher(screenshot, bitmapWidth, bitmapHeight, renderDpi);
                    evidence.Add(new ViewportEvidence(
                        viewport.Label,
                        viewport.WidthDip,
                        viewport.HeightDip,
                        scalePercent,
                        window.ActualWidth,
                        window.ActualHeight,
                        bitmapWidth,
                        bitmapHeight,
                        renderDpi,
                        Path.GetFullPath(screenshot),
                        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(screenshot))),
                        SerializableBounds(windowBounds),
                        SerializableBounds(rootBounds),
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["command"] = SerializableBounds(commandBounds),
                            ["queue"] = SerializableBounds(queueBounds),
                            ["actions"] = SerializableBounds(actionBounds),
                            ["status"] = SerializableBounds(statusBounds)
                        },
                        status.Text,
                        automationName,
                        automationHelpText,
                        tooltipText,
                        status.TextTrimming.ToString(),
                        fullTextAccessible,
                        regionsInsideViewport,
                        regionsDoNotOverlap));
                }
            }
            finally
            {
                window.Width = originalWidth;
                window.Height = originalHeight;
                window.UpdateLayout();
            }

            return evidence;
        });

        public void CaptureScreenshot(string path) => Shared.Value.Dispatcher.Invoke(() =>
        {
            timelinePhase = "capture-screenshot";
            RecordTimelineOnDispatcher("Harness.CaptureScreenshotBegin");
            window!.UpdateLayout();
            int width = Math.Max(1, (int)Math.Ceiling(window.ActualWidth));
            int height = Math.Max(1, (int)Math.Ceiling(window.ActualHeight));
            CaptureScreenshotOnDispatcher(path, width, height, 96);
            RecordTimelineOnDispatcher("Harness.CaptureScreenshotEnd");
        });

        private void CaptureScreenshotOnDispatcher(string path, int width, int height, double dpi)
        {
            var bitmap = new RenderTargetBitmap(width, height, dpi, dpi, PixelFormats.Pbgra32);
            bitmap.Render(window);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using FileStream stream = File.Create(path);
            encoder.Save(stream);
        }

        public async ValueTask DisposeAsync()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            Shared.Value.Dispatcher.Invoke(() => window?.Close());
            await ViewModel.DisposeAsync();
        }

        private FrameworkElement Element(string name)
        {
            var element = (FrameworkElement)(window!.FindName(name) ??
                throw new InvalidOperationException($"Layout element '{name}' was not found."));
            Assert.True(element.IsVisible);
            return element;
        }

        private Rect Bounds(FrameworkElement element) => element
            .TransformToAncestor(window!)
            .TransformBounds(new Rect(0, 0, element.ActualWidth, element.ActualHeight));

        private static bool Contains(Rect outer, Rect inner) =>
            !inner.IsEmpty &&
            inner.Left >= outer.Left &&
            inner.Top >= outer.Top &&
            inner.Right <= outer.Right &&
            inner.Bottom <= outer.Bottom;

        private static object SerializableBounds(Rect bounds) => new
        {
            bounds.X,
            bounds.Y,
            bounds.Width,
            bounds.Height
        };

        private static string? FocusedAutomationId()
        {
            DependencyObject? current = System.Windows.Input.Keyboard.FocusedElement as DependencyObject;
            while (current is not null)
            {
                string automationId = AutomationProperties.GetAutomationId(current);
                if (!string.IsNullOrWhiteSpace(automationId))
                {
                    return automationId;
                }

                current = VisualTreeHelper.GetParent(current);
            }

            return null;
        }

        private void RecordTimelineOnDispatcher(
            string eventName,
            RoutedEventArgs? routedEvent = null,
            IInputElement? oldFocus = null,
            IInputElement? newFocus = null)
        {
            if (window is null)
            {
                return;
            }

            var grid = (System.Windows.Controls.DataGrid)window.FindName("QueueGrid");
            QueueItemViewModel? currentCellItem = grid.CurrentCell.Item as QueueItemViewModel;
            UiEventTimeline.Add(new UiEventTimelineTrace(
                Interlocked.Increment(ref timelineOrder),
                Stopwatch.GetTimestamp(),
                timelinePhase,
                eventName,
                routedEvent?.Source?.GetType().Name,
                routedEvent?.OriginalSource?.GetType().Name,
                AutomationIdFor(oldFocus),
                oldFocus?.GetType().Name,
                AutomationIdFor(newFocus),
                newFocus?.GetType().Name,
                FocusedAutomationId(),
                Keyboard.FocusedElement?.GetType().Name,
                grid.IsKeyboardFocusWithin,
                ViewModel.CurrentItem?.ItemId,
                grid.SelectedItems.OfType<QueueItemViewModel>().Select(static row => row.ItemId).ToArray(),
                currentCellItem?.ItemId,
                grid.CurrentCell.Column?.DisplayIndex,
                grid.CurrentCell.IsValid,
                ViewModel.FocusTargetAutomationId));
        }

        private void RecordObservedKeyEventOnDispatcher(
            string eventName,
            System.Windows.Input.KeyEventArgs eventArgs) =>
            ObservedKeyEvents.Add(new ObservedRoutedKeyEventTrace(
                eventName,
                eventArgs.Key.ToString(),
                eventArgs.SystemKey.ToString(),
                eventArgs.ImeProcessedKey.ToString(),
                eventArgs.DeadCharProcessedKey.ToString(),
                NormalizeObservedKey(eventArgs).ToString(),
                Keyboard.Modifiers.ToString(),
                eventArgs.Handled,
                eventArgs.Source?.GetType().Name,
                eventArgs.OriginalSource?.GetType().Name));

        private static string? AutomationIdFor(IInputElement? element)
        {
            DependencyObject? current = element as DependencyObject;
            while (current is not null)
            {
                string automationId = AutomationProperties.GetAutomationId(current);
                if (!string.IsNullOrWhiteSpace(automationId))
                {
                    return automationId;
                }

                current = VisualTreeHelper.GetParent(current);
            }

            return null;
        }

        private static T? FindVisualAncestor<T>(DependencyObject start) where T : DependencyObject
        {
            DependencyObject? current = start;
            while (current is not null)
            {
                if (current is T match)
                {
                    return match;
                }

                current = VisualTreeHelper.GetParent(current);
            }

            return null;
        }

        private static ushort[] ModifierVirtualKeys(ModifierKeys modifiers)
        {
            const ModifierKeys supported = ModifierKeys.Control | ModifierKeys.Shift;
            if ((modifiers & ~supported) != ModifierKeys.None)
            {
                throw new ArgumentOutOfRangeException(nameof(modifiers), modifiers, "Only Ctrl and Shift are used by UI-10.");
            }

            var keys = new List<ushort>(2);
            if ((modifiers & ModifierKeys.Control) != ModifierKeys.None)
            {
                keys.Add(0x11);
            }

            if ((modifiers & ModifierKeys.Shift) != ModifierKeys.None)
            {
                keys.Add(0x10);
            }

            return keys.ToArray();
        }

        private static Key NormalizeObservedKey(System.Windows.Input.KeyEventArgs eventArgs) =>
            FileTaskQueueUiAutomationTests.NormalizeObservedKey(
            eventArgs.Key,
            eventArgs.SystemKey,
            eventArgs.ImeProcessedKey,
            eventArgs.DeadCharProcessedKey);

        private static NativeInput[] BuildKeyboardChord(ushort virtualKey, Key key, ushort[] modifierKeys)
        {
            var inputs = new List<NativeInput>((modifierKeys.Length * 2) + 2);
            inputs.AddRange(modifierKeys.Select(static keyCode => KeyboardInput(keyCode, keyUp: false, extended: false)));
            inputs.Add(KeyboardInput(virtualKey, keyUp: false, IsExtendedKey(key)));
            inputs.Add(KeyboardInput(virtualKey, keyUp: true, IsExtendedKey(key)));
            inputs.AddRange(modifierKeys.Reverse().Select(static keyCode => KeyboardInput(keyCode, keyUp: true, extended: false)));
            return inputs.ToArray();
        }

        private static NativeInput[] BuildKeyReleases(ushort virtualKey, Key key, ushort[] modifierKeys)
        {
            var inputs = new List<NativeInput>(modifierKeys.Length + 1)
            {
                KeyboardInput(virtualKey, keyUp: true, IsExtendedKey(key))
            };
            inputs.AddRange(modifierKeys.Reverse().Select(static keyCode => KeyboardInput(keyCode, keyUp: true, extended: false)));
            return inputs.ToArray();
        }

        private static NativeInput KeyboardInput(ushort virtualKey, bool keyUp, bool extended)
        {
            const uint keyboardInput = 1;
            const uint keyEventExtendedKey = 0x0001;
            const uint keyEventKeyUp = 0x0002;
            uint flags = (extended ? keyEventExtendedKey : 0) | (keyUp ? keyEventKeyUp : 0);
            return new NativeInput
            {
                Type = keyboardInput,
                Data = new NativeInputUnion
                {
                    Keyboard = new NativeKeyboardInput
                    {
                        VirtualKey = virtualKey,
                        Flags = flags
                    }
                }
            };
        }

        private static bool IsKeyDown(ushort virtualKey) => (GetAsyncKeyState(virtualKey) & 0x8000) != 0;

        private static bool IsExtendedKey(Key key) => key is
            Key.Up or Key.Down or Key.Left or Key.Right or
            Key.Insert or Key.Delete or Key.Home or Key.End or Key.PageUp or Key.PageDown;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint inputCount, [In] NativeInput[] inputs, int inputSize);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(ushort virtualKey);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr windowHandle);

        [DllImport("user32.dll")]
        private static extern IntPtr GetFocus();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr windowHandle, out uint processId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeInput
        {
            public uint Type;
            public NativeInputUnion Data;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct NativeInputUnion
        {
            [FieldOffset(0)] public NativeMouseInput Mouse;
            [FieldOffset(0)] public NativeKeyboardInput Keyboard;
            [FieldOffset(0)] public NativeHardwareInput Hardware;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeMouseInput
        {
            public int X;
            public int Y;
            public uint MouseData;
            public uint Flags;
            public uint Time;
            public UIntPtr ExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeKeyboardInput
        {
            public ushort VirtualKey;
            public ushort ScanCode;
            public uint Flags;
            public uint Time;
            public UIntPtr ExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeHardwareInput
        {
            public uint Message;
            public ushort ParameterLow;
            public ushort ParameterHigh;
        }

        private static IEnumerable<DependencyObject> Enumerate(DependencyObject root)
        {
            var stack = new Stack<DependencyObject>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                DependencyObject current = stack.Pop();
                yield return current;
                for (int index = VisualTreeHelper.GetChildrenCount(current) - 1; index >= 0; index--)
                {
                    stack.Push(VisualTreeHelper.GetChild(current, index));
                }
            }
        }
    }

    private sealed class WpfDispatcherHost
    {
        private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public WpfDispatcherHost()
        {
            var thread = new Thread(Run) { IsBackground = true, Name = "CodeSigner.FileTaskQueueUi.STA" };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            ready.Task.Wait(TimeSpan.FromSeconds(10));
            Assert.True(ready.Task.IsCompletedSuccessfully);
        }

        public Dispatcher Dispatcher { get; private set; } = null!;
        public uint NativeThreadId { get; private set; }
        public int ManagedThreadId { get; private set; }

        private void Run()
        {
            Dispatcher = Dispatcher.CurrentDispatcher;
            NativeThreadId = GetCurrentThreadId();
            ManagedThreadId = Environment.CurrentManagedThreadId;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher));
            var application = new System.Windows.Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            application.Resources.MergedDictionaries.Add(new ResourceDictionary
            {
                Source = new Uri(
                    "pack://application:,,,/CodeSigner.App;component/Themes/DesignTokens.xaml",
                    UriKind.Absolute)
            });
            ready.TrySetResult();
            Dispatcher.Run();
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();
    }

    private sealed class FakeIntakeAdapter : IIntakeAdapter
    {
        private readonly Dictionary<string, int> detections = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> plans = new(StringComparer.OrdinalIgnoreCase);

        public int AdmissionCalls { get; private set; }
        public int TotalDetectionCalls => detections.Values.Sum();
        public int TotalPlanCalls => plans.Values.Sum();
        public int IntegrityCalls { get; private set; }
        public Dictionary<string, QueuedSourceDetectionStatus> DetectionResults { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, QueuedSourceDetectionStatus> IntegrityResults { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> IdentityAliases { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> FailingOutputRoots { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Task<QueuedSourceAdmissionResult> AdmitAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AdmissionCalls++;
            QueuedSource[] sources = inputs.Select(path =>
            {
                string identity = IdentityAliases.GetValueOrDefault(path, path);
                return new QueuedSource(path, Path.GetFileName(path), new StableFileIdentity(1, identity));
            }).ToArray();
            return Task.FromResult(new QueuedSourceAdmissionResult(sources, []));
        }

        public Task<QueuedSourceDetectionResult> DetectAsync(QueuedSource source, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            detections[source.CanonicalPath] = DetectionCount(source.CanonicalPath) + 1;
            QueuedSourceDetectionStatus status = DetectionResults.GetValueOrDefault(
                source.CanonicalPath,
                QueuedSourceDetectionStatus.Supported);
            DetectedQueuedSource? detected = status == QueuedSourceDetectionStatus.Supported
                ? Detected(source)
                : null;
            return Task.FromResult(new QueuedSourceDetectionResult(status, detected, IntakeError.NotSignableSubject));
        }

        public Task<IntakeFile> PlanOutputAsync(
            DetectedQueuedSource detectedSource,
            string outputRoot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = detectedSource.Source.CanonicalPath;
            plans[path] = PlanCount(path) + 1;
            if (FailingOutputRoots.Contains(outputRoot))
            {
                throw new IntakeValidationException(IntakeError.DestinationCollision, "fake output rejection", path);
            }

            return Task.FromResult(new IntakeFile(
                path,
                detectedSource.Source.RelativePath,
                Path.Combine(outputRoot, detectedSource.Source.RelativePath),
                outputRoot,
                detectedSource.Source.Identity,
                detectedSource.Subject));
        }

        public Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
            DetectedQueuedSource detectedSource,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IntegrityCalls++;
            QueuedSourceDetectionStatus status = IntegrityResults.GetValueOrDefault(
                detectedSource.Source.CanonicalPath,
                QueuedSourceDetectionStatus.Supported);
            return Task.FromResult(new QueuedSourceDetectionResult(
                status,
                status == QueuedSourceDetectionStatus.Supported ? detectedSource : null,
                status == QueuedSourceDetectionStatus.Supported ? null : IntakeError.InvalidInput));
        }

        public int DetectionCount(string path) => detections.GetValueOrDefault(path);
        public int PlanCount(string path) => plans.GetValueOrDefault(path);

        private static DetectedQueuedSource Detected(QueuedSource source) => new(
            source,
            new SignableSubject(
                string.Equals(Path.GetExtension(source.CanonicalPath), ".msi", StringComparison.OrdinalIgnoreCase)
                    ? SignableFileType.WindowsInstaller
                    : SignableFileType.PortableExecutable,
                Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee")),
            new SourceFingerprint(source.Identity, 4, DateTime.UnixEpoch, new string('A', 64)));
    }

    private sealed class FakeBatchAdapter : IBatchAdapter
    {
        private readonly FakeHostProtectedOperationTracker protectedOperations;

        public FakeBatchAdapter(FakeHostProtectedOperationTracker protectedOperations)
        {
            this.protectedOperations = protectedOperations;
        }

        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;
        public int RunCount { get; private set; }
        public Task<BatchProgressUpdate> RunAsync(BatchItemRequest request, CancellationToken cancellationToken)
        {
            RunCount++;
            protectedOperations.RecordSigningCall();
            throw new InvalidOperationException("The fake UI scenarios never execute Sign.");
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            protectedOperations.RecordSigningCall();
            throw new InvalidOperationException("The fake UI scenarios never execute Retry.");
        }
        public void PruneItems(IReadOnlyCollection<string> itemIds) { }
        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void EmitLate(string itemId) => ProgressChanged?.Invoke(
            this,
            new BatchProgressChangedEventArgs(new BatchProgressUpdate(itemId, BatchItemState.Failed, null)));
    }

    private sealed class RecordingAuditSink : IQueueAuditSink
    {
        public List<string> Entries { get; } = [];
        public bool CheckHealth() => true;
        public bool WriteQueueEvent(
            string eventName,
            string itemId,
            string operationId,
            string phase,
            string? check = null,
            string? action = null,
            string? outcome = null,
            string? reason = null)
        {
            Entries.Add(string.Join('|', eventName, itemId, operationId, phase, check, action, outcome, reason));
            return true;
        }

        public bool WriteAdmissionEvent(string eventName, string operationId, string? outcome = null, string? reason = null)
        {
            Entries.Add(string.Join('|', eventName, operationId, outcome, reason));
            return true;
        }

        public string RecordPresentedStatus(string message)
        {
            string safe = SigningDiagnosticRedactor.RedactText(message) ?? string.Empty;
            Entries.Add($"audit-presentation|{safe}");
            return safe;
        }
    }

    private sealed class FakeReadinessAdapter : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => new(
            new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
            NativeApiAvailability.Available,
            new SimplySignInstallation(SimplySignInstallationStatus.Installed, "{A}", "{B}", "SimplySign Desktop", "Certum", "9.2"),
            new CertificateCatalog(CertificateAvailabilityStatus.Unavailable, [], []),
            new TimestampConfiguration(TimestampConfigurationStatus.Configured, timestampUri),
            ProviderAuthorizationStatus.AuthorizationUnknown);
    }

    private sealed class ThrowingWorkerHealthService(FakeHostProtectedOperationTracker protectedOperations)
        : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken)
        {
            protectedOperations.RecordWorkerStart();
            throw new InvalidOperationException("Worker probes are prohibited in the fake UI host.");
        }
    }

    private sealed class NoopWorkerRepairService(FakeHostProtectedOperationTracker protectedOperations)
        : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken)
        {
            protectedOperations.RecordProtectedLaunch();
            throw new InvalidOperationException("Worker repair is prohibited in the fake UI host.");
        }
        public void Dispose() { }
    }

    private sealed class ThrowingShell(FakeHostProtectedOperationTracker protectedOperations) : IOperatorShell
    {
        public void OpenFolder(string path)
        {
            protectedOperations.RecordProtectedLaunch();
            throw new InvalidOperationException("Shell calls are prohibited in the fake UI host.");
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> values,
            int retentionDays,
            CancellationToken cancellationToken)
        {
            protectedOperations.RecordProtectedLaunch();
            throw new InvalidOperationException("Shell calls are prohibited in the fake UI host.");
        }
    }

    private sealed class ScriptedDialogs : IWorkbenchDialogs
    {
        private readonly Queue<IReadOnlyList<string>> fileSelections = new();

        public int PickExeFilesCallCount { get; private set; }

        public void ConfigureTwoFileSelections(string firstSource, string secondSource)
        {
            if (fileSelections.Count != 0)
            {
                throw new InvalidOperationException("The direct-add file picker was already configured.");
            }

            fileSelections.Enqueue([firstSource]);
            fileSelections.Enqueue([secondSource]);
        }

        public IReadOnlyList<string> PickExeFiles(Window owner)
        {
            PickExeFilesCallCount++;
            return fileSelections.TryDequeue(out IReadOnlyList<string>? selection)
                ? selection
                : throw new InvalidOperationException("The direct-add file picker was invoked more than twice.");
        }

        public string? PickInputFolder(Window owner) => null;
        public string? PickOutputRoot(Window owner, string? currentOutputRoot) => null;
    }

    private static string ResolveRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("CodeSigner.sln was not found.");
    }
}

[Collection(FileTaskQueueUiSerialGroup.Name)]
public sealed class FileTaskQueueUiManualHostTests
{
    [Fact]
    [Trait("Category", "UserOperatedUiHost")]
    public async Task VisibleFakeHostWaitsForExplicitUserCompletionWithoutSyntheticInput()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("CODESIGNER_MANUAL_UI_QA"), "1", StringComparison.Ordinal))
        {
            return;
        }

        string completionFile = Environment.GetEnvironmentVariable("CODESIGNER_MANUAL_UI_QA_COMPLETION_FILE")
            ?? throw new InvalidOperationException("CODESIGNER_MANUAL_UI_QA_COMPLETION_FILE is required.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromHours(8));
        await FileTaskQueueUiAutomationTests.RunManualHostAsync(completionFile, timeout.Token);
    }
}
