using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

public sealed partial class QueueInteractionAuditLogTests
{
    private static readonly string[] BoundedActions =
    [
        QueueAuditActions.CurrentSelection,
        QueueAuditActions.CurrentDeselection,
        QueueAuditActions.OutputReplan,
        QueueAuditActions.ModeChange,
        QueueAuditActions.PrimaryCertificateRoleChange,
        QueueAuditActions.SecondaryCertificateRoleChange,
        QueueAuditActions.TimestampSettingsApply,
        QueueAuditActions.ReadinessRefresh,
        QueueAuditActions.Sign,
        QueueAuditActions.Retry,
        QueueAuditActions.Cancel,
        QueueAuditActions.Remove,
        QueueAuditActions.ReAdd
    ];

    [Fact]
    public async Task RefreshWorkerCommandWritesExactlyOneReadinessRefreshPair()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        await fixture.QueueReadyAsync(viewModel, sink);
        int eventCountBeforeCommand = fixture.Log.Read().Count;

        Assert.True(viewModel.RefreshWorkerCommand.CanExecute(null));
        await viewModel.RefreshWorkerCommand.ExecuteAsync(null);

        SigningRuntimeEvent[] pair = fixture.Log.Read()
            .Skip(eventCountBeforeCommand)
            .Where(entry => entry.Action == QueueAuditActions.ReadinessRefresh)
            .ToArray();
        Assert.Equal(2, pair.Length);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, pair[0].Event);
        Assert.Equal(SigningRuntimeEventNames.UserActionCompleted, pair[1].Event);
        Assert.Equal(QueueAuditOutcomes.Completed, pair[1].Outcome);
        Assert.Equal(pair[0].ItemId, pair[1].ItemId);
        Assert.Equal(pair[0].OperationId, pair[1].OperationId);
        Assert.Matches("^[0-9a-f]{32}$", pair[0].OperationId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PreActionFailureBlocksRefreshEntryWithoutWorkerOrQueueMutation(bool useWorkerOnlyCommand)
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);
        WorkerHealthState healthBefore = viewModel.WorkerHealthState;
        WorkerLaunchDiagnostic? diagnosticBefore = viewModel.WorkerDiagnostic;
        string readinessBefore = viewModel.ReadinessAnnouncement;
        BatchItemState rowStateBefore = row.State;
        string sourceHash = fixture.SourceHash();
        int workerProbeCallsBefore = fixture.Worker.ProbeCalls;
        int eventCountBeforeAttempt = fixture.Log.Read().Count;
        int writeAttemptCountBefore = sink.UserActionWriteAttempts.Count;
        sink.FailNextUserStart = true;

        if (useWorkerOnlyCommand)
        {
            await viewModel.RefreshWorkerCommand.ExecuteAsync(null);
        }
        else
        {
            await viewModel.RefreshReadinessAsync();
        }

        ControllableAuditSink.UserActionWriteAttempt[] attempts = sink.UserActionWriteAttempts
            .Skip(writeAttemptCountBefore)
            .ToArray();
        SigningRuntimeEvent[] entries = fixture.Log.Read().Skip(eventCountBeforeAttempt).ToArray();
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        Assert.Equal(workerProbeCallsBefore, fixture.Worker.ProbeCalls);
        Assert.Equal(healthBefore, viewModel.WorkerHealthState);
        Assert.Same(diagnosticBefore, viewModel.WorkerDiagnostic);
        Assert.Equal(readinessBefore, viewModel.ReadinessAnnouncement);
        Assert.Same(row, viewModel.CurrentItem);
        Assert.Equal(rowStateBefore, row.State);
        Assert.Equal(0, batch.RunCalls);
        Assert.Equal(0, batch.ResumeCalls);
        Assert.Equal(0, batch.CancelCalls);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Single(attempts);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, attempts[0].EventName);
        Assert.Equal(QueueAuditActions.ReadinessRefresh, attempts[0].Action);
        Assert.Equal(row.ItemId, attempts[0].ItemId);
        Assert.DoesNotContain(attempts, attempt => attempt.EventName is
            SigningRuntimeEventNames.UserActionCompleted or
            SigningRuntimeEventNames.UserActionRejected);
        Assert.Empty(entries);
    }

    [Fact]
    public async Task AuditedActionChecksHealthBeforeRecoveryAndMutatesOnlyAfterSinkRestores()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);
        CertificateOptionViewModel? primaryBefore = viewModel.PrimaryCertificate;
        string sourceHash = fixture.SourceHash();
        sink.FailNextUserTerminal = true;

        viewModel.SelectedMode = SigningMode.Dual;

        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        sink.Healthy = false;
        int eventCountBeforeBlockedAttempt = fixture.Log.Read().Count;
        viewModel.PrimaryCertificate = null;

        Assert.Equal(1, sink.CheckHealthCalls);
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        Assert.Same(primaryBefore, viewModel.PrimaryCertificate);
        Assert.Same(row, viewModel.CurrentItem);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.DoesNotContain(
            fixture.Log.Read().Skip(eventCountBeforeBlockedAttempt),
            entry => entry.Action == QueueAuditActions.PrimaryCertificateRoleChange);

        sink.Healthy = true;
        int eventCountBeforeRecoveredAttempt = fixture.Log.Read().Count;
        viewModel.PrimaryCertificate = null;

        SigningRuntimeEvent[] pair = fixture.Log.Read()
            .Skip(eventCountBeforeRecoveredAttempt)
            .Where(entry => entry.Action == QueueAuditActions.PrimaryCertificateRoleChange)
            .ToArray();
        Assert.Equal(2, sink.CheckHealthCalls);
        Assert.Null(viewModel.AuditBlockerReasonCode);
        Assert.Null(viewModel.PrimaryCertificate);
        Assert.Equal(SigningMode.Dual, viewModel.SelectedMode);
        Assert.Same(row, viewModel.CurrentItem);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Equal(2, pair.Length);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, pair[0].Event);
        Assert.Equal(SigningRuntimeEventNames.UserActionCompleted, pair[1].Event);
        Assert.Equal(pair[0].OperationId, pair[1].OperationId);
    }

    [Fact]
    public async Task BusyCurrentSelectionWritesRejectedPairWithoutChangingCurrentItem()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter { BlockRun = true };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel first = await fixture.QueueReadyAsync(viewModel, sink);
        await viewModel.QueueFilesAsync([fixture.SecondSourcePath]);
        QueueItemViewModel second = viewModel.Rows.Single(row => !ReferenceEquals(row, first));
        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        int eventCountBeforeSelection = fixture.Log.Read().Count;

        await viewModel.SetCurrentItemAsync(second.ItemId);

        SigningRuntimeEvent[] pair = fixture.Log.Read()
            .Skip(eventCountBeforeSelection)
            .Where(entry => entry.Action == QueueAuditActions.CurrentSelection)
            .ToArray();
        Assert.Same(first, viewModel.CurrentItem);
        Assert.Equal(2, pair.Length);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, pair[0].Event);
        Assert.Equal(SigningRuntimeEventNames.UserActionRejected, pair[1].Event);
        Assert.Equal(QueueAuditOutcomes.Rejected, pair[1].Outcome);
        Assert.Equal(QueueAuditReasons.Busy, pair[1].Reason);
        Assert.Equal(second.ItemId, pair[0].ItemId);
        Assert.Equal(pair[0].OperationId, pair[1].OperationId);

        batch.ReleaseRun();
        await signing;
    }

    [Fact]
    public async Task BusyCurrentDeselectionWritesRejectedPairWithoutChangingCurrentItem()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter { BlockRun = true };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel current = await fixture.QueueReadyAsync(viewModel, sink);
        string sourceHash = fixture.SourceHash();
        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        BatchItemState stateBeforeDeselection = current.State;
        int eventCountBeforeDeselection = fixture.Log.Read().Count;

        await viewModel.SetCurrentItemAsync(null);

        SigningRuntimeEvent[] pair = fixture.Log.Read()
            .Skip(eventCountBeforeDeselection)
            .Where(entry => entry.Action == QueueAuditActions.CurrentDeselection)
            .ToArray();
        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal(stateBeforeDeselection, current.State);
        Assert.Equal(1, batch.RunCalls);
        Assert.Equal(0, batch.ResumeCalls);
        Assert.Equal(0, batch.CancelCalls);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Equal(2, pair.Length);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, pair[0].Event);
        Assert.Equal(SigningRuntimeEventNames.UserActionRejected, pair[1].Event);
        Assert.Equal(QueueAuditOutcomes.Rejected, pair[1].Outcome);
        Assert.Equal(QueueAuditReasons.Busy, pair[1].Reason);
        Assert.Equal(current.ItemId, pair[0].ItemId);
        Assert.Equal(pair[0].ItemId, pair[1].ItemId);
        Assert.Equal(pair[0].OperationId, pair[1].OperationId);
        Assert.Matches("^[0-9a-f]{32}$", pair[0].OperationId);

        batch.ReleaseRun();
        await signing;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BusyCurrentTransitionPreActionFailureKeepsCurrentItemWithoutTerminalOrMutation(bool deselect)
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter { BlockRun = true };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel current = await fixture.QueueReadyAsync(viewModel, sink);
        await viewModel.QueueFilesAsync([fixture.SecondSourcePath]);
        QueueItemViewModel candidate = viewModel.Rows.Single(row => !ReferenceEquals(row, current));
        string sourceHash = fixture.SourceHash();
        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        BatchItemState stateBeforeAttempt = current.State;
        int eventCountBeforeAttempt = fixture.Log.Read().Count;
        int writeAttemptCountBefore = sink.UserActionWriteAttempts.Count;
        sink.FailNextUserStart = true;

        await viewModel.SetCurrentItemAsync(deselect ? null : candidate.ItemId);

        string expectedAction = deselect
            ? QueueAuditActions.CurrentDeselection
            : QueueAuditActions.CurrentSelection;
        string expectedItemId = deselect ? current.ItemId : candidate.ItemId;
        ControllableAuditSink.UserActionWriteAttempt[] attempts = sink.UserActionWriteAttempts
            .Skip(writeAttemptCountBefore)
            .ToArray();
        SigningRuntimeEvent[] entries = fixture.Log.Read().Skip(eventCountBeforeAttempt).ToArray();
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal(stateBeforeAttempt, current.State);
        Assert.Equal(1, batch.RunCalls);
        Assert.Equal(0, batch.ResumeCalls);
        Assert.Equal(0, batch.CancelCalls);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Single(attempts);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, attempts[0].EventName);
        Assert.Equal(expectedAction, attempts[0].Action);
        Assert.Equal(expectedItemId, attempts[0].ItemId);
        Assert.DoesNotContain(attempts, attempt => attempt.EventName is
            SigningRuntimeEventNames.UserActionCompleted or
            SigningRuntimeEventNames.UserActionRejected);
        Assert.Empty(entries);

        batch.ReleaseRun();
        await signing;
    }

    [Fact]
    public async Task RepeatedUnhealthyAuditedEntriesRecheckBeforeRecoveryThenWriteOneNormalPair()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);
        string sourceHash = fixture.SourceHash();
        WorkerHealthState healthBefore = viewModel.WorkerHealthState;
        WorkerLaunchDiagnostic? diagnosticBefore = viewModel.WorkerDiagnostic;
        sink.FailNextUserTerminal = true;

        viewModel.SelectedMode = SigningMode.Dual;

        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        sink.Healthy = false;
        CertificateOptionViewModel? primaryBefore = viewModel.PrimaryCertificate;
        int eventCountBeforeBlockedAttempts = fixture.Log.Read().Count;
        int writeAttemptCountBeforeBlockedAttempts = sink.UserActionWriteAttempts.Count;
        viewModel.PrimaryCertificate = null;
        viewModel.SelectedMode = SigningMode.Single;

        ControllableAuditSink.UserActionWriteAttempt[] blockedAttempts = sink.UserActionWriteAttempts
            .Skip(writeAttemptCountBeforeBlockedAttempts)
            .ToArray();
        Assert.Equal(2, sink.CheckHealthCalls);
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        Assert.Same(primaryBefore, viewModel.PrimaryCertificate);
        Assert.Equal(SigningMode.Dual, viewModel.SelectedMode);
        Assert.Same(row, viewModel.CurrentItem);
        Assert.Equal(healthBefore, viewModel.WorkerHealthState);
        Assert.Same(diagnosticBefore, viewModel.WorkerDiagnostic);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Empty(blockedAttempts);
        Assert.Empty(fixture.Log.Read().Skip(eventCountBeforeBlockedAttempts));

        sink.Healthy = true;
        int eventCountBeforeRecoveredAttempt = fixture.Log.Read().Count;
        viewModel.PrimaryCertificate = null;

        SigningRuntimeEvent[] pair = fixture.Log.Read()
            .Skip(eventCountBeforeRecoveredAttempt)
            .Where(entry => entry.Action == QueueAuditActions.PrimaryCertificateRoleChange)
            .ToArray();
        Assert.Equal(3, sink.CheckHealthCalls);
        Assert.Null(viewModel.AuditBlockerReasonCode);
        Assert.Null(viewModel.PrimaryCertificate);
        Assert.Equal(SigningMode.Dual, viewModel.SelectedMode);
        Assert.Same(row, viewModel.CurrentItem);
        Assert.Equal(healthBefore, viewModel.WorkerHealthState);
        Assert.Same(diagnosticBefore, viewModel.WorkerDiagnostic);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Equal(2, pair.Length);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, pair[0].Event);
        Assert.Equal(SigningRuntimeEventNames.UserActionCompleted, pair[1].Event);
        Assert.Equal(pair[0].ItemId, pair[1].ItemId);
        Assert.Equal(pair[0].OperationId, pair[1].OperationId);
    }

    [Fact]
    public void EveryBoundedActionRoundTripsAsOneOrderedLowercaseHexPairWithoutSecrets()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        foreach (string action in BoundedActions)
        {
            string actionId = Guid.NewGuid().ToString("N");
            Assert.True(log.WriteQueueEvent(
                SigningRuntimeEventNames.UserActionStarted,
                "41",
                actionId,
                QueueAuditPhases.UserAction,
                action: action));
            Assert.True(log.WriteQueueEvent(
                SigningRuntimeEventNames.UserActionCompleted,
                "41",
                actionId,
                QueueAuditPhases.UserAction,
                action: action,
                outcome: QueueAuditOutcomes.Completed));
        }

        string[] lines = File.ReadAllLines(log.Path);
        Assert.Equal(BoundedActions.Length * 2, lines.Length);
        JsonElement[] entries = lines.Select(line => JsonDocument.Parse(line).RootElement.Clone()).ToArray();
        foreach (string action in BoundedActions)
        {
            JsonElement[] pair = entries.Where(entry => entry.GetProperty("action").GetString() == action).ToArray();
            Assert.Equal(2, pair.Length);
            Assert.Equal("user-action-started", pair[0].GetProperty("event").GetString());
            Assert.Equal("user-action-completed", pair[1].GetProperty("event").GetString());
            Assert.Equal(pair[0].GetProperty("itemId").GetString(), pair[1].GetProperty("itemId").GetString());
            string actionId = pair[0].GetProperty("operationId").GetString()!;
            Assert.Equal(actionId, pair[1].GetProperty("operationId").GetString());
            Assert.Matches("^[0-9a-f]{32}$", actionId);
        }

        const string forbidden = "C:/hostile/cert.pfx pin=9231 token=inject https://tsa.invalid CN=Secret";
        Assert.DoesNotContain(forbidden, string.Join('\n', lines), StringComparison.Ordinal);
        QueueLogFixture.CopyEvidence(log.Path, "task8-action-matrix.jsonl");
    }

    [Fact]
    public async Task PreActionFailureRejectsSignWithoutBatchCallAndHealthRecoveryClearsOnlyAuditBlocker()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);
        string sourceHash = fixture.SourceHash();
        string outputBefore = viewModel.OutputRoot;
        sink.FailNextUserStart = true;

        await viewModel.SignAsync();

        Assert.Equal(0, batch.RunCalls);
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        sink.Healthy = false;
        viewModel.OutputRoot = fixture.OtherOutputRoot;
        Assert.Equal(outputBefore, viewModel.OutputRoot);

        sink.Healthy = true;
        Assert.True(viewModel.CheckAuditHealth());
        Assert.Null(viewModel.AuditBlockerReasonCode);
        row.IsSelected = true;
        sink.FailNextUserStart = true;
        viewModel.RemoveSelected();
        Assert.Same(row, Assert.Single(viewModel.Rows));
        Assert.True(viewModel.CheckAuditHealth());
        viewModel.OutputRoot = fixture.OtherOutputRoot;
        Assert.Equal(fixture.OtherOutputRoot, viewModel.OutputRoot);
        Assert.Equal(BatchItemState.Pending, row.State);
        Assert.Equal(sourceHash, fixture.SourceHash());
    }

    [Fact]
    public async Task TerminalFailurePreservesMutationBlocksLaterActionAndReAddUsesFreshItemCorrelation()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        QueueItemViewModel original = await fixture.QueueReadyAsync(viewModel, sink);
        string sourceHash = fixture.SourceHash();
        sink.FailNextUserTerminal = true;

        viewModel.SelectedMode = SigningMode.Dual;

        Assert.Equal(SigningMode.Dual, viewModel.SelectedMode);
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
        CertificateOptionViewModel? primaryBefore = viewModel.PrimaryCertificate;
        sink.Healthy = false;
        viewModel.PrimaryCertificate = null;
        Assert.Same(primaryBefore, viewModel.PrimaryCertificate);

        sink.Healthy = true;
        Assert.True(viewModel.CheckAuditHealth());
        original.IsSelected = true;
        viewModel.RemoveSelected();
        Assert.Empty(viewModel.Rows);
        await viewModel.QueueFilesAsync([fixture.SourcePath]);
        QueueItemViewModel reAdded = Assert.Single(viewModel.Rows);
        Assert.NotEqual(original.ItemId, reAdded.ItemId);
        using var planningTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await sink.WaitForPlanningCompletedAsync(reAdded.ItemId, planningTimeout.Token);

        SigningRuntimeEvent[] events = fixture.Log.Read().Where(entry => entry.Action == QueueAuditActions.ReAdd).ToArray();
        Assert.Equal(2, events.Length);
        Assert.All(events, entry => Assert.Equal(reAdded.ItemId, entry.ItemId));
        Assert.Equal(events[0].OperationId, events[1].OperationId);
        string serialized = JsonSerializer.Serialize(fixture.Log.Read());
        Assert.DoesNotContain(fixture.SourcePath, serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fixture-secret", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(sourceHash, fixture.SourceHash());
        QueueLogFixture.CopyEvidence(fixture.Log.Path, "task8-viewmodel-actions.jsonl");
    }

    [Fact]
    public async Task CurrentAndConfigurationEntryPointsEmitExactlyOnePairPerSemanticMutation()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        QueueItemViewModel first = await fixture.QueueReadyAsync(viewModel, sink);

        viewModel.PrimaryCertificate = null;
        viewModel.PrimaryCertificate = Assert.Single(viewModel.Certificates);
        viewModel.SecondaryCertificate = viewModel.PrimaryCertificate;
        viewModel.SelectedMode = SigningMode.Dual;
        await viewModel.ReplanOutputRootAsync(fixture.OtherOutputRoot);
        Assert.True(viewModel.ApplySettings("https://timestamp.invalid/bounded", 90));
        await viewModel.RefreshReadinessAsync();
        await viewModel.SetCurrentItemAsync(first.ItemId);

        await viewModel.QueueFilesAsync([fixture.SecondSourcePath]);
        QueueItemViewModel second = viewModel.Rows.Single(row => row.ItemId != first.ItemId);
        await viewModel.SetCurrentItemAsync(second.ItemId);

        string[] expected =
        [
            QueueAuditActions.PrimaryCertificateRoleChange,
            QueueAuditActions.SecondaryCertificateRoleChange,
            QueueAuditActions.ModeChange,
            QueueAuditActions.OutputReplan,
            QueueAuditActions.TimestampSettingsApply,
            QueueAuditActions.ReadinessRefresh,
            QueueAuditActions.CurrentDeselection,
            QueueAuditActions.CurrentSelection
        ];
        SigningRuntimeEvent[] actions = fixture.Log.Read()
            .Where(entry => entry.Phase == QueueAuditPhases.UserAction)
            .ToArray();
        foreach (string action in expected)
        {
            foreach (IGrouping<string?, SigningRuntimeEvent> pair in actions
                .Where(entry => entry.Action == action)
                .GroupBy(entry => entry.OperationId))
            {
                SigningRuntimeEvent[] entries = pair.ToArray();
                Assert.Equal(2, entries.Length);
                Assert.Equal(SigningRuntimeEventNames.UserActionStarted, entries[0].Event);
                Assert.True(entries[1].Event is
                    SigningRuntimeEventNames.UserActionCompleted or
                    SigningRuntimeEventNames.UserActionRejected);
                Assert.Equal(entries[0].ItemId, entries[1].ItemId);
            }
            Assert.Contains(actions, entry => entry.Action == action);
        }
    }

    [Fact]
    public async Task CancelCallsAdapterBeforeAuditAndStillAttemptsOneTerminalPair()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter { BlockRun = true };
        sink.AdapterCancelObserved = () => batch.CancelCalls == 1;
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        await fixture.QueueReadyAsync(viewModel, sink);
        Task signing = viewModel.SignAsync();
        await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        sink.FailNextUserStart = true;

        await viewModel.CancelAsync();
        await signing;

        Assert.Equal(1, batch.CancelCalls);
        Assert.True(sink.CancelStartAttemptedAfterAdapterCall);
        Assert.True(sink.CancelTerminalAttempted);
        Assert.Equal(QueueAuditReasons.AuditLogUnavailable, viewModel.AuditBlockerReasonCode);
    }

    [Fact]
    public async Task RetryEntryPointUsesRetainedItemAndWritesOneCompletedPair()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);
        SigningPlan plan = viewModel.BuildSigningPlan(row.File);
        row.RetainRequest(new BatchItemRequest(
            row.ItemId,
            row.File,
            SigningPlanJson.Serialize(plan),
            Guid.NewGuid().ToString("N")));
        row.Apply(BatchItemState.Failed, null);

        await viewModel.RetryAsync();

        Assert.Equal(1, batch.ResumeCalls);
        SigningRuntimeEvent[] pair = fixture.Log.Read()
            .Where(entry => entry.Action == QueueAuditActions.Retry)
            .ToArray();
        Assert.Equal(2, pair.Length);
        Assert.Equal(SigningRuntimeEventNames.UserActionStarted, pair[0].Event);
        Assert.Equal(QueueAuditOutcomes.Completed, pair[1].Outcome);
        Assert.Equal(pair[0].OperationId, pair[1].OperationId);
    }

    [Fact]
    public async Task RetryAuditFailureBlocksResumeAndRemoveWhilePreservingFailedRowAndSource()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        var batch = new AuditBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, batch);
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);
        SigningPlan plan = viewModel.BuildSigningPlan(row.File);
        row.RetainRequest(new BatchItemRequest(
            row.ItemId,
            row.File,
            SigningPlanJson.Serialize(plan),
            Guid.NewGuid().ToString("N")));
        row.Apply(BatchItemState.Failed, null);
        string sourceHash = fixture.SourceHash();
        sink.FailNextUserStart = true;

        await viewModel.RetryAsync();

        Assert.Equal(0, batch.ResumeCalls);
        Assert.Equal(BatchItemState.Failed, row.State);
        Assert.Equal("OpenLogDirectoryButton", viewModel.FocusTargetAutomationId);
        sink.Healthy = false;
        row.IsSelected = true;
        viewModel.RemoveSelected();
        Assert.Same(row, Assert.Single(viewModel.Rows));
        Assert.Equal(sourceHash, fixture.SourceHash());
    }

    [Fact]
    public async Task QueueLifecyclePersistsStartBeforeStageWithExactItemCorrelationAndOneTerminal()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log);
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        QueueItemViewModel row = await fixture.QueueReadyAsync(viewModel, sink);

        SigningRuntimeEvent[] events = fixture.Log.Read().ToArray();
        AssertLifecyclePair(events, SigningRuntimeEventNames.AdmissionStarted,
            SigningRuntimeEventNames.AdmissionCompleted, expectedItemId: null);
        AssertLifecyclePair(events, SigningRuntimeEventNames.DetectionStarted,
            SigningRuntimeEventNames.DetectionCompleted, row.ItemId);
        AssertLifecyclePair(events, SigningRuntimeEventNames.PlanningStarted,
            SigningRuntimeEventNames.PlanningCompleted, row.ItemId);
        SigningRuntimeEvent selected = Assert.Single(events,
            entry => entry.Event == SigningRuntimeEventNames.ItemSelected && entry.ItemId == row.ItemId);
        Assert.Matches("^[0-9a-f]{32}$", selected.OperationId);
        Assert.Equal(QueueAuditPhases.Selection, selected.Phase);
        Assert.Equal(1, fixture.Intake.DetectCalls);
        Assert.Equal(1, fixture.Intake.PlanCalls);
        await AssertInstanceReadWaitsForPendingPlanningTerminalWriteAsync(fixture.Log);
    }

    private static async Task AssertInstanceReadWaitsForPendingPlanningTerminalWriteAsync(SigningRuntimeEventLog log)
    {
        const string itemId = "1";
        string operationId = Guid.NewGuid().ToString("N");
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PlanningStarted,
            itemId,
            operationId,
            QueueAuditPhases.Planning));

        FieldInfo syncField = typeof(SigningRuntimeEventLog).GetField(
            "sync",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object sync = Assert.IsType<object>(syncField.GetValue(log));
        using var releaseSync = new ManualResetEventSlim();
        var syncAcquired = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var writerStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task lockOwner = Task.Factory.StartNew(() =>
        {
            lock (sync)
            {
                syncAcquired.TrySetResult();
                releaseSync.Wait();
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Task<bool>? terminalWrite = null;
        Task<IReadOnlyList<SigningRuntimeEvent>>? read = null;
        try
        {
            await syncAcquired.Task.WaitAsync(TimeSpan.FromSeconds(5));
            terminalWrite = Task.Factory.StartNew(() =>
            {
                writerStarted.TrySetResult();
                return log.WriteQueueEvent(
                    SigningRuntimeEventNames.PlanningCompleted,
                    itemId,
                    operationId,
                    QueueAuditPhases.Planning,
                    outcome: QueueAuditOutcomes.Ready);
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            await writerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

            read = Task.Run(log.Read);
            Task completed = await Task.WhenAny(read, Task.Delay(TimeSpan.FromMilliseconds(100)));
            Assert.NotSame(read, completed);

            releaseSync.Set();
            await lockOwner.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(await terminalWrite.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Contains(await read.WaitAsync(TimeSpan.FromSeconds(5)), entry =>
                entry.Event == SigningRuntimeEventNames.PlanningCompleted && entry.ItemId == itemId);
        }
        finally
        {
            releaseSync.Set();
            await lockOwner.WaitAsync(TimeSpan.FromSeconds(5));
            if (terminalWrite is not null)
            {
                await terminalWrite.WaitAsync(TimeSpan.FromSeconds(5));
            }
            if (read is not null)
            {
                await read.WaitAsync(TimeSpan.FromSeconds(5));
            }
        }
    }

    [Theory]
    [InlineData(SigningRuntimeEventNames.DetectionStarted)]
    [InlineData(SigningRuntimeEventNames.PlanningStarted)]
    public async Task LifecycleStartFailureBlocksStagePreservesRowAndFocusesAuditRecovery(string failedEvent)
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log) { FailNextEvent = failedEvent };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        string sourceHash = fixture.SourceHash();
        await viewModel.ReplanOutputRootAsync(fixture.OutputRoot);

        await viewModel.QueueFilesAsync([fixture.SourcePath]);
        await WaitUntilAsync(() => viewModel.AuditBlockerReasonCode == QueueAuditReasons.AuditLogUnavailable);

        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        Assert.Equal("OpenLogDirectoryButton", viewModel.FocusTargetAutomationId);
        Assert.Equal(sourceHash, fixture.SourceHash());
        if (failedEvent == SigningRuntimeEventNames.DetectionStarted)
        {
            Assert.Equal(0, fixture.Intake.DetectCalls);
            Assert.Equal(QueueItemDetectionState.Pending, row.DetectionState);
            Assert.True(viewModel.CheckAuditHealth());
            await WaitUntilAsync(() => row.PreflightState == QueueItemPreflightState.Ready);
            Assert.Equal(1, fixture.Intake.DetectCalls);
            Assert.Equal(1, fixture.Intake.PlanCalls);
        }
        else
        {
            Assert.Equal(1, fixture.Intake.DetectCalls);
            Assert.Equal(0, fixture.Intake.PlanCalls);
            Assert.Equal(QueueItemPreflightState.Blocked, row.PreflightState);
        }
    }

    [Fact]
    public async Task AuditRecoveryReplansOnlyCurrentAndAcceptedAdmissionClearsStaleInputError()
    {
        using var fixture = new AuditViewModelFixture();
        var sink = new ControllableAuditSink(fixture.Log) { FailNextEvent = SigningRuntimeEventNames.PlanningStarted };
        await using SigningWorkbenchViewModel viewModel = await fixture.CreateReadyAsync(sink, new AuditBatchAdapter());
        await viewModel.ReplanOutputRootAsync(fixture.OutputRoot);
        await viewModel.QueueFilesAsync([fixture.SourcePath, fixture.SecondSourcePath]);
        await WaitUntilAsync(() => viewModel.AuditBlockerReasonCode == QueueAuditReasons.AuditLogUnavailable);
        await WaitUntilAsync(() => viewModel.Rows.All(row => row.DetectionState is not QueueItemDetectionState.Running));

        QueueItemViewModel current = Assert.IsType<QueueItemViewModel>(viewModel.CurrentItem);
        QueueItemViewModel other = viewModel.Rows.Single(row => !ReferenceEquals(row, current));
        Assert.True(viewModel.CheckAuditHealth());
        await WaitUntilAsync(() => current.PreflightState == QueueItemPreflightState.Ready);
        Assert.Equal(QueueItemPreflightState.Unplanned, other.PreflightState);

        await viewModel.QueueFolderAsync(string.Empty);
        Assert.NotEmpty(viewModel.InputError);
        await viewModel.QueueFilesAsync([Path.Combine(fixture.Root, "third.exe")]);
        Assert.Empty(viewModel.InputError);
        Assert.NotEqual("InputError", viewModel.FocusTargetAutomationId);
    }

    private static void AssertLifecyclePair(
        SigningRuntimeEvent[] events,
        string startEvent,
        string terminalEvent,
        string? expectedItemId)
    {
        SigningRuntimeEvent start = Assert.Single(events,
            entry => entry.Event == startEvent && entry.ItemId == expectedItemId);
        SigningRuntimeEvent terminal = Assert.Single(events,
            entry => entry.Event == terminalEvent && entry.OperationId == start.OperationId);
        Assert.Equal(expectedItemId, terminal.ItemId);
        Assert.True(events.IndexOf(start) < events.IndexOf(terminal));
        Assert.Matches("^[0-9a-f]{32}$", start.OperationId);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition())
        {
            await Task.Delay(10, cancellation.Token);
        }
    }

    private sealed class AuditViewModelFixture : IDisposable
    {
        public AuditViewModelFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSigner-Task8-" + Guid.NewGuid().ToString("N"));
            OutputRoot = Path.Combine(Root, "out");
            OtherOutputRoot = Path.Combine(Root, "other-out");
            SourcePath = Path.Combine(Root, "secret-path-token-pin-uri.exe");
            SecondSourcePath = Path.Combine(Root, "hostile-provider-message.exe");
            Directory.CreateDirectory(OutputRoot);
            Directory.CreateDirectory(OtherOutputRoot);
            File.WriteAllBytes(SourcePath, [0x4D, 0x5A, 0x01, 0x02]);
            File.WriteAllBytes(SecondSourcePath, [0x4D, 0x5A, 0x03, 0x04]);
            File.WriteAllBytes(Path.Combine(Root, "third.exe"), [0x4D, 0x5A, 0x05, 0x06]);
            Log = new SigningRuntimeEventLog(Path.Combine(Root, "logs"));
        }

        public string Root { get; }
        public string OutputRoot { get; }
        public string OtherOutputRoot { get; }
        public string SourcePath { get; }
        public string SecondSourcePath { get; }
        public SigningRuntimeEventLog Log { get; }
        public IntakeAdapter Intake { get; } = new();
        public HealthyWorker Worker { get; } = new();

        public string SourceHash() => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(SourcePath)));

        public async Task<SigningWorkbenchViewModel> CreateReadyAsync(IQueueAuditSink sink, AuditBatchAdapter batch)
        {
            var viewModel = new SigningWorkbenchViewModel(
                new ReadyAdapter(),
                Intake,
                batch,
                new NoopShell(),
                Worker,
                new NoopRepair(),
                static _ => ValueTask.FromResult(true),
                queueAuditSink: sink);
            Assert.True(viewModel.ApplySettings(TimestampPolicy.DefaultUri, 30));
            await viewModel.RefreshReadinessAsync();
            return viewModel;
        }

        public async Task<QueueItemViewModel> QueueReadyAsync(
            SigningWorkbenchViewModel viewModel,
            ControllableAuditSink sink)
        {
            await viewModel.ReplanOutputRootAsync(OutputRoot);
            await viewModel.QueueFilesAsync([SourcePath]);
            QueueItemViewModel row = Assert.Single(viewModel.Rows);
            await viewModel.SetCurrentItemAsync(row.ItemId);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await sink.WaitForPlanningCompletedAsync(row.ItemId, cancellation.Token);
            Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
            return row;
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }

    private sealed class ControllableAuditSink(SigningRuntimeEventLog log) : IQueueAuditSink
    {
        public sealed record UserActionWriteAttempt(
            string EventName,
            string? Action,
            string ItemId,
            string OperationId);

        public bool FailNextUserStart { get; set; }
        public bool FailNextUserTerminal { get; set; }
        public string? FailNextEvent { get; set; }
        public bool Healthy { get; set; } = true;
        public int CheckHealthCalls { get; private set; }
        public bool CancelStartAttemptedAfterAdapterCall { get; private set; }
        public bool CancelTerminalAttempted { get; private set; }
        public Func<bool>? AdapterCancelObserved { get; set; }
        public List<UserActionWriteAttempt> UserActionWriteAttempts { get; } = [];
        private readonly object planningCompletionSync = new();
        private readonly Dictionary<string, TaskCompletionSource> planningCompletions = new(StringComparer.Ordinal);

        public bool CheckHealth()
        {
            CheckHealthCalls++;
            return Healthy;
        }

        public bool WriteAdmissionEvent(
            string eventName,
            string operationId,
            string? outcome = null,
            string? reason = null)
        {
            if (ConsumeLifecycleFailure(eventName))
            {
                return false;
            }

            return log.WriteQueueEvent(
                eventName,
                itemId: null,
                operationId,
                QueueAuditPhases.Admission,
                outcome: outcome,
                reason: reason);
        }

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
            if (ConsumeLifecycleFailure(eventName))
            {
                return false;
            }

            if (phase == QueueAuditPhases.UserAction)
            {
                UserActionWriteAttempts.Add(new UserActionWriteAttempt(eventName, action, itemId, operationId));
            }
            if (eventName == SigningRuntimeEventNames.UserActionStarted && action == QueueAuditActions.Cancel)
            {
                CancelStartAttemptedAfterAdapterCall = AdapterCancelObserved?.Invoke() == true;
            }
            if (eventName is SigningRuntimeEventNames.UserActionCompleted or SigningRuntimeEventNames.UserActionRejected &&
                action == QueueAuditActions.Cancel)
            {
                CancelTerminalAttempted = true;
            }
            if (eventName == SigningRuntimeEventNames.UserActionStarted && FailNextUserStart)
            {
                FailNextUserStart = false;
                return false;
            }
            if (eventName is SigningRuntimeEventNames.UserActionCompleted or SigningRuntimeEventNames.UserActionRejected &&
                FailNextUserTerminal)
            {
                FailNextUserTerminal = false;
                return false;
            }
            bool written = log.WriteQueueEvent(eventName, itemId, operationId, phase, check, action, outcome, reason);
            if (written && eventName == SigningRuntimeEventNames.PlanningCompleted)
            {
                GetPlanningCompletion(itemId).TrySetResult();
            }

            return written;
        }

        public async Task WaitForPlanningCompletedAsync(string itemId, CancellationToken cancellationToken)
        {
            TaskCompletionSource completion = GetPlanningCompletion(itemId);
            try
            {
                await completion.Task.WaitAsync(cancellationToken);
            }
            finally
            {
                lock (planningCompletionSync)
                {
                    if (planningCompletions.TryGetValue(itemId, out TaskCompletionSource? registered) &&
                        ReferenceEquals(registered, completion))
                    {
                        planningCompletions.Remove(itemId);
                    }
                }
            }
        }

        private TaskCompletionSource GetPlanningCompletion(string itemId)
        {
            lock (planningCompletionSync)
            {
                return GetPlanningCompletionLocked(itemId);
            }
        }

        private TaskCompletionSource GetPlanningCompletionLocked(string itemId)
        {
            if (!planningCompletions.TryGetValue(itemId, out TaskCompletionSource? completion))
            {
                completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                planningCompletions.Add(itemId, completion);
            }

            return completion;
        }

        private bool ConsumeLifecycleFailure(string eventName)
        {
            if (!string.Equals(FailNextEvent, eventName, StringComparison.Ordinal))
            {
                return false;
            }

            FailNextEvent = null;
            return true;
        }
    }

    private sealed class IntakeAdapter : IIntakeAdapter
    {
        public int DetectCalls { get; private set; }
        public int PlanCalls { get; private set; }

        public Task<QueuedSourceAdmissionResult> AdmitAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(QueuedSourceAdmission.Admit(inputs, recurseDirectories, cancellationToken));
        }

        public Task<QueuedSourceDetectionResult> DetectAsync(
            QueuedSource source,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DetectCalls++;
            SigningSubject subject = SigningSubject.TryCreateForExtension(Path.GetExtension(source.CanonicalPath)).Value!;
            var detected = new DetectedQueuedSource(
                source,
                new SignableSubject(subject, Guid.NewGuid(), null),
                new SourceFingerprint(source.Identity, 0, DateTime.UnixEpoch, new string('A', 64)));
            return Task.FromResult(new QueuedSourceDetectionResult(
                QueuedSourceDetectionStatus.Supported,
                detected,
                Error: null));
        }

        public Task<IntakeFile> PlanOutputAsync(
            DetectedQueuedSource detectedSource,
            string outputRoot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PlanCalls++;
            QueuedSource source = detectedSource.Source;
            return Task.FromResult(new IntakeFile(
                source.CanonicalPath,
                source.RelativePath,
                Path.Combine(outputRoot, Path.GetFileName(source.CanonicalPath)),
                outputRoot,
                source.Identity,
                detectedSource.Subject));
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

    private sealed class AuditBatchAdapter : IBatchAdapter
    {
        private readonly TaskCompletionSource releaseRun = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }
        public int RunCalls { get; private set; }
        public int CancelCalls { get; private set; }
        public int ResumeCalls { get; private set; }
        public bool BlockRun { get; set; }
        public TaskCompletionSource RunStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void ReleaseRun() => releaseRun.TrySetResult();

        public async Task<BatchProgressUpdate> RunAsync(BatchItemRequest request, CancellationToken cancellationToken)
        {
            RunCalls++;
            RunStarted.TrySetResult();
            if (BlockRun)
            {
                await releaseRun.Task.WaitAsync(cancellationToken);
            }
            return new BatchProgressUpdate(request.ItemId, BatchItemState.Published, null);
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            ResumeCalls++;
            return Task.FromResult(new BatchProgressUpdate(itemId, BatchItemState.Published, null));
        }
        public void PruneItems(IReadOnlyCollection<string> itemIds) { }
        public Task CancelAsync(string itemId, CancellationToken cancellationToken)
        {
            CancelCalls++;
            return Task.CompletedTask;
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class ReadyAdapter : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => new(
            new WorkstationReadiness(WorkstationSupportStatus.Supported, "bounded"),
            NativeApiAvailability.Available,
            new SimplySignInstallation(
                SimplySignInstallationStatus.Installed,
                "{A}",
                "{B}",
                "SimplySign",
                "Certum",
                "1.0"),
            new CertificateCatalog(
                CertificateAvailabilityStatus.CertificateAvailable,
                [new EligibleCertificate(
                    StoreLocation.CurrentUser,
                    "My",
                    new string('A', 40),
                    "CN=fixture-secret",
                    "CN=fixture-issuer",
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddDays(1),
                    true,
                    [CertificateCatalogProbe.CodeSigningEkuOid])],
                []),
            new TimestampConfiguration(TimestampConfigurationStatus.Configured, timestampUri),
            ProviderAuthorizationStatus.AuthorizationUnknown,
            new WindowsPowerShellBridgeReadiness(
                WindowsPowerShellBridgeStatus.Available,
                "fixture-powershell-path",
                "5.1",
                "bounded"));
    }

    private sealed class NoopShell : IOperatorShell
    {
        public void OpenFolder(string path) { }
        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken) => Task.FromResult(string.Empty);
    }

    private sealed class HealthyWorker : IWorkerHealthService
    {
        public int ProbeCalls { get; private set; }

        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Probe());

        private WorkerLaunchDiagnostic Probe()
        {
            ProbeCalls++;
            return WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy);
        }
    }

    private sealed class NoopRepair : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public void Dispose() { }
    }
}
