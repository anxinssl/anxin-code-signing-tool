using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private void OnBatchProgressChanged(object? sender, BatchProgressChangedEventArgs e)
    {
        long observationId = Volatile.Read(ref activeBatchObservationId);
        if (synchronizationContext is not null && SynchronizationContext.Current != synchronizationContext)
        {
            synchronizationContext.Post(_ => ApplyBatchProgress(e.Update, observationId), null);
            return;
        }

        ApplyBatchProgress(e.Update, observationId);
    }

    private void ApplyBatchProgress(BatchProgressUpdate update, long observationId)
    {
        if (observationId == 0 ||
            observationId != Volatile.Read(ref activeBatchObservationId))
        {
            return;
        }

        ExecutionProgressDisposition disposition = ClassifyExecutionProgress(update);
        if (disposition is ExecutionProgressDisposition.IgnoreStaleGeneration or
            ExecutionProgressDisposition.IgnoreWrongOperation or
            ExecutionProgressDisposition.IgnoreCompleted or
            ExecutionProgressDisposition.IgnoreTombstoned)
        {
            return;
        }

        if (disposition == ExecutionProgressDisposition.AdapterContractViolation)
        {
            ExecutionAttemptContext? failedAttempt = FailActiveExecutionContractViolation();
            QueueItemViewModel? failedRow = failedAttempt is null
                ? null
                : Rows.FirstOrDefault(candidate => string.Equals(
                    candidate.ItemId,
                    failedAttempt.ItemId,
                    StringComparison.Ordinal));
            if (failedRow is not null)
            {
                failedRow.Apply(BatchItemState.Failed, receipt: null);
                StatusMessage = "签名适配器返回了无法关联的结果，当前签名文件项目已失败关闭";
                FocusTargetAutomationId = failedRow.AutomationId;
                activeOperation?.Cancel();
                UpdateAggregateProgress();
                RefreshValidation();
            }

            return;
        }

        QueueItemViewModel? row = Rows.FirstOrDefault(
            candidate => string.Equals(candidate.ItemId, update.ItemId, StringComparison.Ordinal));
        if (row is null)
        {
            if (IsRemovedItemTombstoned(update.ItemId))
            {
                return;
            }

            throw new InvalidOperationException(
                $"Batch progress referenced queue item '{update.ItemId}' that is not retained by the workbench.");
        }

        if (activeBatchItemId is null ||
            !string.Equals(activeBatchItemId, update.ItemId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Batch progress for queue item '{update.ItemId}' did not match the active item.");
        }

        bool isLatestObservation = IsLatestWorkerObservation(observationId);
        if (isLatestObservation &&
            update.Receipt is { Code: BatchResultCode.WorkerLaunchFailed, LaunchDiagnostic: not null })
        {
            ApplyWorkerDiagnostic(observationId, update.Receipt.LaunchDiagnostic);
        }
        else if (isLatestObservation &&
                 update.Receipt?.Code is BatchResultCode.Published or BatchResultCode.AlreadySigned)
        {
            ApplyWorkerDiagnostic(
                observationId,
                WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
        }

        row.Apply(update.State, update.Receipt);
        if (update.Receipt is { SigningDiagnostic: not null } or { LaunchDiagnostic: not null } or
            { Code: BatchResultCode.OutputSaveFailed })
        {
            lastSigningDiagnosticEvent = batchAdapter.LastDiagnosticRuntimeEvent;
        }

        UpdateAggregateProgress();
        if (!IsLatestWorkerObservation(observationId))
        {
            RefreshValidation();
            return;
        }

        int completed = Rows.Count(candidate => candidate.ProgressPercent == 100);
        StatusMessage = $"正在签名：{completed} / {Rows.Count} 个签名文件项目：{row.StateText}。";
        if (update.Receipt?.Code == BatchResultCode.WorkerLaunchFailed &&
            update.Receipt.LaunchDiagnostic is not null)
        {
            StatusMessage = WorkerRecoveryMessage;
            ReadinessAnnouncement = WorkerRecoveryAutomationName;
            FocusTargetAutomationId = "WorkerRecoveryRegion";
        }
        else if (update.State is BatchItemState.Failed or BatchItemState.PausedProvider or BatchItemState.PausedTimestamp)
        {
            FocusTargetAutomationId = row.AutomationId;
        }

        RefreshValidation();
    }

    private void UpdateSummaryAndFocus()
    {
        QueueItemViewModel? blocking = Rows.FirstOrDefault(row => row.State is
            BatchItemState.Failed or BatchItemState.PausedProvider or
            BatchItemState.PausedTimestamp or BatchItemState.Cancelled);
        if (blocking is not null)
        {
            if (blocking.Receipt?.Code == BatchResultCode.OutputSaveFailed)
            {
                StatusMessage = QueueItemViewModel.OutputSaveRecoveryMessage;
                FocusTargetAutomationId = "OutputRootTextBox";
                return;
            }

            StatusMessage = $"{Rows.Count(row => row.State == BatchItemState.Published)} 个已发布；" +
                $"{Rows.Count(row => row.State != BatchItemState.Published)} 个项目需要处理";
            FocusTargetAutomationId = blocking.AutomationId;
            return;
        }

        StatusMessage = $"{Rows.Count(row => row.State == BatchItemState.Published)} 个签名文件项目已验证并发布";
        FocusTargetAutomationId = "SummaryRegion";
    }

    private void UpdateAggregateProgress()
    {
        AggregateProgressPercent = Rows.Count == 0
            ? 0
            : (int)Math.Round(Rows.Average(row => row.ProgressPercent), MidpointRounding.AwayFromZero);
    }
}
