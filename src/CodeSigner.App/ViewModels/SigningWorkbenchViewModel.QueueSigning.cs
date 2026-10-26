using CodeSigner.Windows.Batch;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private CancellationTokenSource? queueCancellation;
    private TaskCompletionSource? queueCompletion;

    public bool CanSignQueue => string.IsNullOrEmpty(QueueSignDisabledReason);

    public string QueueSignDisabledReason
    {
        get
        {
            if (disposeRequested != 0) return "软件正在关闭";
            if (auditIncomplete) return "审计日志不可用，请先恢复审计日志";
            if (IsBusy) return "签名正在进行中";
            if (Rows.Any(row => row.State == BatchItemState.Failed &&
                row.Receipt?.Code == BatchResultCode.OutputSaveFailed))
                return "请更改输出位置，移除并重新添加保存失败的文件后再签名";
            if (Rows.Any(IsRetainedProblem)) return "请先重试或移除失败、暂停或已取消的文件";
            if (!Rows.Any(row => row.State == BatchItemState.Pending)) return "队列中没有待签文件";
            if (!HasValidOutputRoot()) return "选择有效的输出目录";
            return string.Empty;
        }
    }

    public string QueueStatusText => IsBusy
        ? StatusMessage
        : CurrentItem is { State: BatchItemState.Pending, PreflightState: QueueItemPreflightState.Blocked }
            ? FormatCurrentFileStatusText()
            : CanSignQueue
                ? $"待签文件：{Rows.Count(row => row.State == BatchItemState.Pending)} 个"
                : QueueSignDisabledReason;

    public async Task SignQueueAsync()
    {
        if (IsBusy || disposeRequested != 0)
        {
            return;
        }

        if (!CanSignQueue)
        {
            StatusMessage = QueueSignDisabledReason;
            return;
        }

        // Snapshot the queue once; each item still uses the existing single-file path.
        QueueItemViewModel[] pending = Rows.Where(row => row.State == BatchItemState.Pending).ToArray();
        using var cancellation = new CancellationTokenSource();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        queueCancellation = cancellation;
        queueCompletion = completion;
        NotifyBusyStateChanged();
        int completed = 0;
        try
        {
            StatusMessage = $"正在准备批量签名：共 {pending.Length} 个文件";
            Task? detection;
            lock (detectionSync)
            {
                detection = detectionConsumer;
            }
            if (detection is not null)
            {
                await detection.WaitAsync(cancellation.Token);
            }

            foreach (QueueItemViewModel item in pending)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                if (!Rows.Contains(item) || item.State != BatchItemState.Pending)
                {
                    StatusMessage = "队列状态已变化，批量签名已停止";
                    return;
                }

                SetCurrentItem(item);
                StatusMessage = $"正在处理：第 {completed + 1} / {pending.Length} 个文件";
                await SignCurrentAsync(allowQueueExecution: true, cancellation.Token);
                cancellation.Token.ThrowIfCancellationRequested();
                if (item.State is not (BatchItemState.Published or BatchItemState.SkippedAlreadySigned))
                {
                    if (item.RetainedRequest is not null && !IsRetainedProblem(item))
                    {
                        item.Apply(BatchItemState.Failed, receipt: null);
                    }
                    string reason = item.State == BatchItemState.Pending
                        ? FirstBlocking(allowQueueExecution: true).Reason ?? "当前文件未完成预检"
                        : item.ResultText;
                    StatusMessage = $"批量签名已停止：{reason}；后续文件保持待处理";
                    FocusTargetAutomationId = item.AutomationId;
                    return;
                }

                completed++;
            }

            StatusMessage = $"批量签名完成：{completed} / {pending.Length} 个文件已完成";
            FocusTargetAutomationId = "SummaryRegion";
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            completed = pending.Count(row => row.State is BatchItemState.Published or BatchItemState.SkippedAlreadySigned);
            if (CurrentItem is { RetainedRequest: not null } interrupted &&
                !IsRetainedProblem(interrupted) &&
                interrupted.State is not (BatchItemState.Published or BatchItemState.SkippedAlreadySigned))
            {
                interrupted.Apply(BatchItemState.Cancelled, receipt: null);
            }
            StatusMessage = $"批量签名已取消：{completed} 个文件已完成，后续文件保持待处理";
            FocusTargetAutomationId = "SummaryRegion";
        }
        catch (Exception)
        {
            // Leave unstarted rows pending; never turn a scheduling exception into a retry.
            if (CurrentItem is { RetainedRequest: not null } interrupted &&
                !IsRetainedProblem(interrupted) &&
                interrupted.State is not (BatchItemState.Published or BatchItemState.SkippedAlreadySigned))
            {
                interrupted.Apply(BatchItemState.Failed, receipt: null);
            }
            StatusMessage = "批量签名已停止，后续文件保持待处理，请导出诊断信息";
            FocusTargetAutomationId = CurrentItem?.AutomationId ?? "SummaryRegion";
        }
        finally
        {
            queueCancellation = null;
            queueCompletion = null;
            NotifyBusyStateChanged();
            completion.TrySetResult();
        }
    }

    private void NotifyBusyStateChanged()
    {
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(SignButtonText));
        RefreshValidation();
    }
}
