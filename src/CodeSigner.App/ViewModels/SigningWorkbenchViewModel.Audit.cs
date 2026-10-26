using CodeSigner.App.Services;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private bool auditIncomplete;
    private int auditSuppression;

    public string? AuditBlockerReasonCode => auditIncomplete
        ? QueueAuditReasons.AuditLogUnavailable
        : null;

    public bool CheckAuditHealth()
    {
        if (queueAuditSink?.CheckHealth() != true)
        {
            SetAuditUnavailable();
            return false;
        }

        auditIncomplete = false;
        ResumePendingDetectionsAfterAuditRecovery();
        if (CurrentItem is { State: Windows.Batch.BatchItemState.Pending } current &&
            current.PreflightIssue?.DetailCode == QueueAuditReasons.AuditLogUnavailable)
        {
            current.SetPreflightUnchecked();
        }
        if (StatusMessage == "审计日志不可用，除取消外的操作已暂停")
        {
            StatusMessage = Rows.Count == 0
                ? "请添加支持的签名文件或文件夹开始"
                : "审计日志已恢复";
        }
        OnPropertyChanged(nameof(AuditBlockerReasonCode));
        RefreshValidation();
        return true;
    }

    private bool IsAuditSuppressed => auditSuppression > 0 || queueAuditSink is null;

    private AuditSuppression SuppressActionAudit()
    {
        auditSuppression++;
        return new AuditSuppression(this);
    }

    private ActionAudit? BeginActionAudit(string action, QueueItemViewModel? item, bool allowWhileIncomplete = false)
        => BeginActionAudit(action, item?.ItemId, allowWhileIncomplete);

    private ActionAudit? BeginActionAudit(string action, string? itemId, bool allowWhileIncomplete = false)
    {
        if (IsAuditSuppressed)
        {
            return ActionAudit.Disabled;
        }

        if (itemId is null)
        {
            return ActionAudit.Disabled;
        }

        if (auditIncomplete && !allowWhileIncomplete && !CheckAuditHealth())
        {
            return null;
        }

        string actionId = Guid.NewGuid().ToString("N");
        if (!queueAuditSink!.WriteQueueEvent(
                SigningRuntimeEventNames.UserActionStarted,
                itemId,
                actionId,
                QueueAuditPhases.UserAction,
                action: action))
        {
            SetAuditUnavailable();
            return null;
        }
        return new ActionAudit(itemId, actionId, action, Enabled: true);
    }

    private void EndActionAudit(ActionAudit audit, string outcome, string? reason = null)
    {
        if (!audit.Enabled)
        {
            return;
        }

        string eventName = outcome == QueueAuditOutcomes.Rejected
            ? SigningRuntimeEventNames.UserActionRejected
            : SigningRuntimeEventNames.UserActionCompleted;
        if (queueAuditSink?.WriteQueueEvent(
                eventName,
                audit.ItemId,
                audit.ActionId,
                QueueAuditPhases.UserAction,
                action: audit.Action,
                outcome: outcome,
                reason: reason) != true)
        {
            SetAuditUnavailable();
        }
    }

    private void WriteCancelAuditAfterExecution(QueueItemViewModel? item, string outcome, string? reason = null)
    {
        if (IsAuditSuppressed || item is null)
        {
            return;
        }

        string actionId = Guid.NewGuid().ToString("N");
        bool started = queueAuditSink!.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionStarted,
            item.ItemId,
            actionId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Cancel);
        string eventName = outcome == QueueAuditOutcomes.Rejected
            ? SigningRuntimeEventNames.UserActionRejected
            : SigningRuntimeEventNames.UserActionCompleted;
        bool terminal = queueAuditSink.WriteQueueEvent(
            eventName,
            item.ItemId,
            actionId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Cancel,
            outcome: outcome,
            reason: reason);
        if (!started || !terminal)
        {
            SetAuditUnavailable();
        }
    }

    private AdmissionAudit? BeginAdmissionAudit()
    {
        if (queueAuditSink is null)
        {
            return AdmissionAudit.Disabled;
        }

        string operationId = Guid.NewGuid().ToString("N");
        if (!queueAuditSink.WriteAdmissionEvent(SigningRuntimeEventNames.AdmissionStarted, operationId))
        {
            SetAuditUnavailable();
            return null;
        }

        return new AdmissionAudit(operationId, Enabled: true);
    }

    private void EndAdmissionAudit(AdmissionAudit audit, string outcome, string? reason)
    {
        if (audit.Enabled && queueAuditSink?.WriteAdmissionEvent(
                SigningRuntimeEventNames.AdmissionCompleted,
                audit.OperationId,
                outcome,
                reason) != true)
        {
            SetAuditUnavailable();
        }
    }

    private DetectionAudit? BeginDetectionAudit(string itemId)
    {
        if (queueAuditSink is null)
        {
            return DetectionAudit.Disabled;
        }

        if (auditIncomplete)
        {
            return null;
        }

        string operationId = Guid.NewGuid().ToString("N");
        if (!queueAuditSink.WriteQueueEvent(
                SigningRuntimeEventNames.DetectionStarted,
                itemId,
                operationId,
                QueueAuditPhases.Detection))
        {
            SetAuditUnavailable();
            return null;
        }

        return new DetectionAudit(itemId, operationId, Enabled: true);
    }

    private PlanningAudit? BeginPlanningAudit(string itemId)
    {
        if (queueAuditSink is null)
        {
            return PlanningAudit.Disabled;
        }

        if (auditIncomplete)
        {
            return null;
        }

        string operationId = Guid.NewGuid().ToString("N");
        if (!queueAuditSink.WriteQueueEvent(
                SigningRuntimeEventNames.PlanningStarted,
                itemId,
                operationId,
                QueueAuditPhases.Planning))
        {
            SetAuditUnavailable();
            return null;
        }

        return new PlanningAudit(itemId, operationId, Enabled: true);
    }

    private void EndPlanningAudit(PlanningAudit audit, string outcome, string? reason)
    {
        if (audit.Enabled && queueAuditSink?.WriteQueueEvent(
                SigningRuntimeEventNames.PlanningCompleted,
                audit.ItemId,
                audit.OperationId,
                QueueAuditPhases.Planning,
                outcome: outcome,
                reason: reason) != true)
        {
            SetAuditUnavailable();
        }
    }

    private void WriteSelectionEvent(string eventName, QueueItemViewModel item)
    {
        if (queueAuditSink is null)
        {
            return;
        }

        if (!queueAuditSink.WriteQueueEvent(
                eventName,
                item.ItemId,
                Guid.NewGuid().ToString("N"),
                QueueAuditPhases.Selection))
        {
            SetAuditUnavailable();
        }
    }

    private void EndDetectionAudit(DetectionAudit audit, string outcome, string? reason)
    {
        if (audit.Enabled && queueAuditSink?.WriteQueueEvent(
                SigningRuntimeEventNames.DetectionCompleted,
                audit.ItemId,
                audit.OperationId,
                QueueAuditPhases.Detection,
                outcome: outcome,
                reason: reason) != true)
        {
            SetAuditUnavailable();
        }
    }

    private void SetAuditUnavailable()
    {
        auditIncomplete = true;
        StatusMessage = "审计日志不可用，除取消外的操作已暂停";
        FocusTargetAutomationId = "OpenLogDirectoryButton";
        OnPropertyChanged(nameof(AuditBlockerReasonCode));
        RefreshValidation();
    }

    private sealed record ActionAudit(
        string ItemId,
        string ActionId,
        string Action,
        bool Enabled)
    {
        public static ActionAudit Disabled { get; } = new(string.Empty, string.Empty, string.Empty, false);
    }

    private sealed record AdmissionAudit(string OperationId, bool Enabled)
    {
        public static AdmissionAudit Disabled { get; } = new(string.Empty, false);
    }

    private sealed record DetectionAudit(string ItemId, string OperationId, bool Enabled)
    {
        public static DetectionAudit Disabled { get; } = new(string.Empty, string.Empty, false);
    }

    private sealed record PlanningAudit(string ItemId, string OperationId, bool Enabled)
    {
        public static PlanningAudit Disabled { get; } = new(string.Empty, string.Empty, false);
    }

    private sealed class AuditSuppression(SigningWorkbenchViewModel owner) : IDisposable
    {
        private SigningWorkbenchViewModel? owner = owner;

        public void Dispose()
        {
            SigningWorkbenchViewModel? current = Interlocked.Exchange(ref owner, null);
            if (current is not null)
            {
                current.auditSuppression--;
            }
        }
    }
}
