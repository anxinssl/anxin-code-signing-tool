using CodeSigner.App.Services;

namespace CodeSigner.App.ViewModels;

public enum PreflightRecoveryAction
{
    None,
    OutputRoot,
    PrimaryCertificate,
    SecondaryCertificate,
    TimestampSettings,
    DiagnosticsAccess,
    RefreshReadiness,
    RepairReadiness,
    RemoveAndReAdd
}

public interface IQueueAuditSink
{
    bool CheckHealth() => false;

    bool WriteQueueEvent(
        string eventName,
        string itemId,
        string operationId,
        string phase,
        string? check = null,
        string? action = null,
        string? outcome = null,
        string? reason = null);

    bool WriteAdmissionEvent(
        string eventName,
        string operationId,
        string? outcome = null,
        string? reason = null) => false;
}

public sealed class SigningRuntimeQueueAuditSink(SigningRuntimeEventLog eventLog) : IQueueAuditSink
{
    private readonly SigningRuntimeEventLog eventLog = eventLog ??
        throw new ArgumentNullException(nameof(eventLog));

    public bool CheckHealth() => eventLog.CheckQueueAuditHealth();

    public bool WriteQueueEvent(
        string eventName,
        string itemId,
        string operationId,
        string phase,
        string? check = null,
        string? action = null,
        string? outcome = null,
        string? reason = null) => eventLog.WriteQueueEvent(
            eventName,
            itemId,
            operationId,
            phase,
            check,
            action,
            outcome,
            reason);

    public bool WriteAdmissionEvent(
        string eventName,
        string operationId,
        string? outcome = null,
        string? reason = null) => eventLog.WriteQueueEvent(
            eventName,
            itemId: null,
            operationId,
            QueueAuditPhases.Admission,
            outcome: outcome,
            reason: reason);
}

internal sealed class UnavailableQueueAuditSink : IQueueAuditSink
{
    public bool WriteQueueEvent(
        string eventName,
        string itemId,
        string operationId,
        string phase,
        string? check = null,
        string? action = null,
        string? outcome = null,
        string? reason = null) => false;
}

internal sealed record SelectedFilePreflightCapture(
    string ItemId,
    long RowGeneration,
    long ConfigGeneration,
    long OutputGeneration,
    long ReadinessGeneration,
    long ValidationGeneration,
    string OperationId);

internal enum PreflightCancellationKind
{
    Cancelled,
    Superseded
}
