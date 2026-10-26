using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using System.Windows;

namespace CodeSigner.App.Services;

public interface IReadinessAdapter
{
    ReadinessSnapshot Probe(Uri timestampUri);
}

public interface IWorkerHealthService
{
    Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken);
}

public interface IWorkerRepairService : IDisposable
{
    Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken);
}

public interface IIntakeAdapter
{
    Task<QueuedSourceAdmissionResult> AdmitAsync(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        CancellationToken cancellationToken);

    Task<QueuedSourceDetectionResult> DetectAsync(
        QueuedSource source,
        CancellationToken cancellationToken);

    Task<IntakeFile> PlanOutputAsync(
        DetectedQueuedSource detectedSource,
        string outputRoot,
        CancellationToken cancellationToken);

    Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
        DetectedQueuedSource detectedSource,
        CancellationToken cancellationToken);
}

public sealed record ExecutionAttemptContext
{
    private const int OperationIdLength = 32;

    public ExecutionAttemptContext(string itemId, string operationId, long executionGeneration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        ArgumentException.ThrowIfNullOrEmpty(operationId);
        if (operationId.Length != OperationIdLength ||
            operationId.Any(static character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                "The attempt operation identifier must be lowercase 32-character hexadecimal.",
                nameof(operationId));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(executionGeneration);
        ItemId = itemId;
        OperationId = operationId;
        ExecutionGeneration = executionGeneration;
    }

    public string ItemId { get; }

    public string OperationId { get; }

    public long ExecutionGeneration { get; }
}

public sealed class ExecutionAttemptContextFactory
{
    private readonly object sync = new();
    private readonly Dictionary<string, long> generations = new(StringComparer.Ordinal);

    public ExecutionAttemptContext Next(string itemId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        lock (sync)
        {
            generations.TryGetValue(itemId, out long current);
            long next = checked(current + 1);
            generations[itemId] = next;
            return new ExecutionAttemptContext(itemId, Guid.NewGuid().ToString("N"), next);
        }
    }
}

public enum ExecutionProgressDisposition
{
    Apply,
    IgnoreStaleGeneration,
    IgnoreWrongOperation,
    IgnoreCompleted,
    IgnoreTombstoned,
    AdapterContractViolation
}

public sealed class ExecutionAttemptRegistry
{
    private readonly Dictionary<string, AttemptRegistration> registrations = new(StringComparer.Ordinal);

    public void RegisterLiveItem(string itemId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        if (!registrations.TryAdd(itemId, new AttemptRegistration()))
        {
            throw new InvalidOperationException("The execution item is already registered.");
        }
    }

    public void Begin(ExecutionAttemptContext attempt)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        AttemptRegistration registration = GetLive(attempt.ItemId);
        if (registration.Active is not null &&
            attempt.ExecutionGeneration <= registration.Active.ExecutionGeneration)
        {
            throw new InvalidOperationException("Execution generations must increase for each row.");
        }

        registration.Active = attempt;
        registration.Completed = false;
    }

    public void Complete(ExecutionAttemptContext attempt)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        AttemptRegistration registration = GetLive(attempt.ItemId);
        if (!Equals(registration.Active, attempt))
        {
            throw new InvalidOperationException("Only the active execution attempt can be completed.");
        }

        registration.Completed = true;
    }

    public void Tombstone(string itemId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        if (!registrations.TryGetValue(itemId, out AttemptRegistration? registration))
        {
            registration = new AttemptRegistration();
            registrations.Add(itemId, registration);
        }

        registration.Tombstoned = true;
    }

    public ExecutionProgressDisposition Classify(BatchProgressUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (!registrations.TryGetValue(update.ItemId, out AttemptRegistration? registration))
        {
            return ExecutionProgressDisposition.AdapterContractViolation;
        }

        if (registration.Tombstoned)
        {
            return ExecutionProgressDisposition.IgnoreTombstoned;
        }

        ExecutionAttemptContext? active = registration.Active;
        if (active is null)
        {
            return ExecutionProgressDisposition.AdapterContractViolation;
        }

        if (update.Attempt.ExecutionGeneration < active.ExecutionGeneration)
        {
            return ExecutionProgressDisposition.IgnoreStaleGeneration;
        }

        if (update.Attempt.ExecutionGeneration > active.ExecutionGeneration)
        {
            return ExecutionProgressDisposition.AdapterContractViolation;
        }

        if (!string.Equals(update.Attempt.OperationId, active.OperationId, StringComparison.Ordinal))
        {
            return ExecutionProgressDisposition.IgnoreWrongOperation;
        }

        return registration.Completed
            ? ExecutionProgressDisposition.IgnoreCompleted
            : ExecutionProgressDisposition.Apply;
    }

    private AttemptRegistration GetLive(string itemId)
    {
        if (!registrations.TryGetValue(itemId, out AttemptRegistration? registration) || registration.Tombstoned)
        {
            throw new InvalidOperationException("The execution item is not registered as live.");
        }

        return registration;
    }

    private sealed class AttemptRegistration
    {
        public ExecutionAttemptContext? Active { get; set; }

        public bool Completed { get; set; }

        public bool Tombstoned { get; set; }
    }
}

public sealed record BatchProgressUpdate(
    ExecutionAttemptContext Attempt,
    BatchItemState State,
    BatchItemReceipt? Receipt)
{
    public BatchProgressUpdate(string itemId, BatchItemState state, BatchItemReceipt? receipt)
        : this(
            new ExecutionAttemptContext(itemId, Guid.NewGuid().ToString("N"), 1),
            state,
            receipt)
    {
    }

    public string ItemId => Attempt.ItemId;
}

public sealed class BatchProgressChangedEventArgs(BatchProgressUpdate update) : EventArgs
{
    public BatchProgressUpdate Update { get; } = update;
}

public enum BatchAdapterItemContextError
{
    InvalidItemId,
    UnknownItem,
    DuplicateItem,
    InactiveItem,
    OperationActive
}

public sealed class BatchAdapterItemContextException(
    BatchAdapterItemContextError error,
    string message) : InvalidOperationException(message)
{
    public BatchAdapterItemContextError Error { get; } = error;
}

public interface IBatchAdapter : IAsyncDisposable
{
    event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

    string? RuntimeEventLogPath => null;

    SigningRuntimeEvent? LastRuntimeEvent => null;

    SigningRuntimeEvent? LastDiagnosticRuntimeEvent => null;

    Task<BatchProgressUpdate> RunAsync(
        BatchItemRequest request,
        CancellationToken cancellationToken);

    async Task<BatchProgressUpdate> RunAsync(
        BatchItemRequest request,
        ExecutionAttemptContext attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        if (!string.Equals(request.ItemId, attempt.ItemId, StringComparison.Ordinal))
        {
            throw new ArgumentException("The execution attempt must match the request item.", nameof(attempt));
        }

        BatchProgressUpdate update = await RunAsync(request, cancellationToken).ConfigureAwait(false);
        return new BatchProgressUpdate(attempt, update.State, update.Receipt);
    }

    Task<BatchProgressUpdate> ResumeAsync(
        string itemId,
        bool retryFailed,
        CancellationToken cancellationToken);

    async Task<BatchProgressUpdate> ResumeAsync(
        ExecutionAttemptContext attempt,
        bool retryFailed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        BatchProgressUpdate update = await ResumeAsync(
            attempt.ItemId,
            retryFailed,
            cancellationToken).ConfigureAwait(false);
        return new BatchProgressUpdate(attempt, update.State, update.Receipt);
    }

    void PruneItems(IReadOnlyCollection<string> itemIds);

    Task CancelAsync(string itemId, CancellationToken cancellationToken);
}

public interface IOperatorShell
{
    void OpenFolder(string path);

    Task<string> ExportDiagnosticsAsync(
        IReadOnlyDictionary<string, object?> diagnostics,
        int retentionDays,
        CancellationToken cancellationToken);
}

public interface IWorkbenchDialogs
{
    IReadOnlyList<string> PickExeFiles(Window owner);

    string? PickInputFolder(Window owner);

    string? PickOutputRoot(Window owner, string? currentOutputRoot);
}
