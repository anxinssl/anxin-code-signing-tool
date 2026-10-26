using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Batch;

public enum BatchItemState
{
    Pending,
    Ready,
    SigningPrimary,
    SigningSecondary,
    Verifying,
    Published,
    SkippedAlreadySigned,
    Failed,
    PausedProvider,
    PausedTimestamp,
    Cancelled
}

public enum BatchResultCode
{
    Published,
    AlreadySigned,
    UnsupportedFileType,
    InvalidSigningPlan,
    WorkerFailure,
    WorkerLaunchFailed,
    WorkerCrashed,
    WorkerTimedOut,
    WorkerProtocolFailure,
    MisleadingWorkerSuccess,
    ProviderUnavailable,
    TimestampUnavailable,
    OriginalChanged,
    DestinationCollision,
    CleanupFailed,
    Cancelled,
    OutputSaveFailed
}

public sealed record BatchItemRequest(
    string ItemId,
    IntakeFile File,
    string SigningPlanJson,
    string? OperationId = null,
    WorkerSdkFallback? SdkFallback = null);

public sealed record BatchItemReceipt(
    string ItemId,
    BatchItemState State,
    BatchResultCode Code,
    string OriginalPath,
    string DestinationPath,
    string? OriginalSha256,
    string? PublishedSha256,
    string? AttemptId,
    int? WorkerProcessId,
    int? HResult,
    WorkerLaunchDiagnostic? LaunchDiagnostic = null,
    [property: JsonIgnore] WorkerResponse? SigningDiagnostic = null,
    [property: JsonIgnore] string? WorkerStderrTail = null,
    [property: JsonIgnore] bool WorkerStderrTruncated = false)
{
    [JsonIgnore]
    public WorkerLaunchDiagnostic? WorkerLaunchDiagnostic => LaunchDiagnostic;
}

public sealed record BatchItemSnapshot(
    BatchItemRequest Request,
    BatchItemState State,
    IReadOnlyList<BatchItemReceipt> Receipts);

public static class BatchItemStateMachine
{
    public static bool CanTransition(BatchItemState current, BatchItemState next) => current switch
    {
        BatchItemState.Pending => next is BatchItemState.Ready or
            BatchItemState.SkippedAlreadySigned or BatchItemState.Failed or BatchItemState.Cancelled,
        BatchItemState.Ready => next is BatchItemState.SigningPrimary or
            BatchItemState.Failed or BatchItemState.Cancelled,
        BatchItemState.SigningPrimary => next is BatchItemState.SigningSecondary or
            BatchItemState.Verifying or BatchItemState.SkippedAlreadySigned or
            BatchItemState.Failed or BatchItemState.PausedProvider or
            BatchItemState.PausedTimestamp or BatchItemState.Cancelled,
        BatchItemState.SigningSecondary => next is BatchItemState.Verifying or
            BatchItemState.Failed or BatchItemState.PausedProvider or
            BatchItemState.PausedTimestamp or BatchItemState.Cancelled,
        BatchItemState.Verifying => next is BatchItemState.Published or BatchItemState.Failed or
            BatchItemState.PausedProvider or BatchItemState.PausedTimestamp or BatchItemState.Cancelled,
        BatchItemState.Failed => next == BatchItemState.Ready,
        BatchItemState.PausedProvider or BatchItemState.PausedTimestamp =>
            next is BatchItemState.Ready or BatchItemState.Cancelled,
        _ => false
    };
}

public sealed class BatchItem
{
    private readonly List<BatchItemState> stateHistory;
    private readonly List<BatchItemReceipt> receipts;

    internal BatchItem(BatchItemRequest request)
        : this(request, BatchItemState.Pending, [], [BatchItemState.Pending])
    {
    }

    private BatchItem(
        BatchItemRequest request,
        BatchItemState state,
        IEnumerable<BatchItemReceipt> receipts,
        IEnumerable<BatchItemState> stateHistory)
    {
        Request = request ?? throw new ArgumentNullException(nameof(request));
        State = state;
        this.receipts = [.. receipts];
        this.stateHistory = [.. stateHistory];
    }

    public BatchItemRequest Request { get; }

    public BatchItemState State { get; private set; }

    public BatchItemReceipt? Receipt => receipts.Count == 0 ? null : receipts[^1];

    public IReadOnlyList<BatchItemReceipt> Receipts => new ReadOnlyCollection<BatchItemReceipt>(receipts);

    public IReadOnlyList<BatchItemState> StateHistory => new ReadOnlyCollection<BatchItemState>(stateHistory);

    internal static BatchItem Restore(BatchItemSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        bool interrupted = snapshot.State is BatchItemState.Ready or
            BatchItemState.SigningPrimary or BatchItemState.SigningSecondary or BatchItemState.Verifying;
        BatchItemState restoredState = interrupted ? BatchItemState.Pending : snapshot.State;
        return new BatchItem(
            snapshot.Request,
            restoredState,
            snapshot.Receipts,
            restoredState == BatchItemState.Pending
                ? [snapshot.State, BatchItemState.Pending]
                : [restoredState]);
    }

    internal void Transition(BatchItemState next)
    {
        if (!BatchItemStateMachine.CanTransition(State, next))
        {
            throw new InvalidOperationException($"The batch transition {State} -> {next} is not allowed.");
        }

        State = next;
        stateHistory.Add(next);
    }

    internal void Record(BatchItemReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (!string.Equals(receipt.ItemId, Request.ItemId, StringComparison.Ordinal) || receipt.State != State)
        {
            throw new InvalidOperationException("The receipt does not match the current batch item state.");
        }

        receipts.Add(receipt);
    }
}

public sealed class SigningBatch
{
    private readonly IReadOnlyList<BatchItem> items;

    public SigningBatch(IEnumerable<BatchItemRequest> requests)
    {
        ArgumentNullException.ThrowIfNull(requests);
        BatchItemRequest[] materialized = [.. requests];
        if (materialized.Length == 0 ||
            materialized.Any(static item =>
                item is null || string.IsNullOrWhiteSpace(item.ItemId) || item.File is null ||
                string.IsNullOrWhiteSpace(item.SigningPlanJson)) ||
            materialized.Select(static item => item.ItemId).Distinct(StringComparer.Ordinal).Count() != materialized.Length)
        {
            throw new ArgumentException("Batch item identifiers, files, and signing plans must be present and unique.", nameof(requests));
        }

        items = new ReadOnlyCollection<BatchItem>(materialized.Select(static request => new BatchItem(request)).ToArray());
    }

    private SigningBatch(IEnumerable<BatchItem> restoredItems)
    {
        items = new ReadOnlyCollection<BatchItem>(restoredItems.ToArray());
    }

    public IReadOnlyList<BatchItem> Items => items;

    public bool IsPaused => items.Any(static item =>
        item.State is BatchItemState.PausedProvider or BatchItemState.PausedTimestamp);

    public bool IsComplete => items.All(static item => item.State is
        BatchItemState.Published or BatchItemState.SkippedAlreadySigned or
        BatchItemState.Failed or BatchItemState.Cancelled);

    public IReadOnlyList<BatchItemSnapshot> Snapshot() => items
        .Select(static item => new BatchItemSnapshot(item.Request, item.State, item.Receipts.ToArray()))
        .ToArray();

    public static SigningBatch Restore(IEnumerable<BatchItemSnapshot> snapshots)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        BatchItemSnapshot[] materialized = snapshots.ToArray();
        foreach (BatchItemSnapshot snapshot in materialized)
        {
            ValidateProtectedStateReceipt(snapshot);
        }

        BatchItem[] restored = materialized.Select(BatchItem.Restore).ToArray();
        if (restored.Length == 0 ||
            restored.Select(static item => item.Request.ItemId).Distinct(StringComparer.Ordinal).Count() != restored.Length)
        {
            throw new ArgumentException("A restored batch must contain unique item identifiers.", nameof(snapshots));
        }

        return new SigningBatch(restored);
    }

    private static void ValidateProtectedStateReceipt(BatchItemSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        bool requiresReceipt = snapshot.State is BatchItemState.Published or
            BatchItemState.SkippedAlreadySigned or BatchItemState.Failed or
            BatchItemState.PausedProvider or BatchItemState.PausedTimestamp or
            BatchItemState.Cancelled;
        if (!requiresReceipt)
        {
            return;
        }

        BatchItemReceipt? receipt = snapshot.Receipts.Count == 0 ? null : snapshot.Receipts[^1];
        bool matches = receipt is not null &&
            receipt.State == snapshot.State &&
            string.Equals(receipt.ItemId, snapshot.Request.ItemId, StringComparison.Ordinal) &&
            string.Equals(
                receipt.OriginalPath,
                snapshot.Request.File.OriginalPath,
                StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                receipt.DestinationPath,
                snapshot.Request.File.DestinationPath,
                StringComparison.OrdinalIgnoreCase) &&
            HasCompatibleCode(snapshot.State, receipt.Code) &&
            (receipt.Code != BatchResultCode.WorkerLaunchFailed || receipt.LaunchDiagnostic is not null);
        if (!matches)
        {
            throw new ArgumentException(
                "A terminal or paused batch snapshot must contain an exact matching receipt.",
                nameof(snapshot));
        }
    }

    private static bool HasCompatibleCode(BatchItemState state, BatchResultCode code) => state switch
    {
        BatchItemState.Published => code == BatchResultCode.Published,
        BatchItemState.SkippedAlreadySigned => code == BatchResultCode.AlreadySigned,
        BatchItemState.PausedProvider => code == BatchResultCode.ProviderUnavailable,
        BatchItemState.PausedTimestamp => code == BatchResultCode.TimestampUnavailable,
        BatchItemState.Cancelled => code == BatchResultCode.Cancelled,
        BatchItemState.Failed => code is BatchResultCode.UnsupportedFileType or
            BatchResultCode.InvalidSigningPlan or BatchResultCode.WorkerFailure or
            BatchResultCode.WorkerLaunchFailed or BatchResultCode.WorkerCrashed or
            BatchResultCode.WorkerTimedOut or BatchResultCode.WorkerProtocolFailure or
            BatchResultCode.MisleadingWorkerSuccess or
            BatchResultCode.OriginalChanged or BatchResultCode.DestinationCollision or
            BatchResultCode.CleanupFailed or BatchResultCode.OutputSaveFailed,
        _ => false
    };
}
