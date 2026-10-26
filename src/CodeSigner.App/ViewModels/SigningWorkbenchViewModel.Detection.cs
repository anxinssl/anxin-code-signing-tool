using CodeSigner.App.Services;
using CodeSigner.Windows.Files;
using System.IO;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private readonly SemaphoreSlim admissionGate = new(1, 1);
    private readonly CancellationTokenSource detectionLifetimeCancellation = new();
    private readonly object detectionSync = new();
    private readonly LinkedList<DetectionWork> pendingDetections = [];
    private readonly Dictionary<string, DetectionWork> detectionWorkByItem = new(StringComparer.Ordinal);
    private readonly HashSet<string> admittedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<StableFileIdentity> admittedIdentities = [];
    private Task? detectionConsumer;
    private DetectionWork? activeDetection;

    private bool TryAddAdmissionIndex(QueuedSource source)
    {
        if (admittedPaths.Contains(source.CanonicalPath) || admittedIdentities.Contains(source.Identity))
        {
            return false;
        }

        admittedPaths.Add(source.CanonicalPath);
        admittedIdentities.Add(source.Identity);
        return true;
    }

    private void RemoveAdmissionIndex(QueuedSource source)
    {
        admittedPaths.Remove(source.CanonicalPath);
        admittedIdentities.Remove(source.Identity);
    }

    private void EnqueueDetections(IReadOnlyCollection<QueueItemViewModel> rows)
    {
        lock (detectionSync)
        {
            foreach (QueueItemViewModel row in rows)
            {
                var work = new DetectionWork(
                    row,
                    CancellationTokenSource.CreateLinkedTokenSource(detectionLifetimeCancellation.Token));
                work.Node = pendingDetections.AddLast(work);
                detectionWorkByItem.Add(row.ItemId, work);
            }

            detectionConsumer ??= ConsumeDetectionsAsync();
        }
    }

    private void ResumePendingDetectionsAfterAuditRecovery()
    {
        QueueItemViewModel[] pending;
        lock (detectionSync)
        {
            pending = Rows.Where(row =>
                    row.DetectionState == QueueItemDetectionState.Pending &&
                    !detectionWorkByItem.ContainsKey(row.ItemId))
                .ToArray();
        }

        if (pending.Length > 0)
        {
            EnqueueDetections(pending);
        }
    }

    private void PrioritizeDetection(QueueItemViewModel? row)
    {
        if (row is null)
        {
            return;
        }

        lock (detectionSync)
        {
            if (!detectionWorkByItem.TryGetValue(row.ItemId, out DetectionWork? work) || work.Node is null)
            {
                return;
            }

            pendingDetections.Remove(work.Node);
            work.Node = pendingDetections.AddFirst(work);
        }
    }

    private void CancelDetection(string itemId)
    {
        lock (detectionSync)
        {
            if (!detectionWorkByItem.TryGetValue(itemId, out DetectionWork? work))
            {
                return;
            }

            if (work.Node is not null)
            {
                pendingDetections.Remove(work.Node);
                work.Node = null;
                detectionWorkByItem.Remove(itemId);
                work.Cancellation.Cancel();
                work.Cancellation.Dispose();
                return;
            }

            work.Cancellation.Cancel();
        }
    }

    private async Task StopDetectionConsumerAsync()
    {
        detectionLifetimeCancellation.Cancel();
        Task? consumer;
        lock (detectionSync)
        {
            foreach (DetectionWork work in detectionWorkByItem.Values)
            {
                work.Cancellation.Cancel();
            }

            consumer = detectionConsumer;
        }

        if (consumer is not null)
        {
            await consumer;
        }

        await admissionGate.WaitAsync();
        admissionGate.Release();
    }

    private async Task ConsumeDetectionsAsync()
    {
        await Task.Yield();
        while (true)
        {
            DetectionWork work;
            lock (detectionSync)
            {
                if (pendingDetections.First is not LinkedListNode<DetectionWork> node)
                {
                    detectionConsumer = null;
                    return;
                }

                work = node.Value;
                pendingDetections.RemoveFirst();
                work.Node = null;
                activeDetection = work;
            }

            await DetectRowAsync(work);
            lock (detectionSync)
            {
                if (ReferenceEquals(activeDetection, work))
                {
                    activeDetection = null;
                }

                if (detectionWorkByItem.TryGetValue(work.Row.ItemId, out DetectionWork? registered) &&
                    ReferenceEquals(registered, work))
                {
                    detectionWorkByItem.Remove(work.Row.ItemId);
                }
            }
            work.Cancellation.Dispose();
        }
    }

    private async Task DetectRowAsync(DetectionWork work)
    {
        QueueItemViewModel row = work.Row;
        if (!IsLiveDetectionRow(row))
        {
            return;
        }

        DetectionAudit? audit = BeginDetectionAudit(row.ItemId);
        if (audit is null)
        {
            return;
        }

        long generation = row.BeginDetection();
        try
        {
            QueuedSourceDetectionResult result = await intakeAdapter.DetectAsync(
                row.Source,
                work.Cancellation.Token);
            if (work.Cancellation.IsCancellationRequested)
            {
                ApplyCancelled(row, generation);
                EndDetectionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
                return;
            }

            ApplyDetectionResult(row, generation, result);
            (string outcome, string? reason) = DetectionTerminal(result);
            EndDetectionAudit(audit, outcome, reason);
        }
        catch (OperationCanceledException) when (work.Cancellation.IsCancellationRequested)
        {
            ApplyCancelled(row, generation);
            EndDetectionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ApplyFaulted(row, generation);
            EndDetectionAudit(audit, QueueAuditOutcomes.Faulted, QueueAuditReasons.UnexpectedFailure);
        }
        finally
        {
            RefreshValidation();
        }
    }

    private void ApplyDetectionResult(
        QueueItemViewModel row,
        long generation,
        QueuedSourceDetectionResult result)
    {
        if (!IsCurrentDetectionGeneration(row, generation))
        {
            return;
        }

        switch (result.Status)
        {
            case QueuedSourceDetectionStatus.Supported when result.DetectedSource is not null:
                row.CompleteDetection(result.DetectedSource, generation);
                break;
            case QueuedSourceDetectionStatus.Blocked:
                row.BlockDetection(generation);
                break;
            case QueuedSourceDetectionStatus.Unavailable:
            case QueuedSourceDetectionStatus.Changed:
            case QueuedSourceDetectionStatus.Supported:
                row.FaultDetection(generation);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(result), result.Status, "未知检测状态");
        }
    }

    private void ApplyCancelled(QueueItemViewModel row, long generation)
    {
        if (IsCurrentDetectionGeneration(row, generation))
        {
            row.CancelDetection(generation);
        }
    }

    private void ApplyFaulted(QueueItemViewModel row, long generation)
    {
        if (IsCurrentDetectionGeneration(row, generation))
        {
            row.FaultDetection(generation);
        }
    }

    private bool IsCurrentDetectionGeneration(QueueItemViewModel row, long generation) =>
        IsLiveDetectionRow(row) &&
        row.DetectionState == QueueItemDetectionState.Running &&
        row.DetectionGeneration == generation;

    private bool IsLiveDetectionRow(QueueItemViewModel row) =>
        disposeRequested == 0 &&
        row.State == Windows.Batch.BatchItemState.Pending &&
        !IsRemovedItemTombstoned(row.ItemId) &&
        Rows.Contains(row);

    private static (string Outcome, string? Reason) DetectionTerminal(QueuedSourceDetectionResult result) =>
        result.Status switch
        {
            QueuedSourceDetectionStatus.Supported when result.DetectedSource is not null =>
                (QueueAuditOutcomes.Supported, null),
            QueuedSourceDetectionStatus.Blocked =>
                (QueueAuditOutcomes.Blocked, QueueAuditReasons.UnsupportedFormat),
            QueuedSourceDetectionStatus.Unavailable =>
                (QueueAuditOutcomes.Unavailable, QueueAuditReasons.SourceUnavailable),
            QueuedSourceDetectionStatus.Changed =>
                (QueueAuditOutcomes.Changed, QueueAuditReasons.SourceChanged),
            _ => (QueueAuditOutcomes.Faulted, QueueAuditReasons.UnexpectedFailure)
        };

    private static IntakeValidationException DetectionFailure(
        QueuedSource source,
        QueuedSourceDetectionResult detection) => new(
            detection.Error ?? IntakeError.NotSignableSubject,
            "签名文件内容或格式不受支持",
            source.CanonicalPath);

    private sealed class DetectionWork(
        QueueItemViewModel row,
        CancellationTokenSource cancellation)
    {
        public QueueItemViewModel Row { get; } = row;
        public CancellationTokenSource Cancellation { get; } = cancellation;
        public LinkedListNode<DetectionWork>? Node { get; set; }
    }

}
