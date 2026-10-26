using System.Collections.Concurrent;
using System.IO;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.App.Tests;

public sealed partial class FileTaskQueueAdmissionDetectionTests
{
    private static SigningWorkbenchViewModel CreateViewModel(
        ControlledIntakeAdapter intake,
        IQueueAuditSink? auditSink = null) => new(
        new ThrowingReadinessAdapter(),
        intake,
        new ThrowingBatchAdapter(),
        new NoopOperatorShell(),
        new ThrowingWorkerHealthService(),
        new NoopWorkerRepairService(),
        static _ => ValueTask.FromResult(false),
        queueAuditSink: auditSink);

    private sealed class ControlledIntakeAdapter : IIntakeAdapter
    {
        private readonly ConcurrentDictionary<string, TaskCompletionSource> detectionStarts = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, TaskCompletionSource> detectionReleases = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, QueuedSourceDetectionStatus> results = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, byte> faults = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, byte> malformedSupported = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, QueuedSourceAdmissionError> admissionFailures = new(StringComparer.OrdinalIgnoreCase);
        private TaskCompletionSource? admissionRelease;
        private int activeAdmissions;
        private int completedDetections;

        public int AdmissionCalls { get; private set; }
        public int MaxConcurrentAdmissions { get; private set; }
        public int PlanOutputCalls { get; private set; }
        public bool IgnoreDetectionCancellation { get; init; }
        public bool DetectionCancellationObserved { get; private set; }
        public List<string> DetectionOrder { get; } = [];
        public ConcurrentDictionary<string, int> DetectionCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public TaskCompletionSource FirstAdmissionStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void BlockNextAdmission() => admissionRelease = NewSignal();
        public void ReleaseAdmission() => admissionRelease?.TrySetResult();
        public void BlockDetection(string name) => detectionReleases[name] = NewSignal();
        public void ReleaseDetection(string name) => detectionReleases[name].TrySetResult();
        public void SetResult(string name, QueuedSourceDetectionStatus status) => results[name] = status;
        public void SetFault(string name) => faults[name] = 0;
        public void SetMalformedSupported(string name) => malformedSupported[name] = 0;
        public void SetAdmissionFailure(string name, QueuedSourceAdmissionError error) => admissionFailures[name] = error;

        public async Task<QueuedSourceAdmissionResult> AdmitAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            CancellationToken cancellationToken)
        {
            AdmissionCalls++;
            int concurrent = Interlocked.Increment(ref activeAdmissions);
            MaxConcurrentAdmissions = Math.Max(MaxConcurrentAdmissions, concurrent);
            FirstAdmissionStarted.TrySetResult();
            try
            {
                if (admissionRelease is not null)
                {
                    await admissionRelease.Task.WaitAsync(cancellationToken);
                    admissionRelease = null;
                }

                QueuedSource[] sources = inputs
                    .Where(input => !admissionFailures.ContainsKey(Path.GetFileName(input)))
                    .Select(CreateSource)
                    .ToArray();
                QueuedSourceAdmissionFailure[] failures = inputs
                    .Where(input => admissionFailures.ContainsKey(Path.GetFileName(input)))
                    .Select(input => new QueuedSourceAdmissionFailure(
                        admissionFailures[Path.GetFileName(input)],
                        input))
                    .ToArray();
                return new QueuedSourceAdmissionResult(sources, failures);
            }
            finally
            {
                Interlocked.Decrement(ref activeAdmissions);
            }
        }

        public async Task<QueuedSourceDetectionResult> DetectAsync(
            QueuedSource source,
            CancellationToken cancellationToken)
        {
            string name = source.RelativePath;
            lock (DetectionOrder)
            {
                DetectionOrder.Add(name);
            }
            DetectionCounts.AddOrUpdate(name, 1, static (_, count) => count + 1);
            detectionStarts.GetOrAdd(name, static _ => NewSignal()).TrySetResult();
            try
            {
                if (detectionReleases.TryGetValue(name, out TaskCompletionSource? release))
                {
                    if (IgnoreDetectionCancellation)
                    {
                        await release.Task;
                    }
                    else
                    {
                        await release.Task.WaitAsync(cancellationToken);
                    }
                }

                if (faults.ContainsKey(name))
                {
                    throw new IOException("synthetic detection failure");
                }

                QueuedSourceDetectionStatus status = results.GetValueOrDefault(name, QueuedSourceDetectionStatus.Supported);
                DetectedQueuedSource? detected = status == QueuedSourceDetectionStatus.Supported &&
                    !malformedSupported.ContainsKey(name)
                    ? CreateDetected(source)
                    : null;
                return new QueuedSourceDetectionResult(status, detected, IntakeError.NotSignableSubject);
            }
            catch (OperationCanceledException)
            {
                DetectionCancellationObserved = true;
                throw;
            }
            finally
            {
                Interlocked.Increment(ref completedDetections);
            }
        }

        public Task<IntakeFile> PlanOutputAsync(DetectedQueuedSource source, string outputRoot, CancellationToken token)
        {
            PlanOutputCalls++;
            throw new InvalidOperationException("Output planning is prohibited in admission/detection tests.");
        }

        public Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(DetectedQueuedSource source, CancellationToken token) =>
            throw new InvalidOperationException("Integrity verification is outside Todo7.");

        public Task WaitForDetectionAsync(string name) =>
            detectionStarts.GetOrAdd(name, static _ => NewSignal()).Task.WaitAsync(TimeSpan.FromSeconds(5));

        public Task WaitForDetectionCountAsync(string name, int expected) =>
            WaitUntilAsync(() => DetectionCounts.GetValueOrDefault(name) >= expected);

        public Task WaitForAllDetectionsAsync(int expected) =>
            WaitUntilAsync(() => Volatile.Read(ref completedDetections) >= expected);

        private static async Task WaitUntilAsync(Func<bool> predicate)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!predicate())
            {
                await Task.Delay(10, timeout.Token);
            }
        }

        private static QueuedSource CreateSource(string path)
        {
            string name = Path.GetFileName(path);
            string identity = name.Equals("first-alias.exe", StringComparison.OrdinalIgnoreCase) ? "first.exe" : name;
            return new QueuedSource(path, name, new StableFileIdentity(1, identity));
        }

        private static DetectedQueuedSource CreateDetected(QueuedSource source) => new(
            source,
            new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()),
            new SourceFingerprint(source.Identity, 10, DateTime.UnixEpoch, new string('A', 64)));

        private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class ThrowingReadinessAdapter : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) =>
            throw new InvalidOperationException("Readiness is prohibited in admission/detection tests.");
    }

    private sealed class ThrowingBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged { add { } remove { } }
        public Task<BatchProgressUpdate> RunAsync(BatchItemRequest request, CancellationToken token) => throw Forbidden();
        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken token) => throw Forbidden();
        public void PruneItems(IReadOnlyCollection<string> itemIds) => throw Forbidden();
        public Task CancelAsync(string itemId, CancellationToken token) => throw Forbidden();
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        private static InvalidOperationException Forbidden() => new("Batch calls are prohibited in admission/detection tests.");
    }

    private sealed class NoopOperatorShell : IOperatorShell
    {
        public void OpenFolder(string path) => throw new InvalidOperationException("Shell calls are prohibited.");
        public Task<string> ExportDiagnosticsAsync(IReadOnlyDictionary<string, object?> values, int days, CancellationToken token) =>
            throw new InvalidOperationException("Shell calls are prohibited.");
    }

    private sealed class ThrowingWorkerHealthService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken token) =>
            throw new InvalidOperationException("Worker probes are prohibited.");
    }

    private sealed class NoopWorkerRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken token) =>
            throw new InvalidOperationException("Worker repair is prohibited.");
        public void Dispose() { }
    }

    private sealed class RecordingAuditSink : IQueueAuditSink
    {
        public List<string> EventNames { get; } = [];
        public List<string?> ItemIds { get; } = [];
        public List<string> OperationIds { get; } = [];
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
            Record(eventName, itemId, operationId);
            return true;
        }

        public bool WriteAdmissionEvent(
            string eventName,
            string operationId,
            string? outcome = null,
            string? reason = null)
        {
            Record(eventName, null, operationId);
            return true;
        }

        private void Record(string eventName, string? itemId, string operationId)
        {
            EventNames.Add(eventName);
            ItemIds.Add(itemId);
            OperationIds.Add(operationId);
        }
    }
}
