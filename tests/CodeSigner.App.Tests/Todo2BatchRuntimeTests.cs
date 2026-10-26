using System.IO;
using System.Reflection;
using CodeSigner.App.Services;
using CodeSigner.Core.Worker;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.Tests;

public sealed class Todo2BatchRuntimeTests
{
    [Fact]
    public async Task PublicBatchRecoversThenReachesWorkerAndReportsTypedLaunchFailure()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-Todo2Adapter-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            BatchItemRequest request = await CreateRequestAsync(root, "adapter-secure-publication");
            string activeAttempt = TransactionalStaging.CreateAttemptDirectory(request.File.OutputRoot);
            await File.WriteAllTextAsync(Path.Combine(activeAttempt, "payload.exe"), "active-stage");
            var runtimeLog = new SigningRuntimeEventLog(Path.Combine(root, "diagnostics"));
            string missingWorker = Path.Combine(root, "missing", "CodeSigner.Worker.exe");
            await using var adapter = new SequentialBatchAdapter(missingWorker, runtimeLog);
            var orchestrator = Assert.IsType<SequentialBatchOrchestrator>(
                typeof(SequentialBatchAdapter)
                    .GetField("orchestrator", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .GetValue(adapter));

            BatchProgressUpdate update = await adapter.RunAsync(request, CancellationToken.None);
            SigningRuntimeEvent[] events = runtimeLog.Read().ToArray();

            Assert.Equal(
                [
                    SigningRuntimeEventNames.BatchStart,
                    SigningRuntimeEventNames.WorkerStarting,
                    SigningRuntimeEventNames.WorkerStartFailed,
                    SigningRuntimeEventNames.BatchFailed
                ],
                events.Select(static entry => entry.Event));
            Assert.Equal(SigningRuntimeEventNames.WorkerStartFailed, adapter.LastDiagnosticRuntimeEvent?.Event);
            Assert.Equal(request.ItemId, update.ItemId);
            Assert.Equal(BatchItemState.Failed, update.State);
            Assert.Equal("WorkerLaunchFailed", update.Receipt?.Code.ToString());
            Assert.Null(update.Receipt?.OriginalSha256);
            Assert.Null(update.Receipt?.WorkerProcessId);
            Assert.Equal(WorkerLaunchReason.Missing, update.Receipt?.LaunchDiagnostic?.Reason);
            Assert.Equal(0, orchestrator.LastRecoveryReceipt.RemovedAttemptCount);
            Assert.Equal(1, orchestrator.LastRecoveryReceipt.SkippedAttemptCount);
            Assert.True(Directory.Exists(activeAttempt));
            Assert.False(File.Exists(request.File.DestinationPath));

            BatchProgressUpdate retry = await adapter.ResumeAsync(
                request.ItemId,
                retryFailed: true,
                cancellationToken: CancellationToken.None);
            SigningRuntimeEvent[] retryEvents = runtimeLog.Read().ToArray();
            Assert.Equal(BatchItemState.Failed, retry.State);
            Assert.Equal("WorkerLaunchFailed", retry.Receipt?.Code.ToString());
            Assert.Equal(
                [
                    SigningRuntimeEventNames.BatchStart,
                    SigningRuntimeEventNames.WorkerStarting,
                    SigningRuntimeEventNames.WorkerStartFailed,
                    SigningRuntimeEventNames.BatchFailed,
                    SigningRuntimeEventNames.BatchStart,
                    SigningRuntimeEventNames.BatchFailed,
                    SigningRuntimeEventNames.WorkerStarting,
                    SigningRuntimeEventNames.WorkerStartFailed,
                    SigningRuntimeEventNames.BatchFailed
                ],
                retryEvents.Select(static entry => entry.Event));
            Assert.Equal(0, orchestrator.LastRecoveryReceipt.RemovedAttemptCount);
            Assert.Equal(1, orchestrator.LastRecoveryReceipt.SkippedAttemptCount);
            Assert.Null(retry.Receipt?.OriginalSha256);
            Assert.Null(retry.Receipt?.WorkerProcessId);
            Assert.Equal(WorkerLaunchReason.Missing, retry.Receipt?.LaunchDiagnostic?.Reason);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task PublicBatchReadsSourceBeforeWorkerStartAndReportsLockedSourceFailure()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-Todo2LockedSource-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            BatchItemRequest request = await CreateRequestAsync(root, "adapter-locked-source");
            string missingWorker = Path.Combine(root, "missing", "CodeSigner.Worker.exe");
            await using var adapter = new SequentialBatchAdapter(missingWorker);
            await using var sourceLease = new FileStream(
                request.File.OriginalPath,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None);

            BatchProgressUpdate update = await adapter.RunAsync(request, CancellationToken.None);

            Assert.Equal(BatchItemState.Failed, update.State);
            Assert.Equal("WorkerCrashed", update.Receipt?.Code.ToString());
            Assert.Null(update.Receipt?.OriginalSha256);
            Assert.Null(update.Receipt?.WorkerProcessId);
            Assert.Equal(WorkerLaunchReason.Crashed, update.Receipt?.LaunchDiagnostic?.Reason);
            Assert.False(File.Exists(request.File.DestinationPath));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task<BatchItemRequest> CreateRequestAsync(string root, string itemId)
    {
        string originalPath = Path.Combine(root, "input.exe");
        string outputRoot = Path.Combine(root, "output");
        Directory.CreateDirectory(outputRoot);
        await File.WriteAllTextAsync(originalPath, "original");
        CertificateRef certificate = CertificateRef.TryCreate(
            CertificateStoreLocation.CurrentUser,
            "My",
            new string('A', 40)).Value
            ?? throw new InvalidOperationException("The test certificate reference was not created.");
        SigningPlan plan = SigningPlan.TryCreateSingle(certificate, ".exe").Value
            ?? throw new InvalidOperationException("The test signing plan was not created.");
        return new BatchItemRequest(
            itemId,
            new IntakeFile(
                originalPath,
                "input.exe",
                Path.Combine(outputRoot, "input.exe"),
                outputRoot,
                new StableFileIdentity(7, "TODO2-INPUT"),
                new SignableSubject(SignableFileType.PortableExecutable, Guid.Empty)),
            SigningPlanJson.Serialize(plan));
    }
}
