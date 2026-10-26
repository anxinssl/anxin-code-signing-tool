using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.IntegrationTests;

internal sealed class IntegrationTestSecureFileCommitter : ISecureFileCommitter
{
    public static IntegrationTestSecureFileCommitter Instance { get; } = new();

    private IntegrationTestSecureFileCommitter()
    {
    }

    public bool IsAvailable => true;

    public Task<SecureFileCommitReceipt> CommitAsync(
        SecureFileCommitRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(request.StagingPath))
        {
            File.Delete(request.StagingPath);
        }

        File.Move(request.CandidatePath, request.StagingPath, overwrite: false);

        return Task.FromResult(new SecureFileCommitReceipt(
            request.StagingPath,
            request.CandidateSha256,
            request.CandidateLength));
    }

}

internal static class IntegrationTestBatchOrchestrators
{
    public static SequentialBatchOrchestrator Create(
        IBatchWorkerSessionFactory workerFactory,
        TimeSpan perFileTimeout,
        Action<string, string?, int?>? runtimeEventSink = null,
        Action<string, string?, int?, CodeSigner.Core.Worker.WorkerLaunchDiagnostic?>? diagnosticRuntimeEventSink = null) => new(
            workerFactory,
            perFileTimeout,
            runtimeEventSink,
            diagnosticRuntimeEventSink);
}
