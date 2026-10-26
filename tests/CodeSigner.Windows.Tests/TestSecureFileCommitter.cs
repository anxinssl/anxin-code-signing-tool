using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using CodeSigner.Windows.Batch;

namespace CodeSigner.Windows.Tests;

internal sealed class TestSecureFileCommitter : ISecureFileCommitter
{
    public static TestSecureFileCommitter Instance { get; } = new();

    private TestSecureFileCommitter()
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

internal static class TestSigningExecutors
{
    public static ProductionSigningExecutor Create(
        INativeSigningLegExecutor legExecutor,
        IProductionSignedFileVerifier verifier,
        IProductionSigningSubjectClassifier? subjectClassifier = null) => new(
            legExecutor,
            verifier,
            subjectClassifier ?? new ProductionSigningSubjectClassifier(),
            TestSecureFileCommitter.Instance);

    public static ProductionSigningExecutor Create(
        IPeAuthenticodeSigningEngine peEngine,
        IProductionSignedFileVerifier verifier,
        ITrustedSdkSignToolExecutor? sdkFallbackExecutor = null,
        TrustedSdkSignToolCandidate? sdkFallbackCandidate = null,
        IProductionSigningSubjectClassifier? subjectClassifier = null) => new(
            peEngine,
            verifier,
            sdkFallbackExecutor,
            sdkFallbackCandidate,
            subjectClassifier ?? new ProductionSigningSubjectClassifier(),
            TestSecureFileCommitter.Instance);
}

internal static class TestTransactionalFilePublishers
{
    public static TransactionalFilePublisher Create(
        IStagedFileSigner signer,
        IStagedFileVerifier verifier,
        TransactionalFilePipelineHooks? hooks = null,
        Action<string>? runtimeEventSink = null) => new(
            signer,
            verifier,
            hooks,
            runtimeEventSink);
}

internal static class TestBatchOrchestrators
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
