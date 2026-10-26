using System.Security.Cryptography;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.IntegrationTests;

public sealed class SequentialBatchHashCasingTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private static readonly JsonSerializerOptions EvidenceJsonOptions = new() { WriteIndented = true };

    [Fact]
    public async Task PublicProductionBatchPublishesRequestedDestinationWithCanonicalHash()
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-HashCasing-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            BatchItemRequest request = CreateRequest(root);
            var batch = new SigningBatch([request]);
            var workerFactory = new LowercaseHashWorkerFactory();
            await using var orchestrator = new SequentialBatchOrchestrator(
                workerFactory,
                TimeSpan.FromSeconds(5));

            await orchestrator.RunAsync(batch, CancellationToken.None);

            BatchItem item = Assert.Single(batch.Items);
            Assert.Equal(BatchItemState.Published, item.State);
            Assert.Equal(BatchResultCode.Published, item.Receipt!.Code);
            Assert.Equal(request.File.DestinationPath, item.Receipt.DestinationPath);
            Assert.Equal(Hash(request.File.DestinationPath), item.Receipt.PublishedSha256, ignoreCase: true);
            Assert.Equal(1, workerFactory.StartCalls);
            Assert.True(File.Exists(request.File.DestinationPath));
            Assert.Equal(item.Receipt.OriginalSha256, Hash(request.File.OriginalPath));
            WriteEvidence(item.Receipt);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static BatchItemRequest CreateRequest(string root)
    {
        string inputRoot = Path.Combine(root, "input");
        string outputRoot = Path.Combine(root, "output");
        Directory.CreateDirectory(inputRoot);
        Directory.CreateDirectory(outputRoot);
        string originalPath = Path.Combine(inputRoot, "input.exe");
        File.WriteAllText(originalPath, "fixture");
        using var stream = new FileStream(originalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        StableFileIdentity identity = WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
        CertificateRef certificate = CertificateRef.TryCreate(
            CertificateStoreLocation.CurrentUser,
            "My",
            Thumbprint).Value ?? throw new InvalidOperationException("Test certificate creation failed.");
        SigningPlan plan = SigningPlan.TryCreateSingle(certificate, ".exe").Value
            ?? throw new InvalidOperationException("Test signing plan creation failed.");
        var file = new IntakeFile(
            originalPath,
            "input.exe",
            Path.Combine(outputRoot, "input.exe"),
            outputRoot,
            identity,
            new SignableSubject(SignableFileType.PortableExecutable, Guid.Empty));
        return new BatchItemRequest(
            "hash-case",
            file,
            SigningPlanJson.Serialize(plan),
            OperationId: OperationId);
    }

    private static string Hash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void WriteEvidence(BatchItemReceipt receipt)
    {
        string? directory = Environment.GetEnvironmentVariable("CODESIGNER_TASK5_LANE_A_EVIDENCE_DIR");
        if (string.IsNullOrWhiteSpace(directory))
        {
            return;
        }

        Directory.CreateDirectory(directory);
        File.WriteAllBytes(
            Path.Combine(directory, "batch-receipt-intent.json"),
            JsonSerializer.SerializeToUtf8Bytes(receipt, EvidenceJsonOptions));
    }

    private sealed class LowercaseHashWorkerFactory : IBatchWorkerSessionFactory
    {
        public int StartCalls { get; private set; }

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCalls++;
            return ValueTask.FromResult<IBatchWorkerSession>(new LowercaseHashWorkerSession());
        }
    }

    private sealed class LowercaseHashWorkerSession : IBatchWorkerSession
    {
        public int ProcessId => 1;

        public bool IsRunning => true;

        public Task<WorkerResponse> SignAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WorkerSigningContract contract = WorkerSigningContract.FromSigningPlanJson(signingPlanJson);
            reportProgress(BatchWorkerPhase.SigningPrimary);
            reportProgress(BatchWorkerPhase.Verifying);
            string candidateSha256 = Hash(stagedPath).ToLowerInvariant();
            return Task.FromResult(new WorkerResponse(
                WorkerProtocol.Version,
                true,
                WorkerResponseCodes.SigningCompleted,
                0,
                OriginalSha256: Hash(originalPath).ToLowerInvariant(),
                StagedSha256: candidateSha256,
                Subject: contract.Subject,
                Capability: contract.Capability,
                Engine: contract.Engine,
                Verification: contract.Verification,
                OperationId: OperationId,
                Outcome: WorkerSigningOutcome.Signed,
                Route: WorkerExecutionRoute.ProductPe));
        }

        public Task<int> CompleteAsync(CancellationToken cancellationToken) => Task.FromResult(0);

        public Task TerminateAsync() => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
