using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.IntegrationTests;

public sealed class Todo6QueueRetryInvariantTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string RunOperationId = "0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task RetryInvokesWorkerAndPublicationOnlyForRetainedFailedWork()
    {
        string root = Directory.CreateTempSubdirectory("codesigner-todo6-retry-").FullName;
        try
        {
            string outputRoot = Path.Combine(root, "signed");
            BatchItemRequest failed = CreateRequest(root, outputRoot, "retained-failed");
            BatchItemRequest published = CreateRequest(root, outputRoot, "already-published");
            var factory = new RetryWorkerFactory();
            factory.Set(failed.ItemId, false, true);
            factory.Set(published.ItemId, true);
            var runtimeEvents = new List<(string Name, string? ItemId)>();
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(
                factory,
                TimeSpan.FromSeconds(5),
                (name, itemId, _) => runtimeEvents.Add((name, itemId)));
            var batch = new SigningBatch([failed, published]);
            string failedSourceHash = Hash(failed.File.OriginalPath);
            string publishedSourceHash = Hash(published.File.OriginalPath);

            await orchestrator.RunAsync(batch, CancellationToken.None);

            Assert.Equal(BatchItemState.Failed, Item(batch, failed.ItemId).State);
            Assert.Equal(BatchItemState.Published, Item(batch, published.ItemId).State);
            Assert.Equal([failed.File.OriginalPath, published.File.OriginalPath], factory.InvocationPaths);
            Assert.Equal([RunOperationId, RunOperationId], factory.LogicalOperationIds);
            Assert.Equal(
                [published.ItemId],
                runtimeEvents.Where(static entry => entry.Name == "publish-done").Select(static entry => entry.ItemId));
            Assert.False(File.Exists(failed.File.DestinationPath));
            Assert.True(File.Exists(published.File.DestinationPath));
            AssertPublishedReceipt(Item(batch, published.ItemId));

            runtimeEvents.Clear();
            await orchestrator.ResumeAsync(batch, retryFailed: true, CancellationToken.None);

            Assert.Equal(BatchItemState.Published, Item(batch, failed.ItemId).State);
            Assert.Equal(BatchItemState.Published, Item(batch, published.ItemId).State);
            Assert.Equal(
                [failed.File.OriginalPath, published.File.OriginalPath, failed.File.OriginalPath],
                factory.InvocationPaths);
            Assert.Equal([RunOperationId, RunOperationId, RunOperationId], factory.LogicalOperationIds);
            Assert.Equal(
                [failed.ItemId],
                runtimeEvents.Where(static entry => entry.Name == "publish-done").Select(static entry => entry.ItemId));
            Assert.True(File.Exists(failed.File.DestinationPath));
            AssertPublishedReceipt(Item(batch, failed.ItemId));
            Assert.Equal(failedSourceHash, Hash(failed.File.OriginalPath));
            Assert.Equal(publishedSourceHash, Hash(published.File.OriginalPath));

            runtimeEvents.Clear();
            await orchestrator.ResumeAsync(batch, retryFailed: true, CancellationToken.None);

            Assert.Equal(3, factory.InvocationPaths.Count);
            Assert.DoesNotContain(runtimeEvents, static entry => entry.Name == "publish-done");
            Assert.Equal(failedSourceHash, Hash(failed.File.OriginalPath));
            Assert.Equal(publishedSourceHash, Hash(published.File.OriginalPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static BatchItemRequest CreateRequest(string root, string outputRoot, string itemId)
    {
        string inputRoot = Path.Combine(root, "inputs");
        Directory.CreateDirectory(inputRoot);
        string originalPath = Path.Combine(inputRoot, itemId + ".exe");
        File.WriteAllBytes(originalPath, [0x4D, 0x5A, 0x00, (byte)itemId.Length]);
        StableFileIdentity identity;
        using (FileStream stream = new(originalPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            identity = WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
        }

        IntakeFile file = new(
            originalPath,
            Path.GetFileName(originalPath),
            Path.Combine(outputRoot, Path.GetFileName(originalPath)),
            outputRoot,
            identity,
            new SignableSubject(SignableFileType.PortableExecutable, Guid.Empty));
        return new BatchItemRequest(itemId, file, CreatePlanJson(), OperationId: RunOperationId);
    }

    private static string CreatePlanJson()
    {
        CertificateRef certificate = CertificateRef.TryCreate(
            CertificateStoreLocation.CurrentUser,
            "My",
            Thumbprint).Value ?? throw new InvalidOperationException("Could not create the test certificate reference.");
        SigningPlan plan = SigningPlan.TryCreateSingle(certificate, ".exe").Value
            ?? throw new InvalidOperationException("Could not create the test signing plan.");
        return SigningPlanJson.Serialize(plan);
    }

    private static BatchItem Item(SigningBatch batch, string itemId) =>
        Assert.Single(batch.Items, item => string.Equals(item.Request.ItemId, itemId, StringComparison.Ordinal));

    private static string Hash(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void AssertPublishedReceipt(BatchItem item)
    {
        BatchItemReceipt receipt = Assert.IsType<BatchItemReceipt>(item.Receipt);
        Assert.Equal(item.Request.File.DestinationPath, receipt.DestinationPath, ignoreCase: true);
        Assert.True(File.Exists(receipt.DestinationPath));
        Assert.Matches("^[0-9A-F]{64}$", receipt.PublishedSha256!);
    }

    private sealed class RetryWorkerFactory : IBatchWorkerSessionFactory
    {
        private readonly Dictionary<string, Queue<bool>> outcomes = new(StringComparer.Ordinal);

        public List<string> InvocationPaths { get; } = [];

        public List<string?> LogicalOperationIds { get; } = [];

        public void Set(string itemId, params bool[] success) =>
            outcomes[itemId] = new Queue<bool>(success);

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IBatchWorkerSession>(new Session(this));
        }

        private Task<WorkerResponse> ExecuteAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            Action<BatchWorkerPhase> reportProgress,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            InvocationPaths.Add(originalPath);
            string itemId = Path.GetFileNameWithoutExtension(originalPath);
            bool success = outcomes.TryGetValue(itemId, out Queue<bool>? scripted) && scripted.Count > 0
                ? scripted.Dequeue()
                : throw new InvalidOperationException("No retry outcome was configured for " + itemId + ".");
            SigningPlan plan = SigningPlanJson.Parse(signingPlanJson).Value
                ?? throw new InvalidOperationException("The test worker received an invalid signing plan.");
            WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);
            string originalHash = Hash(originalPath);
            reportProgress(BatchWorkerPhase.SigningPrimary);
            if (!success)
            {
                return Task.FromResult(new WorkerResponse(
                    WorkerProtocol.Version,
                    false,
                    WorkerResponseCodes.NativeSigningFailed,
                    unchecked((int)0x80004005),
                    FailedLegIndex: 0,
                    OriginalSha256: originalHash,
                    Subject: contract.Subject,
                    Capability: contract.Capability,
                    Engine: contract.Engine,
                    Verification: contract.Verification));
            }

            File.AppendAllText(stagedPath, ":signed");
            reportProgress(BatchWorkerPhase.Verifying);
            string candidateHash = Hash(stagedPath).ToLowerInvariant();
            return Task.FromResult(new WorkerResponse(
                WorkerProtocol.Version,
                true,
                WorkerResponseCodes.SigningCompleted,
                0,
                OriginalSha256: originalHash.ToLowerInvariant(),
                StagedSha256: candidateHash,
                OperationId: RunOperationId,
                Subject: contract.Subject,
                Capability: contract.Capability,
                Engine: contract.Engine,
                Verification: contract.Verification,
                LegacyFallbackAttempted: false,
                Outcome: WorkerSigningOutcome.Signed,
                Route: WorkerExecutionRoute.ProductPe));
        }

        private sealed class Session(RetryWorkerFactory owner) : IBatchWorkerSession
        {
            private bool running = true;

            public int ProcessId => 62006;

            public bool IsRunning => running;

            public Task<WorkerResponse> SignAsync(
                string originalPath,
                string stagedPath,
                string signingPlanJson,
                Action<BatchWorkerPhase> reportProgress,
                TimeSpan timeout,
                CancellationToken cancellationToken) =>
                owner.ExecuteAsync(
                    originalPath,
                    stagedPath,
                    signingPlanJson,
                    reportProgress,
                    cancellationToken);

            public async Task<BatchWorkerSigningResult> SignWithDiagnosticsAsync(
                string originalPath,
                string stagedPath,
                string signingPlanJson,
                string? operationId,
                Action<BatchWorkerPhase> reportProgress,
                TimeSpan timeout,
                CancellationToken cancellationToken)
            {
                owner.LogicalOperationIds.Add(operationId);
                WorkerResponse response = await owner.ExecuteAsync(
                    originalPath,
                    stagedPath,
                    signingPlanJson,
                    reportProgress,
                    cancellationToken);
                return new BatchWorkerSigningResult(response, null, false);
            }

            public Task<int> CompleteAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                running = false;
                return Task.FromResult(0);
            }

            public Task TerminateAsync()
            {
                running = false;
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                running = false;
                return ValueTask.CompletedTask;
            }
        }
    }
}
