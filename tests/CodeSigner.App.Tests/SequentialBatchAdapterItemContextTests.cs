using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.Tests;

public sealed class SequentialBatchAdapterItemContextTests
{
    [Fact]
    public async Task RunAndResumeEchoExactAttemptContextWhileRetainingRequest()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory();
            var orchestrator = new SequentialBatchOrchestrator(workerFactory, TimeSpan.FromSeconds(5));
            var observedRequests = new List<BatchItemRequest>();
            orchestrator.StateChanged += (_, args) => observedRequests.Add(args.Item.Request);
            await using var adapter = new SequentialBatchAdapter(
                orchestrator,
                runtimeEventLog: null,
                stallThreshold: TimeSpan.FromSeconds(1));
            BatchItemRequest request = await CreateRequestAsync(root, "item-a", "a.exe");
            var attempts = new ExecutionAttemptContextFactory();
            ExecutionAttemptContext firstAttempt = attempts.Next(request.ItemId);
            var observed = new List<ExecutionAttemptContext>();
            adapter.ProgressChanged += (_, args) => observed.Add(args.Update.Attempt);

            BatchProgressUpdate first = await adapter.RunAsync(
                request,
                firstAttempt,
                CancellationToken.None);
            int firstAttemptEventCount = observed.Count;
            ExecutionAttemptContext retryAttempt = attempts.Next(request.ItemId);
            BatchProgressUpdate retry = await adapter.ResumeAsync(
                retryAttempt,
                retryFailed: true,
                cancellationToken: CancellationToken.None);

            Assert.Same(firstAttempt, first.Attempt);
            Assert.Same(retryAttempt, retry.Attempt);
            Assert.NotEqual(0, firstAttemptEventCount);
            Assert.All(observed.Take(firstAttemptEventCount), context => Assert.Same(firstAttempt, context));
            Assert.All(observed.Skip(firstAttemptEventCount), context => Assert.Same(retryAttempt, context));
            Assert.Equal(1, firstAttempt.ExecutionGeneration);
            Assert.Equal(2, retryAttempt.ExecutionGeneration);
            Assert.NotEqual(firstAttempt.OperationId, retryAttempt.OperationId);
            Assert.Matches("^[0-9a-f]{32}$", firstAttempt.OperationId);
            Assert.Matches("^[0-9a-f]{32}$", retryAttempt.OperationId);
            Assert.NotEmpty(observedRequests);
            Assert.All(observedRequests, observedRequest => Assert.Same(request, observedRequest));
            Assert.Equal([request.SigningPlanJson, request.SigningPlanJson], workerFactory.SigningPlanJsonValues);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SingleItemCharacterizationReturnsTypedFailureWithoutStartingWorkerProcess()
    {
        string root = CreateRoot();
        try
        {
            int workerCountBefore = CountWorkerProcesses();
            BatchItemRequest request = await CreateRequestAsync(root, "item-a", "a.exe");
            var workerFactory = new FakeWorkerSessionFactory();
            await using var adapter = CreateAdapter(workerFactory);

            BatchProgressUpdate result = await adapter.RunAsync(request, CancellationToken.None);

            Assert.Equal("item-a", result.ItemId);
            Assert.Equal(BatchItemState.Failed, result.State);
            Assert.Equal(BatchResultCode.WorkerFailure, result.Receipt?.Code);
            Assert.Equal(1, workerFactory.StartCount);
            Assert.Equal(workerCountBefore, CountWorkerProcesses());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FailedAThenRunBThenResumeAUsesRetainedAContext()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory();
            await using var adapter = CreateAdapter(workerFactory);
            BatchItemRequest requestA = await CreateRequestAsync(root, "item-a", "a.exe");
            BatchItemRequest requestB = await CreateRequestAsync(root, "item-b", "b.exe");

            BatchProgressUpdate firstA = await adapter.RunAsync(requestA, CancellationToken.None);
            BatchProgressUpdate firstB = await adapter.RunAsync(requestB, CancellationToken.None);
            BatchProgressUpdate resumedA = await adapter.ResumeAsync(
                requestA.ItemId,
                retryFailed: true,
                cancellationToken: CancellationToken.None);

            Assert.Equal(BatchItemState.Failed, firstA.State);
            Assert.Equal(BatchItemState.Failed, firstB.State);
            Assert.Equal(requestA.ItemId, resumedA.ItemId);
            Assert.Equal(BatchItemState.Failed, resumedA.State);
            Assert.Equal([requestA.ItemId, requestB.ItemId, requestA.ItemId], workerFactory.SignedItemIds);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UnknownResumeAndDuplicateRunAreTypedAndDoNotReplaceRetainedContext()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory();
            await using var adapter = CreateAdapter(workerFactory);
            BatchItemRequest request = await CreateRequestAsync(root, "item-a", "a.exe");
            await adapter.RunAsync(request, CancellationToken.None);

            BatchAdapterItemContextException unknown = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.ResumeAsync("unknown", retryFailed: true, cancellationToken: CancellationToken.None));
            BatchAdapterItemContextException duplicate = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.RunAsync(request, CancellationToken.None));
            BatchAdapterItemContextException malformed = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.ResumeAsync(" ", retryFailed: true, cancellationToken: CancellationToken.None));
            BatchProgressUpdate resumed = await adapter.ResumeAsync(
                request.ItemId,
                retryFailed: true,
                cancellationToken: CancellationToken.None);

            Assert.Equal(BatchAdapterItemContextError.UnknownItem, unknown.Error);
            Assert.Equal(BatchAdapterItemContextError.DuplicateItem, duplicate.Error);
            Assert.Equal(BatchAdapterItemContextError.InvalidItemId, malformed.Error);
            Assert.Equal(request.ItemId, resumed.ItemId);
            Assert.Equal(2, workerFactory.StartCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PruneADeletesOnlyAAndLeavesBRetained()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory();
            await using var adapter = CreateAdapter(workerFactory);
            BatchItemRequest requestA = await CreateRequestAsync(root, "item-a", "a.exe");
            BatchItemRequest requestB = await CreateRequestAsync(root, "item-b", "b.exe");
            await adapter.RunAsync(requestA, CancellationToken.None);
            await adapter.RunAsync(requestB, CancellationToken.None);

            BatchAdapterItemContextException atomicReject = Assert.Throws<BatchAdapterItemContextException>(
                () => adapter.PruneItems([requestA.ItemId, "unknown"]));
            BatchProgressUpdate retainedA = await adapter.ResumeAsync(
                requestA.ItemId,
                retryFailed: true,
                cancellationToken: CancellationToken.None);
            adapter.PruneItems([requestA.ItemId]);

            BatchAdapterItemContextException missingA = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.ResumeAsync(requestA.ItemId, retryFailed: true, cancellationToken: CancellationToken.None));
            BatchProgressUpdate resumedB = await adapter.ResumeAsync(
                requestB.ItemId,
                retryFailed: true,
                cancellationToken: CancellationToken.None);
            Assert.Equal(BatchAdapterItemContextError.UnknownItem, missingA.Error);
            Assert.Equal(BatchAdapterItemContextError.UnknownItem, atomicReject.Error);
            Assert.Equal(requestA.ItemId, retainedA.ItemId);
            Assert.Equal(requestB.ItemId, resumedB.ItemId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ParallelRunAndWrongItemCancelAreTypedAndDoNotMutateContexts()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory(blockSequence: 1);
            await using var adapter = CreateAdapter(workerFactory);
            BatchItemRequest requestA = await CreateRequestAsync(root, "item-a", "a.exe");
            BatchItemRequest requestB = await CreateRequestAsync(root, "item-b", "b.exe");

            Task<BatchProgressUpdate> activeRun = adapter.RunAsync(requestA, CancellationToken.None);
            await workerFactory.FirstSignEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

            BatchAdapterItemContextException parallel = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.RunAsync(requestB, CancellationToken.None));
            BatchAdapterItemContextException wrongCancel = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.CancelAsync(requestB.ItemId, CancellationToken.None));
            BatchAdapterItemContextException pruneActive = Assert.Throws<BatchAdapterItemContextException>(
                () => adapter.PruneItems([requestA.ItemId]));

            Assert.Equal(BatchAdapterItemContextError.OperationActive, parallel.Error);
            Assert.Equal(BatchAdapterItemContextError.InactiveItem, wrongCancel.Error);
            Assert.Equal(BatchAdapterItemContextError.OperationActive, pruneActive.Error);
            await adapter.CancelAsync(requestA.ItemId, CancellationToken.None);
            workerFactory.ReleaseFirstSign.TrySetResult();
            BatchProgressUpdate cancelledA = await activeRun;
            Assert.Equal(BatchItemState.Cancelled, cancelledA.State);

            BatchProgressUpdate resultB = await adapter.RunAsync(requestB, CancellationToken.None);
            Assert.Equal(requestB.ItemId, resultB.ItemId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CancelAtOperationPublicationNeverObservesActiveItemWithoutRetainedBatch()
    {
        string root = CreateRoot();
        var publicationReached = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releasePublication = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            var workerFactory = new FakeWorkerSessionFactory();
            await using var adapter = CreateAdapter(
                workerFactory,
                () =>
                {
                    publicationReached.TrySetResult();
                    releasePublication.Task.GetAwaiter().GetResult();
                });
            BatchItemRequest request = await CreateRequestAsync(root, "item-a", "a.exe");

            Task<BatchProgressUpdate> activeRun = Task.Run(
                () => adapter.RunAsync(request, CancellationToken.None));
            await publicationReached.Task.WaitAsync(TimeSpan.FromSeconds(5));

            try
            {
                await adapter.CancelAsync(request.ItemId, CancellationToken.None);
            }
            finally
            {
                releasePublication.TrySetResult();
            }

            BatchProgressUpdate cancelled = await activeRun;
            Assert.Equal(BatchItemState.Cancelled, cancelled.State);
        }
        finally
        {
            releasePublication.TrySetResult();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task MalformedRunAndCancelAreTypedAndDoNotChangeRetainedState()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory();
            await using var adapter = CreateAdapter(workerFactory);
            BatchItemRequest request = await CreateRequestAsync(root, "item-a", "a.exe");

            BatchAdapterItemContextException malformedRun = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.RunAsync(request with { ItemId = " " }, CancellationToken.None));
            BatchAdapterItemContextException malformedCancel = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.CancelAsync(" ", CancellationToken.None));
            BatchProgressUpdate result = await adapter.RunAsync(request, CancellationToken.None);

            Assert.Equal(BatchAdapterItemContextError.InvalidItemId, malformedRun.Error);
            Assert.Equal(BatchAdapterItemContextError.InvalidItemId, malformedCancel.Error);
            Assert.Equal(request.ItemId, result.ItemId);
            Assert.Equal(1, workerFactory.StartCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CancelDuringResumeClearsActiveStateAndRetainsOtherContexts()
    {
        string root = CreateRoot();
        try
        {
            var workerFactory = new FakeWorkerSessionFactory(blockSequence: 2);
            await using var adapter = CreateAdapter(workerFactory);
            BatchItemRequest requestA = await CreateRequestAsync(root, "item-a", "a.exe");
            BatchItemRequest requestB = await CreateRequestAsync(root, "item-b", "b.exe");
            await adapter.RunAsync(requestA, CancellationToken.None);

            Task<BatchProgressUpdate> activeResume = adapter.ResumeAsync(
                requestA.ItemId,
                retryFailed: true,
                cancellationToken: CancellationToken.None);
            await workerFactory.FirstSignEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await adapter.CancelAsync(requestA.ItemId, CancellationToken.None);
            workerFactory.ReleaseFirstSign.TrySetResult();

            BatchProgressUpdate cancelled = await activeResume;
            BatchAdapterItemContextException repeatedCancel = await Assert.ThrowsAsync<BatchAdapterItemContextException>(
                () => adapter.CancelAsync(requestA.ItemId, CancellationToken.None));
            BatchProgressUpdate resultB = await adapter.RunAsync(requestB, CancellationToken.None);

            Assert.Equal(BatchItemState.Cancelled, cancelled.State);
            Assert.Equal(BatchAdapterItemContextError.InactiveItem, repeatedCancel.Error);
            Assert.Equal(requestB.ItemId, resultB.ItemId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateRoot()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-ItemContext-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static async Task<BatchItemRequest> CreateRequestAsync(
        string root,
        string itemId,
        string fileName)
    {
        string originalPath = Path.Combine(root, fileName);
        string outputRoot = Path.Combine(root, "output");
        Directory.CreateDirectory(outputRoot);
        await File.WriteAllTextAsync(originalPath, "original");
        QueuedSource source = Assert.Single(
            QueuedSourceAdmission.Admit([originalPath], recurseDirectories: false, CancellationToken.None).Sources);
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
                fileName,
                Path.Combine(outputRoot, fileName),
                outputRoot,
                source.Identity,
                new SignableSubject(SignableFileType.PortableExecutable, Guid.Empty)),
            SigningPlanJson.Serialize(plan));
    }

    private static int CountWorkerProcesses() => Process.GetProcessesByName("CodeSigner.Worker").Length;

    private static SequentialBatchAdapter CreateAdapter(
        FakeWorkerSessionFactory workerFactory,
        Action? operationPublished = null) =>
        new(
            new SequentialBatchOrchestrator(workerFactory, TimeSpan.FromSeconds(5)),
            runtimeEventLog: null,
            stallThreshold: TimeSpan.FromSeconds(1),
            operationPublished);

    private sealed class FakeWorkerSessionFactory(int blockSequence = 0) : IBatchWorkerSessionFactory
    {
        private readonly int blockedSequence = blockSequence;
        private int startCount;

        public int StartCount => Volatile.Read(ref startCount);

        public List<string> SignedItemIds { get; } = [];

        public List<string> SigningPlanJsonValues { get; } = [];

        public TaskCompletionSource FirstSignEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseFirstSign { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int sequence = Interlocked.Increment(ref startCount);
            return ValueTask.FromResult<IBatchWorkerSession>(new FakeWorkerSession(this, sequence));
        }

        private sealed class FakeWorkerSession(FakeWorkerSessionFactory owner, int sequence) : IBatchWorkerSession
        {
            private bool running = true;

            public int ProcessId => Environment.ProcessId;

            public bool IsRunning => running;

            public async Task<WorkerResponse> SignAsync(
                string originalPath,
                string stagedPath,
                string signingPlanJson,
                Action<BatchWorkerPhase> reportProgress,
                TimeSpan timeout,
                CancellationToken cancellationToken)
            {
                string itemId = Path.GetFileNameWithoutExtension(originalPath) switch
                {
                    "a" => "item-a",
                    "b" => "item-b",
                    _ => throw new InvalidOperationException("Unexpected fake-session source file.")
                };
                owner.SignedItemIds.Add(itemId);
                owner.SigningPlanJsonValues.Add(signingPlanJson);
                if (sequence == owner.blockedSequence)
                {
                    owner.FirstSignEntered.TrySetResult();
                    await owner.ReleaseFirstSign.Task.WaitAsync(cancellationToken);
                }

                PolicyResult<SigningPlan> parsed = SigningPlanJson.Parse(signingPlanJson);
                WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(
                    parsed.Value ?? throw new InvalidOperationException("The fake session received an invalid plan."));
                string originalHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(
                    originalPath,
                    cancellationToken)));
                return new WorkerResponse(
                    WorkerProtocol.Version,
                    false,
                    WorkerResponseCodes.NativeSigningFailed,
                    unchecked((int)0x80004005),
                    OriginalSha256: originalHash,
                    DiagnosticId: Guid.NewGuid().ToString("N"),
                    DiagnosticPhase: WorkerDiagnosticPhases.WorkerBridge,
                    HResultOrigin: WorkerHResultOrigins.WorkerBridge,
                    Subject: contract.Subject,
                    Capability: contract.Capability,
                    Engine: contract.Engine,
                    Verification: contract.Verification);
            }

            public Task<int> CompleteAsync(CancellationToken cancellationToken)
            {
                running = false;
                return Task.FromResult(0);
            }

            public Task TerminateAsync()
            {
                running = false;
                owner.ReleaseFirstSign.TrySetResult();
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
