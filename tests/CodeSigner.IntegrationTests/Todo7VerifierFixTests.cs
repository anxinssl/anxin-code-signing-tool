using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.IntegrationTests;

public sealed class Todo7VerifierFixTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Fact]
    [Trait("Category", "Todo7VerifierFixRed")]
    public async Task ConcurrentCancelInterruptsActiveWorkerTreeAndCleansCurrentAndTailWithinFiveSeconds()
    {
        string root = CreateRoot("cancel");
        try
        {
            string outputRoot = Path.Combine(root, "Signed");
            BatchItemRequest current = CreateRequest(root, outputRoot, "current", ".exe");
            BatchItemRequest tail = CreateRequest(root, outputRoot, "tail", ".exe");
            var factory = new BlockingWorkerFactory();
            var batch = new SigningBatch([current, tail]);
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(factory, TimeSpan.FromMinutes(5));
            Task<SigningBatch> run = orchestrator.RunAsync(batch, CancellationToken.None);
            await factory.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Stopwatch stopwatch = Stopwatch.StartNew();
            Task cancel = orchestrator.CancelAsync(batch);
            Exception? concurrencyFailure = null;
            try
            {
                await Task.WhenAll(run, cancel).WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception error)
            {
                concurrencyFailure = error;
            }
            finally
            {
                if (concurrencyFailure is not null)
                {
                    await factory.ForceStopAsync();
                    await Task.WhenAll(run, cancel).WaitAsync(TimeSpan.FromSeconds(5));
                }
            }

            stopwatch.Stop();
            Assert.Null(concurrencyFailure);
            Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(5));
            Assert.Equal(BatchItemState.Cancelled, batch.Items[0].State);
            Assert.Equal(BatchResultCode.Cancelled, batch.Items[0].Receipt!.Code);
            Assert.Equal(BatchItemState.Cancelled, batch.Items[1].State);
            Assert.Equal(BatchResultCode.Cancelled, batch.Items[1].Receipt!.Code);
            Assert.False(factory.Session.IsRunning);
            Assert.False(IsProcessRunning(factory.Session.ProcessId));
            Assert.False(IsProcessRunning(factory.Session.ChildProcessId));
            Assert.False(File.Exists(current.File.DestinationPath));
            Assert.False(File.Exists(tail.File.DestinationPath));
            AssertNoStaging(root);
            Assert.Equal(Hash(current.File.OriginalPath), factory.Session.OriginalSha256);
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
    [Trait("Category", "Todo7VerifierFixRed")]
    public async Task BatchStartsWorkerAndRendersWorkerOwnedSkipDecision()
    {
        string root = CreateRoot("nonexe-skip");
        try
        {
            string outputRoot = Path.Combine(root, "Signed");
            BatchItemRequest request = CreateRequest(root, outputRoot, "supported", ".dll");
            var factory = new SkipWorkerFactory();
            var batch = new SigningBatch([request]);
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(factory, TimeSpan.FromSeconds(5));

            await orchestrator.RunAsync(batch, CancellationToken.None);

            BatchItem item = Assert.Single(batch.Items);
            Assert.Equal(BatchItemState.SkippedAlreadySigned, item.State);
            Assert.Equal(BatchResultCode.AlreadySigned, item.Receipt!.Code);
            Assert.Equal(1, factory.StartCount);
            Assert.Equal(1, factory.Session.SignCount);
            Assert.False(File.Exists(request.File.DestinationPath));
            AssertNoStaging(root);
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
    [Trait("Category", "Todo7VerifierFixRed")]
    public void RestoreRejectsTerminalOrPausedSnapshotsWithoutAnExactReceipt()
    {
        string root = CreateRoot("restore");
        try
        {
            BatchItemRequest request = CreateRequest(
                root,
                Path.Combine(root, "Signed"),
                "snapshot",
                ".exe");
            BatchItemState[] protectedStates =
            [
                BatchItemState.Published,
                BatchItemState.Failed,
                BatchItemState.PausedProvider,
                BatchItemState.PausedTimestamp
            ];
            foreach (BatchItemState state in protectedStates)
            {
                Assert.Throws<ArgumentException>(() => SigningBatch.Restore(
                    [new BatchItemSnapshot(request, state, [])]));
                BatchItemReceipt mismatched = new(
                    request.ItemId,
                    BatchItemState.Cancelled,
                    BatchResultCode.Cancelled,
                    request.File.OriginalPath,
                    request.File.DestinationPath,
                    null,
                    null,
                    null,
                    null,
                    null);
                Assert.Throws<ArgumentException>(() => SigningBatch.Restore(
                    [new BatchItemSnapshot(request, state, [mismatched])]));
            }

            SigningBatch interrupted = SigningBatch.Restore(
                [new BatchItemSnapshot(request, BatchItemState.SigningSecondary, [])]);
            Assert.Equal(BatchItemState.Pending, Assert.Single(interrupted.Items).State);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static string CreateRoot(string scenario)
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-Todo7-Fix-" + scenario + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static BatchItemRequest CreateRequest(
        string root,
        string outputRoot,
        string itemId,
        string extension)
    {
        string inputRoot = Path.Combine(root, "inputs");
        Directory.CreateDirectory(inputRoot);
        string originalPath = Path.GetFullPath(Path.Combine(inputRoot, itemId + extension));
        File.WriteAllText(originalPath, "original:" + itemId);
        StableFileIdentity identity;
        using (FileStream stream = new(originalPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            identity = WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
        }

        IntakeFile file = new(
            originalPath,
            itemId + extension,
            Path.GetFullPath(Path.Combine(outputRoot, itemId + extension)),
            Path.GetFullPath(outputRoot),
            identity,
            new SignableSubject(
                SigningSubject.TryCreateForExtension(extension).Value
                    ?? throw new InvalidOperationException("Could not create the test signing subject."),
                Guid.Empty,
                scriptProfile: null));
        return new BatchItemRequest(itemId, file, CreatePlanJson(extension));
    }

    private static string CreatePlanJson(string extension = ".exe")
    {
        CertificateRef certificate = CertificateRef.TryCreate(
            CertificateStoreLocation.CurrentUser,
            "My",
            Thumbprint).Value ?? throw new InvalidOperationException("Could not create the test certificate reference.");
        SigningPlan plan = SigningPlan.TryCreateSingle(certificate, extension).Value
            ?? throw new InvalidOperationException("Could not create the test signing plan.");
        return SigningPlanJson.Serialize(plan);
    }

    private static void AssertNoStaging(string root)
    {
        string[] residue = Directory.Exists(root)
            ? Directory.GetDirectories(root, ".codesigner-staging-*", SearchOption.AllDirectories)
            : [];
        Assert.Empty(residue);
    }

    private static string Hash(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool IsProcessRunning(int processId)
    {
        if (processId <= 0)
        {
            return false;
        }

        try
        {
            using Process process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private sealed class SkipWorkerFactory : IBatchWorkerSessionFactory
    {
        public int StartCount { get; private set; }

        public SkipWorkerSession Session { get; } = new();

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCount++;
            return ValueTask.FromResult<IBatchWorkerSession>(Session);
        }
    }

    private sealed class SkipWorkerSession : IBatchWorkerSession
    {
        public int ProcessId => Environment.ProcessId;

        public bool IsRunning { get; private set; } = true;

        public int SignCount { get; private set; }

        public Task<WorkerResponse> SignAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The batch must preserve the operation identifier.");

        public Task<BatchWorkerSigningResult> SignWithDiagnosticsAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            string? operationId,
            WorkerSdkFallback sdkFallback,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SignCount++;
            WorkerSigningContract contract = WorkerSigningContract.FromSigningPlanJson(signingPlanJson);
            WorkerResponse response = new(
                WorkerProtocol.Version,
                true,
                WorkerResponseCodes.SkippedExistingSignature,
                0,
                OriginalSha256: Hash(originalPath).ToLowerInvariant(),
                StagedSha256: Hash(stagedPath).ToLowerInvariant(),
                OperationId: operationId ?? "0123456789abcdef0123456789abcdef",
                Subject: contract.Subject,
                Capability: contract.Capability,
                Engine: contract.Engine,
                Verification: contract.Verification,
                LegacyFallbackAttempted: false,
                Outcome: WorkerSigningOutcome.SkippedExistingSignature,
                Route: WorkerExecutionRoute.Skip);
            return Task.FromResult(new BatchWorkerSigningResult(response, null, false));
        }

        public Task<int> CompleteAsync(CancellationToken cancellationToken)
        {
            IsRunning = false;
            return Task.FromResult(0);
        }

        public Task TerminateAsync()
        {
            IsRunning = false;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            IsRunning = false;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class BlockingWorkerFactory : IBatchWorkerSessionFactory
    {
        public TaskCompletionSource<string> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public BlockingWorkerSession Session { get; private set; } = null!;

        public async ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Session = await BlockingWorkerSession.CreateAsync(Started);
            return Session;
        }

        public Task ForceStopAsync() => Session.TerminateAsync();
    }

    private sealed class BlockingWorkerSession : IBatchWorkerSession
    {
        private readonly TaskCompletionSource<string> started;
        private readonly CancellationTokenSource stop = new();
        private readonly Process parent;
        private readonly WorkerJob job;
        private readonly int parentId;
        private readonly object stopSync = new();
        private Task? stopTask;
        private bool disposed;

        private BlockingWorkerSession(
            TaskCompletionSource<string> started,
            Process parent,
            WorkerJob job,
            int childProcessId)
        {
            this.started = started;
            this.parent = parent;
            this.job = job;
            parentId = parent.Id;
            ChildProcessId = childProcessId;
        }

        public int ProcessId => parentId;

        public int ChildProcessId { get; }

        public bool IsRunning => !stop.IsCancellationRequested && IsProcessRunning(parentId);

        public string? OriginalSha256 { get; private set; }

        public static async Task<BlockingWorkerSession> CreateAsync(TaskCompletionSource<string> started)
        {
            ProcessStartInfo startInfo = new("powershell.exe")
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-Command");
            startInfo.ArgumentList.Add("$null=[Console]::ReadLine(); $child=Start-Process ping.exe -ArgumentList @('127.0.0.1','-n','120') -PassThru -WindowStyle Hidden; [Console]::Out.WriteLine($child.Id); [Console]::Out.Flush(); Wait-Process -Id $child.Id");
            Process parent = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Could not start the blocking worker fixture.");
            WorkerJob job = WorkerJob.CreateKillOnClose();
            try
            {
                job.Assign(parent);
                await parent.StandardInput.WriteLineAsync(string.Empty);
                await parent.StandardInput.FlushAsync();
                string? childLine = await parent.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
                int childId = int.Parse(childLine!, System.Globalization.CultureInfo.InvariantCulture);
                return new BlockingWorkerSession(started, parent, job, childId);
            }
            catch
            {
                try
                {
                    job.Terminate(WorkerJob.TimeoutExitCode);
                }
                catch (Exception)
                {
                }

                parent.Dispose();
                job.Dispose();
                throw;
            }
        }

        public async Task<WorkerResponse> SignAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            OriginalSha256 = Hash(originalPath);
            started.TrySetResult(stagedPath);
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                stop.Token);
            await Task.Delay(Timeout.InfiniteTimeSpan, linked.Token);
            throw new InvalidOperationException("The blocking worker must terminate through cancellation.");
        }

        public async Task<int> CompleteAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await TerminateAsync();
            return 0;
        }

        public Task TerminateAsync()
        {
            lock (stopSync)
            {
                stopTask ??= StopCoreAsync();
                return stopTask;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            await TerminateAsync();
            stop.Dispose();
            parent.Dispose();
            job.Dispose();
        }

        private async Task StopCoreAsync()
        {
            stop.Cancel();
            if (!parent.HasExited)
            {
                job.Terminate(WorkerJob.TimeoutExitCode);
                await parent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            }
        }
    }
}
