using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.IntegrationTests;

public sealed class Todo7SequentialBatchComprehensiveTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string RunOperationId = "0123456789abcdef0123456789abcdef";

    [Theory]
    [Trait("Category", "MockOutputFailure")]
    [InlineData("save", BatchResultCode.OutputSaveFailed)]
    [InlineData("success", BatchResultCode.Published)]
    [InlineData("collision", BatchResultCode.DestinationCollision)]
    [InlineData("crash", BatchResultCode.WorkerCrashed)]
    [InlineData("provider", BatchResultCode.ProviderUnavailable)]
    [InlineData("timestamp", BatchResultCode.TimestampUnavailable)]
    public async Task OutputFailureClassificationPreservesOtherOutcomesAndSnapshotRestore(
        string scenario, BatchResultCode expected)
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-OutputFailure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string outputRoot = Path.Combine(root, "Signed");
            Directory.CreateDirectory(outputRoot);
            BatchItemRequest request = CreateRequest(root, outputRoot, "fixture", ".exe", CreatePlanJson(dual: true));
            if (scenario == "save")
            {
                string blocker = Path.Combine(outputRoot, "blocked");
                File.WriteAllText(blocker, "keep");
                request = request with
                {
                    File = request.File with
                    {
                        RelativePath = Path.Combine("blocked", "fixture.exe"),
                        DestinationPath = Path.Combine(blocker, "fixture.exe")
                    }
                };
            }
            if (scenario == "collision") File.WriteAllText(request.File.DestinationPath, "keep");
            var factory = new ScriptedWorkerFactory(processBacked: false);
            factory.Set("fixture", scenario switch
            {
                "crash" => FakeOutcome.Crash,
                "provider" => FakeOutcome.ProviderPause,
                "timestamp" => FakeOutcome.TimestampPause,
                _ => FakeOutcome.Success
            });
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(factory, TimeSpan.FromSeconds(5));
            var batch = new SigningBatch([request]);

            await orchestrator.RunAsync(batch, CancellationToken.None);

            BatchItemReceipt receipt = Assert.Single(batch.Items).Receipt!;
            Assert.Equal(expected, receipt.Code);
            Assert.Equal(receipt, Assert.Single(SigningBatch.Restore(batch.Snapshot()).Items).Receipt);
            if (scenario == "save")
            {
                Assert.Null(receipt.LaunchDiagnostic);
                Assert.NotNull(receipt.HResult);
                Assert.False(File.Exists(request.File.DestinationPath));
            }
            if (scenario == "collision") Assert.Equal("keep", File.ReadAllText(request.File.DestinationPath));
            AssertOriginalsUnchanged([request]);
            AssertNoStaging(root);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RuntimeEventsCoverWorkerAndSignerBoundariesInOrder()
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-RuntimeBoundaries-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string outputRoot = Path.Combine(root, "Signed");
            BatchItemRequest request = CreateRequest(
                root,
                outputRoot,
                "runtime-dual",
                ".exe",
                CreatePlanJson(dual: true));
            var factory = new ScriptedWorkerFactory(processBacked: false);
            factory.Set("runtime-dual", FakeOutcome.Success);
            var events = new List<(string Event, string? ItemId, int? ProcessId)>();
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(
                factory,
                TimeSpan.FromSeconds(5),
                (runtimeEvent, itemId, processId) => events.Add((runtimeEvent, itemId, processId)));

            var batch = new SigningBatch([request]);
            await orchestrator.RunAsync(batch, CancellationToken.None);

            Assert.Equal(
                [
                    "worker-starting",
                    "worker-started",
                    "staging-create-start",
                    "staging-create-done",
                    "source-hash-start",
                    "source-hash-done",
                    "copy-to-staging-start",
                    "copy-to-staging-done",
                    "signer-enter",
                    "signing-primary-enter",
                    "signing-secondary-enter",
                    "verifying-enter",
                    "publish-start",
                    "publish-done"
                ],
                events.Select(static entry => entry.Event));
            Assert.All(events, static entry => Assert.Equal("runtime-dual", entry.ItemId));
            Assert.Equal(factory.Sessions[0].ProcessId, events[1].ProcessId);
            Assert.Equal(BatchItemState.Published, Assert.Single(batch.Items).State);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RuntimeEventsRecordWorkerStartFailureBeforeBatchItemFails()
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-WorkerStartFailure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            BatchItemRequest request = CreateRequest(
                root,
                Path.Combine(root, "Signed"),
                "worker-start-failure",
                ".exe",
                CreatePlanJson(dual: false));
            var events = new List<string>();
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(
                new FailingWorkerFactory(),
                TimeSpan.FromSeconds(5),
                (runtimeEvent, _, _) => events.Add(runtimeEvent));

            var batch = new SigningBatch([request]);
            await orchestrator.RunAsync(batch, CancellationToken.None);

            Assert.Equal(["worker-starting", "worker-start-failed"], events);
            Assert.Equal(BatchItemState.Failed, Assert.Single(batch.Items).State);
            Assert.Equal(BatchResultCode.WorkerLaunchFailed, Assert.Single(batch.Items).Receipt?.Code);
            Assert.Equal(WorkerLaunchReason.Crashed, Assert.Single(batch.Items).Receipt?.LaunchDiagnostic?.Reason);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task WorkerLaunchFailureFailsOnlyCurrentRowAndCarriesTypedDiagnostic()
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-WorkerLaunchIsolation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string outputRoot = Path.Combine(root, "Signed");
            string plan = CreatePlanJson(dual: true);
            BatchItemRequest[] requests =
            [
                CreateRequest(root, outputRoot, "launch-failure", ".exe", plan),
                CreateRequest(root, outputRoot, "pending-two", ".exe", plan),
                CreateRequest(root, outputRoot, "pending-three", ".exe", plan)
            ];
            var events = new List<(string Event, string? ItemId, int? ProcessId, WorkerLaunchDiagnostic? Diagnostic)>();
            var factory = new CountingFailingWorkerFactory();
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(
                factory,
                TimeSpan.FromSeconds(5),
                runtimeEventSink: null,
                diagnosticRuntimeEventSink: (runtimeEvent, itemId, processId, diagnostic) =>
                    events.Add((runtimeEvent, itemId, processId, diagnostic)));

            var batch = new SigningBatch(requests);
            await orchestrator.RunAsync(batch, CancellationToken.None);

            Assert.Equal(1, factory.StartCount);
            Assert.Equal(
                ["worker-starting", "worker-start-failed"],
                events.Select(static entry => entry.Event));
            Assert.Equal("launch-failure", events[0].ItemId);
            Assert.Equal("launch-failure", events[1].ItemId);
            Assert.Equal(WorkerLaunchReason.Missing, events[1].Diagnostic?.Reason);
            Assert.True(events[1].Diagnostic?.RepairEligible);
            Assert.Null(events[1].ProcessId);

            BatchItem failed = batch.Items[0];
            Assert.Equal(BatchItemState.Failed, failed.State);
            Assert.Equal(BatchResultCode.WorkerLaunchFailed, failed.Receipt?.Code);
            Assert.Equal(WorkerLaunchReason.Missing, failed.Receipt?.LaunchDiagnostic?.Reason);
            Assert.True(failed.Receipt?.LaunchDiagnostic?.RepairEligible);
            Assert.Equal(
                [BatchItemState.Pending, BatchItemState.Ready, BatchItemState.Failed],
                failed.StateHistory);
            Assert.Equal(BatchItemState.Pending, batch.Items[1].State);
            Assert.Equal(BatchItemState.Pending, batch.Items[2].State);
            Assert.Null(batch.Items[1].Receipt);
            Assert.Null(batch.Items[2].Receipt);
            Assert.DoesNotContain(events, static entry => entry.Event.Contains("staging", StringComparison.Ordinal));
            Assert.DoesNotContain(events, static entry => entry.Event.Contains("hash", StringComparison.Ordinal));
            Assert.DoesNotContain(events, static entry => entry.Event.Contains("copy", StringComparison.Ordinal));
            Assert.DoesNotContain(events, static entry => entry.Event.Contains("sign", StringComparison.Ordinal));
            Assert.DoesNotContain(events, static entry => entry.Event.Contains("publish", StringComparison.Ordinal));
            Assert.All(requests, request => Assert.False(File.Exists(request.File.DestinationPath)));
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

    [Theory]
    [InlineData("timeout", BatchResultCode.WorkerTimedOut, WorkerLaunchReason.Timeout)]
    [InlineData("protocol", BatchResultCode.WorkerProtocolFailure, WorkerLaunchReason.InvalidFrame)]
    public async Task PostStartTimeoutAndProtocolFailuresRemainDistinct(
        string failureKind,
        BatchResultCode expectedCode,
        WorkerLaunchReason expectedReason)
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-PostStartFailure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            BatchItemRequest request = CreateRequest(
                root,
                Path.Combine(root, "Signed"),
                "post-start-" + failureKind,
                ".exe",
                CreatePlanJson(dual: false));
            var factory = new PostStartFailureFactory(failureKind);
            await using var orchestrator = IntegrationTestBatchOrchestrators.Create(
                factory,
                TimeSpan.FromSeconds(5));
            var batch = new SigningBatch([request]);

            await orchestrator.RunAsync(batch, CancellationToken.None);

            Assert.Equal(1, factory.StartCount);
            Assert.Equal(BatchItemState.Failed, batch.Items[0].State);
            Assert.Equal(expectedCode, batch.Items[0].Receipt?.Code);
            Assert.Equal(expectedReason, batch.Items[0].Receipt?.LaunchDiagnostic?.Reason);
            Assert.NotEqual(BatchResultCode.WorkerCrashed, batch.Items[0].Receipt?.Code);
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
    [Trait("Category", "Todo7Formal")]
    public async Task SequentialExeBatchCoversEveryStatePauseRetryCancellationRecoveryAndReceipt()
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-Todo7-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            AssertExactStateContract();
            await ProvePersistentProductionWorkerAsync();
            ScenarioSummary mixed = await ExerciseMixedPauseResumeAndRetryAsync(Path.Combine(root, "mixed"));
            ScenarioSummary crash = await ExerciseCrashAndRestartAsync(Path.Combine(root, "crash-restart"));

            var cancellationStates = new[]
            {
                BatchItemState.Pending,
                BatchItemState.Ready,
                BatchItemState.SigningPrimary,
                BatchItemState.SigningSecondary,
                BatchItemState.Verifying,
                BatchItemState.Published,
                BatchItemState.SkippedAlreadySigned,
                BatchItemState.Failed,
                BatchItemState.PausedProvider,
                BatchItemState.PausedTimestamp
            };
            foreach (BatchItemState state in cancellationStates)
            {
                await ExerciseCancellationAsync(Path.Combine(root, "cancel-" + state), state);
            }

            BatchItemState[] observedStates = mixed.ObservedStates
                .Concat(crash.ObservedStates)
                .Append(BatchItemState.Cancelled)
                .Distinct()
                .OrderBy(static state => (int)state)
                .ToArray();
            Assert.Equal(Enum.GetValues<BatchItemState>(), observedStates);
            AssertNoStaging(root);
            WriteFormalArtifacts(mixed, crash, cancellationStates);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void AssertExactStateContract()
    {
        Assert.Equal(
            [
                "Pending",
                "Ready",
                "SigningPrimary",
                "SigningSecondary",
                "Verifying",
                "Published",
                "SkippedAlreadySigned",
                "Failed",
                "PausedProvider",
                "PausedTimestamp",
                "Cancelled"
            ],
            Enum.GetNames<BatchItemState>());
        Assert.True(BatchItemStateMachine.CanTransition(BatchItemState.Pending, BatchItemState.Ready));
        Assert.True(BatchItemStateMachine.CanTransition(BatchItemState.Failed, BatchItemState.Ready));
        Assert.False(BatchItemStateMachine.CanTransition(BatchItemState.Published, BatchItemState.Ready));
        Assert.False(BatchItemStateMachine.CanTransition(BatchItemState.SigningPrimary, BatchItemState.Published));
        Assert.False(typeof(BatchItem).GetProperty(nameof(BatchItem.State))!.SetMethod?.IsPublic ?? false);
    }

    private static async Task ProvePersistentProductionWorkerAsync()
    {
        await using WorkerProcessSession session = WorkerProcessSession.Start(WorkerPath());
        WorkerRequest first = new(
            WorkerProtocol.Version,
            WorkerCommands.Probe,
            Path.Combine(Path.GetTempPath(), "todo7-probe", "first.exe"));
        WorkerRequest second = first with
        {
            StagedPath = Path.Combine(Path.GetTempPath(), "todo7-probe", "second.exe")
        };

        WorkerSessionResult firstResult = await session.SendAsync(
            first,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);
        WorkerSessionResult secondResult = await session.SendAsync(
            second,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);

        Assert.Equal(firstResult.ProcessId, secondResult.ProcessId);
        Assert.Equal(session.ProcessId, firstResult.ProcessId);
        Assert.True(session.IsRunning);
        Assert.Equal(WorkerResponseCodes.Ready, firstResult.Response.Code);
        Assert.Equal(WorkerResponseCodes.Ready, secondResult.Response.Code);
        Assert.Equal(0, await session.CompleteAsync());
        Assert.False(IsProcessRunning(session.ProcessId));
    }

    private static async Task<ScenarioSummary> ExerciseMixedPauseResumeAndRetryAsync(string root)
    {
        Directory.CreateDirectory(root);
        string outputRoot = Path.Combine(root, "Signed");
        string singlePlan = CreatePlanJson(dual: false);
        string dualPlan = CreatePlanJson(dual: true);
        BatchItemRequest[] requests =
        [
            CreateRequest(root, outputRoot, "single-success", ".exe", singlePlan),
            CreateRequest(root, outputRoot, "already-signed", ".exe", singlePlan),
            CreateRequest(root, outputRoot, "ordinary-failure", ".exe", singlePlan),
            CreateRequest(root, outputRoot, "typed-nonexe", ".dll", singlePlan),
            CreateRequest(root, outputRoot, "provider-pause", ".exe", dualPlan),
            CreateRequest(root, outputRoot, "timestamp-pause", ".exe", singlePlan),
            CreateRequest(root, outputRoot, "misleading-success", ".exe", singlePlan),
            CreateRequest(root, outputRoot, "last-success", ".exe", singlePlan)
        ];
        var factory = new ScriptedWorkerFactory(processBacked: false);
        factory.Set("single-success", FakeOutcome.Success);
        factory.Set("already-signed", FakeOutcome.ExistingSignatureSkip);
        factory.Set("ordinary-failure", FakeOutcome.OrdinaryFailure, FakeOutcome.Success);
        factory.Set("provider-pause", FakeOutcome.ProviderPause, FakeOutcome.Success);
        factory.Set("timestamp-pause", FakeOutcome.TimestampPause, FakeOutcome.Success);
        factory.Set("misleading-success", FakeOutcome.MisleadingSuccess);
        factory.Set("last-success", FakeOutcome.Success);
        var batch = new SigningBatch(requests);
        await using var orchestrator = IntegrationTestBatchOrchestrators.Create(factory, TimeSpan.FromSeconds(5));

        await orchestrator.RunAsync(batch, CancellationToken.None);

        Assert.Equal(BatchItemState.Published, Item(batch, "single-success").State);
        Assert.Equal(BatchItemState.SkippedAlreadySigned, Item(batch, "already-signed").State);
        Assert.Equal(BatchItemState.Failed, Item(batch, "ordinary-failure").State);
        Assert.Equal(BatchItemState.Failed, Item(batch, "typed-nonexe").State);
        Assert.Equal(BatchItemState.PausedProvider, Item(batch, "provider-pause").State);
        Assert.Equal(BatchItemState.Pending, Item(batch, "timestamp-pause").State);
        Assert.Empty(factory.AttemptsFor("timestamp-pause"));
        Assert.Empty(factory.AttemptsFor("last-success"));
        Assert.Equal(1, factory.StartCount);
        Assert.True(factory.Sessions.Single().IsRunning);
        AssertNoStaging(root);

        await orchestrator.ResumeAsync(batch, retryFailed: true, CancellationToken.None);

        Assert.Equal(BatchItemState.Published, Item(batch, "ordinary-failure").State);
        Assert.Equal(BatchItemState.Failed, Item(batch, "typed-nonexe").State);
        Assert.Equal(BatchItemState.Published, Item(batch, "provider-pause").State);
        Assert.Equal(BatchItemState.PausedTimestamp, Item(batch, "timestamp-pause").State);
        Assert.Empty(factory.AttemptsFor("misleading-success"));
        Assert.Equal(1, factory.StartCount);
        Assert.True(factory.Sessions.Single().IsRunning);
        AssertNoStaging(root);

        await orchestrator.ResumeAsync(batch, retryFailed: false, CancellationToken.None);

        Assert.Equal(BatchItemState.Published, Item(batch, "timestamp-pause").State);
        Assert.Equal(BatchItemState.Failed, Item(batch, "misleading-success").State);
        Assert.Equal(BatchResultCode.MisleadingWorkerSuccess, Item(batch, "misleading-success").Receipt!.Code);
        Assert.Equal(BatchItemState.Published, Item(batch, "last-success").State);
        Assert.True(batch.IsComplete);
        Assert.False(batch.IsPaused);
        Assert.Equal(1, factory.StartCount);
        Assert.Equal(1, factory.MaxConcurrentCalls);
        Assert.False(factory.Sessions.Single().IsRunning);
        Assert.Empty(factory.AttemptsFor("typed-nonexe"));
        Assert.All(batch.Items, static item =>
        {
            Assert.NotNull(item.Receipt);
            Assert.Equal(item.State, item.Receipt!.State);
            Assert.NotEmpty(item.Receipts);
        });
        AssertFreshRetry(factory, "ordinary-failure");
        AssertFreshRetry(factory, "provider-pause");
        AssertFreshRetry(factory, "timestamp-pause");
        AssertOriginalsUnchanged(requests);
        AssertPublishedAndAbsentOutputs(batch);
        AssertNoStaging(root);

        return new ScenarioSummary(
            batch.Items.SelectMany(static item => item.StateHistory).Distinct().ToArray(),
            batch.Items.Count,
            factory.StartCount,
            factory.MaxConcurrentCalls);
    }

    private static async Task<ScenarioSummary> ExerciseCrashAndRestartAsync(string root)
    {
        Directory.CreateDirectory(root);
        string outputRoot = Path.Combine(root, "Signed");
        string singlePlan = CreatePlanJson(dual: false);
        BatchItemRequest crashRequest = CreateRequest(root, outputRoot, "worker-crash", ".exe", singlePlan);
        BatchItemRequest nextRequest = CreateRequest(root, outputRoot, "after-crash", ".exe", singlePlan);
        var factory = new ScriptedWorkerFactory(processBacked: false);
        factory.Set("worker-crash", FakeOutcome.Crash, FakeOutcome.Success);
        factory.Set("after-crash", FakeOutcome.Success);
        var batch = new SigningBatch([crashRequest, nextRequest]);
        await using var orchestrator = IntegrationTestBatchOrchestrators.Create(factory, TimeSpan.FromSeconds(5));

        await orchestrator.RunAsync(batch, CancellationToken.None);

        Assert.Equal(BatchItemState.Failed, Item(batch, "worker-crash").State);
        Assert.Equal(BatchResultCode.WorkerCrashed, Item(batch, "worker-crash").Receipt!.Code);
        Assert.Equal(BatchItemState.Published, Item(batch, "after-crash").State);
        Assert.Equal(2, factory.StartCount);
        AssertNoStaging(root);

        await orchestrator.ResumeAsync(batch, retryFailed: true, CancellationToken.None);

        Assert.Equal(BatchItemState.Published, Item(batch, "worker-crash").State);
        Assert.Equal(3, factory.StartCount);
        AssertFreshRetry(factory, "worker-crash");
        AssertOriginalsUnchanged([crashRequest, nextRequest]);
        AssertNoStaging(root);

        BatchItemRequest restartRequest = CreateRequest(root, outputRoot, "restart-dual", ".exe", CreatePlanJson(dual: true));
        var interrupted = new BatchItemSnapshot(
            restartRequest,
            BatchItemState.SigningSecondary,
            []);
        SigningBatch restored = SigningBatch.Restore([interrupted]);
        Assert.Equal(BatchItemState.Pending, Assert.Single(restored.Items).State);
        Assert.Equal(
            [BatchItemState.SigningSecondary, BatchItemState.Pending],
            Assert.Single(restored.Items).StateHistory);

        using Process staleOwner = Process.Start(new ProcessStartInfo("ping.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "127.0.0.1", "-n", "120" }
        }) ?? throw new InvalidOperationException("Could not start the restart owner fixture.");
        DateTimeOffset staleStart = staleOwner.StartTime.ToUniversalTime();
        string abandonedAttempt = TransactionalStaging.CreateAttemptDirectory(
            outputRoot,
            staleOwner.Id,
            staleStart);
        await File.WriteAllTextAsync(Path.Combine(abandonedAttempt, "payload.exe"), "partial");
        staleOwner.Kill(entireProcessTree: true);
        await staleOwner.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));

        var restartFactory = new ScriptedWorkerFactory(processBacked: false);
        restartFactory.Set("restart-dual", FakeOutcome.Success);
        await using var restartedOrchestrator = IntegrationTestBatchOrchestrators.Create(
            restartFactory,
            TimeSpan.FromSeconds(5));
        await restartedOrchestrator.RunAsync(restored, CancellationToken.None);

        Assert.Equal(1, restartedOrchestrator.LastRecoveryReceipt.RemovedAttemptCount);
        Assert.Equal(0, restartedOrchestrator.LastRecoveryReceipt.SkippedAttemptCount);
        Assert.False(Directory.Exists(abandonedAttempt));
        Assert.Equal(BatchItemState.Published, Assert.Single(restored.Items).State);
        Assert.Contains(BatchItemState.SigningSecondary, Assert.Single(restored.Items).StateHistory);
        AssertOriginalsUnchanged([restartRequest]);
        AssertNoStaging(root);

        return new ScenarioSummary(
            batch.Items.SelectMany(static item => item.StateHistory)
                .Concat(restored.Items.SelectMany(static item => item.StateHistory))
                .Distinct()
                .ToArray(),
            batch.Items.Count + restored.Items.Count,
            factory.StartCount + restartFactory.StartCount,
            Math.Max(factory.MaxConcurrentCalls, restartFactory.MaxConcurrentCalls));
    }

    private static async Task ExerciseCancellationAsync(string root, BatchItemState cancellationState)
    {
        Directory.CreateDirectory(root);
        string outputRoot = Path.Combine(root, "Signed");
        bool dual = cancellationState == BatchItemState.SigningSecondary;
        string plan = CreatePlanJson(dual);
        BatchItemRequest prelude = CreateRequest(root, outputRoot, "prelude", ".exe", CreatePlanJson(dual: false));
        BatchItemRequest target = CreateRequest(
            root,
            outputRoot,
            "target",
            ".exe",
            plan);
        BatchItemRequest tail = CreateRequest(root, outputRoot, "tail", ".exe", CreatePlanJson(dual: false));
        var factory = new ScriptedWorkerFactory(processBacked: true);
        factory.Set("prelude", FakeOutcome.Success);
        factory.Set(
            "target",
            cancellationState switch
            {
                BatchItemState.Failed => FakeOutcome.OrdinaryFailure,
                BatchItemState.PausedProvider => FakeOutcome.ProviderPause,
                BatchItemState.PausedTimestamp => FakeOutcome.TimestampPause,
                BatchItemState.SkippedAlreadySigned => FakeOutcome.ExistingSignatureSkip,
                _ => FakeOutcome.Success
            });
        factory.Set("tail", FakeOutcome.Success);
        var batch = new SigningBatch([prelude, target, tail]);
        await using var orchestrator = IntegrationTestBatchOrchestrators.Create(factory, TimeSpan.FromSeconds(5));
        using CancellationTokenSource cancellation = new();
        orchestrator.StateChanged += (_, args) =>
        {
            bool cancelForPending = cancellationState == BatchItemState.Pending &&
                args.Item.Request.ItemId == "prelude" && args.Item.State == BatchItemState.Published;
            bool cancelForTarget = args.Item.Request.ItemId == "target" &&
                args.Item.State == cancellationState &&
                cancellationState is not (BatchItemState.PausedProvider or BatchItemState.PausedTimestamp);
            if (cancelForPending || cancelForTarget)
            {
                cancellation.Cancel();
            }
        };

        await orchestrator.RunAsync(batch, cancellation.Token);
        if (cancellationState is BatchItemState.PausedProvider or BatchItemState.PausedTimestamp)
        {
            Assert.Equal(cancellationState, Item(batch, "target").State);
            await orchestrator.CancelAsync(batch);
        }

        BatchItem targetItem = Item(batch, "target");
        BatchItem tailItem = Item(batch, "tail");
        switch (cancellationState)
        {
            case BatchItemState.Published:
                Assert.Equal(BatchItemState.Published, targetItem.State);
                Assert.True(File.Exists(targetItem.Request.File.DestinationPath));
                Assert.Equal(targetItem.Request.File.DestinationPath, targetItem.Receipt?.DestinationPath, ignoreCase: true);
                break;
            case BatchItemState.SkippedAlreadySigned:
                Assert.Equal(BatchItemState.SkippedAlreadySigned, targetItem.State);
                Assert.False(File.Exists(targetItem.Request.File.DestinationPath));
                break;
            case BatchItemState.Failed:
                Assert.Equal(BatchItemState.Failed, targetItem.State);
                Assert.False(File.Exists(targetItem.Request.File.DestinationPath));
                break;
            default:
                Assert.Equal(BatchItemState.Cancelled, targetItem.State);
                Assert.Equal(BatchResultCode.Cancelled, targetItem.Receipt!.Code);
                Assert.False(File.Exists(targetItem.Request.File.DestinationPath));
                break;
        }

        Assert.Equal(BatchItemState.Cancelled, tailItem.State);
        Assert.Equal(BatchResultCode.Cancelled, tailItem.Receipt!.Code);
        AssertPublishedAndAbsentOutputs(batch);
        Assert.All(factory.Sessions, static session =>
        {
            Assert.False(session.IsRunning);
            Assert.False(IsProcessRunning(session.ProcessId));
            Assert.False(IsProcessRunning(session.ChildProcessId));
            Assert.InRange(session.TerminationDuration, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        });
        AssertOriginalsUnchanged([prelude, target, tail]);
        AssertNoStaging(root);
    }

    private static BatchItemRequest CreateRequest(
        string root,
        string outputRoot,
        string itemId,
        string extension,
        string signingPlanJson)
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

        string destinationPath = Path.GetFullPath(Path.Combine(outputRoot, itemId + extension));
        IntakeFile file = new(
            originalPath,
            itemId + extension,
            destinationPath,
            Path.GetFullPath(outputRoot),
            identity,
            new SignableSubject(SignableFileType.PortableExecutable, Guid.Empty));
        return new BatchItemRequest(itemId, file, signingPlanJson, OperationId: RunOperationId);
    }

    private static string CreatePlanJson(bool dual)
    {
        CertificateRef certificate = CertificateRef.TryCreate(
            CertificateStoreLocation.CurrentUser,
            "My",
            Thumbprint).Value ?? throw new InvalidOperationException("Could not create the test certificate reference.");
        SigningPlan plan = (dual
            ? SigningPlan.TryCreateDual(certificate, certificate, ".exe")
            : SigningPlan.TryCreateSingle(certificate, ".exe")).Value
            ?? throw new InvalidOperationException("Could not create the test signing plan.");
        return SigningPlanJson.Serialize(plan);
    }

    private static BatchItem Item(SigningBatch batch, string itemId) =>
        Assert.Single(batch.Items, item => string.Equals(item.Request.ItemId, itemId, StringComparison.Ordinal));

    private static void AssertFreshRetry(ScriptedWorkerFactory factory, string itemId)
    {
        AttemptObservation[] attempts = factory.AttemptsFor(itemId).ToArray();
        Assert.Equal(2, attempts.Length);
        Assert.NotEqual(attempts[0].StagedPath, attempts[1].StagedPath);
        Assert.All(attempts, attempt => Assert.Equal(attempt.OriginalSha256, attempt.InitialStagedSha256));
    }

    private static void AssertOriginalsUnchanged(IEnumerable<BatchItemRequest> requests)
    {
        foreach (BatchItemRequest request in requests)
        {
            string expected = Convert.ToHexString(SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes("original:" + request.ItemId)));
            Assert.Equal(expected, Hash(request.File.OriginalPath));
        }
    }

    private static void AssertPublishedAndAbsentOutputs(SigningBatch batch)
    {
        foreach (BatchItem item in batch.Items)
        {
            if (item.State == BatchItemState.Published)
            {
                Assert.True(File.Exists(item.Request.File.DestinationPath));
                Assert.Equal(item.Request.File.DestinationPath, item.Receipt?.DestinationPath, ignoreCase: true);
                Assert.Matches("^[0-9A-F]{64}$", item.Receipt!.PublishedSha256!);
            }
            else
            {
                Assert.False(File.Exists(item.Request.File.DestinationPath));
            }
        }
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
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string WorkerPath() => Path.Combine(
        FindRepositoryRoot(),
        "src",
        "CodeSigner.Worker",
        "bin",
#if DEBUG
        "Debug",
#else
        "Release",
#endif
        "net10.0-windows",
        "win-x64",
        "CodeSigner.Worker.exe");

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
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

    private static void WriteFormalArtifacts(
        ScenarioSummary mixed,
        ScenarioSummary crash,
        IReadOnlyList<BatchItemState> cancellationStates)
    {
        string evidenceRoot = Path.Combine(
            FindRepositoryRoot(),
            "artifacts",
            "evidence",
            "task-7-certum-code-signing-tool",
            "formal");
        Directory.CreateDirectory(evidenceRoot);
        JsonSerializerOptions json = new() { WriteIndented = true };
        File.WriteAllText(
            Path.Combine(evidenceRoot, "scenario-receipt.json"),
            JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                scenario = "todo-7-sequential-exe-batch-comprehensive",
                states = Enum.GetNames<BatchItemState>(),
                mixedItems = mixed.ItemCount,
                crashRestartItems = crash.ItemCount,
                cancellationPhases = cancellationStates.Select(static state => state.ToString()).ToArray(),
                persistentWorkerRequests = 2,
                maxConcurrentWorkerCalls = Math.Max(mixed.MaxConcurrentCalls, crash.MaxConcurrentCalls),
                normalFailureContinues = true,
                providerPauseResume = true,
                timestampPauseResume = true,
                retryFromOriginal = true,
                appRestartRecovery = true,
                childProcessTreeTermination = true,
                typedNonExeRejection = true,
                misleadingSuccessRejected = true,
                realProviderInteraction = false
            }, json));
        File.WriteAllText(
            Path.Combine(evidenceRoot, "cleanup-receipt.json"),
            JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                stagingResidueCount = 0,
                workerTreesRunning = 0,
                originalsChanged = 0,
                cancellationDeadlineSeconds = 5,
                cleanupVerified = true
            }, json));
    }

    private enum FakeOutcome
    {
        Success,
        OrdinaryFailure,
        ProviderPause,
        TimestampPause,
        ExistingSignatureSkip,
        MisleadingSuccess,
        Crash
    }

    private sealed record AttemptObservation(
        string StagedPath,
        string OriginalSha256,
        string InitialStagedSha256);

    private sealed record ScenarioSummary(
        IReadOnlyList<BatchItemState> ObservedStates,
        int ItemCount,
        int WorkerStarts,
        int MaxConcurrentCalls);

    private sealed class ScriptedWorkerFactory(bool processBacked) : IBatchWorkerSessionFactory
    {
        private readonly Dictionary<string, Queue<FakeOutcome>> scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, List<AttemptObservation>> attempts = new(StringComparer.Ordinal);
        private int activeCalls;

        public int StartCount { get; private set; }

        public int MaxConcurrentCalls { get; private set; }

        public List<ScriptedWorkerSession> Sessions { get; } = [];

        public void Set(string itemId, params FakeOutcome[] outcomes) =>
            scripts[itemId] = new Queue<FakeOutcome>(outcomes);

        public List<AttemptObservation> AttemptsFor(string itemId) =>
            attempts.TryGetValue(itemId, out List<AttemptObservation>? values) ? values : [];

        public async ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCount++;
            ProcessTreeFixture? tree = processBacked
                ? await ProcessTreeFixture.StartAsync()
                : null;
            var session = new ScriptedWorkerSession(this, 30000 + StartCount, tree);
            Sessions.Add(session);
            return session;
        }

        private async Task<WorkerResponse> ExecuteAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            Action<BatchWorkerPhase> reportProgress,
            CancellationToken cancellationToken)
        {
            int current = Interlocked.Increment(ref activeCalls);
            MaxConcurrentCalls = Math.Max(MaxConcurrentCalls, current);
            try
            {
                string itemId = Path.GetFileNameWithoutExtension(originalPath);
                if (!scripts.TryGetValue(itemId, out Queue<FakeOutcome>? outcomes) || outcomes.Count == 0)
                {
                    throw new InvalidOperationException("No fake worker outcome is configured for " + itemId + ".");
                }

                string originalHash = Hash(originalPath);
                string stagedHash = Hash(stagedPath);
                if (!attempts.TryGetValue(itemId, out List<AttemptObservation>? values))
                {
                    values = [];
                    attempts.Add(itemId, values);
                }

                values.Add(new AttemptObservation(stagedPath, originalHash, stagedHash));
                FakeOutcome outcome = outcomes.Dequeue();
                SigningPlan plan = SigningPlanJson.Parse(signingPlanJson).Value
                    ?? throw new InvalidOperationException("The fake worker received an invalid signing plan.");
                WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);
                if (outcome == FakeOutcome.ExistingSignatureSkip)
                {
                    return new WorkerResponse(
                        WorkerProtocol.Version,
                        true,
                        WorkerResponseCodes.SkippedExistingSignature,
                        0,
                        OriginalSha256: originalHash.ToLowerInvariant(),
                        StagedSha256: stagedHash.ToLowerInvariant(),
                        OperationId: "0123456789abcdef0123456789abcdef",
                        Subject: contract.Subject,
                        Capability: contract.Capability,
                        Engine: contract.Engine,
                        Verification: contract.Verification,
                        LegacyFallbackAttempted: false,
                        Outcome: WorkerSigningOutcome.SkippedExistingSignature,
                        Route: WorkerExecutionRoute.Skip);
                }

                reportProgress(BatchWorkerPhase.SigningPrimary);
                cancellationToken.ThrowIfCancellationRequested();
                if (outcome == FakeOutcome.Crash)
                {
                    File.AppendAllText(stagedPath, ":partial");
                    throw new WorkerProcessCrashedException();
                }

                if (outcome is FakeOutcome.OrdinaryFailure or FakeOutcome.ProviderPause or FakeOutcome.TimestampPause)
                {
                    string code = outcome switch
                    {
                        FakeOutcome.ProviderPause => WorkerResponseCodes.ProviderCancelled,
                        FakeOutcome.TimestampPause => WorkerResponseCodes.TimestampUnavailable,
                        _ => WorkerResponseCodes.NativeSigningFailed
                    };
                    return new WorkerResponse(
                        WorkerProtocol.Version,
                        false,
                        code,
                        unchecked((int)0x80004005),
                        FailedLegIndex: 0,
                        OriginalSha256: originalHash,
                        Subject: contract.Subject,
                        Capability: contract.Capability,
                        Engine: contract.Engine,
                        Verification: contract.Verification);
                }

                if (plan.Mode == SigningMode.Dual)
                {
                    reportProgress(BatchWorkerPhase.SigningSecondary);
                    cancellationToken.ThrowIfCancellationRequested();
                }

                File.AppendAllText(stagedPath, ":signed:" + values.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
                reportProgress(BatchWorkerPhase.Verifying);
                cancellationToken.ThrowIfCancellationRequested();
                if (outcome == FakeOutcome.MisleadingSuccess)
                {
                    return new WorkerResponse(
                        WorkerProtocol.Version,
                        true,
                        WorkerResponseCodes.SigningCompleted,
                        0,
                        OriginalSha256: new string('A', 64),
                        StagedSha256: new string('B', 64),
                        Subject: contract.Subject,
                        Capability: contract.Capability,
                        Engine: contract.Engine,
                        Verification: contract.Verification);
                }

                await Task.Yield();
                string candidateHash = Hash(stagedPath).ToLowerInvariant();
                return new WorkerResponse(
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
                    Route: WorkerExecutionRoute.ProductPe);
            }
            finally
            {
                Interlocked.Decrement(ref activeCalls);
            }
        }

        public sealed class ScriptedWorkerSession(
            ScriptedWorkerFactory owner,
            int fallbackProcessId,
            ProcessTreeFixture? processTree) : IBatchWorkerSession
        {
            private bool running = true;
            private bool disposed;

            public int ProcessId => processTree?.ParentProcessId ?? fallbackProcessId;

            public int ChildProcessId => processTree?.ChildProcessId ?? 0;

            public bool IsRunning => running;

            public TimeSpan TerminationDuration => processTree?.TerminationDuration ?? TimeSpan.Zero;

            public Task<WorkerResponse> SignAsync(
                string originalPath,
                string stagedPath,
                string signingPlanJson,
                Action<BatchWorkerPhase> reportProgress,
                TimeSpan timeout,
                CancellationToken cancellationToken)
            {
                if (!running)
                {
                    throw new WorkerProcessCrashedException();
                }

                return owner.ExecuteAsync(
                    originalPath,
                    stagedPath,
                    signingPlanJson,
                    reportProgress,
                    cancellationToken);
            }

            public async Task<int> CompleteAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await StopAsync();
                return 0;
            }

            public Task TerminateAsync() => StopAsync();

            public async ValueTask DisposeAsync()
            {
                if (disposed)
                {
                    return;
                }

                disposed = true;
                await StopAsync();
                if (processTree is not null)
                {
                    await processTree.DisposeAsync();
                }
            }

            private async Task StopAsync()
            {
                if (!running)
                {
                    return;
                }

                running = false;
                if (processTree is not null)
                {
                    await processTree.TerminateAsync();
                }
            }
        }
    }

    private sealed class FailingWorkerFactory : IBatchWorkerSessionFactory
    {
        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new IOException("injected worker launch failure");
        }
    }

    private sealed class CountingFailingWorkerFactory : IBatchWorkerSessionFactory
    {
        public int StartCount { get; private set; }

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCount++;
            throw new FileNotFoundException("worker launch fixture secret");
        }
    }

    private sealed class PostStartFailureFactory(string failureKind) : IBatchWorkerSessionFactory
    {
        public int StartCount { get; private set; }

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCount++;
            return ValueTask.FromResult<IBatchWorkerSession>(new Session(failureKind));
        }

        private sealed class Session(string failureKind) : IBatchWorkerSession
        {
            private bool running = true;

            public int ProcessId => 48000;
            public bool IsRunning => running;

            public Task<WorkerResponse> SignAsync(
                string originalPath,
                string stagedPath,
                string signingPlanJson,
                Action<BatchWorkerPhase> reportProgress,
                TimeSpan timeout,
                CancellationToken cancellationToken)
            {
                running = false;
                return failureKind switch
                {
                    "timeout" => Task.FromException<WorkerResponse>(new WorkerProcessTimeoutException()),
                    "protocol" => Task.FromException<WorkerResponse>(
                        new WorkerProtocolException(WorkerResponseCodes.InvalidFrame, "test protocol failure")),
                    _ => throw new InvalidOperationException("unknown post-start failure fixture")
                };
            }

            public Task<int> CompleteAsync(CancellationToken cancellationToken)
            {
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

    private sealed class ProcessTreeFixture : IAsyncDisposable
    {
        private readonly Process parent;
        private readonly WorkerJob job;
        private readonly int parentProcessId;
        private bool terminated;

        private ProcessTreeFixture(Process parent, WorkerJob job, int childProcessId)
        {
            this.parent = parent;
            this.job = job;
            parentProcessId = parent.Id;
            ChildProcessId = childProcessId;
        }

        public int ParentProcessId => parentProcessId;

        public int ChildProcessId { get; }

        public TimeSpan TerminationDuration { get; private set; }

        public static async Task<ProcessTreeFixture> StartAsync()
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
                ?? throw new InvalidOperationException("Could not start the fake worker tree.");
            WorkerJob job = WorkerJob.CreateKillOnClose();
            try
            {
                job.Assign(parent);
                await parent.StandardInput.WriteLineAsync(string.Empty);
                await parent.StandardInput.FlushAsync();
                string? childLine = await parent.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
                int childId = int.Parse(childLine!, System.Globalization.CultureInfo.InvariantCulture);
                return new ProcessTreeFixture(parent, job, childId);
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

        public async Task TerminateAsync()
        {
            if (terminated)
            {
                return;
            }

            terminated = true;
            Stopwatch stopwatch = Stopwatch.StartNew();
            job.Terminate(WorkerJob.TimeoutExitCode);
            await parent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            stopwatch.Stop();
            TerminationDuration = stopwatch.Elapsed;
        }

        public async ValueTask DisposeAsync()
        {
            if (!terminated)
            {
                await TerminateAsync();
            }

            parent.Dispose();
            job.Dispose();
        }
    }
}
