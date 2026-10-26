using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class Todo7ProductionRoutingTests
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
    private const string RunOperationId = "0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task MixedPeAndSipRowsPublishPeToRequestedDestinationAndRefuseSip()
    {
        using TestTree tree = new();
        string peOriginal = tree.Write("input/pe-row.exe", "pe-pristine");
        string sipOriginal = tree.Write("input/sip-row.ps1", "sip-pristine\r\n");
        string outputRoot = tree.PathOf("out");
        IntakePlan intake = await Planner().CreateAsync(
            [peOriginal, sipOriginal],
            recurseDirectories: false,
            outputRoot,
            CancellationToken.None);
        SigningPlan pePlan = Plan(".exe", SigningMode.Dual);
        SigningPlan sipPlan = Plan(".ps1", SigningMode.Dual);
        var worker = new RoutingWorkerFactory();
        var batch = new SigningBatch(
        [
            Request("pe-row", intake.Files.Single(file => file.OriginalPath == peOriginal), pePlan),
            Request("sip-row", intake.Files.Single(file => file.OriginalPath == sipOriginal), sipPlan)
        ]);
        await using var orchestrator = TestBatchOrchestrators.Create(worker, TimeSpan.FromSeconds(5));

        await orchestrator.RunAsync(batch, CancellationToken.None);

        BatchItem pe = batch.Items.Single(item => item.Request.ItemId == "pe-row");
        BatchItem sip = batch.Items.Single(item => item.Request.ItemId == "sip-row");
        Assert.Equal(BatchItemState.Published, pe.State);
        Assert.Equal(BatchItemState.Failed, sip.State);
        Assert.Equal(
            [BatchWorkerPhase.SigningPrimary, BatchWorkerPhase.SigningSecondary, BatchWorkerPhase.Verifying],
            worker.Phases["pe-row"]);
        Assert.Empty(worker.Phases["sip-row"]);
        Assert.True(File.Exists(pe.Request.File.DestinationPath));
        Assert.False(File.Exists(sip.Request.File.DestinationPath));
        Assert.Equal("pe-pristine", await File.ReadAllTextAsync(peOriginal));
        Assert.Equal("sip-pristine\r\n", await File.ReadAllTextAsync(sipOriginal));
        AssertWorkerContract(pe, pePlan);
        AssertSipContract(sip, sipPlan);
    }

    [Fact]
    public async Task FailureMatrixPreservesEveryOriginalAndLeavesEveryDestinationAbsent()
    {
        using TestTree tree = new();
        FailureScenario[] scenarios =
        [
            new("eligible-sdk-fallback-failed", ".exe", FailureKind.SecondaryNoInterface, BatchResultCode.WorkerFailure),
            new("missing-sdk", ".exe", FailureKind.MissingSdk, BatchResultCode.WorkerFailure),
            new("invalid-sdk", ".exe", FailureKind.InvalidSdk, BatchResultCode.WorkerFailure),
            new("missing-sip", ".ps1", FailureKind.MissingSip, BatchResultCode.WorkerFailure),
            new("cancelled", ".exe", FailureKind.Cancelled, BatchResultCode.Cancelled),
            new("timed-out", ".exe", FailureKind.TimedOut, BatchResultCode.WorkerTimedOut),
            new("original-mutation", ".exe", FailureKind.OriginalMutation, BatchResultCode.OriginalChanged),
            new("verifier-disagreement", ".exe", FailureKind.VerifierDisagreement, BatchResultCode.WorkerFailure)
        ];
        string outputRoot = tree.PathOf("out");
        var requests = new List<BatchItemRequest>();
        var originalBytes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (FailureScenario scenario in scenarios)
        {
            string original = tree.Write(
                $"input/{scenario.ItemId}{scenario.Extension}",
                $"pristine-{scenario.ItemId}");
            IntakePlan intake = await Planner().CreateAsync(
                [original],
                recurseDirectories: false,
                outputRoot,
                CancellationToken.None);
            SigningPlan plan = Plan(scenario.Extension, SigningMode.Dual);
            requests.Add(Request(scenario.ItemId, Assert.Single(intake.Files), plan));
            originalBytes.Add(scenario.ItemId, await File.ReadAllBytesAsync(original));
        }

        var worker = new RoutingWorkerFactory(scenarios.ToDictionary(
            static scenario => scenario.ItemId,
            static scenario => scenario.Failure,
            StringComparer.Ordinal));
        var batch = new SigningBatch(requests);
        await using var orchestrator = TestBatchOrchestrators.Create(worker, TimeSpan.FromMilliseconds(250));

        await orchestrator.RunAsync(batch, CancellationToken.None);

        foreach (FailureScenario scenario in scenarios)
        {
            BatchItem item = batch.Items.Single(candidate => candidate.Request.ItemId == scenario.ItemId);
            Assert.Equal(
                scenario.ExpectedCode == BatchResultCode.Cancelled ? BatchItemState.Cancelled : BatchItemState.Failed,
                item.State);
            Assert.Equal(scenario.ExpectedCode, item.Receipt!.Code);
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(originalBytes[scenario.ItemId])),
                item.Receipt.OriginalSha256,
                ignoreCase: true);
            Assert.Equal(originalBytes[scenario.ItemId], await File.ReadAllBytesAsync(item.Request.File.OriginalPath));
            Assert.False(File.Exists(item.Request.File.DestinationPath));
        }

        Assert.Empty(Directory.Exists(outputRoot)
            ? Directory.GetDirectories(outputRoot, ".codesigner-staging-*", SearchOption.TopDirectoryOnly)
            : []);
    }

    private static void AssertWorkerContract(BatchItem item, SigningPlan plan)
    {
        WorkerResponse response = Assert.IsType<WorkerResponse>(item.Receipt!.SigningDiagnostic);
        WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);
        Assert.True(response.Success);
        Assert.Equal(WorkerResponseCodes.SigningCompleted, response.Code);
        Assert.Equal(contract.Subject, response.Subject);
        Assert.Equal(contract.Capability, response.Capability);
        Assert.Equal(contract.Engine, response.Engine);
        Assert.Equal(contract.Verification, response.Verification);
        Assert.Equal(Hash(item.Request.File.OriginalPath), response.OriginalSha256, ignoreCase: true);
        Assert.Equal(item.Receipt.PublishedSha256, response.StagedSha256, ignoreCase: true);
        Assert.Equal(item.Request.File.DestinationPath, item.Receipt.DestinationPath, ignoreCase: true);
        Assert.True(File.Exists(item.Receipt.DestinationPath));
        Assert.Equal(WorkerSigningOutcome.Signed, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
    }

    private static void AssertSipContract(BatchItem item, SigningPlan plan)
    {
        WorkerResponse response = Assert.IsType<WorkerResponse>(item.Receipt!.SigningDiagnostic);
        WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);
        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.WindowsSipUnavailable, response.Code);
        Assert.Equal(contract.Subject, response.Subject);
        Assert.Equal(contract.Capability, response.Capability);
        Assert.Equal(contract.Engine, response.Engine);
        Assert.Equal(contract.Verification, response.Verification);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.WindowsSip, response.Route);
        Assert.Equal(WorkerFailureCode.WindowsSipUnavailable, response.Failure);
    }

    private static BatchItemRequest Request(string itemId, IntakeFile file, SigningPlan plan) =>
        new(itemId, file, SigningPlanJson.Serialize(plan), OperationId: RunOperationId);

    private static SigningPlan Plan(string extension, SigningMode mode)
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", PrimaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.LocalMachine, "My", SecondaryThumbprint).Value);
        PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(extension);
        Assert.True(subject.IsSuccess);
        return Assert.IsType<SigningPlan>(mode == SigningMode.Dual
            ? SigningPlan.TryCreateDual(primary, secondary, subject.Value).Value
            : SigningPlan.TryCreateSingle(primary, subject.Value).Value);
    }

    private static IntakePlanner Planner() => new(new PolicySubjectProbe());

    private static string Hash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private sealed class PolicySubjectProbe : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path)
        {
            PolicyResult<SigningSubject> result = SigningSubject.TryCreateForExtension(Path.GetExtension(path));
            return new SignableSubject(
                Assert.IsType<SigningSubject>(result.Value),
                Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee"),
                scriptProfile: null);
        }
    }

    private enum FailureKind
    {
        None,
        SecondaryNoInterface,
        MissingSdk,
        InvalidSdk,
        MissingSip,
        Cancelled,
        TimedOut,
        OriginalMutation,
        VerifierDisagreement
    }

    private sealed record FailureScenario(
        string ItemId,
        string Extension,
        FailureKind Failure,
        BatchResultCode ExpectedCode);

    private sealed class RoutingWorkerFactory(
        IReadOnlyDictionary<string, FailureKind>? failures = null) : IBatchWorkerSessionFactory
    {
        private readonly IReadOnlyDictionary<string, FailureKind> failures = failures
            ?? new Dictionary<string, FailureKind>(StringComparer.Ordinal);

        public Dictionary<string, List<BatchWorkerPhase>> Phases { get; } = new(StringComparer.Ordinal);

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IBatchWorkerSession>(new Session(this));
        }

        private sealed class Session(RoutingWorkerFactory owner) : IBatchWorkerSession
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
                string itemId = Path.GetFileNameWithoutExtension(originalPath);
                owner.Phases[itemId] = [];
                void Report(BatchWorkerPhase phase)
                {
                    owner.Phases[itemId].Add(phase);
                    reportProgress(phase);
                }

                PolicyResult<SigningPlan> parsed = SigningPlanJson.Parse(signingPlanJson);
                SigningPlan plan = Assert.IsType<SigningPlan>(parsed.Value);
                WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);
                string originalHash = Hash(originalPath);
                owner.failures.TryGetValue(itemId, out FailureKind failure);
                if (contract.Engine == WorkerEngines.WindowsSip)
                {
                    return SipUnavailable(originalHash, contract);
                }

                Report(BatchWorkerPhase.SigningPrimary);
                if (failure == FailureKind.TimedOut)
                {
                    throw new WorkerProcessTimeoutException();
                }

                if (failure == FailureKind.OriginalMutation)
                {
                    try
                    {
                        await File.AppendAllTextAsync(originalPath, "|mutation", cancellationToken);
                    }
                    catch (IOException)
                    {
                    }

                    return Failure(WorkerResponseCodes.OriginalChanged, originalHash, contract);
                }

                if (failure == FailureKind.Cancelled)
                {
                    return Failure(WorkerResponseCodes.Cancelled, originalHash, contract);
                }

                if (failure == FailureKind.MissingSip)
                {
                    return Failure(WorkerResponseCodes.WindowsSipUnavailable, originalHash, contract);
                }

                if (plan.EffectiveMode == SigningMode.Dual)
                {
                    Report(BatchWorkerPhase.SigningSecondary);
                }

                if (failure == FailureKind.SecondaryNoInterface)
                {
                    return Failure(
                        WorkerResponseCodes.NativeSigningFailed,
                        originalHash,
                        contract,
                        hResult: unchecked((int)0x80004002),
                        diagnosticPhase: WorkerDiagnosticPhases.SigningSecondary);
                }

                if (failure is FailureKind.MissingSdk or FailureKind.InvalidSdk)
                {
                    return Failure(WorkerResponseCodes.NativeSigningFailed, originalHash, contract);
                }

                await File.AppendAllTextAsync(
                    stagedPath,
                    plan.Subject.Capability == SigningCapability.PeImageDualCapable
                        ? "|verified-pe"
                        : "|verified-sip",
                    cancellationToken);
                Report(BatchWorkerPhase.Verifying);
                if (failure == FailureKind.VerifierDisagreement)
                {
                    return Failure(
                        WorkerResponseCodes.VerifierDisagreement,
                        originalHash,
                        contract,
                        diagnosticPhase: WorkerDiagnosticPhases.Verifying);
                }

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

            private static WorkerResponse Failure(
                string code,
                string originalHash,
                WorkerSigningContract contract,
                int hResult = unchecked((int)0x80004005),
                string diagnosticPhase = WorkerDiagnosticPhases.WorkerBridge) => new(
                    WorkerProtocol.Version,
                    false,
                    code,
                    hResult,
                    OriginalSha256: originalHash,
                    DiagnosticId: Guid.NewGuid().ToString("N"),
                    DiagnosticPhase: diagnosticPhase,
                    HResultOrigin: WorkerHResultOrigins.WorkerBridge,
                    Subject: contract.Subject,
                    Capability: contract.Capability,
                    Engine: contract.Engine,
                    Verification: contract.Verification);

            private static WorkerResponse SipUnavailable(
                string originalHash,
                WorkerSigningContract contract) => new(
                    WorkerProtocol.Version,
                    false,
                    WorkerResponseCodes.WindowsSipUnavailable,
                    OriginalSha256: originalHash.ToLowerInvariant(),
                    OperationId: RunOperationId,
                    Subject: contract.Subject,
                    Capability: contract.Capability,
                    Engine: contract.Engine,
                    Verification: contract.Verification,
                    LegacyFallbackAttempted: false,
                    Outcome: WorkerSigningOutcome.Failure,
                    Route: WorkerExecutionRoute.WindowsSip,
                    Failure: WorkerFailureCode.WindowsSipUnavailable);
        }
    }
}
