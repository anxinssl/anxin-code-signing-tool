using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using NativeSignatureLeg = CodeSigner.Windows.Signing.SignatureLeg;

namespace CodeSigner.IntegrationTests;

public sealed class ProductionWorkerWiringTests : IDisposable
{
    private static readonly JsonSerializerOptions EvidenceJsonOptions = new() { WriteIndented = true };

    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private const int NoInterfaceHResult = unchecked((int)0x80004002);
    private readonly string root = Path.Combine(Path.GetTempPath(), "CodeSigner-WorkerWiring-" + Guid.NewGuid().ToString("N"));

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidSignCommitsVerifiedBytesToOwnedStaging()
    {
        Attempt attempt = CreateAttempt();
        var signer = new FakeLegExecutor();
        var verifier = new FakeVerifier();
        IWorkerCommandHandler handler = CreateHandler(() => signer, () => verifier);

        WorkerResponse response = await handler.HandleAsync(CreateRequest(attempt), CancellationToken.None);

        Assert.True(response.Success);
        Assert.True(response.LegacyFallbackAttempted);
        Assert.Equal(WorkerResponseCodes.SigningCompleted, response.Code);
        Assert.Equal(WorkerSigningOutcome.Signed, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Null(response.Failure);
        Assert.Equal(0, response.HResult);
        Assert.Equal(OperationId, response.OperationId);
        Assert.Null(response.DiagnosticId);
        Assert.Equal(await HashAsync(attempt.OriginalPath), response.OriginalSha256);
        byte[] signedCandidate = [.. UnsignedPeFixture(), .. Encoding.UTF8.GetBytes(":fake-signed")];
        string candidateSha256 = Convert.ToHexString(SHA256.HashData(signedCandidate)).ToLowerInvariant();
        Assert.Equal(candidateSha256, response.StagedSha256);
        string strategyPath = Assert.IsType<string>(signer.Path);
        Assert.NotEqual(attempt.StagedPath, strategyPath);
        Assert.Equal(Path.GetDirectoryName(attempt.StagedPath), Path.GetDirectoryName(strategyPath));
        Assert.Equal(strategyPath, verifier.Path);
        Assert.Equal(NativeDigestAlgorithm.Sha256, Assert.Single(verifier.Plan!.Legs).FileDigest);
        Assert.True(signer.Disposed);
        Assert.True(verifier.Disposed);
        Assert.Equal(UnsignedPeFixture(), await File.ReadAllBytesAsync(attempt.OriginalPath));
        Assert.Equal(signedCandidate, await File.ReadAllBytesAsync(attempt.StagedPath));
        Assert.False(File.Exists(Path.Combine(root, "published.exe")));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task MisleadingNativeSuccessAndVerifierDisagreementFailClosed()
    {
        Attempt misleading = CreateAttempt();
        IWorkerCommandHandler misleadingHandler = CreateHandler(
            () => new FakeLegExecutor(new NativeSigningResult(
                true,
                NativeSigningReasonCode.None,
                unchecked((int)0x80004005))),
            () => new FakeVerifier());

        WorkerResponse misleadingResponse = await misleadingHandler.HandleAsync(
            CreateRequest(misleading),
            CancellationToken.None);

        Assert.False(misleadingResponse.Success);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, misleadingResponse.Code);

        Attempt disagreement = CreateAttempt();
        IWorkerCommandHandler disagreementHandler = CreateHandler(
            () => new FakeLegExecutor(),
            () => new FakeVerifier(NativeSigningResult.Failure(
                NativeSigningReasonCode.VerifierDisagreement,
                unchecked((int)0x800B0100))));

        WorkerResponse disagreementResponse = await disagreementHandler.HandleAsync(
            CreateRequest(disagreement),
            CancellationToken.None);

        Assert.False(disagreementResponse.Success);
        Assert.Equal(WorkerResponseCodes.VerifierDisagreement, disagreementResponse.Code);
        Assert.Equal(OperationId, disagreementResponse.OperationId);
        AssertLowerHexIdentifier(disagreementResponse.DiagnosticId);
        Assert.Equal(WorkerDiagnosticPhases.Verifying, disagreementResponse.DiagnosticPhase);
        Assert.Null(disagreementResponse.FailedLegIndex);
        Assert.Null(disagreementResponse.DiagnosticLeg);
        Assert.Null(disagreementResponse.DigestAlgorithm);
        Assert.Null(disagreementResponse.AppendSignature);
        Assert.Null(disagreementResponse.NativeCall);
        Assert.Null(disagreementResponse.SignerSignEx3Flags);
        Assert.Equal(NativeSigningReasonCode.VerifierDisagreement.ToString(), disagreementResponse.NativeReasonCode);
        Assert.Equal(WorkerHResultOrigins.Native, disagreementResponse.HResultOrigin);
    }

    [Theory]
    [InlineData(0, WorkerDiagnosticPhases.SigningPrimary, WorkerDiagnosticLegs.Primary, WorkerDigestAlgorithms.Sha1, false, 0)]
    [InlineData(1, WorkerDiagnosticPhases.SigningSecondary, WorkerDiagnosticLegs.Secondary, WorkerDigestAlgorithms.Sha256, true, 0x1000)]
    [Trait("Category", "SigningIntegration")]
    public async Task NativeLegFailureMapsExactV3Diagnostic(
        int failedLegIndex,
        string expectedPhase,
        string expectedLeg,
        string expectedDigest,
        bool expectedAppend,
        int expectedFlags)
    {
        Attempt attempt = CreateAttempt();
        var signer = new SequencedFailingLegExecutor(failedLegIndex);
        IWorkerCommandHandler handler = CreateHandler(() => signer, () => new FakeVerifier());

        WorkerResponse response = await handler.HandleAsync(
            CreateDualRequest(attempt),
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.True(response.LegacyFallbackAttempted);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
        Assert.Equal(NoInterfaceHResult, response.HResult);
        Assert.Equal(failedLegIndex, response.FailedLegIndex);
        Assert.Equal(OperationId, response.OperationId);
        AssertLowerHexIdentifier(response.DiagnosticId);
        Assert.Equal(expectedPhase, response.DiagnosticPhase);
        Assert.Equal(expectedLeg, response.DiagnosticLeg);
        Assert.Equal(expectedDigest, response.DigestAlgorithm);
        Assert.Equal(expectedAppend, response.AppendSignature);
        Assert.Equal(WorkerNativeCalls.SignerSignEx3, response.NativeCall);
        Assert.Equal(expectedFlags, response.SignerSignEx3Flags);
        Assert.Equal(NativeSigningReasonCode.NativeSigningFailed.ToString(), response.NativeReasonCode);
        Assert.Equal("E_NOINTERFACE", response.HResultSymbol);
        Assert.Equal(WorkerHResultOrigins.Native, response.HResultOrigin);
        Assert.NotNull(response.LegElapsedMilliseconds);
        Assert.True(response.LegElapsedMilliseconds >= 0);
        Assert.Equal(
            failedLegIndex == 0
                ? ["Sha1:False"]
                : ["Sha1:False", "Sha256:True"],
            signer.ObservedLegs);
        await AssertProtocolRoundTripAsync(response);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ManagedLegExceptionMapsManagedOriginWithoutClaimingNativeCall()
    {
        Attempt attempt = CreateAttempt();
        IWorkerCommandHandler handler = CreateHandler(() => new ThrowingLegExecutor(), () => new FakeVerifier());

        WorkerResponse response = await handler.HandleAsync(CreateDualRequest(attempt), CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerDiagnosticPhases.SigningPrimary, response.DiagnosticPhase);
        Assert.Equal(WorkerDiagnosticLegs.Primary, response.DiagnosticLeg);
        Assert.Equal(WorkerHResultOrigins.Managed, response.HResultOrigin);
        Assert.Null(response.NativeCall);
        Assert.Null(response.SignerSignEx3Flags);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task WorkerFactoryExceptionMapsBridgeOriginAndNoLeg()
    {
        Attempt attempt = CreateAttempt();
        IWorkerCommandHandler handler = CreateHandler(
            () => throw new PlatformNotSupportedException("synthetic bridge failure"),
            () => new FakeVerifier());

        WorkerResponse response = await handler.HandleAsync(CreateRequest(attempt), CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(OperationId, response.OperationId);
        AssertLowerHexIdentifier(response.DiagnosticId);
        Assert.Equal(WorkerDiagnosticPhases.WorkerBridge, response.DiagnosticPhase);
        Assert.Null(response.FailedLegIndex);
        Assert.Null(response.DiagnosticLeg);
        Assert.Equal(WorkerHResultOrigins.WorkerBridge, response.HResultOrigin);
    }

    [Fact]
    public async Task VersionOnePeerFrameFailsWithProtocolVersionMismatch()
    {
        const string versionOneJson = "{\"protocolVersion\":1,\"command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\"}";

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(
                new MemoryStream(Frame(versionOneJson)),
                CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.ProtocolVersionMismatch, error.Code);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task OriginalMutationIsReportedAndNeverPublished()
    {
        Attempt attempt = CreateAttempt();
        IWorkerCommandHandler handler = CreateHandler(
            () => new FakeLegExecutor(afterSign: () => File.AppendAllText(attempt.OriginalPath, "changed")),
            () => new FakeVerifier());

        WorkerResponse response = await handler.HandleAsync(CreateRequest(attempt), CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.OriginalChanged, response.Code);
        Assert.False(File.Exists(Path.Combine(root, "published.exe")));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task OwnerSpoofStaleOwnerAndInvalidPlanFailBeforeFactories()
    {
        Attempt attempt = CreateAttempt();
        int factoryCalls = 0;
        IWorkerCommandHandler handler = CreateHandler(
            () => { factoryCalls++; return new FakeLegExecutor(); },
            () => { factoryCalls++; return new FakeVerifier(); });
        WorkerRequest valid = CreateRequest(attempt);

        WorkerResponse spoofed = await handler.HandleAsync(
            valid with { StagingOwnerPid = int.MaxValue },
            CancellationToken.None);
        WorkerResponse stale = await handler.HandleAsync(
            valid with { StagingOwnerStartUtc = valid.StagingOwnerStartUtc.AddMinutes(-5) },
            CancellationToken.None);
        WorkerResponse invalidPlan = await handler.HandleAsync(
            valid with { SigningPlanJson = "{\"version\":1,\"providerArgs\":\"secret\"}" },
            CancellationToken.None);

        Assert.Equal(WorkerResponseCodes.InvalidStagingOwner, spoofed.Code);
        Assert.Equal(WorkerResponseCodes.InvalidStagingOwner, stale.Code);
        Assert.Equal(WorkerResponseCodes.InvalidSigningPlan, invalidPlan.Code);
        Assert.Equal(0, factoryCalls);
    }

    [Theory]
    [InlineData(ProductionSigningError.None, WorkerResponseCodes.SigningCompleted)]
    [InlineData(ProductionSigningError.InvalidInput, WorkerResponseCodes.InvalidInput)]
    [InlineData(ProductionSigningError.CertificateNotFound, WorkerResponseCodes.CertificateNotFound)]
    [InlineData(ProductionSigningError.CertificateHasNoPrivateKey, WorkerResponseCodes.CertificateHasNoPrivateKey)]
    [InlineData(ProductionSigningError.ProviderCancelled, WorkerResponseCodes.ProviderCancelled)]
    [InlineData(ProductionSigningError.TimestampUnavailable, WorkerResponseCodes.TimestampUnavailable)]
    [InlineData(ProductionSigningError.NativeSigningFailed, WorkerResponseCodes.NativeSigningFailed)]
    [InlineData(ProductionSigningError.VerifierDisagreement, WorkerResponseCodes.VerifierDisagreement)]
    [InlineData(ProductionSigningError.OriginalChanged, WorkerResponseCodes.OriginalChanged)]
    [InlineData(ProductionSigningError.Cancelled, WorkerResponseCodes.Cancelled)]
    public void EveryProductionSigningErrorMapsToExactWorkerCode(
        ProductionSigningError error,
        string expectedCode)
    {
        Type handlerType = LoadHandlerType();
        MethodInfo? map = handlerType.GetMethod(
            "FromReceipt",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(map);
        ProductionSigningReceipt receipt = new(
            error == ProductionSigningError.None,
            error,
            error == ProductionSigningError.None ? 0 : unchecked((int)0x80004005),
            error == ProductionSigningError.None ? new string('a', 64) : "AA",
            error == ProductionSigningError.None ? new string('b', 64) : null);

        SigningPlan plan = Assert.IsType<SigningPlan>(
            SigningPlan.TryCreateSingle(
                Assert.IsType<CertificateRef>(CertificateRef.TryCreate(
                    CertificateStoreLocation.CurrentUser,
                    "My",
                    Thumbprint).Value),
                ".exe").Value);
        WorkerResponse response = Assert.IsType<WorkerResponse>(map.Invoke(
            null,
            [receipt, OperationId, WorkerSigningContract.FromSigningPlan(plan)]));

        Assert.Equal(expectedCode, response.Code);
        Assert.Equal(error == ProductionSigningError.None, response.Success);
    }

    [Fact]
    public async Task BuiltWorkerRejectsInvalidPlanThenMissingCapabilityBeforeStagingOwnerInspection()
    {
        Attempt attempt = CreateAttempt();
        WorkerProcessClient client = new(WorkerExecutablePath(), static (_, _) => { });
        WorkerRequest valid = CreateRequest(attempt);

        WorkerProcessResult invalidPlan = await client.SendAsync(
            valid with { SigningPlanJson = "{}" },
            TimeSpan.FromSeconds(5),
            CancellationToken.None);
        WorkerProcessResult spoofedOwner = await client.SendAsync(
            valid with { StagingOwnerPid = int.MaxValue },
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.Equal(WorkerResponseCodes.InvalidSigningPlan, invalidPlan.Response.Code);
        Assert.Null(invalidPlan.Response.OperationId);
        Assert.Null(invalidPlan.Response.Outcome);
        Assert.Null(invalidPlan.Response.Route);
        Assert.Null(invalidPlan.Response.Failure);
        Assert.Equal(WorkerResponseCodes.InvalidStagingOwner, spoofedOwner.Response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, spoofedOwner.Response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, spoofedOwner.Response.Route);
        Assert.Equal(WorkerFailureCode.InvalidStagingOwner, spoofedOwner.Response.Failure);
        Assert.Equal(2, invalidPlan.ExitCode);
        Assert.Equal(2, spoofedOwner.ExitCode);
    }

    [Fact]
    public async Task BatchSessionReceivesExactSdkSnapshotFromBatchItemRequest()
    {
        Attempt attempt = CreateAttempt();
        SigningPlan plan = CreateSinglePlan();
        WorkerSdkFallback fallback = EnabledSdkFallback();
        string outputRoot = Path.Combine(root, "batch-output");
        using var originalStream = new FileStream(
            attempt.OriginalPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        StableFileIdentity identity = WindowsFileIdentity.FromHandle(originalStream.SafeFileHandle);
        var file = new IntakeFile(
            attempt.OriginalPath,
            Path.GetFileName(attempt.OriginalPath),
            Path.Combine(outputRoot, Path.GetFileName(attempt.OriginalPath)),
            outputRoot,
            identity,
            new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()));
        var factory = new SdkCapturingWorkerFactory();
        await using var orchestrator = new SequentialBatchOrchestrator(
            factory,
            TimeSpan.FromSeconds(5),
            runtimeEventSink: null,
            diagnosticRuntimeEventSink: null);
        var batch = new SigningBatch(
            [new BatchItemRequest(
                "sdk-item",
                file,
                SigningPlanJson.Serialize(plan),
                OperationId: OperationId,
                SdkFallback: fallback)]);

        SigningBatch completed = await orchestrator.RunAsync(batch, CancellationToken.None);

        Assert.Equal(fallback, factory.ObservedSdkFallback);
        BatchItem item = Assert.Single(completed.Items);
        Assert.Equal(BatchItemState.Failed, item.State);
        Assert.Equal(BatchResultCode.WorkerFailure, Assert.IsType<BatchItemReceipt>(item.Receipt).Code);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task DisabledSdkSessionMakesZeroLocatorOrSdkCallsAfterEligiblePrimaryFailure()
    {
        Attempt attempt = CreateAttempt();
        var dependencies = new SdkWorkerDependencies(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                NoInterfaceHResult));
        IWorkerCommandHandler handler = CreateSdkSessionHandler(dependencies);

        WorkerResponse response = await handler.HandleAsync(
            CreateRequest(attempt) with { SdkFallback = WorkerSdkFallback.Disabled },
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
        Assert.Equal(0, dependencies.LocatorFactoryCalls);
        Assert.Equal(0, dependencies.LocatorRevalidationCalls);
        Assert.Equal(0, dependencies.SdkProcessStarts);
        Assert.Equal(1, dependencies.PeEngineFactoryCalls);
        Assert.Equal(1, dependencies.VerifierFactoryCalls);
        Assert.Equal(0, dependencies.PublicationCalls);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidProductPeWithExactSdkCandidateReturnsOriginalPeFailureWithoutSdkFallback()
    {
        Attempt attempt = CreateAttempt();
        var dependencies = new SdkWorkerDependencies(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                NoInterfaceHResult));
        IWorkerCommandHandler handler = CreateSdkSessionHandler(dependencies);

        WorkerResponse response = await handler.HandleAsync(
            CreateRequest(attempt) with { SdkFallback = EnabledSdkFallback() },
            CancellationToken.None);

        WriteRoutingCounterEvidence(
            "product-pe-sdk-candidate-failure",
            response,
            new
            {
                dependencies.PeEngineFactoryCalls,
                dependencies.VerifierFactoryCalls,
                dependencies.LocatorFactoryCalls,
                dependencies.LocatorDiscoveryCalls,
                dependencies.LocatorRevalidationCalls,
                dependencies.SdkLeaseCalls,
                dependencies.SdkExecutorFactoryCalls,
                dependencies.SdkSigningCalls,
                dependencies.SdkProcessStarts,
                dependencies.SipBridgeFactoryCalls,
                dependencies.InspectorFactoryCalls,
                publicationCalls = dependencies.PublicationCalls
            });

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
        Assert.Equal(NoInterfaceHResult, response.HResult);
        Assert.False(response.LegacyFallbackAttempted);
        Assert.Equal(1, dependencies.PeEngineFactoryCalls);
        Assert.Equal(1, dependencies.VerifierFactoryCalls);
        Assert.Equal(0, dependencies.LocatorFactoryCalls);
        Assert.Equal(0, dependencies.LocatorDiscoveryCalls);
        Assert.Equal(0, dependencies.LocatorRevalidationCalls);
        Assert.Equal(0, dependencies.SdkLeaseCalls);
        Assert.Equal(0, dependencies.SdkExecutorFactoryCalls);
        Assert.Equal(0, dependencies.SdkSigningCalls);
        Assert.Equal(0, dependencies.SdkProcessStarts);
        Assert.Equal(0, dependencies.SipBridgeFactoryCalls);
        Assert.Equal(1, dependencies.InspectorFactoryCalls);
        Assert.Equal(0, dependencies.PublicationCalls);
        Assert.Empty(dependencies.Events);
        Assert.Null(dependencies.SelectedCandidateIdentity);
        await AssertProtocolRoundTripAsync(response);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidProductPeWithExactSdkCandidateSignsWithoutSdkFallback()
    {
        Attempt attempt = CreateAttempt();
        var dependencies = new SdkWorkerDependencies(NativeSigningResult.Success());
        IWorkerCommandHandler handler = CreateSdkSessionHandler(dependencies);

        WorkerResponse response = await handler.HandleAsync(
            CreateRequest(attempt) with { SdkFallback = EnabledSdkFallback() },
            CancellationToken.None);

        WriteRoutingCounterEvidence(
            "product-pe-sdk-candidate-success",
            response,
            new
            {
                dependencies.PeEngineFactoryCalls,
                dependencies.VerifierFactoryCalls,
                dependencies.LocatorFactoryCalls,
                dependencies.LocatorDiscoveryCalls,
                dependencies.LocatorRevalidationCalls,
                dependencies.SdkLeaseCalls,
                dependencies.SdkExecutorFactoryCalls,
                dependencies.SdkSigningCalls,
                dependencies.SdkProcessStarts,
                dependencies.SipBridgeFactoryCalls,
                dependencies.InspectorFactoryCalls,
                publicationCalls = dependencies.PublicationCalls
            });

        Assert.True(response.Success);
        Assert.Equal(WorkerResponseCodes.SigningCompleted, response.Code);
        Assert.Equal(WorkerSigningOutcome.Signed, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Null(response.Failure);
        Assert.Equal(0, response.HResult);
        Assert.False(response.LegacyFallbackAttempted);
        Assert.Equal(1, dependencies.PeEngineFactoryCalls);
        Assert.Equal(1, dependencies.VerifierFactoryCalls);
        Assert.Equal(1, dependencies.InspectorFactoryCalls);
        Assert.Equal(1, dependencies.PublicationCalls);
        Assert.Equal(0, dependencies.LocatorFactoryCalls);
        Assert.Equal(0, dependencies.LocatorDiscoveryCalls);
        Assert.Equal(0, dependencies.LocatorRevalidationCalls);
        Assert.Equal(0, dependencies.SdkLeaseCalls);
        Assert.Equal(0, dependencies.SdkExecutorFactoryCalls);
        Assert.Equal(0, dependencies.SdkSigningCalls);
        Assert.Equal(0, dependencies.SdkProcessStarts);
        Assert.Equal(0, dependencies.SipBridgeFactoryCalls);
        Assert.Empty(dependencies.Events);
        Assert.Null(dependencies.SelectedCandidateIdentity);
        await AssertProtocolRoundTripAsync(response);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidProductPeCandidateIgnoresCandidateDriftAndReturnsOriginalPeFailure()
    {
        Attempt attempt = CreateAttempt();
        var dependencies = new SdkWorkerDependencies(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                NoInterfaceHResult))
        {
            CandidateChanged = true
        };
        IWorkerCommandHandler handler = CreateSdkSessionHandler(dependencies);

        WorkerResponse response = await handler.HandleAsync(
            CreateRequest(attempt) with { SdkFallback = EnabledSdkFallback() },
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
        Assert.Equal(NoInterfaceHResult, response.HResult);
        Assert.False(response.LegacyFallbackAttempted);
        Assert.Equal(0, dependencies.LocatorFactoryCalls);
        Assert.Equal(0, dependencies.LocatorDiscoveryCalls);
        Assert.Equal(0, dependencies.LocatorRevalidationCalls);
        Assert.Equal(0, dependencies.SdkLeaseCalls);
        Assert.Equal(0, dependencies.SdkExecutorFactoryCalls);
        Assert.Equal(0, dependencies.SdkSigningCalls);
        Assert.Equal(0, dependencies.SdkProcessStarts);
        Assert.Equal(1, dependencies.PeEngineFactoryCalls);
        Assert.Equal(1, dependencies.VerifierFactoryCalls);
        Assert.Equal(1, dependencies.InspectorFactoryCalls);
        Assert.Equal(0, dependencies.SipBridgeFactoryCalls);
        Assert.Equal(0, dependencies.PublicationCalls);
        Assert.Empty(dependencies.Events);
        Assert.Null(dependencies.SelectedCandidateIdentity);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidProductPeCandidateReturnsNativeFailureWithoutEligibilityOrFallback()
    {
        Attempt attempt = CreateAttempt();
        var dependencies = new SdkWorkerDependencies(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.NativeSigningFailed,
                unchecked((int)0x80004005)));
        IWorkerCommandHandler handler = CreateSdkSessionHandler(dependencies);

        WorkerResponse response = await handler.HandleAsync(
            CreateRequest(attempt) with { SdkFallback = EnabledSdkFallback() },
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
        Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
        Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
        Assert.Equal(unchecked((int)0x80004005), response.HResult);
        Assert.False(response.LegacyFallbackAttempted);
        Assert.Equal(0, dependencies.LocatorFactoryCalls);
        Assert.Equal(0, dependencies.LocatorDiscoveryCalls);
        Assert.Equal(0, dependencies.LocatorRevalidationCalls);
        Assert.Equal(0, dependencies.SdkLeaseCalls);
        Assert.Equal(0, dependencies.SdkExecutorFactoryCalls);
        Assert.Equal(0, dependencies.SdkSigningCalls);
        Assert.Equal(0, dependencies.SdkProcessStarts);
        Assert.Equal(1, dependencies.PeEngineFactoryCalls);
        Assert.Equal(1, dependencies.VerifierFactoryCalls);
        Assert.Equal(1, dependencies.InspectorFactoryCalls);
        Assert.Equal(0, dependencies.SipBridgeFactoryCalls);
        Assert.Equal(0, dependencies.PublicationCalls);
        Assert.Empty(dependencies.Events);
        Assert.Null(dependencies.SelectedCandidateIdentity);
    }

    [Theory]
    [InlineData("contradictory")]
    [InlineData("malformed-version")]
    [Trait("Category", "SigningIntegration")]
    public async Task MalformedSdkSessionInputFailsBeforeLocatorOrSdkCalls(string mutation)
    {
        Attempt attempt = CreateAttempt();
        var dependencies = new SdkWorkerDependencies(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                NoInterfaceHResult));
        IWorkerCommandHandler handler = CreateSdkSessionHandler(dependencies);
        WorkerSdkFallback fallback = mutation switch
        {
            "contradictory" => new WorkerSdkFallback(false, EnabledSdkFallback().Candidate),
            "malformed-version" => new WorkerSdkFallback(
                true,
                EnabledSdkFallback().Candidate! with { SdkVersion = "10.0" }),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown mutation.")
        };

        WorkerResponse response = await handler.HandleAsync(
            CreateRequest(attempt) with { SdkFallback = fallback },
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.InvalidInput, response.Code);
        Assert.Equal(0, dependencies.LocatorFactoryCalls);
        Assert.Equal(0, dependencies.LocatorRevalidationCalls);
        Assert.Equal(0, dependencies.SdkProcessStarts);
        Assert.Equal(0, dependencies.PeEngineFactoryCalls);
        Assert.Equal(0, dependencies.VerifierFactoryCalls);
        Assert.Equal(0, dependencies.PublicationCalls);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private Attempt CreateAttempt()
    {
        Directory.CreateDirectory(root);
        string originalPath = Path.Combine(root, Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(originalPath, UnsignedPeFixture());
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string stagedPath = Path.Combine(attemptDirectory, "payload.exe");
        File.Copy(originalPath, stagedPath);
        return new Attempt(originalPath, stagedPath);
    }

    private Attempt CreateSipAttempt()
    {
        Directory.CreateDirectory(root);
        string originalPath = Path.Combine(root, Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(originalPath, "Write-Output 'isolated'\r\n");
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string stagedPath = Path.Combine(attemptDirectory, "payload.ps1");
        File.Copy(originalPath, stagedPath);
        return new Attempt(originalPath, stagedPath);
    }

    private static WorkerRequest CreateRequest(Attempt attempt)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        SigningPlan plan = Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, ".exe").Value);
        using Process owner = Process.GetCurrentProcess();
        return new WorkerRequest(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(plan),
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
            OperationId);
    }

    private static WorkerRequest CreateDualRequest(Attempt attempt)
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.LocalMachine, "My", SecondaryThumbprint).Value);
        SigningPlan plan = Assert.IsType<SigningPlan>(SigningPlan.TryCreateDual(primary, secondary, ".exe").Value);
        using Process owner = Process.GetCurrentProcess();
        return new WorkerRequest(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(plan),
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
            OperationId);
    }

    private static WorkerRequest CreateSipRequest(Attempt attempt)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        SigningPlan plan = Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, ".ps1").Value);
        using Process owner = Process.GetCurrentProcess();
        return new WorkerRequest(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(plan),
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
            OperationId);
    }

    private static SigningPlan CreateSinglePlan()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, ".exe").Value);
    }

    private static WorkerSdkFallback EnabledSdkFallback() => new(
        true,
        new WorkerSdkCandidateIdentity(
            Path.GetFullPath(
                "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe"),
            "10.0.26100.0",
            "10.0.26100.7463",
            "Microsoft Corporation",
            "Microsoft Corporation",
            "Microsoft® Windows® Operating System",
            new string('a', 64)));

    private static IWorkerCommandHandler CreateHandler(
        Func<INativeSigningLegExecutor> signerFactory,
        Func<IProductionSignedFileVerifier> verifierFactory)
    {
        Type handlerType = LoadHandlerType();
        return Assert.IsAssignableFrom<IWorkerCommandHandler>(
            Activator.CreateInstance(
                handlerType,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args:
                [
                    signerFactory,
                    verifierFactory,
                    (Action<WorkerProcessIdentity, WorkerProcessIdentity>)WorkerProcessLaunchPolicy.Validate,
                    IntegrationTestSecureFileCommitter.Instance
                ],
                culture: null));
    }

    private static IWorkerCommandHandler CreateSdkSessionHandler(SdkWorkerDependencies dependencies)
    {
        Type handlerType = LoadHandlerType();
        return Assert.IsAssignableFrom<IWorkerCommandHandler>(
            Activator.CreateInstance(
                handlerType,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args:
                [
                    (Func<IPeAuthenticodeSigningEngine>)(() => dependencies.CreatePeEngine()),
                    (Func<IProductionSignedFileVerifier>)(() => dependencies.CreateVerifier()),
                    (Func<ITrustedSdkSignToolLocator>)(() => dependencies.CreateLocator()),
                    (Func<ITrustedSdkSignToolLocator, IProductionSignedFileVerifier, ITrustedSdkSignToolExecutor>)
                        ((locator, verifier) => dependencies.CreateSdkExecutor(locator, verifier)),
                    (Func<IWindowsSipSigningBridge>)dependencies.CreateSipBridge,
                    (Func<IExistingSignatureInspector>)dependencies.CreateInspector,
                    (Action<WorkerProcessIdentity, WorkerProcessIdentity>)WorkerProcessLaunchPolicy.Validate,
                    dependencies.Committer
                ],
                culture: null));
    }

    private static void WriteRoutingCounterEvidence(string scenario, WorkerResponse response, object counters)
    {
        string? phase = Environment.GetEnvironmentVariable("CODESIGNER_TASK5_B2_COUNTER_PHASE");
        string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_TASK5_B2_EVIDENCE_DIR");
        if (string.IsNullOrWhiteSpace(phase) || string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            return;
        }

        string canonicalDirectory = Path.GetFullPath(evidenceDirectory);
        Directory.CreateDirectory(canonicalDirectory);
        File.WriteAllText(
            Path.Combine(canonicalDirectory, $"routing-counters-{phase}-{scenario}.json"),
            JsonSerializer.Serialize(
                new
                {
                    scenario,
                    response.Code,
                    outcome = response.Outcome?.ToString(),
                    route = response.Route?.ToString(),
                    failure = response.Failure?.ToString(),
                    response.HResult,
                    legacyFallbackAttempted = response.LegacyFallbackAttempted,
                    counters
                },
                EvidenceJsonOptions));
    }

    private static Type LoadHandlerType()
    {
        Assembly workerAssembly = Assembly.LoadFrom(WorkerAssemblyPath());
        return workerAssembly.GetType(
            "CodeSigner.Worker.ProductionSigningWorkerCommandHandler",
            throwOnError: true)!;
    }

    private static string WorkerAssemblyPath() => Path.Combine(
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
        "CodeSigner.Worker.dll");

    private static string WorkerExecutablePath() => Path.ChangeExtension(WorkerAssemblyPath(), ".exe");

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

    private static async Task<string> HashAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
    }

    private static StableFileIdentity ReadIdentity(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
    }

    private static bool IsProcessRunning(int processId)
    {
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

    private static byte[] Frame(string json)
    {
        byte[] payload = Encoding.UTF8.GetBytes(json);
        byte[] frame = new byte[WorkerProtocol.HeaderBytes + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(WorkerProtocol.HeaderBytes));
        return frame;
    }

    private static byte[] UnsignedPeFixture() => File.ReadAllBytes(Path.Combine(
        FindRepositoryRoot(),
        "tests",
        "fixtures",
        "generated",
        "valid-unsigned.exe"));

    private static void AssertLowerHexIdentifier(string? value)
    {
        Assert.NotNull(value);
        Assert.Equal(32, value.Length);
        Assert.All(value, character => Assert.True(character is >= '0' and <= '9' or >= 'a' and <= 'f'));
    }

    private static async Task AssertProtocolRoundTripAsync(WorkerResponse response)
    {
        using var frame = new MemoryStream();
        await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);
        frame.Position = 0;
        Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(frame, CancellationToken.None));
    }

    private sealed record Attempt(string OriginalPath, string StagedPath);

    private sealed class SdkCapturingWorkerFactory : IBatchWorkerSessionFactory
    {
        public WorkerSdkFallback? ObservedSdkFallback { get; private set; }

        public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IBatchWorkerSession>(new Session(this));
        }

        private sealed class Session(SdkCapturingWorkerFactory owner) : IBatchWorkerSession
        {
            public int ProcessId => Environment.ProcessId;

            public bool IsRunning => true;

            public Task<WorkerResponse> SignAsync(
                string originalPath,
                string stagedPath,
                string signingPlanJson,
                Action<BatchWorkerPhase> reportProgress,
                TimeSpan timeout,
                CancellationToken cancellationToken) => Task.FromResult(
                    Failure(signingPlanJson, operationId: null));

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
                owner.ObservedSdkFallback = sdkFallback;
                return Task.FromResult(new BatchWorkerSigningResult(
                    Failure(signingPlanJson, operationId),
                    WorkerStderrTail: null,
                    WorkerStderrTruncated: false));
            }

            public Task<int> CompleteAsync(CancellationToken cancellationToken) => Task.FromResult(2);

            public Task TerminateAsync() => Task.CompletedTask;

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;

            private static WorkerResponse Failure(string signingPlanJson, string? operationId)
            {
                WorkerSigningContract contract = WorkerSigningContract.FromSigningPlanJson(signingPlanJson);
                return new WorkerResponse(
                    WorkerProtocol.Version,
                    false,
                    WorkerResponseCodes.SdkStartFailed,
                    unchecked((int)0x80004005),
                    OperationId: operationId,
                    Subject: contract.Subject,
                    Capability: contract.Capability,
                    Engine: contract.Engine,
                    Verification: contract.Verification,
                    LegacyFallbackAttempted: false,
                    Outcome: WorkerSigningOutcome.Failure,
                    Route: WorkerExecutionRoute.SdkSignTool,
                    Failure: WorkerFailureCode.SdkStartFailed);
            }
        }
    }

    private sealed class SdkWorkerDependencies(NativeSigningResult primaryResult)
    {
        private readonly CountingSecureFileCommitter committer =
            new(IntegrationTestSecureFileCommitter.Instance);

        public int PeEngineFactoryCalls { get; private set; }

        public bool CandidateChanged { get; set; }

        public int LocatorFactoryCalls { get; private set; }

        public int VerifierFactoryCalls { get; private set; }

        public int LocatorDiscoveryCalls { get; private set; }

        public int LocatorRevalidationCalls { get; private set; }

        public int SdkLeaseCalls { get; private set; }

        public int SdkProcessStarts { get; private set; }

        public int SipBridgeFactoryCalls { get; private set; }

        public int InspectorFactoryCalls { get; private set; }

        public int SdkExecutorFactoryCalls { get; private set; }

        public int SdkSigningCalls { get; private set; }

        public int PublicationCalls => committer.CommitCalls;

        public ISecureFileCommitter Committer => committer;

        public List<string> Events { get; } = [];

        public WorkerSdkCandidateIdentity? SelectedCandidateIdentity { get; private set; }

        public FailingPeEngine CreatePeEngine()
        {
            PeEngineFactoryCalls++;
            return new FailingPeEngine(primaryResult);
        }

        public FakeVerifier CreateVerifier()
        {
            VerifierFactoryCalls++;
            return new FakeVerifier();
        }

        public ITrustedSdkSignToolLocator CreateLocator()
        {
            LocatorFactoryCalls++;
            return new Locator(this);
        }

        public SdkExecutor CreateSdkExecutor(
            ITrustedSdkSignToolLocator locator,
            IProductionSignedFileVerifier verifier)
        {
            SdkExecutorFactoryCalls++;
            return new SdkExecutor(this, locator);
        }

        public IWindowsSipSigningBridge CreateSipBridge()
        {
            SipBridgeFactoryCalls++;
            throw new InvalidOperationException("SIP bridge must remain isolated from the SDK route.");
        }

        public UnsignedInspector CreateInspector()
        {
            InspectorFactoryCalls++;
            return new UnsignedInspector();
        }

        private sealed class Locator(SdkWorkerDependencies owner) : ITrustedSdkSignToolLocator
        {
            public SdkSignToolDiscoveryResult Discover()
            {
                owner.LocatorDiscoveryCalls++;
                throw new InvalidOperationException("Worker session fallback must never discover another candidate.");
            }

            public SdkSignToolDiscoveryResult Revalidate(TrustedSdkSignToolCandidate candidate)
            {
                owner.LocatorRevalidationCalls++;
                owner.Events.Add("revalidate");
                return owner.CandidateChanged
                    ? SdkSignToolDiscoveryResult.Rejected(
                        SdkSignToolRejectionReason.CandidateChanged,
                        candidate.Path)
                    : SdkSignToolDiscoveryResult.Available(candidate);
            }
        }

        public sealed class SdkExecutor(
            SdkWorkerDependencies owner,
            ITrustedSdkSignToolLocator locator) : ITrustedSdkSignToolExecutor
        {
            public Task<SdkSignToolFallbackResult> ExecuteAsync(
                TrustedSdkSignToolCandidate selectedCandidate,
                SdkSignToolFallbackEligibility eligibility,
                string originalPath,
                string failedStagedPath,
                ProductionNativeSigningPlan plan,
                int stagingOwnerPid,
                DateTimeOffset stagingOwnerStartUtc,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                owner.SdkSigningCalls++;
                owner.SelectedCandidateIdentity = new WorkerSdkCandidateIdentity(
                    selectedCandidate.Path,
                    selectedCandidate.SdkVersion.ToString(4),
                    selectedCandidate.ProductVersion.ToString(4),
                    selectedCandidate.Publisher,
                    selectedCandidate.CompanyName,
                    selectedCandidate.ProductName,
                    selectedCandidate.Sha256.ToLowerInvariant());
                owner.SdkLeaseCalls++;
                SdkSignToolDiscoveryResult revalidation = locator.Revalidate(selectedCandidate);
                if (!revalidation.IsAvailable)
                {
                    return Task.FromResult(SdkSignToolFallbackResult.Failure(
                        SdkSignToolFallbackError.CandidateChanged,
                        Hash(originalPath)));
                }

                owner.Events.Add("process-start");
                owner.SdkProcessStarts++;
                string freshStage = Path.Combine(
                    Path.GetDirectoryName(failedStagedPath)!,
                    $".codesigner-sdk-worker-test-{Guid.NewGuid():N}.exe");
                File.Copy(originalPath, freshStage);
                File.AppendAllText(freshStage, ":sdk-signed");
                return Task.FromResult(new SdkSignToolFallbackResult(
                    true,
                    SdkSignToolFallbackError.None,
                    Hash(originalPath),
                    Hash(freshStage),
                    freshStage,
                    []));
            }

            private static string Hash(string path) =>
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        }
    }

    private sealed class CountingSecureFileCommitter(ISecureFileCommitter inner) : ISecureFileCommitter
    {
        private int commitCalls;

        public bool IsAvailable => inner.IsAvailable;

        public int CommitCalls => Volatile.Read(ref commitCalls);

        public Task<SecureFileCommitReceipt> CommitAsync(
            SecureFileCommitRequest request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref commitCalls);
            return inner.CommitAsync(request, cancellationToken);
        }
    }

    private sealed class UnsignedInspector : IExistingSignatureInspector
    {
        public ExistingSignatureInspectionResult Inspect(
            string originalPath,
            string stagedPath,
            SigningPlan plan,
            CancellationToken cancellationToken) => new(
                ExistingSignatureInspectionStatus.Unsigned,
                unchecked((int)0x800B0100));
    }

    private sealed class FailingPeEngine(
        NativeSigningResult result,
        Action? onExecute = null) : IPeAuthenticodeSigningEngine
    {
        public Task<NativeSigningResult> ExecuteAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            nint providerWindowHandle,
            CancellationToken cancellationToken) => ExecuteAsync(
                stagedPath,
                plan,
                stagingOwnerPid,
                stagingOwnerStartUtc,
                providerWindowHandle,
                static (_, _) => ValueTask.CompletedTask,
                cancellationToken);

        public async Task<NativeSigningResult> ExecuteAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            nint providerWindowHandle,
            Func<int, CancellationToken, ValueTask> reportLeg,
            CancellationToken cancellationToken)
        {
            onExecute?.Invoke();
            for (int index = 0; index < plan.Legs.Count; index++)
            {
                await reportLeg(index, cancellationToken);
            }

            File.AppendAllText(stagedPath, ":failed-product-pe");
            return result;
        }
    }

    private sealed class FakeLegExecutor(
        NativeSigningResult? result = null,
        Action? afterSign = null) : INativeSigningLegExecutor, IDisposable
    {
        public string? Path { get; private set; }

        public bool Disposed { get; private set; }

        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            NativeSignatureLeg leg,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Path = path;
            File.AppendAllText(path, ":fake-signed");
            afterSign?.Invoke();
            return Task.FromResult(result ?? NativeSigningResult.Success());
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class SequencedFailingLegExecutor(int failedLegIndex) : INativeSigningLegExecutor
    {
        private int callCount;

        public List<string> ObservedLegs { get; } = [];

        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            NativeSignatureLeg leg,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int index = callCount++;
            ObservedLegs.Add($"{leg.FileDigest}:{leg.Append}");
            return Task.FromResult(index == failedLegIndex
                ? NativeSigningResult.Failure(NativeSigningReasonCode.NativeSigningFailed, NoInterfaceHResult)
                : NativeSigningResult.Success());
        }
    }

    private sealed class ThrowingLegExecutor : INativeSigningLegExecutor
    {
        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            NativeSignatureLeg leg,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("synthetic managed leg failure");
    }

    private sealed class FakeVerifier(NativeSigningResult? result = null) : IProductionSignedFileVerifier, IDisposable
    {
        public string? Path { get; private set; }

        public ProductionNativeSigningPlan? Plan { get; private set; }

        public bool Disposed { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Path = stagedPath;
            Plan = plan;
            return Task.FromResult(result ?? NativeSigningResult.Success());
        }

        public void Dispose() => Disposed = true;
    }
}
