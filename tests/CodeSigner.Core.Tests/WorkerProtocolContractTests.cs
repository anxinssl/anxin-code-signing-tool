using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;

namespace CodeSigner.Core.Tests;

public sealed class WorkerProtocolContractTests
{
    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private const string PublicationCandidateSha256 =
        "2222222222222222222222222222222222222222222222222222222222222222";

    public static TheoryData<WorkerExecutionRoute> SuccessfulRoutes => new()
    {
        WorkerExecutionRoute.ProductPe,
        WorkerExecutionRoute.SdkSignTool,
        WorkerExecutionRoute.WindowsSip
    };

    private static readonly WorkerFailureCode[] ProductPeFailures =
    [
        WorkerFailureCode.HandlerFailure,
        WorkerFailureCode.InvalidSigningPlan,
        WorkerFailureCode.SubjectCapabilityMismatch,
        WorkerFailureCode.InvalidStagingOwner,
        WorkerFailureCode.InvalidInput,
        WorkerFailureCode.UnsupportedFileType,
        WorkerFailureCode.CertificateNotFound,
        WorkerFailureCode.CertificateHasNoPrivateKey,
        WorkerFailureCode.ProviderCancelled,
        WorkerFailureCode.TimestampUnavailable,
        WorkerFailureCode.NativeSigningFailed,
        WorkerFailureCode.VerifierDisagreement,
        WorkerFailureCode.OriginalChanged,
        WorkerFailureCode.Cancelled,
        WorkerFailureCode.ExistingSignatureRejected
    ];

    private static readonly WorkerFailureCode[] SdkSignToolFailures =
    [
        WorkerFailureCode.InvalidInput,
        WorkerFailureCode.OriginalChanged,
        WorkerFailureCode.Cancelled,
        WorkerFailureCode.SdkCandidateChanged,
        WorkerFailureCode.SdkStartFailed,
        WorkerFailureCode.SdkTimedOut,
        WorkerFailureCode.SdkExitFailed,
        WorkerFailureCode.SdkVerificationFailed
    ];

    private static readonly WorkerFailureCode[] WindowsSipFailures =
    [
        WorkerFailureCode.HandlerFailure,
        WorkerFailureCode.InvalidSigningPlan,
        WorkerFailureCode.SubjectCapabilityMismatch,
        WorkerFailureCode.InvalidStagingOwner,
        WorkerFailureCode.InvalidInput,
        WorkerFailureCode.UnsupportedFileType,
        WorkerFailureCode.CertificateNotFound,
        WorkerFailureCode.CertificateHasNoPrivateKey,
        WorkerFailureCode.ProviderCancelled,
        WorkerFailureCode.TimestampUnavailable,
        WorkerFailureCode.NativeSigningFailed,
        WorkerFailureCode.VerifierDisagreement,
        WorkerFailureCode.OriginalChanged,
        WorkerFailureCode.Cancelled,
        WorkerFailureCode.WindowsPowerShellUnavailable,
        WorkerFailureCode.WindowsPowerShellExecutionDenied,
        WorkerFailureCode.WindowsSipUnavailable,
        WorkerFailureCode.PackageIncompatible,
        WorkerFailureCode.CertificateMismatch,
        WorkerFailureCode.ExistingSignatureRejected,
        WorkerFailureCode.InvalidBridgeResponse
    ];

    public static TheoryData<WorkerFailureCode> SdkFailures => TheoryDataFor(
        WorkerFailureCode.SdkCandidateChanged,
        WorkerFailureCode.SdkStartFailed,
        WorkerFailureCode.SdkTimedOut,
        WorkerFailureCode.SdkExitFailed,
        WorkerFailureCode.SdkVerificationFailed);

    public static TheoryData<WorkerFailureCode> EveryFailureCode
    {
        get
        {
            var data = new TheoryData<WorkerFailureCode>();
            foreach (WorkerFailureCode failure in Enum.GetValues<WorkerFailureCode>())
            {
                data.Add(failure);
            }

            return data;
        }
    }

    public static TheoryData<WorkerExecutionRoute, WorkerFailureCode> CompatibleRouteFailurePairs =>
        RouteFailurePairs(includeCompatible: true);

    public static TheoryData<WorkerExecutionRoute, WorkerFailureCode> ImpossibleRouteFailurePairs =>
        RouteFailurePairs(includeCompatible: false);

    [Fact]
    public async Task V4EnabledSdkFallbackRoundTripsExactCandidateIdentity()
    {
        WorkerSdkCandidateIdentity candidate = Candidate();
        WorkerRequest request = Request(new WorkerSdkFallback(true, candidate));
        using MemoryStream frame = new();

        await WorkerProtocol.WriteRequestAsync(frame, request, CancellationToken.None);

        using JsonDocument document = ReadPayload(frame);
        Assert.Equal(4, WorkerProtocol.Version);
        JsonElement sdkFallback = document.RootElement.GetProperty("sdkFallback");
        Assert.Equal(["enabled", "candidate"], sdkFallback.EnumerateObject().Select(property => property.Name));
        Assert.True(sdkFallback.GetProperty("enabled").GetBoolean());
        Assert.Equal(
            ["path", "sdkVersion", "productVersion", "publisher", "companyName", "productName", "sha256"],
            sdkFallback.GetProperty("candidate").EnumerateObject().Select(property => property.Name));
        frame.Position = 0;
        Assert.Equal(request, await WorkerProtocol.ReadRequestAsync(frame, CancellationToken.None));
    }

    [Fact]
    public async Task V4DisabledSdkFallbackRoundTripsWithoutCandidate()
    {
        WorkerRequest request = Request(WorkerSdkFallback.Disabled);
        using MemoryStream frame = new();

        await WorkerProtocol.WriteRequestAsync(frame, request, CancellationToken.None);

        using JsonDocument document = ReadPayload(frame);
        JsonElement sdkFallback = document.RootElement.GetProperty("sdkFallback");
        Assert.False(sdkFallback.GetProperty("enabled").GetBoolean());
        Assert.Equal(JsonValueKind.Null, sdkFallback.GetProperty("candidate").ValueKind);
        frame.Position = 0;
        Assert.Equal(request, await WorkerProtocol.ReadRequestAsync(frame, CancellationToken.None));
    }

    [Theory]
    [MemberData(nameof(SuccessfulRoutes))]
    public async Task SignedOutcomeRoundTripsEveryExecutionRoute(WorkerExecutionRoute route)
    {
        WorkerResponse response = SigningResponse(
            success: true,
            WorkerResponseCodes.SigningCompleted,
            WorkerSigningOutcome.Signed,
            route,
            failure: null);

        Assert.Equal(response, await RoundTripAsync(response));
    }

    [Fact]
    public async Task ExistingSignatureSkipHasAuthoritativeSkipOutcomeAndRoute()
    {
        WorkerResponse response = SigningResponse(
            success: true,
            WorkerResponseCodes.SkippedExistingSignature,
            WorkerSigningOutcome.SkippedExistingSignature,
            WorkerExecutionRoute.Skip,
            failure: null);

        Assert.Equal(response, await RoundTripAsync(response));
    }

    [Theory]
    [MemberData(nameof(SdkFailures))]
    public async Task NormalizedSdkFailureRoundTrips(WorkerFailureCode failure)
    {
        WorkerResponse response = SigningResponse(
            success: false,
            WorkerProtocol.FailureCodeFor(failure),
            WorkerSigningOutcome.Failure,
            WorkerExecutionRoute.SdkSignTool,
            failure);

        Assert.Equal(response, await RoundTripAsync(response));
    }

    [Theory]
    [MemberData(nameof(CompatibleRouteFailurePairs))]
    public async Task EveryCompatibleRouteFailurePairRoundTrips(
        WorkerExecutionRoute route,
        WorkerFailureCode failure)
    {
        WorkerResponse response = SigningResponse(
            success: false,
            WorkerProtocol.FailureCodeFor(failure),
            WorkerSigningOutcome.Failure,
            route,
            failure);

        Assert.Equal(response, await RoundTripAsync(response));
    }

    [Theory]
    [MemberData(nameof(ImpossibleRouteFailurePairs))]
    public async Task EveryImpossibleRouteFailurePairIsRejected(
        WorkerExecutionRoute route,
        WorkerFailureCode failure)
    {
        WorkerResponse response = SigningResponse(
            success: false,
            WorkerProtocol.FailureCodeFor(failure),
            WorkerSigningOutcome.Failure,
            route,
            failure);

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => RoundTripAsync(response));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    [Theory]
    [MemberData(nameof(EveryFailureCode))]
    public async Task SuccessfulResponseRejectsEveryFailure(WorkerFailureCode failure)
    {
        WorkerExecutionRoute route = RepresentativeRouteFor(failure);
        WorkerResponse response = SigningResponse(
            success: true,
            WorkerProtocol.FailureCodeFor(failure),
            WorkerSigningOutcome.Failure,
            route,
            failure);

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => RoundTripAsync(response));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    [Fact]
    public async Task CancellationFailureRoundTripsWithoutUnknownEnumFallback()
    {
        WorkerResponse response = SigningResponse(
            success: false,
            WorkerResponseCodes.Cancelled,
            WorkerSigningOutcome.Failure,
            WorkerExecutionRoute.ProductPe,
            WorkerFailureCode.Cancelled);

        Assert.Equal(response, await RoundTripAsync(response));

        JsonObject unknown = ResponseJson(response);
        unknown["failure"] = "future_failure";
        await AssertInvalidResponseAsync(unknown);
    }

    [Fact]
    public async Task StrictRequestParsingRejectsContradictoryOldExtraAndCallerAuthorityFields()
    {
        JsonObject enabledWithoutCandidate = RequestJson(new WorkerSdkFallback(true, Candidate()));
        enabledWithoutCandidate["sdkFallback"]!["candidate"] = null;
        JsonObject disabledWithCandidate = RequestJson(WorkerSdkFallback.Disabled);
        disabledWithCandidate["sdkFallback"]!["candidate"] = JsonSerializer.SerializeToNode(Candidate());
        JsonObject oldVersion = RequestJson(WorkerSdkFallback.Disabled);
        oldVersion["protocolVersion"] = 3;
        JsonObject extraNested = RequestJson(new WorkerSdkFallback(true, Candidate()));
        extraNested["sdkFallback"]!["candidate"]!["authorization"] = true;
        JsonObject callerAlreadySigned = RequestJson(WorkerSdkFallback.Disabled);
        callerAlreadySigned["alreadySigned"] = true;

        await AssertInvalidRequestAsync(enabledWithoutCandidate);
        await AssertInvalidRequestAsync(disabledWithCandidate);
        WorkerProtocolException stale = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => ReadRequestAsync(oldVersion));
        Assert.Equal(WorkerResponseCodes.ProtocolVersionMismatch, stale.Code);
        await AssertInvalidRequestAsync(extraNested);
        await AssertInvalidRequestAsync(callerAlreadySigned);
        Assert.DoesNotContain(
            typeof(WorkerRequest).GetProperties(),
            property => string.Equals(property.Name, "AlreadySigned", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StrictResponseParsingRejectsContradictoryOldExtraAndUnknownEnums()
    {
        WorkerResponse signed = SigningResponse(
            true,
            WorkerResponseCodes.SigningCompleted,
            WorkerSigningOutcome.Signed,
            WorkerExecutionRoute.ProductPe,
            null);
        JsonObject contradictory = ResponseJson(signed);
        contradictory["route"] = "skip";
        JsonObject oldVersion = ResponseJson(signed);
        oldVersion["protocolVersion"] = 3;
        JsonObject extra = ResponseJson(signed);
        extra["authoritative"] = true;
        JsonObject unknownOutcome = ResponseJson(signed);
        unknownOutcome["outcome"] = "future_outcome";
        JsonObject numericRoute = ResponseJson(signed);
        numericRoute["route"] = 0;

        await AssertInvalidResponseAsync(contradictory);
        WorkerProtocolException stale = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => ReadResponseAsync(oldVersion));
        Assert.Equal(WorkerResponseCodes.ProtocolVersionMismatch, stale.Code);
        await AssertInvalidResponseAsync(extra);
        await AssertInvalidResponseAsync(unknownOutcome);
        await AssertInvalidResponseAsync(numericRoute);
    }

    [Fact]
    public async Task RemovedPublicationResponseFieldsAreRejectedAsUnknownFields()
    {
        WorkerResponse signed = SigningResponse(
            true,
            WorkerResponseCodes.SigningCompleted,
            WorkerSigningOutcome.Signed,
            WorkerExecutionRoute.ProductPe,
            null);
        foreach (string field in new[]
        {
            "protected" + "ResultPath",
            "candidate" + "Sha256",
            "caller" + "Sid",
            "job" + "Id",
            "receipt" + "Sha256"
        })
        {
            JsonObject enriched = ResponseJson(signed);
            enriched[field] = "obsolete";
            await AssertInvalidResponseAsync(enriched);
        }
    }

    private static WorkerRequest Request(WorkerSdkFallback sdkFallback) => new(
        WorkerProtocol.Version,
        WorkerCommands.Sign,
        "C:\\input\\fixture.exe",
        "C:\\stage\\fixture.exe",
        CreateSigningPlanJson(),
        1234,
        new DateTimeOffset(2026, 7, 29, 0, 0, 0, TimeSpan.Zero),
        OperationId,
        WorkerSubjects.PeImage,
        WorkerCapabilities.PeImageDualCapable,
        WorkerEngines.PeImage,
        WorkerVerifications.PeImage,
        sdkFallback);

    private static TheoryData<WorkerFailureCode> TheoryDataFor(params WorkerFailureCode[] failures)
    {
        var data = new TheoryData<WorkerFailureCode>();
        foreach (WorkerFailureCode failure in failures)
        {
            data.Add(failure);
        }

        return data;
    }

    private static TheoryData<WorkerExecutionRoute, WorkerFailureCode> RouteFailurePairs(bool includeCompatible)
    {
        var data = new TheoryData<WorkerExecutionRoute, WorkerFailureCode>();
        foreach (WorkerExecutionRoute route in Enum.GetValues<WorkerExecutionRoute>())
        {
            foreach (WorkerFailureCode failure in Enum.GetValues<WorkerFailureCode>())
            {
                if (IsCompatible(route, failure) == includeCompatible)
                {
                    data.Add(route, failure);
                }
            }
        }

        return data;
    }

    private static bool IsCompatible(WorkerExecutionRoute route, WorkerFailureCode failure) => route switch
    {
        WorkerExecutionRoute.ProductPe => ProductPeFailures.Contains(failure),
        WorkerExecutionRoute.SdkSignTool => SdkSignToolFailures.Contains(failure),
        WorkerExecutionRoute.WindowsSip => WindowsSipFailures.Contains(failure),
        WorkerExecutionRoute.Skip => false,
        _ => false
    };

    private static WorkerExecutionRoute RepresentativeRouteFor(WorkerFailureCode failure)
    {
        foreach (WorkerExecutionRoute route in Enum.GetValues<WorkerExecutionRoute>())
        {
            if (IsCompatible(route, failure))
            {
                return route;
            }
        }

        return WorkerExecutionRoute.ProductPe;
    }

    private static WorkerSdkCandidateIdentity Candidate() => new(
        "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe",
        "10.0.26100.0",
        "10.0.26100.7463",
        "Microsoft Windows",
        "Microsoft Corporation",
        "Microsoft Windows Operating System",
        new string('a', 64));

    private static WorkerResponse SigningResponse(
        bool success,
        string code,
        WorkerSigningOutcome outcome,
        WorkerExecutionRoute route,
        WorkerFailureCode? failure) => new(
            WorkerProtocol.Version,
            success,
            code,
            OriginalSha256: success && route == WorkerExecutionRoute.ProductPe
                ? new string('1', 64)
                : null,
            StagedSha256: success && route == WorkerExecutionRoute.ProductPe
                ? PublicationCandidateSha256
                : null,
            OperationId: OperationId,
            Subject: route == WorkerExecutionRoute.WindowsSip
                ? WorkerSubjects.WindowsInstaller
                : WorkerSubjects.PeImage,
            Capability: route == WorkerExecutionRoute.WindowsSip
                ? WorkerCapabilities.WindowsSipSingleOnly
                : WorkerCapabilities.PeImageDualCapable,
            Engine: route == WorkerExecutionRoute.WindowsSip
                ? WorkerEngines.WindowsSip
                : WorkerEngines.PeImage,
            Verification: route == WorkerExecutionRoute.WindowsSip
                ? WorkerVerifications.WindowsSip
                : WorkerVerifications.PeImage,
            Outcome: outcome,
            Route: route,
            Failure: failure);

    private static async Task<WorkerResponse> RoundTripAsync(WorkerResponse response)
    {
        using MemoryStream frame = new();
        await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);
        frame.Position = 0;
        return await WorkerProtocol.ReadResponseAsync(frame, CancellationToken.None);
    }

    private static JsonObject RequestJson(WorkerSdkFallback sdkFallback) =>
        JsonNode.Parse(SerializePayload(Request(sdkFallback)))!.AsObject();

    private static JsonObject ResponseJson(WorkerResponse response) =>
        JsonNode.Parse(SerializePayload(response))!.AsObject();

    private static async Task<WorkerRequest> ReadRequestAsync(JsonObject json) =>
        await WorkerProtocol.ReadRequestAsync(new MemoryStream(Frame(json.ToJsonString())), CancellationToken.None);

    private static async Task<WorkerResponse> ReadResponseAsync(JsonObject json) =>
        await WorkerProtocol.ReadResponseAsync(new MemoryStream(Frame(json.ToJsonString())), CancellationToken.None);

    private static async Task AssertInvalidRequestAsync(JsonObject json)
    {
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(() => ReadRequestAsync(json));
        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    private static async Task AssertInvalidResponseAsync(JsonObject json)
    {
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(() => ReadResponseAsync(json));
        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    private static JsonDocument ReadPayload(MemoryStream frame)
    {
        byte[] bytes = frame.ToArray();
        int length = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        return JsonDocument.Parse(bytes.AsMemory(WorkerProtocol.HeaderBytes, length));
    }

    private static string SerializePayload<T>(T value)
    {
        using MemoryStream frame = new();
        if (value is WorkerRequest request)
        {
            WorkerProtocol.WriteRequestAsync(frame, request, CancellationToken.None).GetAwaiter().GetResult();
        }
        else
        {
            WorkerProtocol.WriteResponseAsync(frame, Assert.IsType<WorkerResponse>(value), CancellationToken.None)
                .GetAwaiter().GetResult();
        }

        using JsonDocument document = ReadPayload(frame);
        return document.RootElement.GetRawText();
    }

    private static byte[] Frame(string json)
    {
        byte[] payload = Encoding.UTF8.GetBytes(json);
        byte[] frame = new byte[WorkerProtocol.HeaderBytes + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(WorkerProtocol.HeaderBytes));
        return frame;
    }

    private static string CreateSigningPlanJson()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                "00112233445566778899AABBCCDDEEFF00112233").Value);
        SigningPlan plan = Assert.IsType<SigningPlan>(
            SigningPlan.TryCreateDual(certificate, certificate, ".exe").Value);
        return SigningPlanJson.Serialize(plan);
    }
}
