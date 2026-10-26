using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class SigningDiagnosticProtocolTests
{
    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private const string DiagnosticId = "fedcba9876543210fedcba9876543210";
    private static readonly string[] ResponseFieldNames =
    [
        "protocolVersion",
        "success",
        "code",
        "hresult",
        "failedLegIndex",
        "originalSha256",
        "stagedSha256",
        "operationId",
        "diagnosticId",
        "diagnosticPhase",
        "diagnosticLeg",
        "digestAlgorithm",
        "appendSignature",
        "nativeCall",
        "signerSignEx3Flags",
        "nativeReasonCode",
        "hresultSymbol",
        "hresultOrigin",
        "legElapsedMilliseconds",
        "subject",
        "capability",
        "engine",
        "verification",
        "legacyFallbackAttempted",
        "outcome",
        "route",
        "failure"
    ];

    public static TheoryData<string> RequiredResponseFields
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (string fieldName in ResponseFieldNames)
            {
                data.Add(fieldName);
            }

            return data;
        }
    }

    public static TheoryData<string, string> WrongTypedResponseFields => new()
    {
        { "protocolVersion", "\"2\"" },
        { "success", "\"false\"" },
        { "code", "false" },
        { "hresult", "\"-2147467262\"" },
        { "failedLegIndex", "\"1\"" },
        { "originalSha256", "1" },
        { "stagedSha256", "1" },
        { "operationId", "1" },
        { "diagnosticId", "1" },
        { "diagnosticPhase", "1" },
        { "diagnosticLeg", "1" },
        { "digestAlgorithm", "1" },
        { "appendSignature", "\"true\"" },
        { "nativeCall", "1" },
        { "signerSignEx3Flags", "1.5" },
        { "nativeReasonCode", "1" },
        { "hresultSymbol", "1" },
        { "hresultOrigin", "1" },
        { "legElapsedMilliseconds", "1.5" },
        { "subject", "1" },
        { "capability", "1" },
        { "engine", "1" },
        { "verification", "1" },
        { "legacyFallbackAttempted", "\"true\"" },
        { "outcome", "1" },
        { "route", "1" },
        { "failure", "1" }
    };

    public static TheoryData<string, string> InvalidEnumFields => new()
    {
        { "diagnosticPhase", "SIGNING_SECONDARY" },
        { "diagnosticLeg", "tertiary" },
        { "digestAlgorithm", "SHA256" },
        { "nativeCall", "signtool" },
        { "nativeReasonCode", "ProviderInterfaceUnavailable" },
        { "hresultOrigin", "provider" },
        { "subject", "portableExecutable" },
        { "capability", "dual" },
        { "engine", "signtool" },
        { "verification", "trustOnly" },
        { "outcome", "future_outcome" },
        { "route", "arbitrary_path" },
        { "failure", "future_failure" }
    };

    public static TheoryData<string, string> ContradictorySecondaryFields => new()
    {
        { "failedLegIndex", "0" },
        { "diagnosticPhase", "\"signing_primary\"" },
        { "diagnosticLeg", "\"primary\"" },
        { "digestAlgorithm", "\"sha1\"" },
        { "appendSignature", "false" }
    };

    [Fact]
    public async Task V4RequestAndResponseUseTheExactVersionedFieldContract()
    {
        Assert.Equal(4, WorkerProtocol.Version);
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            "C:\\input\\fixture.exe",
            "C:\\stage\\fixture.exe",
            CreateSigningPlanJson(),
            1234,
            new DateTimeOffset(2026, 7, 27, 0, 0, 0, TimeSpan.Zero),
            OperationId);
        using MemoryStream requestFrame = new();

        await WorkerProtocol.WriteRequestAsync(requestFrame, request, CancellationToken.None);

        using JsonDocument requestDocument = ReadPayload(requestFrame.ToArray());
        Assert.Equal(
            [
                "protocolVersion",
                "command",
                "originalPath",
                "stagedPath",
                "signingPlanJson",
                "stagingOwnerPid",
                "stagingOwnerStartUtc",
                "operationId",
                "subject",
                "capability",
                "engine",
                "verification",
                "sdkFallback"
            ],
            requestDocument.RootElement.EnumerateObject().Select(property => property.Name));
        Assert.Equal(OperationId, requestDocument.RootElement.GetProperty("operationId").GetString());
        JsonElement sdkFallback = requestDocument.RootElement.GetProperty("sdkFallback");
        Assert.False(sdkFallback.GetProperty("enabled").GetBoolean());
        Assert.Equal(JsonValueKind.Null, sdkFallback.GetProperty("candidate").ValueKind);
        requestFrame.Position = 0;
        Assert.Equal(request, await WorkerProtocol.ReadRequestAsync(requestFrame, CancellationToken.None));

        WorkerResponse response = CreateSecondaryResponse();
        using MemoryStream responseFrame = new();

        await WorkerProtocol.WriteResponseAsync(responseFrame, response, CancellationToken.None);

        using JsonDocument responseDocument = ReadPayload(responseFrame.ToArray());
        JsonElement root = responseDocument.RootElement;
        Assert.Equal(ResponseFieldNames, root.EnumerateObject().Select(property => property.Name));
        Assert.All(
            root.EnumerateObject(),
            property =>
            {
                Assert.NotEqual(JsonValueKind.Object, property.Value.ValueKind);
                Assert.NotEqual(JsonValueKind.Array, property.Value.ValueKind);
            });
        Assert.Equal(JsonValueKind.Number, root.GetProperty("protocolVersion").ValueKind);
        Assert.Equal(JsonValueKind.False, root.GetProperty("success").ValueKind);
        Assert.Equal(JsonValueKind.String, root.GetProperty("code").ValueKind);
        Assert.Equal(JsonValueKind.Number, root.GetProperty("hresult").ValueKind);
        Assert.Equal(JsonValueKind.Number, root.GetProperty("failedLegIndex").ValueKind);
        Assert.Equal(JsonValueKind.String, root.GetProperty("operationId").ValueKind);
        Assert.Equal(JsonValueKind.String, root.GetProperty("diagnosticId").ValueKind);
        Assert.Equal(JsonValueKind.True, root.GetProperty("appendSignature").ValueKind);
        Assert.Equal(JsonValueKind.Number, root.GetProperty("signerSignEx3Flags").ValueKind);
        Assert.Equal(JsonValueKind.Number, root.GetProperty("legElapsedMilliseconds").ValueKind);
        responseFrame.Position = 0;
        Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(responseFrame, CancellationToken.None));
    }

    [Fact]
    public async Task NullableResponseFieldsSerializeAsExplicitNulls()
    {
        WorkerResponse response = new(WorkerProtocol.Version, true, WorkerResponseCodes.Ready);
        using MemoryStream frame = new();

        await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);

        using JsonDocument document = ReadPayload(frame.ToArray());
        Assert.Equal(ResponseFieldNames, document.RootElement.EnumerateObject().Select(property => property.Name));
        foreach (string field in ResponseFieldNames.Skip(3))
        {
            Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty(field).ValueKind);
        }

        frame.Position = 0;
        Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(frame, CancellationToken.None));
    }

    [Theory]
    [MemberData(nameof(RequiredResponseFields))]
    public async Task EveryV4ResponseFieldIsRequired(string field)
    {
        JsonObject incomplete = CreateSecondaryResponseJson();
        Assert.True(incomplete.Remove(field));

        await AssertInvalidResponseAsync(incomplete);
    }

    [Fact]
    public async Task EveryAllowedPhaseRelationshipRoundTrips()
    {
        WorkerResponse[] responses =
        [
            CreateLegResponse(
                WorkerDiagnosticPhases.SigningPrimary,
                WorkerDiagnosticLegs.Primary,
                WorkerDigestAlgorithms.Sha1,
                appendSignature: false,
                failedLegIndex: 0,
                flags: 0),
            CreateSecondaryResponse(),
            new WorkerResponse(
                WorkerProtocol.Version,
                false,
                WorkerResponseCodes.VerifierDisagreement,
                unchecked((int)0x800B0100),
                OperationId: OperationId,
                DiagnosticId: DiagnosticId,
                DiagnosticPhase: WorkerDiagnosticPhases.Verifying,
                NativeReasonCode: NativeSigningReasonCode.VerifierDisagreement.ToString(),
                HResultOrigin: WorkerHResultOrigins.Native,
                Subject: WorkerSubjects.PeImage,
                Capability: WorkerCapabilities.PeImageDualCapable,
                Engine: WorkerEngines.PeImage,
                Verification: WorkerVerifications.PeImage,
                Outcome: WorkerSigningOutcome.Failure,
                Route: WorkerExecutionRoute.ProductPe,
                Failure: WorkerFailureCode.VerifierDisagreement),
            new WorkerResponse(
                WorkerProtocol.Version,
                false,
                WorkerResponseCodes.HandlerFailure,
                unchecked((int)0x80004005),
                OperationId: OperationId,
                DiagnosticId: DiagnosticId,
                DiagnosticPhase: WorkerDiagnosticPhases.WorkerBridge,
                HResultOrigin: WorkerHResultOrigins.WorkerBridge,
                Subject: WorkerSubjects.PeImage,
                Capability: WorkerCapabilities.PeImageDualCapable,
                Engine: WorkerEngines.PeImage,
                Verification: WorkerVerifications.PeImage,
                Outcome: WorkerSigningOutcome.Failure,
                Route: WorkerExecutionRoute.ProductPe,
                Failure: WorkerFailureCode.HandlerFailure)
        ];

        foreach (WorkerResponse response in responses)
        {
            using MemoryStream frame = new();
            await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);
            frame.Position = 0;
            Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(frame, CancellationToken.None));
        }
    }

    [Fact]
    public async Task NativeReasonCodeAcceptsOnlyExactEnumNames()
    {
        foreach (string reasonCode in Enum.GetNames<NativeSigningReasonCode>())
        {
            JsonObject json = CreateSecondaryResponseJson();
            json["nativeReasonCode"] = reasonCode;
            await ReadResponseAsync(json);
        }

        JsonObject invalid = CreateSecondaryResponseJson();
        invalid["nativeReasonCode"] = "nativeSigningFailed";
        await AssertInvalidResponseAsync(invalid);
    }

    [Theory]
    [MemberData(nameof(WrongTypedResponseFields))]
    public async Task EveryResponseFieldRejectsTheWrongJsonType(string field, string replacementJson)
    {
        JsonObject json = CreateSecondaryResponseJson();
        json[field] = JsonNode.Parse(replacementJson);

        await AssertInvalidResponseAsync(json);
    }

    [Theory]
    [MemberData(nameof(InvalidEnumFields))]
    public async Task InvalidEnumValuesAreRejected(string field, string value)
    {
        JsonObject json = CreateSecondaryResponseJson();
        json[field] = value;

        await AssertInvalidResponseAsync(json);
    }

    [Theory]
    [MemberData(nameof(ContradictorySecondaryFields))]
    public async Task ContradictorySecondaryRelationshipsAreRejected(string field, string replacementJson)
    {
        JsonObject json = CreateSecondaryResponseJson();
        json[field] = JsonNode.Parse(replacementJson);

        await AssertInvalidResponseAsync(json);
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcde")]
    [InlineData("0123456789abcdef0123456789abcdef0")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("01234567-89ab-cdef-0123-456789abcdef")]
    [InlineData("gggggggggggggggggggggggggggggggg")]
    public async Task MalformedOperationAndDiagnosticIdentifiersAreRejected(string malformedId)
    {
        JsonObject operation = CreateSecondaryResponseJson();
        operation["operationId"] = malformedId;
        await AssertInvalidResponseAsync(operation);

        JsonObject diagnostic = CreateSecondaryResponseJson();
        diagnostic["diagnosticId"] = malformedId;
        await AssertInvalidResponseAsync(diagnostic);
    }

    [Theory]
    [InlineData("protocolVersion", "1")]
    [InlineData("unknown", "null")]
    [InlineData("ProtocolVersion", "2")]
    public async Task StaleUnknownAndWrongCaseResponseFieldsAreRejected(string field, string value)
    {
        JsonObject json = CreateSecondaryResponseJson();
        if (field == "ProtocolVersion")
        {
            json.Remove("protocolVersion");
        }

        json[field] = JsonNode.Parse(value);
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => ReadResponseAsync(json));

        Assert.Equal(
            field == "protocolVersion"
                ? WorkerResponseCodes.ProtocolVersionMismatch
                : WorkerResponseCodes.InvalidRequest,
            error.Code);
    }

    [Fact]
    public async Task DuplicateResponseFieldIsRejected()
    {
        string json = CreateSecondaryResponseJson().ToJsonString();
        json = json.Replace(
            "\"code\":\"native_signing_failed\"",
            "\"code\":\"native_signing_failed\",\"code\":\"signed\"",
            StringComparison.Ordinal);

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadResponseAsync(new MemoryStream(Frame(json)), CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    [Fact]
    public async Task RequestIdentifierRulesRejectStaleUnknownDuplicateWrongCaseAndMalformedFrames()
    {
        string valid = CreateSignRequestJson(OperationId).ToJsonString();
        string[] invalidFrames =
        [
            CreateSignRequestJson(null).ToJsonString(),
            CreateSignRequestJson("0123456789ABCDEF0123456789ABCDEF").ToJsonString(),
            valid.Replace("\"protocolVersion\":4", "\"protocolVersion\":1", StringComparison.Ordinal),
            valid.Replace("\"operationId\":", "\"unknown\":null,\"operationId\":", StringComparison.Ordinal),
            valid.Replace("\"operationId\":", "\"OperationId\":", StringComparison.Ordinal),
            valid.Replace(
                "\"operationId\":\"" + OperationId + "\"",
                "\"operationId\":\"" + OperationId + "\",\"operationId\":\"" + OperationId + "\"",
                StringComparison.Ordinal),
            "{"
        ];

        foreach (string json in invalidFrames)
        {
            await Assert.ThrowsAsync<WorkerProtocolException>(
                () => WorkerProtocol.ReadRequestAsync(new MemoryStream(Frame(json)), CancellationToken.None));
        }

        JsonObject probeWithOperation = CreateSignRequestJson(OperationId);
        probeWithOperation["command"] = WorkerCommands.Probe;
        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(
                new MemoryStream(Frame(probeWithOperation.ToJsonString())),
                CancellationToken.None));
    }

    [Fact]
    public async Task SdkSessionStateAcceptsExactEnabledAndDisabledShapesAndRejectsContradictions()
    {
        JsonObject disabled = CreateSignRequestJson(OperationId);
        WorkerRequest disabledRequest = await WorkerProtocol.ReadRequestAsync(
            new MemoryStream(Frame(disabled.ToJsonString())),
            CancellationToken.None);
        Assert.Equal(WorkerSdkFallback.Disabled, disabledRequest.SdkFallback);

        JsonObject enabled = CreateSignRequestJson(OperationId);
        enabled["sdkFallback"] = new JsonObject
        {
            ["enabled"] = true,
            ["candidate"] = CreateSdkCandidateJson()
        };
        WorkerRequest enabledRequest = await WorkerProtocol.ReadRequestAsync(
            new MemoryStream(Frame(enabled.ToJsonString())),
            CancellationToken.None);
        Assert.True(enabledRequest.SdkFallback!.Enabled);
        Assert.Equal(new string('a', 64), enabledRequest.SdkFallback.Candidate!.Sha256);

        JsonObject enabledWithoutCandidate = CreateSignRequestJson(OperationId);
        enabledWithoutCandidate["sdkFallback"]!["enabled"] = true;
        JsonObject disabledWithCandidate = CreateSignRequestJson(OperationId);
        disabledWithCandidate["sdkFallback"]!["candidate"] = CreateSdkCandidateJson();
        JsonObject staleCandidate = enabled.DeepClone().AsObject();
        staleCandidate["sdkFallback"]!["candidate"]!["sha256"] = new string('b', 63);
        JsonObject nestedExtra = enabled.DeepClone().AsObject();
        nestedExtra["sdkFallback"]!["candidate"]!["authorization"] = true;
        JsonObject callerAuthority = CreateSignRequestJson(OperationId);
        callerAuthority["alreadySigned"] = true;

        foreach (JsonObject invalid in new[]
                 {
                     enabledWithoutCandidate,
                     disabledWithCandidate,
                     staleCandidate,
                     nestedExtra,
                     callerAuthority
                 })
        {
            WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
                () => WorkerProtocol.ReadRequestAsync(
                    new MemoryStream(Frame(invalid.ToJsonString())),
                    CancellationToken.None));
            Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
        }
    }

    [Fact]
    public async Task CrossFieldDiagnosticContradictionsAreRejected()
    {
        JsonObject[] invalidFrames =
        [
            Mutate("diagnosticPhase", null),
            Mutate("diagnosticId", null),
            Mutate("operationId", null),
            Mutate("nativeCall", null),
            Mutate("signerSignEx3Flags", null),
            Mutate("hresultOrigin", "managed"),
            Mutate("hresult", null),
            Mutate("hresultSymbol", "pin=unsafe"),
            Mutate("legElapsedMilliseconds", -1),
            Mutate("signerSignEx3Flags", -1),
            Mutate("originalSha256", new string('A', 64)),
            Mutate("stagedSha256", "abc"),
            Mutate("subject", null),
            Mutate("capability", null),
            Mutate("engine", null),
            Mutate("verification", null)
        ];

        foreach (JsonObject json in invalidFrames)
        {
            await AssertInvalidResponseAsync(json);
        }
    }

    private static WorkerResponse CreateSecondaryResponse() => CreateLegResponse(
        WorkerDiagnosticPhases.SigningSecondary,
        WorkerDiagnosticLegs.Secondary,
        WorkerDigestAlgorithms.Sha256,
        appendSignature: true,
        failedLegIndex: 1,
        flags: 1024);

    private static WorkerResponse CreateLegResponse(
        string phase,
        string leg,
        string digestAlgorithm,
        bool appendSignature,
        int failedLegIndex,
        int flags) => new(
            WorkerProtocol.Version,
            false,
            WorkerResponseCodes.NativeSigningFailed,
            unchecked((int)0x80004002),
            failedLegIndex,
            new string('a', 64),
            new string('b', 64),
            OperationId,
            DiagnosticId,
            phase,
            leg,
            digestAlgorithm,
            appendSignature,
            WorkerNativeCalls.SignerSignEx3,
            flags,
            NativeSigningReasonCode.NativeSigningFailed.ToString(),
            "E_NOINTERFACE",
            WorkerHResultOrigins.Native,
            42,
            WorkerSubjects.PeImage,
            WorkerCapabilities.PeImageDualCapable,
            WorkerEngines.PeImage,
            WorkerVerifications.PeImage,
            LegacyFallbackAttempted: true,
            Outcome: WorkerSigningOutcome.Failure,
            Route: WorkerExecutionRoute.ProductPe,
            Failure: WorkerFailureCode.NativeSigningFailed);

    private static JsonObject CreateSecondaryResponseJson() => new()
    {
        ["protocolVersion"] = 4,
        ["success"] = false,
        ["code"] = WorkerResponseCodes.NativeSigningFailed,
        ["hresult"] = unchecked((int)0x80004002),
        ["failedLegIndex"] = 1,
        ["originalSha256"] = new string('a', 64),
        ["stagedSha256"] = new string('b', 64),
        ["operationId"] = OperationId,
        ["diagnosticId"] = DiagnosticId,
        ["diagnosticPhase"] = "signing_secondary",
        ["diagnosticLeg"] = "secondary",
        ["digestAlgorithm"] = "sha256",
        ["appendSignature"] = true,
        ["nativeCall"] = "SignerSignEx3",
        ["signerSignEx3Flags"] = 1024,
        ["nativeReasonCode"] = NativeSigningReasonCode.NativeSigningFailed.ToString(),
        ["hresultSymbol"] = "E_NOINTERFACE",
        ["hresultOrigin"] = "native",
        ["legElapsedMilliseconds"] = 42,
        ["subject"] = WorkerSubjects.PeImage,
        ["capability"] = WorkerCapabilities.PeImageDualCapable,
        ["engine"] = WorkerEngines.PeImage,
        ["verification"] = WorkerVerifications.PeImage,
        ["legacyFallbackAttempted"] = true,
        ["outcome"] = "failure",
        ["route"] = "product_pe",
        ["failure"] = "native_signing_failed"
    };

    private static JsonObject CreateSignRequestJson(string? operationId) => new()
    {
        ["protocolVersion"] = 4,
        ["command"] = WorkerCommands.Sign,
        ["originalPath"] = "C:\\input\\fixture.exe",
        ["stagedPath"] = "C:\\stage\\fixture.exe",
        ["signingPlanJson"] = CreateSigningPlanJson(),
        ["stagingOwnerPid"] = 1234,
        ["stagingOwnerStartUtc"] = "2026-07-27T00:00:00+00:00",
        ["operationId"] = operationId,
        ["subject"] = WorkerSubjects.PeImage,
        ["capability"] = WorkerCapabilities.PeImageDualCapable,
        ["engine"] = WorkerEngines.PeImage,
        ["verification"] = WorkerVerifications.PeImage,
        ["sdkFallback"] = new JsonObject
        {
            ["enabled"] = false,
            ["candidate"] = null
        }
    };

    private static JsonObject CreateSdkCandidateJson() => new()
    {
        ["path"] = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe",
        ["sdkVersion"] = "10.0.26100.0",
        ["productVersion"] = "10.0.26100.7463",
        ["publisher"] = "Microsoft Windows",
        ["companyName"] = "Microsoft Corporation",
        ["productName"] = "Microsoft Windows Operating System",
        ["sha256"] = new string('a', 64)
    };

    private static JsonObject Mutate(string field, object? value)
    {
        JsonObject json = CreateSecondaryResponseJson();
        json[field] = JsonValue.Create(value);
        return json;
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

    private static async Task<WorkerResponse> ReadResponseAsync(JsonObject json) =>
        await WorkerProtocol.ReadResponseAsync(
            new MemoryStream(Frame(json.ToJsonString())),
            CancellationToken.None);

    private static async Task AssertInvalidResponseAsync(JsonObject json)
    {
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => ReadResponseAsync(json));
        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    private static JsonDocument ReadPayload(byte[] frame)
    {
        int payloadLength = BinaryPrimitives.ReadInt32LittleEndian(frame);
        Assert.Equal(frame.Length - WorkerProtocol.HeaderBytes, payloadLength);
        return JsonDocument.Parse(frame.AsMemory(WorkerProtocol.HeaderBytes, payloadLength));
    }

    private static byte[] Frame(string json)
    {
        byte[] payload = Encoding.UTF8.GetBytes(json);
        byte[] frame = new byte[WorkerProtocol.HeaderBytes + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(WorkerProtocol.HeaderBytes));
        return frame;
    }
}
