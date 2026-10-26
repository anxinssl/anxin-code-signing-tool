using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Evidence;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.Tests;

public sealed class SigningDiagnosticProjectionTests
{
    [Fact]
    public void OutputSaveFailureDiagnosticKeepsIoCodeWithoutClaimingWorkerCrash()
    {
        SigningRuntimeDiagnostic diagnostic = SigningRuntimeDiagnostic.FromOutputSaveFailure(
            unchecked((int)0x80131620), OperationId).Redact();
        Assert.Equal("OutputSaveFailed", diagnostic.NativeReasonCode);
        Assert.Equal(unchecked((int)0x80131620), diagnostic.HResult);
        Assert.Equal(WorkerHResultOrigins.Managed, diagnostic.HResultOrigin);
        Assert.Equal(OperationId, diagnostic.OperationId);
        Assert.Contains("更改输出位置", diagnostic.FailureSummary, StringComparison.Ordinal);
        Assert.Null(diagnostic.DiagnosticPhase);
        Assert.Null(diagnostic.WorkerExitCode);
        Assert.DoesNotContain("crashed", diagnostic.FailureSummary, StringComparison.Ordinal);
    }

    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private const string DiagnosticId = "fedcba9876543210fedcba9876543210";
    private const int ENoInterface = unchecked((int)0x80004002);
    private const string ExpectedSummary =
        "追加 SHA-256 签名失败 / SignerSignEx3 / 0x80004002 (E_NOINTERFACE)";

    private static readonly string[] RuntimeFields =
    [
        "schemaVersion",
        "timestampUtc",
        "event",
        "itemId",
        "processId",
        "detail",
        "operationId",
        "diagnosticId",
        "diagnosticPhase",
        "diagnosticLeg",
        "digestAlgorithm",
        "appendSignature",
        "nativeCall",
        "signerSignEx3Flags",
        "nativeReasonCode",
        "hresult",
        "hresultHex",
        "hresultSymbol",
        "hresultOrigin",
        "legElapsedMilliseconds",
        "workerProtocolVersion",
        "workerExitCode",
        "workerStderrTail",
        "workerStderrTruncated",
        "failureSummary",
        "responseCode",
        "subject",
        "capability",
        "engine",
        "verification",
        "detectedFormat",
        "contentProbeResult",
        "requestedPolicy",
        "effectivePolicy",
        "selectedEngine",
        "legacyFallbackAttempt",
        "sdkSignToolAvailable",
        "sdkSignToolVersion",
        "sdkSignToolPathStatus",
        "powerShellBridgeAvailability",
        "providerFamily",
        "structuredStage",
        "hresultClass",
        "exitClass",
        "finalVerification"
    ];

    public static TheoryData<string, string?, string> TypedFailureMappings => new()
    {
        { WorkerResponseCodes.WindowsPowerShellUnavailable, null, "Windows PowerShell 5.1 签名桥不可用" },
        { WorkerResponseCodes.WindowsPowerShellExecutionDenied, null, "Windows PowerShell 5.1 签名桥被系统策略阻止" },
        { WorkerResponseCodes.WindowsSipUnavailable, null, "此格式没有可用的 Windows 签名处理程序" },
        { WorkerResponseCodes.SecureSipPublicationUnavailable, null, "当前系统无法安全发布 SIP 签名结果" },
        { WorkerResponseCodes.PackageIncompatible, null, "应用包结构或摘要策略不兼容" },
        { WorkerResponseCodes.CertificateMismatch, null, "证书主题与应用包发布者不匹配" },
        { WorkerResponseCodes.CertificateNotFound, null, "未找到所选签名证书" },
        { WorkerResponseCodes.CertificateHasNoPrivateKey, null, "所选证书没有可用私钥" },
        { WorkerResponseCodes.ExistingSignatureRejected, null, "现有签名状态不允许覆盖" },
        { WorkerResponseCodes.ProviderCancelled, null, "签名提供程序操作已取消" },
        { WorkerResponseCodes.TimestampUnavailable, null, "RFC 3161 时间戳不可用" },
        { WorkerResponseCodes.VerifierDisagreement, null, "最终签名验证失败" },
        { WorkerResponseCodes.InvalidBridgeResponse, null, "Windows 签名桥返回无效结果" },
        { WorkerResponseCodes.NativeSigningFailed, null, "Windows 签名处理程序执行失败" },
        { WorkerResponseCodes.OriginalChanged, null, "原始文件在签名期间发生变更" },
        { WorkerResponseCodes.Cancelled, null, "签名操作已取消" },
        { WorkerResponseCodes.InvalidInput, null, "签名输入无效" },
        { WorkerResponseCodes.HandlerFailure, null, "Windows 签名处理程序发生故障" },
        { WorkerResponseCodes.NativeSigningFailed, "UnsupportedKeyAlgorithm", "密钥算法不受 PE 签名引擎支持，符合自动 PE 恢复条件" }
    };

    private static readonly string[] ExportOnlyFields =
    [
        "diagnosticLogFileName",
        "sourceSizeBytes",
        "stagedSizeBytes",
        "signatureCountBefore",
        "signatureCountAfter",
        "signatureAlgorithmsBefore",
        "signatureAlgorithmsAfter",
        "verificationState",
        "providerName",
        "providerType",
        "keySpec",
        "timestampScheme",
        "timestampHost"
    ];

    [Fact]
    public async Task SecondaryNativeFailureUsesOneCorrelatedV3ProjectionAcrossRuntimeExportAndUi()
    {
        string root = CreateTemporaryDirectory();
        try
        {
            WorkerResponse response = SecondaryNativeFailure();
            SigningRuntimeDiagnostic diagnostic = SigningRuntimeDiagnostic.FromWorkerResponse(response);
            var log = new SigningRuntimeEventLog(root);

            Assert.True(log.Write(
                SigningRuntimeEventNames.BatchFailed,
                itemId: "17",
                processId: 321,
                detail: "typed-secondary-failure",
                signingDiagnostic: diagnostic));

            string runtimeJson = Assert.Single(await File.ReadAllLinesAsync(log.Path));
            using JsonDocument runtimeDocument = JsonDocument.Parse(runtimeJson);
            JsonElement runtime = runtimeDocument.RootElement;
            AssertExactFields(runtime, RuntimeFields);
            AssertSecondaryNativeProjection(runtime);
            Assert.Equal(3, runtime.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("17", runtime.GetProperty("itemId").GetString());
            Assert.Equal(321, runtime.GetProperty("processId").GetInt32());

            IReadOnlyDictionary<string, object?> candidate = SigningDiagnosticExportProjection.Create(
                Assert.IsType<SigningRuntimeEvent>(log.LastEvent),
                new SigningDiagnosticExportContext(
                    DiagnosticLogPath: log.Path,
                    SourceSizeBytes: 4096,
                    StagedSizeBytes: 8192,
                    SignatureCountBefore: 1,
                    SignatureCountAfter: 1,
                    SignatureAlgorithmsBefore: "sha1",
                    SignatureAlgorithmsAfter: "sha1",
                    VerificationState: "not_started",
                    ProviderName: "Safe Provider",
                    ProviderType: 1,
                    KeySpec: 2,
                    TimestampUri: new Uri("https://timestamp.example.test/rfc3161?token=not-exported")));
            string exportJson = await WriteEvidenceAsync(candidate);
            using JsonDocument exportDocument = JsonDocument.Parse(exportJson);
            JsonElement export = exportDocument.RootElement;
            AssertExactFields(export, [.. RuntimeFields, .. ExportOnlyFields]);
            AssertSecondaryNativeProjection(export);
            Assert.Equal(Path.GetFileName(log.Path), export.GetProperty("diagnosticLogFileName").GetString());
            Assert.False(export.TryGetProperty("runtimeEventLogPath", out _));
            Assert.Equal("https", export.GetProperty("timestampScheme").GetString());
            Assert.Equal("timestamp.example.test", export.GetProperty("timestampHost").GetString());

            var row = new QueueItemViewModel("17", Intake(root));
            row.Apply(
                BatchItemState.Failed,
                new BatchItemReceipt(
                    "17",
                    BatchItemState.Failed,
                    BatchResultCode.WorkerFailure,
                    Path.Combine(root, "source.exe"),
                    Path.Combine(root, "signed.exe"),
                    null,
                    null,
                    null,
                    321,
                    ENoInterface,
                    SigningDiagnostic: response));

            Assert.Equal(ExpectedSummary, row.DetailText);
            Assert.DoesNotContain("stderr", row.DetailText, StringComparison.OrdinalIgnoreCase);
            await WriteEvidenceFixtureAsync("secondary-runtime.jsonl", runtimeJson + Environment.NewLine);
            await WriteEvidenceFixtureAsync("secondary-export.json", exportJson);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RuntimeAndEvidencePersistenceRemoveSensitiveValuesFromEveryStringIngress()
    {
        string root = CreateTemporaryDirectory();
        try
        {
            const string detailSecret = "detail-secret-551";
            const string itemSecret = "item-secret-552";
            const string providerSecret = "provider-secret-553";
            const string stderrSecret = "stderr-secret-554";
            const string timestampSecret = "timestamp-secret-555";
            WorkerResponse response = SecondaryNativeFailure();
            SigningRuntimeDiagnostic diagnostic = SigningRuntimeDiagnostic.FromWorkerResponse(response) with
            {
                WorkerStderrTail = $"--pin {stderrSecret} C:\\private\\profile.json",
                WorkerStderrTruncated = false
            };
            var log = new SigningRuntimeEventLog(root);

            Assert.True(log.Write(
                SigningRuntimeEventNames.BatchFailed,
                itemId: $"17?token={itemSecret}",
                processId: 321,
                detail: $"C:\\private\\{detailSecret}.pfx?token={detailSecret}",
                signingDiagnostic: diagnostic));

            string runtimeJson = await File.ReadAllTextAsync(log.Path);
            AssertNoSecrets(runtimeJson, detailSecret, itemSecret, stderrSecret);
            using JsonDocument runtimeDocument = JsonDocument.Parse(runtimeJson);
            Assert.True(runtimeDocument.RootElement.GetProperty("itemId").ValueKind is JsonValueKind.Null);

            IReadOnlyDictionary<string, object?> candidate = SigningDiagnosticExportProjection.Create(
                Assert.IsType<SigningRuntimeEvent>(log.LastEvent),
                new SigningDiagnosticExportContext(
                    DiagnosticLogPath: Path.Combine(root, detailSecret, "runtime.jsonl"),
                    ProviderName: $"provider transcript: {providerSecret}",
                    TimestampUri: new Uri(
                        $"https://timestamp.example.test/rfc3161?token={timestampSecret}#fragment")));
            string exportJson = await WriteEvidenceAsync(candidate);
            AssertNoSecrets(
                exportJson,
                detailSecret,
                itemSecret,
                providerSecret,
                stderrSecret,
                timestampSecret);
            Assert.DoesNotContain(root, exportJson, StringComparison.OrdinalIgnoreCase);

            using JsonDocument exportDocument = JsonDocument.Parse(exportJson);
            JsonElement export = exportDocument.RootElement;
            Assert.Equal("runtime.jsonl", export.GetProperty("diagnosticLogFileName").GetString());
            Assert.Equal("timestamp.example.test", export.GetProperty("timestampHost").GetString());
            Assert.False(export.TryGetProperty("runtimeEventLogPath", out _));
            await WriteEvidenceFixtureAsync("leak-runtime.jsonl", runtimeJson);
            await WriteEvidenceFixtureAsync("leak-export.json", exportJson);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeDiagnosticExportContainsApprovedRoutingReadinessAndVerificationFieldsOnly()
    {
        WorkerResponse response = SecondaryNativeFailure() with
        {
            NativeReasonCode = "UnsupportedKeyAlgorithm",
            Subject = WorkerSubjects.PeImage,
            Capability = WorkerCapabilities.PeImageDualCapable,
            Engine = WorkerEngines.PeImage,
            Verification = WorkerVerifications.PeImage
        };
        SigningRuntimeEvent runtimeEvent = SigningRuntimeEventLog.CreateEvent(
            SigningRuntimeEventNames.BatchFailed,
            "17",
            321,
            detail: null,
            SigningRuntimeDiagnostic.FromWorkerResponse(response));
        var context = new SigningDiagnosticExportContext(
            DetectedFormat: WorkerSubjects.PeImage,
            ContentProbeResult: "validated",
            RequestedPolicy: "dual",
            EffectivePolicy: "dual",
            SelectedEngine: WorkerEngines.PeImage,
            SdkSignToolAvailable: true,
            SdkSignToolVersion: "10.0.26100.0",
            SdkSignToolPathStatus: "canonical_verified",
            PowerShellBridgeAvailability: "available",
            ProviderFamily: "windows_native",
            StructuredStage: WorkerDiagnosticPhases.SigningSecondary,
            HResultClass: "failure",
            ExitClass: "not_available",
            FinalVerification: "not_started");
        var candidate = new Dictionary<string, object?>(
            SigningDiagnosticExportProjection.Create(runtimeEvent, context),
            StringComparer.Ordinal)
        {
            ["providerCommand"] = "signtool.exe sign /p pe-pin-canary",
            ["temporaryJson"] = "{\"token\":\"pe-token-canary\"}",
            ["certificatePrivateKey"] = "pe-private-key-canary",
            ["sessionData"] = "pe-session-canary"
        };

        string json = await WriteEvidenceAsync(candidate);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;

        Assert.Equal(3, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(WorkerSubjects.PeImage, root.GetProperty("detectedFormat").GetString());
        Assert.Equal("validated", root.GetProperty("contentProbeResult").GetString());
        Assert.Equal("dual", root.GetProperty("requestedPolicy").GetString());
        Assert.Equal("dual", root.GetProperty("effectivePolicy").GetString());
        Assert.Equal(WorkerEngines.PeImage, root.GetProperty("selectedEngine").GetString());
        Assert.True(root.GetProperty("legacyFallbackAttempt").GetBoolean());
        Assert.True(root.GetProperty("sdkSignToolAvailable").GetBoolean());
        Assert.Equal("10.0.26100.0", root.GetProperty("sdkSignToolVersion").GetString());
        Assert.Equal("canonical_verified", root.GetProperty("sdkSignToolPathStatus").GetString());
        Assert.Equal("available", root.GetProperty("powerShellBridgeAvailability").GetString());
        Assert.Equal("windows_native", root.GetProperty("providerFamily").GetString());
        Assert.Equal("signing_secondary", root.GetProperty("structuredStage").GetString());
        Assert.Equal("failure", root.GetProperty("hresultClass").GetString());
        Assert.Equal("not_available", root.GetProperty("exitClass").GetString());
        Assert.Equal("not_started", root.GetProperty("finalVerification").GetString());
        Assert.Equal(WorkerSubjects.PeImage, root.GetProperty("subject").GetString());
        Assert.Equal(WorkerCapabilities.PeImageDualCapable, root.GetProperty("capability").GetString());
        Assert.Equal(WorkerEngines.PeImage, root.GetProperty("engine").GetString());
        Assert.Equal(WorkerVerifications.PeImage, root.GetProperty("verification").GetString());
        AssertNoSecrets(
            json,
            "pe-pin-canary",
            "pe-token-canary",
            "pe-private-key-canary",
            "pe-session-canary",
            "signtool.exe");
        Assert.False(root.TryGetProperty("providerCommand", out _));
        Assert.False(root.TryGetProperty("temporaryJson", out _));
        Assert.False(root.TryGetProperty("certificatePrivateKey", out _));
        Assert.False(root.TryGetProperty("sessionData", out _));
        await WriteEvidenceFixtureAsync("pe-export.json", json);
    }

    [Fact]
    public async Task SipDiagnosticExportContainsSinglePolicyAndUnsupportedHandlerWithoutSecrets()
    {
        WorkerResponse response = new(
            WorkerProtocol.Version,
            Success: false,
            WorkerResponseCodes.WindowsSipUnavailable,
            HResult: unchecked((int)0x80004005),
            OperationId: OperationId,
            DiagnosticId: DiagnosticId,
            DiagnosticPhase: WorkerDiagnosticPhases.WorkerBridge,
            HResultOrigin: WorkerHResultOrigins.WorkerBridge,
            Subject: WorkerSubjects.WindowsInstaller,
            Capability: WorkerCapabilities.WindowsSipSingleOnly,
            Engine: WorkerEngines.WindowsSip,
            Verification: WorkerVerifications.WindowsSip,
            LegacyFallbackAttempted: false);
        SigningRuntimeEvent runtimeEvent = SigningRuntimeEventLog.CreateEvent(
            SigningRuntimeEventNames.BatchFailed,
            "18",
            654,
            detail: null,
            SigningRuntimeDiagnostic.FromWorkerResponse(response, "--token sip-token-canary provider transcript: sip-provider-canary"));
        var context = new SigningDiagnosticExportContext(
            DetectedFormat: WorkerSubjects.WindowsInstaller,
            ContentProbeResult: "validated",
            RequestedPolicy: "dual",
            EffectivePolicy: "single",
            SelectedEngine: WorkerEngines.WindowsSip,
            SdkSignToolAvailable: false,
            SdkSignToolPathStatus: "not_found",
            PowerShellBridgeAvailability: "unavailable",
            ProviderFamily: "windows_sip",
            StructuredStage: WorkerDiagnosticPhases.WorkerBridge,
            HResultClass: "failure",
            ExitClass: "not_available",
            FinalVerification: "not_started");

        string json = await WriteEvidenceAsync(SigningDiagnosticExportProjection.Create(runtimeEvent, context));
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;

        Assert.Equal(WorkerSubjects.WindowsInstaller, root.GetProperty("detectedFormat").GetString());
        Assert.Equal("dual", root.GetProperty("requestedPolicy").GetString());
        Assert.Equal("single", root.GetProperty("effectivePolicy").GetString());
        Assert.Equal(WorkerEngines.WindowsSip, root.GetProperty("selectedEngine").GetString());
        Assert.False(root.GetProperty("legacyFallbackAttempt").GetBoolean());
        Assert.False(root.GetProperty("sdkSignToolAvailable").GetBoolean());
        Assert.Equal("unavailable", root.GetProperty("powerShellBridgeAvailability").GetString());
        Assert.Equal("windows_sip", root.GetProperty("providerFamily").GetString());
        Assert.Equal("此格式没有可用的 Windows 签名处理程序", root.GetProperty("failureSummary").GetString());
        AssertNoSecrets(json, "sip-token-canary", "sip-provider-canary", "--token");
        await WriteEvidenceFixtureAsync("sip-export.json", json);
    }

    [Theory]
    [MemberData(nameof(TypedFailureMappings))]
    public void TypedSigningFailureHasExactChineseDiagnostic(
        string responseCode,
        string? nativeReasonCode,
        string expected)
    {
        bool pe = nativeReasonCode == "UnsupportedKeyAlgorithm";
        WorkerResponse response = new(
            WorkerProtocol.Version,
            Success: false,
            responseCode,
            HResult: ENoInterface,
            OperationId: OperationId,
            DiagnosticId: DiagnosticId,
            DiagnosticPhase: pe ? WorkerDiagnosticPhases.SigningPrimary : WorkerDiagnosticPhases.WorkerBridge,
            NativeReasonCode: nativeReasonCode,
            HResultOrigin: pe ? WorkerHResultOrigins.Native : WorkerHResultOrigins.WorkerBridge,
            Subject: pe ? WorkerSubjects.PeImage : WorkerSubjects.WindowsInstaller,
            Capability: pe ? WorkerCapabilities.PeImageDualCapable : WorkerCapabilities.WindowsSipSingleOnly,
            Engine: pe ? WorkerEngines.PeImage : WorkerEngines.WindowsSip,
            Verification: pe ? WorkerVerifications.PeImage : WorkerVerifications.WindowsSip);

        string? summary = SigningRuntimeDiagnostic.FromWorkerResponse(response).Redact().FailureSummary;

        Assert.Equal(expected, summary);
    }

    [Fact]
    public async Task OpeningExistingDiagnosticsDirectoryUsesExplorerAndDoesNotChangeSourceFiles()
    {
        string repositoryRoot = ResolveRepositoryRoot();
        string sourceRoot = Path.Combine(repositoryRoot, "src");
        Dictionary<string, string> before = HashSourceFiles(sourceRoot);
        Directory.CreateDirectory(SigningRuntimeEventLog.DefaultDiagnosticsRoot);
        ProcessStartInfo? observed = null;
        var shell = new WindowsOperatorShell(startInfo =>
        {
            observed = startInfo;
            return new Process();
        });

        shell.OpenFolder(SigningRuntimeEventLog.DefaultDiagnosticsRoot);

        Assert.NotNull(observed);
        Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), observed.FileName);
        Assert.True(observed.UseShellExecute);
        Assert.Equal(
            Path.GetFullPath(SigningRuntimeEventLog.DefaultDiagnosticsRoot),
            Assert.Single(observed.ArgumentList));
        Dictionary<string, string> after = HashSourceFiles(sourceRoot);
        Assert.Equal(before, after);
        await WriteEvidenceFixtureAsync(
            "directory-open-boundary.json",
            JsonSerializer.Serialize(new
            {
                scenario = "open existing diagnostics directory through the fake process boundary",
                invocation = nameof(WindowsOperatorShell.OpenFolder),
                fileName = observed.FileName,
                useShellExecute = observed.UseShellExecute,
                argument = Assert.Single(observed.ArgumentList),
                expectedPath = Path.GetFullPath(SigningRuntimeEventLog.DefaultDiagnosticsRoot),
                sourceFileCount = before.Count,
                sourceHashesUnchanged = before.OrderBy(static entry => entry.Key, StringComparer.OrdinalIgnoreCase)
                    .SequenceEqual(after.OrderBy(static entry => entry.Key, StringComparer.OrdinalIgnoreCase))
            }));
    }

    private static WorkerResponse SecondaryNativeFailure() => new(
        WorkerProtocol.Version,
        Success: false,
        WorkerResponseCodes.NativeSigningFailed,
        HResult: ENoInterface,
        FailedLegIndex: 1,
        OriginalSha256: new string('a', 64),
        StagedSha256: null,
        OperationId: OperationId,
        DiagnosticId: DiagnosticId,
        DiagnosticPhase: WorkerDiagnosticPhases.SigningSecondary,
        DiagnosticLeg: WorkerDiagnosticLegs.Secondary,
        DigestAlgorithm: WorkerDigestAlgorithms.Sha256,
        AppendSignature: true,
        NativeCall: WorkerNativeCalls.SignerSignEx3,
        SignerSignEx3Flags: 0x00002000,
        NativeReasonCode: "SecondLegFailed",
        HResultSymbol: "E_NOINTERFACE",
        HResultOrigin: WorkerHResultOrigins.Native,
        LegElapsedMilliseconds: 47,
        LegacyFallbackAttempted: true);

    private static IntakeFile Intake(string root) => new(
        Path.Combine(root, "source.exe"),
        "source.exe",
        Path.Combine(root, "signed.exe"),
        root,
        new StableFileIdentity(1, "projection-fixture"),
        new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()));

    private static async Task<string> WriteEvidenceAsync(IReadOnlyDictionary<string, object?> candidate)
    {
        await using var stream = new MemoryStream();
        await AllowListEvidenceWriter.WriteAsync(stream, candidate, CancellationToken.None);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void AssertSecondaryNativeProjection(JsonElement value)
    {
        Assert.Equal(OperationId, value.GetProperty("operationId").GetString());
        Assert.Equal(DiagnosticId, value.GetProperty("diagnosticId").GetString());
        Assert.Equal("signing_secondary", value.GetProperty("diagnosticPhase").GetString());
        Assert.Equal("secondary", value.GetProperty("diagnosticLeg").GetString());
        Assert.Equal("sha256", value.GetProperty("digestAlgorithm").GetString());
        Assert.True(value.GetProperty("appendSignature").GetBoolean());
        Assert.Equal("SignerSignEx3", value.GetProperty("nativeCall").GetString());
        Assert.Equal(0x00002000, value.GetProperty("signerSignEx3Flags").GetInt32());
        Assert.Equal("SecondLegFailed", value.GetProperty("nativeReasonCode").GetString());
        Assert.Equal(ENoInterface, value.GetProperty("hresult").GetInt32());
        Assert.Equal("0x80004002", value.GetProperty("hresultHex").GetString());
        Assert.Equal("E_NOINTERFACE", value.GetProperty("hresultSymbol").GetString());
        Assert.Equal("native", value.GetProperty("hresultOrigin").GetString());
        Assert.Equal(47, value.GetProperty("legElapsedMilliseconds").GetInt64());
        Assert.Equal(WorkerProtocol.Version, value.GetProperty("workerProtocolVersion").GetInt32());
        Assert.Equal(ExpectedSummary, value.GetProperty("failureSummary").GetString());
    }

    private static void AssertExactFields(JsonElement value, IReadOnlyCollection<string> expected)
    {
        string[] actual = value.EnumerateObject().Select(static property => property.Name).ToArray();
        Assert.Equal(expected.Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    private static void AssertNoSecrets(string json, params string[] secrets)
    {
        foreach (string secret in secrets)
        {
            Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
        }
    }

    private static async Task WriteEvidenceFixtureAsync(string fileName, string content)
    {
        string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
        if (string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            return;
        }

        string fullDirectory = Path.GetFullPath(evidenceDirectory);
        Directory.CreateDirectory(fullDirectory);
        await File.WriteAllTextAsync(Path.Combine(fullDirectory, fileName), content, Encoding.UTF8);
    }

    private static string CreateTemporaryDirectory()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-DiagnosticProjection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static Dictionary<string, string> HashSourceFiles(string sourceRoot) =>
        Directory.EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories)
            .Where(static path => !path.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            .Where(static path => !path.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            .Where(static path => Path.GetExtension(path) is ".cs" or ".xaml" or ".csproj")
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static path => path,
                static path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                StringComparer.OrdinalIgnoreCase);

    private static string ResolveRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return Assert.IsType<DirectoryInfo>(directory).FullName;
    }
}
