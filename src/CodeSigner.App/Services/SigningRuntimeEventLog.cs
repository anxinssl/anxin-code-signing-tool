using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSigner.Core.Diagnostics;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;

namespace CodeSigner.App.Services;

public static class SigningRuntimeEventNames
{
    public const string WorkerProbeStart = "worker-probe-start";
    public const string WorkerProbeSucceeded = "worker-probe-succeeded";
    public const string WorkerProbeFailed = "worker-probe-failed";
    public const string BatchStart = "batch-start";
    public const string WorkerStarting = "worker-starting";
    public const string WorkerStarted = "worker-started";
    public const string WorkerStartFailed = "worker-start-failed";
    public const string StagingCreateStart = "staging-create-start";
    public const string StagingCreateDone = "staging-create-done";
    public const string SourceHashStart = "source-hash-start";
    public const string SourceHashDone = "source-hash-done";
    public const string CopyToStagingStart = "copy-to-staging-start";
    public const string CopyToStagingDone = "copy-to-staging-done";
    public const string SignerEnter = "signer-enter";
    public const string SigningPrimaryEnter = "signing-primary-enter";
    public const string SigningSecondaryEnter = "signing-secondary-enter";
    public const string VerifyingEnter = "verifying-enter";
    public const string PublishStart = "publish-start";
    public const string PublishDone = "publish-done";
    public const string BatchFailed = "batch-failed";
    public const string BatchCancelled = "batch-cancelled";
    public const string BatchCompleted = "batch-completed";
    public const string StallDetected = "stall-detected";
    public const string ItemSelected = "item-selected";
    public const string ItemDeselected = "item-deselected";
    public const string PreflightStarted = "preflight-started";
    public const string PreflightCheckCompleted = "preflight-check-completed";
    public const string PreflightCompleted = "preflight-completed";
    public const string UserActionStarted = "user-action-started";
    public const string UserActionCompleted = "user-action-completed";
    public const string UserActionRejected = "user-action-rejected";
    public const string AdmissionStarted = "admission-started";
    public const string AdmissionCompleted = "admission-completed";
    public const string DetectionStarted = "detection-started";
    public const string DetectionCompleted = "detection-completed";
    public const string PlanningStarted = "planning-started";
    public const string PlanningCompleted = "planning-completed";

    public static IReadOnlyList<string> All { get; } =
    [
        WorkerProbeStart,
        WorkerProbeSucceeded,
        WorkerProbeFailed,
        BatchStart,
        WorkerStarting,
        WorkerStarted,
        WorkerStartFailed,
        StagingCreateStart,
        StagingCreateDone,
        SourceHashStart,
        SourceHashDone,
        CopyToStagingStart,
        CopyToStagingDone,
        SignerEnter,
        SigningPrimaryEnter,
        SigningSecondaryEnter,
        VerifyingEnter,
        PublishStart,
        PublishDone,
        BatchFailed,
        BatchCancelled,
        BatchCompleted,
        StallDetected,
        ItemSelected,
        ItemDeselected,
        PreflightStarted,
        PreflightCheckCompleted,
        PreflightCompleted,
        UserActionStarted,
        UserActionCompleted,
        UserActionRejected,
        AdmissionStarted,
        AdmissionCompleted,
        DetectionStarted,
        DetectionCompleted,
        PlanningStarted,
        PlanningCompleted
    ];
}

public static class QueueAuditPhases
{
    public const string Selection = "selection";
    public const string Preflight = "preflight";
    public const string UserAction = "user-action";
    public const string Admission = "admission";
    public const string Detection = "detection";
    public const string Planning = "planning";

    internal static bool Contains(string value) => value is
        Selection or Preflight or UserAction or Admission or Detection or Planning;
}

public static class QueueAuditChecks
{
    public const string AuditWritable = "audit-writable";
    public const string SourceIdentity = "source-identity";
    public const string SourceAccess = "source-access";
    public const string Intake = "intake";
    public const string Workstation = "workstation";
    public const string FormatHandler = "format-handler";
    public const string SimplySign = "simplysign";
    public const string CertificateCatalog = "certificate-catalog";
    public const string PrimaryCertificate = "primary-certificate";
    public const string SecondaryCertificate = "secondary-certificate";
    public const string Timestamp = "timestamp";
    public const string DestinationSafety = "destination-safety";

    internal static bool Contains(string value) => value is
        AuditWritable or SourceIdentity or SourceAccess or Intake or Workstation or FormatHandler or SimplySign or
        CertificateCatalog or PrimaryCertificate or SecondaryCertificate or Timestamp or DestinationSafety;
}

public static class QueueAuditActions
{
    public const string CurrentSelection = "current-selection";
    public const string CurrentDeselection = "current-deselection";
    public const string OutputReplan = "output-replan";
    public const string ModeChange = "mode-change";
    public const string PrimaryCertificateRoleChange = "primary-certificate-role-change";
    public const string SecondaryCertificateRoleChange = "secondary-certificate-role-change";
    public const string TimestampSettingsApply = "timestamp-settings-apply";
    public const string ReadinessRefresh = "readiness-refresh";
    public const string Sign = "sign";
    public const string Retry = "retry";
    public const string Cancel = "cancel";
    public const string Remove = "remove";
    public const string ReAdd = "re-add";

    internal static bool Contains(string value) => value is
        CurrentSelection or CurrentDeselection or OutputReplan or ModeChange or
        PrimaryCertificateRoleChange or SecondaryCertificateRoleChange or
        TimestampSettingsApply or ReadinessRefresh or Sign or Retry or Cancel or Remove or ReAdd;
}

public static class QueueAuditOutcomes
{
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string Ready = "ready";
    public const string Blocked = "blocked";
    public const string Superseded = "superseded";
    public const string Cancelled = "cancelled";
    public const string Faulted = "faulted";
    public const string Completed = "completed";
    public const string Rejected = "rejected";
    public const string Accepted = "accepted";
    public const string Partial = "partial";
    public const string Supported = "supported";
    public const string Unavailable = "unavailable";
    public const string Changed = "changed";

    internal static bool Contains(string value) => value is
        Passed or Failed or Ready or Blocked or Superseded or Cancelled or Faulted or Completed or Rejected or
        Accepted or Partial or Supported or Unavailable or Changed;
}

public static class QueueAuditReasons
{
    public const string AuditLogUnavailable = "audit-log-unavailable";
    public const string SourceUnavailable = "source-unavailable";
    public const string SourceChanged = "source-changed";
    public const string SourceAccessDenied = "source-access-denied";
    public const string UnsupportedFormat = "unsupported-format";
    public const string IntakeFailed = "intake-failed";
    public const string OutputRequired = "output-required";
    public const string DestinationUnsafe = "destination-unsafe";
    public const string DestinationExists = "destination-exists";
    public const string WorkstationUnavailable = "workstation-unavailable";
    public const string HandlerUnavailable = "handler-unavailable";
    public const string ProviderUnavailable = "provider-unavailable";
    public const string CertificateCatalogUnavailable = "certificate-catalog-unavailable";
    public const string PrimaryCertificateUnavailable = "primary-certificate-unavailable";
    public const string SecondaryCertificateUnavailable = "secondary-certificate-unavailable";
    public const string TimestampUnavailable = "timestamp-unavailable";
    public const string StaleValidation = "stale-validation";
    public const string Cancelled = "cancelled";
    public const string UnexpectedFailure = "unexpected-failure";
    public const string InvalidState = "invalid-state";
    public const string Busy = "busy";
    public const string NoCurrentItem = "no-current-item";
    public const string ActionUnavailable = "action-unavailable";

    internal static bool Contains(string value) => value is
        AuditLogUnavailable or SourceUnavailable or SourceChanged or SourceAccessDenied or UnsupportedFormat or
        IntakeFailed or OutputRequired or DestinationUnsafe or DestinationExists or WorkstationUnavailable or
        HandlerUnavailable or ProviderUnavailable or CertificateCatalogUnavailable or PrimaryCertificateUnavailable or
        SecondaryCertificateUnavailable or TimestampUnavailable or StaleValidation or Cancelled or UnexpectedFailure or
        InvalidState or Busy or NoCurrentItem or ActionUnavailable;
}

internal static class SigningDiagnosticVocabulary
{
    public const string ValidatedContentProbe = "validated";

    public static string? Subject(string? value) => IsOneOf(
        value,
        WorkerSubjects.PeImage,
        WorkerSubjects.WindowsInstaller,
        WorkerSubjects.Cabinet,
        WorkerSubjects.Catalog,
        WorkerSubjects.AppPackage,
        WorkerSubjects.PowerShellScript,
        WorkerSubjects.WindowsScript);

    public static string? Capability(string? value) => IsOneOf(
        value,
        WorkerCapabilities.PeImageDualCapable,
        WorkerCapabilities.WindowsSipSingleOnly);

    public static string? Engine(string? value) => IsOneOf(value, WorkerEngines.PeImage, WorkerEngines.WindowsSip);

    public static string? Verification(string? value) =>
        IsOneOf(value, WorkerVerifications.PeImage, WorkerVerifications.WindowsSip);

    public static string? ResponseCode(string? value) => value is
        WorkerResponseCodes.Ready or
        WorkerResponseCodes.UnsupportedCommand or
        WorkerResponseCodes.ProtocolVersionMismatch or
        WorkerResponseCodes.InvalidRequest or
        WorkerResponseCodes.InvalidStagedPath or
        WorkerResponseCodes.InvalidFrame or
        WorkerResponseCodes.FrameTooLarge or
        WorkerResponseCodes.ResponseTooLarge or
        WorkerResponseCodes.HandlerFailure or
        WorkerResponseCodes.SigningCompleted or
        WorkerResponseCodes.InvalidSigningPlan or
        WorkerResponseCodes.SubjectCapabilityMismatch or
        WorkerResponseCodes.InvalidStagingOwner or
        WorkerResponseCodes.InvalidInput or
        WorkerResponseCodes.UnsupportedFileType or
        WorkerResponseCodes.CertificateNotFound or
        WorkerResponseCodes.CertificateHasNoPrivateKey or
        WorkerResponseCodes.ProviderCancelled or
        WorkerResponseCodes.TimestampUnavailable or
        WorkerResponseCodes.NativeSigningFailed or
        WorkerResponseCodes.VerifierDisagreement or
        WorkerResponseCodes.OriginalChanged or
        WorkerResponseCodes.Cancelled or
        WorkerResponseCodes.WindowsPowerShellUnavailable or
        WorkerResponseCodes.WindowsPowerShellExecutionDenied or
        WorkerResponseCodes.WindowsSipUnavailable or
        WorkerResponseCodes.SecureSipPublicationUnavailable or
        WorkerResponseCodes.PackageIncompatible or
        WorkerResponseCodes.CertificateMismatch or
        WorkerResponseCodes.ExistingSignatureRejected or
        WorkerResponseCodes.InvalidBridgeResponse
            ? value
            : null;

    public static string? ContentProbeResult(string? value) =>
        IsOneOf(value, ValidatedContentProbe, "failed", "not_available");

    public static string? Policy(string? value) => IsOneOf(value, "single", "dual");

    public static string Policy(SigningMode value) => value switch
    {
        SigningMode.Single => "single",
        SigningMode.Dual => "dual",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing mode.")
    };

    public static string? SdkVersion(string? value) =>
        value is not null && Version.TryParse(value, out Version? parsed) && parsed.ToString() == value
            ? value
            : null;

    public static string? SdkPathStatus(string? value) =>
        IsOneOf(value, "canonical_verified", "not_found", "rejected");

    public static string? PowerShellBridgeAvailability(string? value) => IsOneOf(
        value,
        "available",
        "unavailable",
        "execution_denied",
        "unsupported_version");

    public static string? ProviderFamily(string? value) =>
        IsOneOf(value, "windows_native", "windows_sip", "cng", "csp", "unknown");

    public static string? Stage(string? value) => IsOneOf(
        value,
        WorkerDiagnosticPhases.SigningPrimary,
        WorkerDiagnosticPhases.SigningSecondary,
        WorkerDiagnosticPhases.Verifying,
        WorkerDiagnosticPhases.WorkerBridge);

    public static string? ResultClass(string? value) =>
        IsOneOf(value, "success", "failure", "not_available");

    public static string? FinalVerification(string? value) =>
        IsOneOf(value, "not_started", "passed", "failed", "not_available");

    public static string HResultClass(int? value) => value switch
    {
        null => "not_available",
        < 0 => "failure",
        _ => "success"
    };

    public static string ExitClass(int? value) => value switch
    {
        null => "not_available",
        0 => "success",
        _ => "failure"
    };

    public static string ProviderFamilyForEngine(string? engine) => engine switch
    {
        WorkerEngines.PeImage => "windows_native",
        WorkerEngines.WindowsSip => "windows_sip",
        _ => "unknown"
    };

    private static string? IsOneOf(string? value, params string[] allowed) =>
        value is not null && allowed.Contains(value, StringComparer.Ordinal) ? value : null;
}

[method: JsonConstructor]
public sealed record SigningRuntimeEvent(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("timestampUtc")] DateTimeOffset TimestampUtc,
    [property: JsonPropertyName("event")] string Event,
    [property: JsonPropertyName("itemId")] string? ItemId,
    [property: JsonPropertyName("processId")] int? ProcessId,
    [property: JsonPropertyName("detail")] string? Detail,
    [property: JsonPropertyName("reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Reason = null,
    [property: JsonPropertyName("repairEligible"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    bool? RepairEligible = null,
    [property: JsonPropertyName("hresult")]
    int? HResult = null,
    [property: JsonPropertyName("nativeErrorCode"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    int? NativeErrorCode = null,
    [property: JsonPropertyName("exitCode"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    int? ExitCode = null,
    [property: JsonPropertyName("operationId")] string? OperationId = null,
    [property: JsonPropertyName("diagnosticId")] string? DiagnosticId = null,
    [property: JsonPropertyName("diagnosticPhase")] string? DiagnosticPhase = null,
    [property: JsonPropertyName("diagnosticLeg")] string? DiagnosticLeg = null,
    [property: JsonPropertyName("digestAlgorithm")] string? DigestAlgorithm = null,
    [property: JsonPropertyName("appendSignature")] bool? AppendSignature = null,
    [property: JsonPropertyName("nativeCall")] string? NativeCall = null,
    [property: JsonPropertyName("signerSignEx3Flags")] int? SignerSignEx3Flags = null,
    [property: JsonPropertyName("nativeReasonCode")] string? NativeReasonCode = null,
    [property: JsonPropertyName("hresultHex")] string? HResultHex = null,
    [property: JsonPropertyName("hresultSymbol")] string? HResultSymbol = null,
    [property: JsonPropertyName("hresultOrigin")] string? HResultOrigin = null,
    [property: JsonPropertyName("legElapsedMilliseconds")] long? LegElapsedMilliseconds = null,
    [property: JsonPropertyName("workerProtocolVersion")] int? WorkerProtocolVersion = null,
    [property: JsonPropertyName("workerExitCode")] int? WorkerExitCode = null,
    [property: JsonPropertyName("workerStderrTail")] string? WorkerStderrTail = null,
    [property: JsonPropertyName("workerStderrTruncated")] bool WorkerStderrTruncated = false,
    [property: JsonPropertyName("failureSummary")] string? FailureSummary = null,
    [property: JsonPropertyName("responseCode")] string? ResponseCode = null,
    [property: JsonPropertyName("subject")] string? Subject = null,
    [property: JsonPropertyName("capability")] string? Capability = null,
    [property: JsonPropertyName("engine")] string? Engine = null,
    [property: JsonPropertyName("verification")] string? Verification = null,
    [property: JsonPropertyName("detectedFormat")] string? DetectedFormat = null,
    [property: JsonPropertyName("contentProbeResult")] string? ContentProbeResult = null,
    [property: JsonPropertyName("requestedPolicy")] string? RequestedPolicy = null,
    [property: JsonPropertyName("effectivePolicy")] string? EffectivePolicy = null,
    [property: JsonPropertyName("selectedEngine")] string? SelectedEngine = null,
    [property: JsonPropertyName("legacyFallbackAttempt")] bool? LegacyFallbackAttempt = null,
    [property: JsonPropertyName("sdkSignToolAvailable")] bool? SdkSignToolAvailable = null,
    [property: JsonPropertyName("sdkSignToolVersion")] string? SdkSignToolVersion = null,
    [property: JsonPropertyName("sdkSignToolPathStatus")] string? SdkSignToolPathStatus = null,
    [property: JsonPropertyName("powerShellBridgeAvailability")] string? PowerShellBridgeAvailability = null,
    [property: JsonPropertyName("providerFamily")] string? ProviderFamily = null,
    [property: JsonPropertyName("structuredStage")] string? StructuredStage = null,
    [property: JsonPropertyName("hresultClass")] string? HResultClass = null,
    [property: JsonPropertyName("exitClass")] string? ExitClass = null,
    [property: JsonPropertyName("finalVerification")] string? FinalVerification = null,
    [property: JsonPropertyName("phase"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Phase = null,
    [property: JsonPropertyName("check"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Check = null,
    [property: JsonPropertyName("action"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Action = null,
    [property: JsonPropertyName("outcome"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Outcome = null);

public sealed record SigningRuntimeDiagnostic(
    string? OperationId = null,
    string? DiagnosticId = null,
    string? DiagnosticPhase = null,
    string? DiagnosticLeg = null,
    string? DigestAlgorithm = null,
    bool? AppendSignature = null,
    string? NativeCall = null,
    int? SignerSignEx3Flags = null,
    string? NativeReasonCode = null,
    int? HResult = null,
    string? HResultSymbol = null,
    string? HResultOrigin = null,
    long? LegElapsedMilliseconds = null,
    int? WorkerProtocolVersion = null,
    int? WorkerExitCode = null,
    string? WorkerStderrTail = null,
    bool WorkerStderrTruncated = false,
    string? FailureSummary = null,
    string? ResponseCode = null,
    string? Subject = null,
    string? Capability = null,
    string? Engine = null,
    string? Verification = null,
    string? DetectedFormat = null,
    string? ContentProbeResult = null,
    string? RequestedPolicy = null,
    string? EffectivePolicy = null,
    string? SelectedEngine = null,
    bool? LegacyFallbackAttempt = null,
    bool? SdkSignToolAvailable = null,
    string? SdkSignToolVersion = null,
    string? SdkSignToolPathStatus = null,
    string? PowerShellBridgeAvailability = null,
    string? ProviderFamily = null,
    string? StructuredStage = null,
    string? HResultClass = null,
    string? ExitClass = null,
    string? FinalVerification = null)
{
    public static SigningRuntimeDiagnostic FromOutputSaveFailure(int? hResult, string? operationId) => new(
        OperationId: operationId,
        NativeReasonCode: "OutputSaveFailed",
        HResult: hResult,
        HResultOrigin: WorkerHResultOrigins.Managed,
        FailureSummary: "输出文件保存失败（OutputSaveFailed），请更改输出位置",
        HResultClass: SigningDiagnosticVocabulary.HResultClass(hResult));

    public static SigningRuntimeDiagnostic FromWorkerResponse(
        WorkerResponse response,
        string? workerStderrTail = null,
        bool workerStderrTruncated = false,
        string? signingPlanJson = null)
    {
        ArgumentNullException.ThrowIfNull(response);
        SigningPlan? plan = null;
        if (!string.IsNullOrWhiteSpace(signingPlanJson))
        {
            PolicyResult<SigningPlan> parsed = SigningPlanJson.Parse(signingPlanJson);
            plan = parsed.Value;
        }

        string? subject = SigningDiagnosticVocabulary.Subject(response.Subject);
        string? capability = SigningDiagnosticVocabulary.Capability(response.Capability);
        string? engine = SigningDiagnosticVocabulary.Engine(response.Engine);
        string? verification = SigningDiagnosticVocabulary.Verification(response.Verification);
        string? requestedPolicy = plan is null
            ? null
            : SigningDiagnosticVocabulary.Policy(plan.RequestedMode);
        string? effectivePolicy = plan is null
            ? null
            : SigningDiagnosticVocabulary.Policy(plan.EffectiveMode);
        string finalVerification = response.Success && response.Code == WorkerResponseCodes.SigningCompleted
            ? "passed"
            : response.DiagnosticPhase == WorkerDiagnosticPhases.Verifying ||
                response.Code == WorkerResponseCodes.VerifierDisagreement
                ? "failed"
                : "not_started";
        return new SigningRuntimeDiagnostic(
            response.OperationId,
            response.DiagnosticId,
            response.DiagnosticPhase,
            response.DiagnosticLeg,
            response.DigestAlgorithm,
            response.AppendSignature,
            response.NativeCall,
            response.SignerSignEx3Flags,
            response.NativeReasonCode,
            response.HResult,
            response.HResultSymbol,
            response.HResultOrigin,
            response.LegElapsedMilliseconds,
            response.ProtocolVersion,
            WorkerStderrTail: workerStderrTail,
            WorkerStderrTruncated: workerStderrTruncated,
            FailureSummary: FormatFailureSummary(response),
            ResponseCode: response.Code,
            Subject: subject,
            Capability: capability,
            Engine: engine,
            Verification: verification,
            DetectedFormat: subject,
            ContentProbeResult: subject is not null && capability is not null
                ? SigningDiagnosticVocabulary.ValidatedContentProbe
                : null,
            RequestedPolicy: requestedPolicy,
            EffectivePolicy: effectivePolicy,
            SelectedEngine: engine,
            LegacyFallbackAttempt: response.LegacyFallbackAttempted,
            ProviderFamily: SigningDiagnosticVocabulary.ProviderFamilyForEngine(engine),
            StructuredStage: response.DiagnosticPhase,
            HResultClass: SigningDiagnosticVocabulary.HResultClass(response.HResult),
            ExitClass: "not_available",
            FinalVerification: finalVerification);
    }

    public static SigningRuntimeDiagnostic FromWorkerLaunchDiagnostic(
        WorkerLaunchDiagnostic diagnostic,
        string? operationId = null)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        bool failed = diagnostic.Reason != WorkerLaunchReason.Healthy;
        return new SigningRuntimeDiagnostic(
            OperationId: operationId,
            DiagnosticPhase: failed ? WorkerDiagnosticPhases.WorkerBridge : null,
            HResult: diagnostic.HResult,
            HResultOrigin: diagnostic.HResult is null ? null : WorkerHResultOrigins.WorkerBridge,
            WorkerExitCode: diagnostic.ExitCode,
            WorkerStderrTail: diagnostic.WorkerStderrTail,
            WorkerStderrTruncated: diagnostic.WorkerStderrTruncated,
            FailureSummary: failed ? $"Worker 通信失败 / {diagnostic.ReasonCode}" : null,
            StructuredStage: failed ? WorkerDiagnosticPhases.WorkerBridge : null,
            HResultClass: SigningDiagnosticVocabulary.HResultClass(diagnostic.HResult),
            ExitClass: SigningDiagnosticVocabulary.ExitClass(diagnostic.ExitCode),
            FinalVerification: "not_available");
    }

    internal SigningRuntimeDiagnostic Redact()
    {
        RedactedDiagnosticText stderr = WorkerStderrTail is null
            ? new RedactedDiagnosticText(null, false)
            : SigningDiagnosticRedactor.RedactWorkerStderrTail(Encoding.UTF8.GetBytes(WorkerStderrTail));
        int? hResult = HResult;
        return this with
        {
            OperationId = IsLowerHexIdentifier(OperationId) ? OperationId : null,
            DiagnosticId = IsLowerHexIdentifier(DiagnosticId) ? DiagnosticId : null,
            DiagnosticPhase = IsOneOf(
                DiagnosticPhase,
                WorkerDiagnosticPhases.SigningPrimary,
                WorkerDiagnosticPhases.SigningSecondary,
                WorkerDiagnosticPhases.Verifying,
                WorkerDiagnosticPhases.WorkerBridge),
            DiagnosticLeg = IsOneOf(DiagnosticLeg, WorkerDiagnosticLegs.Primary, WorkerDiagnosticLegs.Secondary),
            DigestAlgorithm = IsOneOf(DigestAlgorithm, WorkerDigestAlgorithms.Sha1, WorkerDigestAlgorithms.Sha256),
            NativeCall = IsOneOf(NativeCall, WorkerNativeCalls.SignerSignEx3),
            SignerSignEx3Flags = SignerSignEx3Flags is >= 0 ? SignerSignEx3Flags : null,
            NativeReasonCode = SigningDiagnosticRedactor.RedactText(NativeReasonCode),
            HResult = hResult,
            HResultSymbol = SigningDiagnosticRedactor.RedactText(HResultSymbol, 64),
            HResultOrigin = IsOneOf(
                HResultOrigin,
                WorkerHResultOrigins.Native,
                WorkerHResultOrigins.Managed,
                WorkerHResultOrigins.WorkerBridge),
            LegElapsedMilliseconds = LegElapsedMilliseconds is >= 0 ? LegElapsedMilliseconds : null,
            WorkerProtocolVersion = WorkerProtocolVersion == WorkerProtocol.Version
                ? WorkerProtocolVersion
                : null,
            WorkerStderrTail = stderr.Value,
            WorkerStderrTruncated = WorkerStderrTail is not null &&
                (WorkerStderrTruncated || stderr.Truncated),
            FailureSummary = SigningDiagnosticRedactor.RedactText(FailureSummary),
            ResponseCode = SigningDiagnosticVocabulary.ResponseCode(ResponseCode),
            Subject = SigningDiagnosticVocabulary.Subject(Subject),
            Capability = SigningDiagnosticVocabulary.Capability(Capability),
            Engine = SigningDiagnosticVocabulary.Engine(Engine),
            Verification = SigningDiagnosticVocabulary.Verification(Verification),
            DetectedFormat = SigningDiagnosticVocabulary.Subject(DetectedFormat),
            ContentProbeResult = SigningDiagnosticVocabulary.ContentProbeResult(ContentProbeResult),
            RequestedPolicy = SigningDiagnosticVocabulary.Policy(RequestedPolicy),
            EffectivePolicy = SigningDiagnosticVocabulary.Policy(EffectivePolicy),
            SelectedEngine = SigningDiagnosticVocabulary.Engine(SelectedEngine),
            SdkSignToolVersion = SigningDiagnosticVocabulary.SdkVersion(SdkSignToolVersion),
            SdkSignToolPathStatus = SigningDiagnosticVocabulary.SdkPathStatus(SdkSignToolPathStatus),
            PowerShellBridgeAvailability = SigningDiagnosticVocabulary.PowerShellBridgeAvailability(
                PowerShellBridgeAvailability),
            ProviderFamily = SigningDiagnosticVocabulary.ProviderFamily(ProviderFamily),
            StructuredStage = SigningDiagnosticVocabulary.Stage(StructuredStage),
            HResultClass = SigningDiagnosticVocabulary.ResultClass(HResultClass),
            ExitClass = SigningDiagnosticVocabulary.ResultClass(ExitClass),
            FinalVerification = SigningDiagnosticVocabulary.FinalVerification(FinalVerification)
        };
    }

    private static string? FormatFailureSummary(WorkerResponse response)
    {
        if (string.Equals(response.NativeReasonCode, "UnsupportedKeyAlgorithm", StringComparison.Ordinal))
        {
            return "密钥算法不受 PE 签名引擎支持，符合自动 PE 恢复条件";
        }

        string? typed = response.Code switch
        {
            WorkerResponseCodes.WindowsPowerShellUnavailable => "Windows PowerShell 5.1 签名桥不可用",
            WorkerResponseCodes.WindowsPowerShellExecutionDenied => "Windows PowerShell 5.1 签名桥被系统策略阻止",
            WorkerResponseCodes.WindowsSipUnavailable => "此格式没有可用的 Windows 签名处理程序",
            WorkerResponseCodes.SecureSipPublicationUnavailable => "当前系统无法安全发布 SIP 签名结果",
            WorkerResponseCodes.PackageIncompatible => "应用包结构或摘要策略不兼容",
            WorkerResponseCodes.CertificateMismatch => "证书主题与应用包发布者不匹配",
            WorkerResponseCodes.CertificateNotFound => "未找到所选签名证书",
            WorkerResponseCodes.CertificateHasNoPrivateKey => "所选证书没有可用私钥",
            WorkerResponseCodes.ExistingSignatureRejected => "现有签名状态不允许覆盖",
            WorkerResponseCodes.ProviderCancelled => "签名提供程序操作已取消",
            WorkerResponseCodes.TimestampUnavailable => "RFC 3161 时间戳不可用",
            WorkerResponseCodes.VerifierDisagreement => "最终签名验证失败",
            WorkerResponseCodes.InvalidBridgeResponse => "Windows 签名桥返回无效结果",
            WorkerResponseCodes.NativeSigningFailed when response.Engine == WorkerEngines.WindowsSip =>
                "Windows 签名处理程序执行失败",
            WorkerResponseCodes.OriginalChanged => "原始文件在签名期间发生变更",
            WorkerResponseCodes.Cancelled => "签名操作已取消",
            WorkerResponseCodes.InvalidInput => "签名输入无效",
            WorkerResponseCodes.HandlerFailure when response.Engine == WorkerEngines.WindowsSip =>
                "Windows 签名处理程序发生故障",
            _ => null
        };
        if (typed is not null)
        {
            return typed;
        }

        if (response.DiagnosticPhase == WorkerDiagnosticPhases.SigningSecondary &&
            response.DiagnosticLeg == WorkerDiagnosticLegs.Secondary &&
            response.DigestAlgorithm == WorkerDigestAlgorithms.Sha256 &&
            response.AppendSignature == true &&
            response.NativeCall == WorkerNativeCalls.SignerSignEx3)
        {
            return $"追加 SHA-256 签名失败 / SignerSignEx3 / {FormatHResult(response.HResult, response.HResultSymbol)}";
        }

        return response.DiagnosticPhase switch
        {
            WorkerDiagnosticPhases.SigningPrimary =>
                $"SHA-1 主签名失败 / {FormatHResult(response.HResult, response.HResultSymbol)}",
            WorkerDiagnosticPhases.Verifying => "最终签名验证失败",
            WorkerDiagnosticPhases.WorkerBridge => "Worker 通信失败",
            _ => "签名失败"
        };
    }

    private static string FormatHResult(int? hResult, string? symbol)
    {
        if (hResult is null)
        {
            return "HRESULT 未提供";
        }

        string value = $"0x{unchecked((uint)hResult.Value):X8}";
        return string.IsNullOrWhiteSpace(symbol) ? value : $"{value} ({symbol})";
    }

    private static bool IsLowerHexIdentifier(string? value) =>
        value is { Length: 32 } && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string? IsOneOf(string? value, params string[] allowed) =>
        value is not null && allowed.Contains(value, StringComparer.Ordinal) ? value : null;
}

public sealed record SigningDiagnosticExportContext(
    string? DiagnosticLogPath = null,
    long? SourceSizeBytes = null,
    long? StagedSizeBytes = null,
    int? SignatureCountBefore = null,
    int? SignatureCountAfter = null,
    string? SignatureAlgorithmsBefore = null,
    string? SignatureAlgorithmsAfter = null,
    string? VerificationState = null,
    string? ProviderName = null,
    int? ProviderType = null,
    int? KeySpec = null,
    Uri? TimestampUri = null,
    string? DetectedFormat = null,
    string? ContentProbeResult = null,
    string? RequestedPolicy = null,
    string? EffectivePolicy = null,
    string? SelectedEngine = null,
    bool? LegacyFallbackAttempt = null,
    bool? SdkSignToolAvailable = null,
    string? SdkSignToolVersion = null,
    string? SdkSignToolPathStatus = null,
    string? PowerShellBridgeAvailability = null,
    string? ProviderFamily = null,
    string? StructuredStage = null,
    string? HResultClass = null,
    string? ExitClass = null,
    string? FinalVerification = null);

public static class SigningDiagnosticExportProjection
{
    public static IReadOnlyDictionary<string, object?> Create(
        SigningRuntimeEvent runtimeEvent,
        SigningDiagnosticExportContext context)
    {
        ArgumentNullException.ThrowIfNull(runtimeEvent);
        ArgumentNullException.ThrowIfNull(context);
        string? timestampScheme = context.TimestampUri?.Scheme.ToLowerInvariant();
        if (timestampScheme is not ("http" or "https"))
        {
            timestampScheme = null;
        }

        string? timestampHost = context.TimestampUri is null
            ? null
            : SigningDiagnosticRedactor.RedactText(context.TimestampUri.IdnHost.ToLowerInvariant(), 253);
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = 3,
            ["timestampUtc"] = runtimeEvent.TimestampUtc.ToUniversalTime(),
            ["event"] = runtimeEvent.Event,
            ["itemId"] = runtimeEvent.ItemId,
            ["processId"] = runtimeEvent.ProcessId,
            ["detail"] = runtimeEvent.Detail,
            ["operationId"] = runtimeEvent.OperationId,
            ["diagnosticId"] = runtimeEvent.DiagnosticId,
            ["diagnosticPhase"] = runtimeEvent.DiagnosticPhase,
            ["diagnosticLeg"] = runtimeEvent.DiagnosticLeg,
            ["digestAlgorithm"] = runtimeEvent.DigestAlgorithm,
            ["appendSignature"] = runtimeEvent.AppendSignature,
            ["nativeCall"] = runtimeEvent.NativeCall,
            ["signerSignEx3Flags"] = runtimeEvent.SignerSignEx3Flags,
            ["nativeReasonCode"] = runtimeEvent.NativeReasonCode,
            ["hresult"] = runtimeEvent.HResult,
            ["hresultHex"] = runtimeEvent.HResultHex,
            ["hresultSymbol"] = runtimeEvent.HResultSymbol,
            ["hresultOrigin"] = runtimeEvent.HResultOrigin,
            ["legElapsedMilliseconds"] = runtimeEvent.LegElapsedMilliseconds,
            ["workerProtocolVersion"] = runtimeEvent.WorkerProtocolVersion,
            ["workerExitCode"] = runtimeEvent.WorkerExitCode,
            ["workerStderrTail"] = runtimeEvent.WorkerStderrTail,
            ["workerStderrTruncated"] = runtimeEvent.WorkerStderrTruncated,
            ["failureSummary"] = runtimeEvent.FailureSummary,
            ["responseCode"] = runtimeEvent.ResponseCode,
            ["subject"] = runtimeEvent.Subject,
            ["capability"] = runtimeEvent.Capability,
            ["engine"] = runtimeEvent.Engine,
            ["verification"] = runtimeEvent.Verification,
            ["detectedFormat"] = SigningDiagnosticVocabulary.Subject(context.DetectedFormat) ??
                runtimeEvent.DetectedFormat,
            ["contentProbeResult"] = SigningDiagnosticVocabulary.ContentProbeResult(context.ContentProbeResult) ??
                runtimeEvent.ContentProbeResult,
            ["requestedPolicy"] = SigningDiagnosticVocabulary.Policy(context.RequestedPolicy) ??
                runtimeEvent.RequestedPolicy,
            ["effectivePolicy"] = SigningDiagnosticVocabulary.Policy(context.EffectivePolicy) ??
                runtimeEvent.EffectivePolicy,
            ["selectedEngine"] = SigningDiagnosticVocabulary.Engine(context.SelectedEngine) ??
                runtimeEvent.SelectedEngine,
            ["legacyFallbackAttempt"] = context.LegacyFallbackAttempt ?? runtimeEvent.LegacyFallbackAttempt,
            ["sdkSignToolAvailable"] = context.SdkSignToolAvailable ?? runtimeEvent.SdkSignToolAvailable,
            ["sdkSignToolVersion"] = SigningDiagnosticVocabulary.SdkVersion(context.SdkSignToolVersion) ??
                runtimeEvent.SdkSignToolVersion,
            ["sdkSignToolPathStatus"] = SigningDiagnosticVocabulary.SdkPathStatus(context.SdkSignToolPathStatus) ??
                runtimeEvent.SdkSignToolPathStatus,
            ["powerShellBridgeAvailability"] = SigningDiagnosticVocabulary.PowerShellBridgeAvailability(
                context.PowerShellBridgeAvailability) ?? runtimeEvent.PowerShellBridgeAvailability,
            ["providerFamily"] = SigningDiagnosticVocabulary.ProviderFamily(context.ProviderFamily) ??
                runtimeEvent.ProviderFamily,
            ["structuredStage"] = SigningDiagnosticVocabulary.Stage(context.StructuredStage) ??
                runtimeEvent.StructuredStage,
            ["hresultClass"] = SigningDiagnosticVocabulary.ResultClass(context.HResultClass) ??
                runtimeEvent.HResultClass ?? SigningDiagnosticVocabulary.HResultClass(runtimeEvent.HResult),
            ["exitClass"] = SigningDiagnosticVocabulary.ResultClass(context.ExitClass) ??
                runtimeEvent.ExitClass ?? SigningDiagnosticVocabulary.ExitClass(runtimeEvent.WorkerExitCode),
            ["finalVerification"] = SigningDiagnosticVocabulary.FinalVerification(context.FinalVerification) ??
                runtimeEvent.FinalVerification,
            ["diagnosticLogFileName"] = SigningDiagnosticRedactor.RedactFileName(context.DiagnosticLogPath),
            ["sourceSizeBytes"] = NonNegative(context.SourceSizeBytes),
            ["stagedSizeBytes"] = NonNegative(context.StagedSizeBytes),
            ["signatureCountBefore"] = NonNegative(context.SignatureCountBefore),
            ["signatureCountAfter"] = NonNegative(context.SignatureCountAfter),
            ["signatureAlgorithmsBefore"] = SignatureAlgorithms(context.SignatureAlgorithmsBefore),
            ["signatureAlgorithmsAfter"] = SignatureAlgorithms(context.SignatureAlgorithmsAfter),
            ["verificationState"] = VerificationState(context.VerificationState),
            ["providerName"] = SigningDiagnosticRedactor.RedactText(context.ProviderName, 256),
            ["providerType"] = NonNegative(context.ProviderType),
            ["keySpec"] = NonNegative(context.KeySpec),
            ["timestampScheme"] = timestampScheme,
            ["timestampHost"] = timestampHost
        };
    }

    private static long? NonNegative(long? value) => value is >= 0 ? value : null;

    private static int? NonNegative(int? value) => value is >= 0 ? value : null;

    private static string? SignatureAlgorithms(string? value) => value is
        "sha1" or "sha256" or "sha1,sha256" ? value : null;

    private static string? VerificationState(string? value) => value is
        "not_started" or "passed" or "failed" or "not_available" ? value : null;
}

public sealed class SigningRuntimeEventLog
{
    private const string RuntimeLogPrefix = "CodeSigner-runtime-";
    private readonly object sync = new();
    private readonly Dictionary<string, QueueOperationState> queueOperations = new(StringComparer.Ordinal);
    private SigningRuntimeEvent? lastEvent;

    public SigningRuntimeEventLog(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        string fullRoot = System.IO.Path.GetFullPath(root);
        Directory.CreateDirectory(fullRoot);
        Path = System.IO.Path.Combine(
            fullRoot,
            $"{RuntimeLogPrefix}{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}-{Environment.ProcessId}-{Guid.NewGuid():N}.jsonl");
    }

    public string Path { get; }

    public SigningRuntimeEvent? LastEvent
    {
        get
        {
            lock (sync)
            {
                return lastEvent;
            }
        }
    }

    public static string DefaultDiagnosticsRoot => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodeSigner",
        "Diagnostics");

    public bool Write(
        string eventName,
        string? itemId = null,
        int? processId = null,
        string? detail = null,
        WorkerLaunchDiagnostic? diagnostic = null,
        SigningRuntimeDiagnostic? signingDiagnostic = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);
        SigningRuntimeDiagnostic? projected = signingDiagnostic ??
            (diagnostic is null ? null : SigningRuntimeDiagnostic.FromWorkerLaunchDiagnostic(diagnostic));
        SigningRuntimeEvent entry = CreateEvent(
            eventName,
            itemId,
            processId,
            detail,
            projected,
            launchDiagnostic: diagnostic);
        lock (sync)
        {
            return TryAppend(JsonSerializer.SerializeToUtf8Bytes(entry), entry);
        }
    }

    public bool WriteQueueEvent(
        string eventName,
        string? itemId,
        string operationId,
        string phase,
        string? check = null,
        string? action = null,
        string? outcome = null,
        string? reason = null)
    {
        if (!TryValidateQueueEvent(eventName, itemId, operationId, phase, check, action, outcome, reason))
        {
            return false;
        }

        DateTimeOffset timestampUtc = DateTimeOffset.UtcNow;
        var entry = new SigningRuntimeEvent(
            5,
            timestampUtc,
            eventName,
            itemId,
            null,
            null,
            Reason: reason,
            OperationId: operationId,
            Phase: phase,
            Check: check,
            Action: action,
            Outcome: outcome);
        var payload = new QueueAuditEventPayload(
            5,
            timestampUtc,
            eventName,
            itemId,
            operationId,
            phase,
            check,
            action,
            outcome,
            reason);

        lock (sync)
        {
            if (!AllowsQueueTransition(eventName, itemId, operationId, action))
            {
                return false;
            }

            if (!TryAppend(JsonSerializer.SerializeToUtf8Bytes(payload), entry, updateLastEvent: false))
            {
                return false;
            }

            RecordQueueTransition(eventName, itemId, operationId, action);
            return true;
        }
    }

    public bool CheckQueueAuditHealth()
    {
        lock (sync)
        {
            try
            {
                using FileStream stream = new(
                    Path,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.ReadWrite,
                    bufferSize: 1,
                    FileOptions.WriteThrough);
                stream.Flush(flushToDisk: true);
                return true;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    internal static SigningRuntimeEvent CreateEvent(
        string eventName,
        string? itemId,
        int? processId,
        string? detail,
        SigningRuntimeDiagnostic? diagnostic,
        DateTimeOffset? timestampUtc = null,
        WorkerLaunchDiagnostic? launchDiagnostic = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);
        SigningRuntimeDiagnostic safe = (diagnostic ?? new SigningRuntimeDiagnostic()).Redact();
        var entry = new SigningRuntimeEvent(
            3,
            (timestampUtc ?? DateTimeOffset.UtcNow).ToUniversalTime(),
            SigningDiagnosticRedactor.RedactText(eventName) ?? SigningRuntimeEventNames.BatchFailed,
            NormalizeItemId(itemId),
            processId is > 0 ? processId : null,
            RedactPersistenceText(detail),
            Reason: launchDiagnostic?.ReasonCode,
            RepairEligible: launchDiagnostic?.RepairEligible,
            HResult: safe.HResult,
            NativeErrorCode: launchDiagnostic?.NativeErrorCode,
            ExitCode: launchDiagnostic?.ExitCode,
            OperationId: safe.OperationId,
            DiagnosticId: safe.DiagnosticId,
            DiagnosticPhase: safe.DiagnosticPhase,
            DiagnosticLeg: safe.DiagnosticLeg,
            DigestAlgorithm: safe.DigestAlgorithm,
            AppendSignature: safe.AppendSignature,
            NativeCall: safe.NativeCall,
            SignerSignEx3Flags: safe.SignerSignEx3Flags,
            NativeReasonCode: safe.NativeReasonCode,
            HResultHex: safe.HResult is int value ? $"0x{unchecked((uint)value):X8}" : null,
            HResultSymbol: safe.HResultSymbol,
            HResultOrigin: safe.HResultOrigin,
            LegElapsedMilliseconds: safe.LegElapsedMilliseconds,
            WorkerProtocolVersion: safe.WorkerProtocolVersion,
            WorkerExitCode: safe.WorkerExitCode,
            WorkerStderrTail: safe.WorkerStderrTail,
            WorkerStderrTruncated: safe.WorkerStderrTruncated,
            FailureSummary: safe.FailureSummary,
            ResponseCode: safe.ResponseCode,
            Subject: safe.Subject,
            Capability: safe.Capability,
            Engine: safe.Engine,
            Verification: safe.Verification,
            DetectedFormat: safe.DetectedFormat,
            ContentProbeResult: safe.ContentProbeResult,
            RequestedPolicy: safe.RequestedPolicy,
            EffectivePolicy: safe.EffectivePolicy,
            SelectedEngine: safe.SelectedEngine,
            LegacyFallbackAttempt: safe.LegacyFallbackAttempt,
            SdkSignToolAvailable: safe.SdkSignToolAvailable,
            SdkSignToolVersion: safe.SdkSignToolVersion,
            SdkSignToolPathStatus: safe.SdkSignToolPathStatus,
            PowerShellBridgeAvailability: safe.PowerShellBridgeAvailability,
            ProviderFamily: safe.ProviderFamily,
            StructuredStage: safe.StructuredStage,
            HResultClass: safe.HResultClass,
            ExitClass: safe.ExitClass,
            FinalVerification: safe.FinalVerification);
        return entry;
    }

    public IReadOnlyList<SigningRuntimeEvent> Read()
    {
        lock (sync)
        {
            return ReadAll(Path);
        }
    }

    public static IReadOnlyList<SigningRuntimeEvent> ReadAll(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = System.IO.Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return [];
        }

        var events = new List<SigningRuntimeEvent>();
        foreach (string line in File.ReadLines(fullPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            SigningRuntimeEvent entry = JsonSerializer.Deserialize<SigningRuntimeEvent>(line)
                ?? throw new InvalidDataException("The runtime event line was empty.");
            if (entry.SchemaVersion is not 1 and not 2 and not 3 and not 4 and not 5)
            {
                throw new InvalidDataException("Unsupported runtime event schema.");
            }

            events.Add(entry);
        }

        return events;
    }

    public async Task MonitorForStallAsync(
        TimeSpan threshold,
        CancellationToken cancellationToken)
    {
        if (threshold <= TimeSpan.Zero || threshold == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(threshold));
        }

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SigningRuntimeEvent? observed = LastEvent;
            if (observed is null ||
                string.Equals(observed.Event, SigningRuntimeEventNames.StallDetected, StringComparison.Ordinal))
            {
                await Task.Delay(threshold, cancellationToken).ConfigureAwait(false);
                continue;
            }

            TimeSpan elapsed = DateTimeOffset.UtcNow - observed.TimestampUtc;
            TimeSpan remaining = elapsed >= threshold ? TimeSpan.Zero : threshold - elapsed;
            if (remaining > TimeSpan.Zero)
            {
                await Task.Delay(remaining, cancellationToken).ConfigureAwait(false);
            }

            if (Equals(LastEvent, observed))
            {
                Write(
                    SigningRuntimeEventNames.StallDetected,
                    observed.ItemId,
                    observed.ProcessId,
                    observed.Event);
                return;
            }
        }
    }

    private static string? NormalizeItemId(string? itemId)
    {
        string? redacted = SigningDiagnosticRedactor.RedactText(itemId);
        return redacted is not null && redacted.Length > 0 &&
            redacted.All(static character => character is >= '0' and <= '9')
                ? redacted
                : null;
    }

    private static string? RedactPersistenceText(string? value)
    {
        string? redacted = SigningDiagnosticRedactor.RedactText(value);
        return value is not null && !string.Equals(value, redacted, StringComparison.Ordinal)
            ? SigningDiagnosticRedactor.RedactedValue
            : redacted;
    }

    private bool TryAppend(byte[] payload, SigningRuntimeEvent entry, bool updateLastEvent = true)
    {
        try
        {
            using FileStream stream = new(
                Path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.ReadWrite,
                bufferSize: 4096,
                FileOptions.WriteThrough);
            stream.Write(payload);
            stream.WriteByte((byte)'\n');
            stream.Flush(flushToDisk: true);
            if (updateLastEvent)
            {
                lastEvent = entry;
            }
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool TryValidateQueueEvent(
        string eventName,
        string? itemId,
        string operationId,
        string phase,
        string? check,
        string? action,
        string? outcome,
        string? reason)
    {
        if (!IsOperationId(operationId) || !QueueAuditPhases.Contains(phase) ||
            (check is not null && !QueueAuditChecks.Contains(check)) ||
            (action is not null && !QueueAuditActions.Contains(action)) ||
            (outcome is not null && !QueueAuditOutcomes.Contains(outcome)) ||
            (reason is not null && !QueueAuditReasons.Contains(reason)))
        {
            return false;
        }

        return eventName switch
        {
            SigningRuntimeEventNames.AdmissionStarted =>
                itemId is null && phase == QueueAuditPhases.Admission && check is null && action is null &&
                outcome is null && reason is null,
            SigningRuntimeEventNames.AdmissionCompleted =>
                itemId is null && phase == QueueAuditPhases.Admission && check is null && action is null &&
                IsAdmissionTerminal(outcome, reason),
            SigningRuntimeEventNames.DetectionStarted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Detection && check is null && action is null &&
                outcome is null && reason is null,
            SigningRuntimeEventNames.DetectionCompleted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Detection && check is null && action is null &&
                IsDetectionTerminal(outcome, reason),
            SigningRuntimeEventNames.PlanningStarted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Planning && check is null && action is null &&
                outcome is null && reason is null,
            SigningRuntimeEventNames.PlanningCompleted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Planning && check is null && action is null &&
                IsPlanningTerminal(outcome, reason),
            SigningRuntimeEventNames.ItemSelected or SigningRuntimeEventNames.ItemDeselected =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Selection && check is null && action is null &&
                outcome is null && reason is null,
            SigningRuntimeEventNames.PreflightStarted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Preflight && check is null && action is null &&
                outcome is null && reason is null,
            SigningRuntimeEventNames.PreflightCheckCompleted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Preflight && check is not null && action is null &&
                outcome is QueueAuditOutcomes.Passed or QueueAuditOutcomes.Failed,
            SigningRuntimeEventNames.PreflightCompleted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.Preflight && check is null && action is null &&
                outcome is QueueAuditOutcomes.Ready or QueueAuditOutcomes.Blocked or QueueAuditOutcomes.Superseded or
                    QueueAuditOutcomes.Cancelled or QueueAuditOutcomes.Faulted,
            SigningRuntimeEventNames.UserActionStarted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.UserAction && check is null && action is not null &&
                outcome is null && reason is null,
            SigningRuntimeEventNames.UserActionCompleted =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.UserAction && check is null && action is not null &&
                outcome is QueueAuditOutcomes.Completed or QueueAuditOutcomes.Cancelled,
            SigningRuntimeEventNames.UserActionRejected =>
                IsNumericItemId(itemId) && phase == QueueAuditPhases.UserAction && check is null && action is not null &&
                outcome == QueueAuditOutcomes.Rejected && reason is not null,
            _ => false
        };
    }

    private static bool IsAdmissionTerminal(string? outcome, string? reason) =>
        (outcome is QueueAuditOutcomes.Accepted or QueueAuditOutcomes.Partial && reason is null) ||
        (outcome == QueueAuditOutcomes.Rejected && reason is not null);

    private static bool IsDetectionTerminal(string? outcome, string? reason) =>
        (outcome == QueueAuditOutcomes.Supported && reason is null) ||
        (outcome == QueueAuditOutcomes.Blocked && reason == QueueAuditReasons.UnsupportedFormat) ||
        (outcome == QueueAuditOutcomes.Unavailable &&
            reason is QueueAuditReasons.SourceUnavailable or QueueAuditReasons.SourceAccessDenied) ||
        (outcome == QueueAuditOutcomes.Changed && reason == QueueAuditReasons.SourceChanged) ||
        (outcome == QueueAuditOutcomes.Superseded && reason == QueueAuditReasons.StaleValidation) ||
        (outcome == QueueAuditOutcomes.Cancelled && reason == QueueAuditReasons.Cancelled) ||
        (outcome == QueueAuditOutcomes.Faulted && reason == QueueAuditReasons.UnexpectedFailure);

    private static bool IsPlanningTerminal(string? outcome, string? reason) =>
        (outcome == QueueAuditOutcomes.Ready && reason is null) ||
        (outcome == QueueAuditOutcomes.Blocked && reason is QueueAuditReasons.OutputRequired or
            QueueAuditReasons.DestinationUnsafe or QueueAuditReasons.DestinationExists or QueueAuditReasons.HandlerUnavailable or
            QueueAuditReasons.WorkstationUnavailable or QueueAuditReasons.ProviderUnavailable or
            QueueAuditReasons.CertificateCatalogUnavailable or QueueAuditReasons.PrimaryCertificateUnavailable or
            QueueAuditReasons.SecondaryCertificateUnavailable or QueueAuditReasons.TimestampUnavailable or
            QueueAuditReasons.SourceUnavailable or QueueAuditReasons.SourceChanged) ||
        (outcome == QueueAuditOutcomes.Superseded && reason == QueueAuditReasons.StaleValidation) ||
        (outcome == QueueAuditOutcomes.Cancelled && reason == QueueAuditReasons.Cancelled) ||
        (outcome == QueueAuditOutcomes.Faulted && reason == QueueAuditReasons.UnexpectedFailure);

    private bool AllowsQueueTransition(string eventName, string? itemId, string operationId, string? action)
    {
        if (eventName is SigningRuntimeEventNames.ItemSelected or SigningRuntimeEventNames.ItemDeselected)
        {
            return !queueOperations.ContainsKey(operationId);
        }

        if (eventName is SigningRuntimeEventNames.AdmissionStarted or SigningRuntimeEventNames.DetectionStarted or
            SigningRuntimeEventNames.PlanningStarted or SigningRuntimeEventNames.PreflightStarted or
            SigningRuntimeEventNames.UserActionStarted)
        {
            return !queueOperations.ContainsKey(operationId);
        }

        return queueOperations.TryGetValue(operationId, out QueueOperationState? state) &&
            !state.Terminal &&
            state.ItemId == itemId &&
            ((eventName is SigningRuntimeEventNames.AdmissionCompleted && state.Kind == QueueOperationKind.Admission) ||
             (eventName is SigningRuntimeEventNames.DetectionCompleted && state.Kind == QueueOperationKind.Detection) ||
             (eventName is SigningRuntimeEventNames.PlanningCompleted && state.Kind == QueueOperationKind.Planning) ||
             (eventName is SigningRuntimeEventNames.PreflightCheckCompleted or SigningRuntimeEventNames.PreflightCompleted &&
                state.Kind == QueueOperationKind.Preflight) ||
             (eventName is SigningRuntimeEventNames.UserActionCompleted or SigningRuntimeEventNames.UserActionRejected &&
                state.Kind == QueueOperationKind.UserAction && state.Action == action));
    }

    private void RecordQueueTransition(string eventName, string? itemId, string operationId, string? action)
    {
        if (eventName is SigningRuntimeEventNames.ItemSelected or SigningRuntimeEventNames.ItemDeselected)
        {
            queueOperations.Add(operationId, new QueueOperationState(itemId, QueueOperationKind.Selection, true, null));
            return;
        }

        if (eventName is SigningRuntimeEventNames.AdmissionStarted or SigningRuntimeEventNames.DetectionStarted or
            SigningRuntimeEventNames.PlanningStarted or SigningRuntimeEventNames.PreflightStarted)
        {
            queueOperations.Add(operationId, new QueueOperationState(itemId, GetLifecycleKind(eventName), false, null));
            return;
        }

        if (eventName == SigningRuntimeEventNames.UserActionStarted)
        {
            queueOperations.Add(operationId, new QueueOperationState(itemId, QueueOperationKind.UserAction, false, action));
            return;
        }

        if (eventName is SigningRuntimeEventNames.AdmissionCompleted or SigningRuntimeEventNames.DetectionCompleted or
            SigningRuntimeEventNames.PlanningCompleted or SigningRuntimeEventNames.PreflightCompleted or
            SigningRuntimeEventNames.UserActionCompleted or SigningRuntimeEventNames.UserActionRejected)
        {
            QueueOperationState state = queueOperations[operationId];
            queueOperations[operationId] = state with { Terminal = true };
        }
    }

    private static QueueOperationKind GetLifecycleKind(string eventName) => eventName switch
    {
        SigningRuntimeEventNames.AdmissionStarted => QueueOperationKind.Admission,
        SigningRuntimeEventNames.DetectionStarted => QueueOperationKind.Detection,
        SigningRuntimeEventNames.PlanningStarted => QueueOperationKind.Planning,
        SigningRuntimeEventNames.PreflightStarted => QueueOperationKind.Preflight,
        _ => throw new ArgumentOutOfRangeException(nameof(eventName), eventName, "Unknown lifecycle start event.")
    };

    private static bool IsNumericItemId(string? value) =>
        !string.IsNullOrEmpty(value) && value.All(static character => character is >= '0' and <= '9');

    private static bool IsOperationId(string value) =>
        value is { Length: 32 } && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private enum QueueOperationKind
    {
        Selection,
        Admission,
        Detection,
        Planning,
        Preflight,
        UserAction
    }

    private sealed record QueueOperationState(
        string? ItemId,
        QueueOperationKind Kind,
        bool Terminal,
        string? Action);

    private sealed record QueueAuditEventPayload(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("timestampUtc")] DateTimeOffset TimestampUtc,
        [property: JsonPropertyName("event")] string Event,
        [property: JsonPropertyName("itemId")] string? ItemId,
        [property: JsonPropertyName("operationId")] string OperationId,
        [property: JsonPropertyName("phase")] string Phase,
        [property: JsonPropertyName("check"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Check,
        [property: JsonPropertyName("action"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Action,
        [property: JsonPropertyName("outcome"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Outcome,
        [property: JsonPropertyName("reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason);
}
