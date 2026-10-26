using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSigner.Core.Signing;

namespace CodeSigner.Core.Worker;

#pragma warning disable CA1720 // Signed is the required protocol outcome term.
public enum WorkerSigningOutcome
{
    Signed,
    SkippedExistingSignature,
    Failure
}
#pragma warning restore CA1720

public enum WorkerExecutionRoute
{
    ProductPe,
    SdkSignTool,
    WindowsSip,
    Skip
}

public enum WorkerFailureCode
{
    HandlerFailure,
    InvalidSigningPlan,
    SubjectCapabilityMismatch,
    InvalidStagingOwner,
    InvalidInput,
    UnsupportedFileType,
    CertificateNotFound,
    CertificateHasNoPrivateKey,
    ProviderCancelled,
    TimestampUnavailable,
    NativeSigningFailed,
    VerifierDisagreement,
    OriginalChanged,
    Cancelled,
    WindowsPowerShellUnavailable,
    WindowsPowerShellExecutionDenied,
    WindowsSipUnavailable,
    SecureSipPublicationUnavailable,
    PackageIncompatible,
    CertificateMismatch,
    ExistingSignatureRejected,
    InvalidBridgeResponse,
    SdkCandidateChanged,
    SdkStartFailed,
    SdkTimedOut,
    SdkExitFailed,
    SdkVerificationFailed
}

// This identity is untrusted session input. The Worker must revalidate it before execution.
public sealed record WorkerSdkCandidateIdentity(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("sdkVersion")] string SdkVersion,
    [property: JsonPropertyName("productVersion")] string ProductVersion,
    [property: JsonPropertyName("publisher")] string Publisher,
    [property: JsonPropertyName("companyName")] string CompanyName,
    [property: JsonPropertyName("productName")] string ProductName,
    [property: JsonPropertyName("sha256")] string Sha256);

public sealed record WorkerSdkFallback(
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("candidate")] WorkerSdkCandidateIdentity? Candidate)
{
    public static WorkerSdkFallback Disabled { get; } = new(false, null);
}

[method: JsonConstructor]
public sealed record WorkerRequest(
    [property: JsonPropertyName("protocolVersion")] int ProtocolVersion,
    [property: JsonPropertyName("command")] string Command,
    [property: JsonPropertyName("originalPath")] string OriginalPath,
    [property: JsonPropertyName("stagedPath")] string StagedPath,
    [property: JsonPropertyName("signingPlanJson")] string SigningPlanJson,
    [property: JsonPropertyName("stagingOwnerPid")] int StagingOwnerPid,
    [property: JsonPropertyName("stagingOwnerStartUtc")] DateTimeOffset StagingOwnerStartUtc,
    [property: JsonPropertyName("operationId")] string? OperationId,
    [property: JsonPropertyName("subject")] string? Subject,
    [property: JsonPropertyName("capability")] string? Capability,
    [property: JsonPropertyName("engine")] string? Engine,
    [property: JsonPropertyName("verification")] string? Verification,
    [property: JsonPropertyName("sdkFallback")] WorkerSdkFallback? SdkFallback = null)
{
    public WorkerRequest(int protocolVersion, string command, string stagedPath)
        : this(protocolVersion, command, string.Empty, stagedPath, string.Empty, 0, default, null, null, null, null, null)
    {
    }

    public WorkerRequest(
        int protocolVersion,
        string command,
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc)
        : this(
            protocolVersion,
            command,
            originalPath,
            stagedPath,
            signingPlanJson,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            null)
    {
    }

    public WorkerRequest(
        int protocolVersion,
        string command,
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        string? operationId)
        : this(
            protocolVersion,
            command,
            originalPath,
            stagedPath,
            signingPlanJson,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            operationId,
            WorkerSigningContract.FromSigningPlanJson(signingPlanJson),
            WorkerSdkFallback.Disabled)
    {
    }

    private WorkerRequest(
        int protocolVersion,
        string command,
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        string? operationId,
        WorkerSigningContract contract,
        WorkerSdkFallback sdkFallback)
        : this(
            protocolVersion,
            command,
            originalPath,
            stagedPath,
            signingPlanJson,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            operationId,
            contract.Subject,
            contract.Capability,
            contract.Engine,
            contract.Verification,
            sdkFallback)
    {
    }
}

public sealed record WorkerResponse(
    [property: JsonPropertyName("protocolVersion")] int ProtocolVersion,
    [property: JsonPropertyName("success")] bool Success,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("hresult")] int? HResult = null,
    [property: JsonPropertyName("failedLegIndex")] int? FailedLegIndex = null,
    [property: JsonPropertyName("originalSha256")] string? OriginalSha256 = null,
    [property: JsonPropertyName("stagedSha256")] string? StagedSha256 = null,
    [property: JsonPropertyName("operationId")] string? OperationId = null,
    [property: JsonPropertyName("diagnosticId")] string? DiagnosticId = null,
    [property: JsonPropertyName("diagnosticPhase")] string? DiagnosticPhase = null,
    [property: JsonPropertyName("diagnosticLeg")] string? DiagnosticLeg = null,
    [property: JsonPropertyName("digestAlgorithm")] string? DigestAlgorithm = null,
    [property: JsonPropertyName("appendSignature")] bool? AppendSignature = null,
    [property: JsonPropertyName("nativeCall")] string? NativeCall = null,
    [property: JsonPropertyName("signerSignEx3Flags")] int? SignerSignEx3Flags = null,
    [property: JsonPropertyName("nativeReasonCode")] string? NativeReasonCode = null,
    [property: JsonPropertyName("hresultSymbol")] string? HResultSymbol = null,
    [property: JsonPropertyName("hresultOrigin")] string? HResultOrigin = null,
    [property: JsonPropertyName("legElapsedMilliseconds")] long? LegElapsedMilliseconds = null,
    [property: JsonPropertyName("subject")] string? Subject = null,
    [property: JsonPropertyName("capability")] string? Capability = null,
    [property: JsonPropertyName("engine")] string? Engine = null,
    [property: JsonPropertyName("verification")] string? Verification = null,
    [property: JsonPropertyName("legacyFallbackAttempted")] bool? LegacyFallbackAttempted = null,
    [property: JsonPropertyName("outcome")] WorkerSigningOutcome? Outcome = null,
    [property: JsonPropertyName("route")] WorkerExecutionRoute? Route = null,
    [property: JsonPropertyName("failure")] WorkerFailureCode? Failure = null);

public sealed record WorkerProgress(
    [property: JsonPropertyName("protocolVersion")] int ProtocolVersion,
    [property: JsonPropertyName("phase")] string Phase,
    [property: JsonPropertyName("subject")] string? Subject = null,
    [property: JsonPropertyName("capability")] string? Capability = null,
    [property: JsonPropertyName("engine")] string? Engine = null,
    [property: JsonPropertyName("verification")] string? Verification = null);

public sealed record WorkerSessionMessage(WorkerProgress? Progress, WorkerResponse? Response);

public static class WorkerSubjects
{
    public const string PeImage = "peImage";
    public const string WindowsInstaller = "windowsInstaller";
    public const string Cabinet = "cabinet";
    public const string Catalog = "catalog";
    public const string AppPackage = "appPackage";
    public const string PowerShellScript = "powerShellScript";
    public const string WindowsScript = "windowsScript";
}

public static class WorkerCapabilities
{
    public const string PeImageDualCapable = "peImageDualCapable";
    public const string WindowsSipSingleOnly = "windowsSipSingleOnly";
}

public static class WorkerEngines
{
    public const string PeImage = "peImage";
    public const string WindowsSip = "windowsSip";
}

public static class WorkerVerifications
{
    public const string PeImage = "peImage";
    public const string WindowsSip = "windowsSip";
}

public sealed record WorkerSigningContract(
    string Subject,
    string Capability,
    string Engine,
    string Verification)
{
    public static WorkerSigningContract FromSigningPlan(SigningPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return new WorkerSigningContract(
            SubjectFor(plan.Subject.FormatFamily),
            CapabilityFor(plan.Subject.Capability),
            EngineFor(plan.Engine),
            VerificationFor(plan.Verification));
    }

    public static WorkerSigningContract FromSigningPlanJson(string signingPlanJson)
    {
        PolicyResult<SigningPlan> result = SigningPlanJson.Parse(signingPlanJson);
        if (!result.IsSuccess)
        {
            throw new ArgumentException("A valid signing plan is required.", nameof(signingPlanJson));
        }

        return FromSigningPlan(result.Value!);
    }

    public bool Matches(WorkerRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return string.Equals(Subject, request.Subject, StringComparison.Ordinal) &&
            string.Equals(Capability, request.Capability, StringComparison.Ordinal) &&
            string.Equals(Engine, request.Engine, StringComparison.Ordinal) &&
            string.Equals(Verification, request.Verification, StringComparison.Ordinal);
    }

    public bool Matches(WorkerProgress progress)
    {
        ArgumentNullException.ThrowIfNull(progress);
        return string.Equals(Subject, progress.Subject, StringComparison.Ordinal) &&
            string.Equals(Capability, progress.Capability, StringComparison.Ordinal) &&
            string.Equals(Engine, progress.Engine, StringComparison.Ordinal) &&
            string.Equals(Verification, progress.Verification, StringComparison.Ordinal);
    }

    public bool Matches(WorkerResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return string.Equals(Subject, response.Subject, StringComparison.Ordinal) &&
            string.Equals(Capability, response.Capability, StringComparison.Ordinal) &&
            string.Equals(Engine, response.Engine, StringComparison.Ordinal) &&
            string.Equals(Verification, response.Verification, StringComparison.Ordinal);
    }

    private static string SubjectFor(SigningFormatFamily value) => value switch
    {
        SigningFormatFamily.PeImage => WorkerSubjects.PeImage,
        SigningFormatFamily.WindowsInstaller => WorkerSubjects.WindowsInstaller,
        SigningFormatFamily.Cabinet => WorkerSubjects.Cabinet,
        SigningFormatFamily.Catalog => WorkerSubjects.Catalog,
        SigningFormatFamily.AppPackage => WorkerSubjects.AppPackage,
        SigningFormatFamily.PowerShellScript => WorkerSubjects.PowerShellScript,
        SigningFormatFamily.WindowsScript => WorkerSubjects.WindowsScript,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing subject.")
    };

    private static string CapabilityFor(SigningCapability value) => value switch
    {
        SigningCapability.PeImageDualCapable => WorkerCapabilities.PeImageDualCapable,
        SigningCapability.WindowsSipSingleOnly => WorkerCapabilities.WindowsSipSingleOnly,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing capability.")
    };

    private static string EngineFor(SigningEngine value) => value switch
    {
        SigningEngine.PeImage => WorkerEngines.PeImage,
        SigningEngine.WindowsSip => WorkerEngines.WindowsSip,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing engine.")
    };

    private static string VerificationFor(SigningVerification value) => value switch
    {
        SigningVerification.PeImage => WorkerVerifications.PeImage,
        SigningVerification.WindowsSip => WorkerVerifications.WindowsSip,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing verification.")
    };
}

public static class WorkerCommands
{
    public const string Probe = "probe";
    public const string Sign = "sign";
    public const string SignBatch = "sign_batch";
}

public static class WorkerProgressPhases
{
    public const string SigningPrimary = "signing_primary";
    public const string SigningSecondary = "signing_secondary";
    public const string Verifying = "verifying";
}

public static class WorkerDiagnosticPhases
{
    public const string SigningPrimary = "signing_primary";
    public const string SigningSecondary = "signing_secondary";
    public const string Verifying = "verifying";
    public const string WorkerBridge = "worker_bridge";
}

public static class WorkerDiagnosticLegs
{
    public const string Primary = "primary";
    public const string Secondary = "secondary";
}

public static class WorkerDigestAlgorithms
{
    public const string Sha1 = "sha1";
    public const string Sha256 = "sha256";
}

public static class WorkerNativeCalls
{
    public const string SignerSignEx3 = "SignerSignEx3";
}

public static class WorkerHResultOrigins
{
    public const string Native = "native";
    public const string Managed = "managed";
    public const string WorkerBridge = "worker_bridge";
}

public static class WorkerResponseCodes
{
    public const string Ready = "ready";
    public const string UnsupportedCommand = "unsupported_command";
    public const string ProtocolVersionMismatch = "protocol_version_mismatch";
    public const string InvalidRequest = "invalid_request";
    public const string InvalidStagedPath = "invalid_staged_path";
    public const string InvalidFrame = "invalid_frame";
    public const string FrameTooLarge = "frame_too_large";
    public const string ResponseTooLarge = "response_too_large";
    public const string HandlerFailure = "handler_failure";
    public const string SigningCompleted = "signed";
    public const string InvalidSigningPlan = "invalid_signing_plan";
    public const string SubjectCapabilityMismatch = "subject_capability_mismatch";
    public const string InvalidStagingOwner = "invalid_staging_owner";
    public const string InvalidInput = "invalid_input";
    public const string UnsupportedFileType = "unsupported_file_type";
    public const string CertificateNotFound = "certificate_not_found";
    public const string CertificateHasNoPrivateKey = "certificate_has_no_private_key";
    public const string ProviderCancelled = "provider_cancelled";
    public const string TimestampUnavailable = "timestamp_unavailable";
    public const string NativeSigningFailed = "native_signing_failed";
    public const string VerifierDisagreement = "verifier_disagreement";
    public const string OriginalChanged = "original_changed";
    public const string Cancelled = "cancelled";
    public const string WindowsPowerShellUnavailable = "windows_powershell_unavailable";
    public const string WindowsPowerShellExecutionDenied = "windows_powershell_execution_denied";
    public const string WindowsSipUnavailable = "windows_sip_unavailable";
    public const string SecureSipPublicationUnavailable = "secure_sip_publication_unavailable";
    public const string PackageIncompatible = "package_incompatible";
    public const string CertificateMismatch = "certificate_mismatch";
    public const string ExistingSignatureRejected = "existing_signature_rejected";
    public const string InvalidBridgeResponse = "invalid_bridge_response";
    public const string SkippedExistingSignature = "skipped_existing_signature";
    public const string SdkCandidateChanged = "sdk_candidate_changed";
    public const string SdkStartFailed = "sdk_start_failed";
    public const string SdkTimedOut = "sdk_timed_out";
    public const string SdkExitFailed = "sdk_exit_failed";
    public const string SdkVerificationFailed = "sdk_verification_failed";
}

public sealed class WorkerProtocolException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = code;
}

internal sealed class WorkerEndOfStreamException(bool isCleanEof)
    : EndOfStreamException("The worker frame ended before the declared length.")
{
    internal bool IsCleanEof { get; } = isCleanEof;
}

public static class WorkerProtocol
{
    public const int Version = 4;
    public const int HeaderBytes = sizeof(int);
    public const int MaxPayloadBytes = 64 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };
    private static readonly JsonStringEnumConverter EnumConverter =
        new(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false);
    private static readonly string[] RequestFields =
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
    ];
    private static readonly string[] ResponseFields =
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
    private static readonly string[] SdkFallbackFields = ["enabled", "candidate"];
    private static readonly string[] SdkCandidateFields =
    [
        "path",
        "sdkVersion",
        "productVersion",
        "publisher",
        "companyName",
        "productName",
        "sha256"
    ];
    private static readonly string[] ProgressFields =
    [
        "protocolVersion",
        "phase",
        "subject",
        "capability",
        "engine",
        "verification"
    ];

    public static async Task<WorkerRequest> ReadRequestAsync(Stream input, CancellationToken cancellationToken)
    {
        byte[] payload = await ReadFrameAsync(input, cancellationToken).ConfigureAwait(false);
        ValidateJsonFields(payload, RequestFields);
        ValidateRequestNestedFields(payload);
        WorkerRequest request = Deserialize<WorkerRequest>(payload);
        ValidateRequest(request);
        return request;
    }

    public static Task WriteRequestAsync(
        Stream output,
        WorkerRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);
        return WriteFrameAsync(output, request, cancellationToken);
    }

    public static async Task<WorkerResponse> ReadResponseAsync(Stream input, CancellationToken cancellationToken)
    {
        byte[] payload = await ReadFrameAsync(input, cancellationToken).ConfigureAwait(false);
        ValidateJsonFields(payload, ResponseFields, requireAllFields: true);
        WorkerResponse response = Deserialize<WorkerResponse>(payload);
        ValidateResponse(response);
        return response;
    }

    public static Task WriteResponseAsync(
        Stream output,
        WorkerResponse response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        ValidateResponse(response);
        return WriteFrameAsync(output, response, cancellationToken);
    }

    public static async Task<WorkerSessionMessage> ReadSessionMessageAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        byte[] payload = await ReadFrameAsync(input, cancellationToken).ConfigureAwait(false);
        if (HasExactProperty(payload, "phase"))
        {
            ValidateJsonFields(payload, ProgressFields);
            WorkerProgress progress = Deserialize<WorkerProgress>(payload);
            ValidateProgress(progress);
            return new WorkerSessionMessage(progress, null);
        }

        ValidateJsonFields(payload, ResponseFields, requireAllFields: true);
        WorkerResponse response = Deserialize<WorkerResponse>(payload);
        ValidateResponse(response);
        return new WorkerSessionMessage(null, response);
    }

    public static Task WriteProgressAsync(
        Stream output,
        WorkerProgress progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(progress);
        ValidateProgress(progress);
        return WriteFrameAsync(output, progress, cancellationToken);
    }

    private static T Deserialize<T>(byte[] payload)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(payload, JsonOptions)
                ?? throw new WorkerProtocolException(WorkerResponseCodes.InvalidRequest, "The JSON payload is null.");
        }
        catch (WorkerProtocolException)
        {
            throw;
        }
        catch (JsonException error)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The JSON payload does not match the protocol schema.",
                error);
        }
    }

    private static void ValidateJsonFields(
        byte[] payload,
        string[] allowedFields,
        bool requireAllFields = false)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(
                payload,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new WorkerProtocolException(
                    WorkerResponseCodes.InvalidRequest,
                    "The JSON payload must be an object.");
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (!allowedFields.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
                {
                    throw new WorkerProtocolException(
                        WorkerResponseCodes.InvalidRequest,
                        "Unknown, duplicate, and incorrectly cased properties are rejected.");
                }
            }

            if (requireAllFields && seen.Count != allowedFields.Length)
            {
                throw new WorkerProtocolException(
                    WorkerResponseCodes.InvalidRequest,
                    "The JSON payload is missing a required property.");
            }
        }
        catch (WorkerProtocolException)
        {
            throw;
        }
        catch (JsonException error)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The JSON payload does not match the protocol schema.",
                error);
        }
    }

    private static bool HasExactProperty(byte[] payload, string propertyName)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(
                payload,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                });
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty(propertyName, out _);
        }
        catch (JsonException error)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The JSON payload does not match the protocol schema.",
                error);
        }
    }

    private static async Task<byte[]> ReadFrameAsync(Stream input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        byte[] header = new byte[HeaderBytes];
        await ReadExactlyAsync(input, header, allowCleanEof: true, cancellationToken).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0)
        {
            throw new WorkerProtocolException(WorkerResponseCodes.InvalidFrame, "The frame length must be positive.");
        }

        if (length > MaxPayloadBytes)
        {
            throw new WorkerProtocolException(WorkerResponseCodes.FrameTooLarge, "The frame exceeds the payload limit.");
        }

        byte[] payload = new byte[length];
        await ReadExactlyAsync(input, payload, allowCleanEof: false, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    private static async Task ReadExactlyAsync(
        Stream input,
        Memory<byte> destination,
        bool allowCleanEof,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int count = await input.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new WorkerEndOfStreamException(allowCleanEof && offset == 0);
            }

            offset += count;
        }
    }

    private static async Task WriteFrameAsync<T>(Stream output, T value, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        if (payload.Length > MaxPayloadBytes)
        {
            throw new WorkerProtocolException(WorkerResponseCodes.ResponseTooLarge, "The encoded frame exceeds the payload limit.");
        }

        byte[] header = new byte[HeaderBytes];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await output.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateRequest(WorkerRequest request)
    {
        if (request.ProtocolVersion != Version)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.ProtocolVersionMismatch,
                "The protocol version is not supported.");
        }

        if (string.IsNullOrWhiteSpace(request.Command))
        {
            throw new WorkerProtocolException(WorkerResponseCodes.InvalidRequest, "The command is required.");
        }

        if (!IsCanonicalAbsolutePath(request.StagedPath))
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidStagedPath,
                "The staged path must be an absolute canonical file path.");
        }

        if (!string.IsNullOrEmpty(request.OperationId) && !IsLowerHexIdentifier(request.OperationId))
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The operation identifier is invalid.");
        }

        bool isSigningCommand =
            string.Equals(request.Command, WorkerCommands.Sign, StringComparison.Ordinal) ||
            string.Equals(request.Command, WorkerCommands.SignBatch, StringComparison.Ordinal);
        if (isSigningCommand &&
            (!IsCanonicalAbsolutePath(request.OriginalPath) ||
             string.IsNullOrWhiteSpace(request.SigningPlanJson) ||
             request.StagingOwnerPid <= 0 ||
             request.StagingOwnerStartUtc == default ||
             request.StagingOwnerStartUtc.Offset != TimeSpan.Zero ||
             !IsLowerHexIdentifier(request.OperationId)))
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The sign request fields are invalid.");
        }

        if (isSigningCommand)
        {
            ValidateSigningMetadata(
                request.Subject,
                request.Capability,
                request.Engine,
                request.Verification);
            PolicyResult<SigningPlan> signingPlan = SigningPlanJson.Parse(request.SigningPlanJson);
            if (signingPlan.IsSuccess &&
                !WorkerSigningContract.FromSigningPlan(signingPlan.Value!).Matches(request))
            {
                throw new WorkerProtocolException(
                    WorkerResponseCodes.InvalidRequest,
                    "The request signing metadata does not match the immutable signing plan.");
            }

            ValidateSdkFallback(request.SdkFallback);
        }

        if (string.Equals(request.Command, WorkerCommands.Probe, StringComparison.Ordinal) &&
            (request.SdkFallback is not null ||
             !string.IsNullOrEmpty(request.OperationId) || HasSigningMetadata(
                request.Subject,
                request.Capability,
                request.Engine,
                request.Verification)))
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The probe request must not carry signing metadata.");
        }
    }

    private static void ValidateSdkFallback(WorkerSdkFallback? sdkFallback)
    {
        if (sdkFallback is null || sdkFallback.Enabled != (sdkFallback.Candidate is not null))
        {
            throw InvalidRequest("The SDK fallback state is contradictory.");
        }

        if (sdkFallback.Candidate is not null)
        {
            ValidateSdkCandidate(sdkFallback.Candidate);
        }
    }

    private static void ValidateSdkCandidate(WorkerSdkCandidateIdentity candidate)
    {
        if (!IsCanonicalAbsolutePath(candidate.Path) ||
            !IsExactFourPartVersion(candidate.SdkVersion) ||
            !IsExactFourPartVersion(candidate.ProductVersion) ||
            !IsBoundedText(candidate.Publisher) ||
            !IsBoundedText(candidate.CompanyName) ||
            !IsBoundedText(candidate.ProductName) ||
            !IsLowerHex(candidate.Sha256, 64))
        {
            throw InvalidRequest("The SDK candidate identity is invalid.");
        }
    }

    public static void ValidateResponse(WorkerResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.ProtocolVersion != Version)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.ProtocolVersionMismatch,
                "The response protocol version is not supported.");
        }

        if (string.IsNullOrWhiteSpace(response.Code))
        {
            throw new WorkerProtocolException(WorkerResponseCodes.InvalidRequest, "The response is invalid.");
        }

        if (response.FailedLegIndex is not (null or 0 or 1) ||
            !IsNullableLowerHex(response.OriginalSha256, 64) ||
            !IsNullableLowerHex(response.StagedSha256, 64) ||
            !IsNullableLowerHexIdentifier(response.OperationId) ||
            !IsNullableLowerHexIdentifier(response.DiagnosticId) ||
            !IsNullableValue(response.DiagnosticPhase, WorkerDiagnosticPhases.SigningPrimary,
                WorkerDiagnosticPhases.SigningSecondary, WorkerDiagnosticPhases.Verifying,
                WorkerDiagnosticPhases.WorkerBridge) ||
            !IsNullableValue(response.DiagnosticLeg, WorkerDiagnosticLegs.Primary, WorkerDiagnosticLegs.Secondary) ||
            !IsNullableValue(response.DigestAlgorithm, WorkerDigestAlgorithms.Sha1, WorkerDigestAlgorithms.Sha256) ||
            !IsNullableValue(response.NativeCall, WorkerNativeCalls.SignerSignEx3) ||
            !IsNullableValue(response.HResultOrigin, WorkerHResultOrigins.Native,
                WorkerHResultOrigins.Managed, WorkerHResultOrigins.WorkerBridge) ||
            !IsNullableNativeReasonCode(response.NativeReasonCode) ||
            !IsNullableHResultSymbol(response.HResultSymbol) ||
            response.SignerSignEx3Flags < 0 ||
            response.LegElapsedMilliseconds < 0)
        {
            throw InvalidResponse();
        }

        bool hasSigningMetadata = HasSigningMetadata(
            response.Subject,
            response.Capability,
            response.Engine,
            response.Verification);
        if (hasSigningMetadata)
        {
            ValidateSigningMetadata(
                response.Subject,
                response.Capability,
                response.Engine,
                response.Verification);
        }

        bool hasDiagnostic = response.DiagnosticId is not null ||
            response.DiagnosticPhase is not null ||
            response.DiagnosticLeg is not null ||
            response.DigestAlgorithm is not null ||
            response.AppendSignature is not null ||
            response.NativeCall is not null ||
            response.SignerSignEx3Flags is not null ||
            response.NativeReasonCode is not null ||
            response.HResultSymbol is not null ||
            response.HResultOrigin is not null ||
            response.LegElapsedMilliseconds is not null;
        if (response.Success && (hasDiagnostic || response.FailedLegIndex is not null) ||
            hasDiagnostic && (response.Success || response.OperationId is null || response.DiagnosticId is null ||
                response.DiagnosticPhase is null) ||
            !hasDiagnostic && response.DiagnosticId is not null ||
            string.Equals(response.Code, WorkerResponseCodes.Ready, StringComparison.Ordinal) &&
                (response.OperationId is not null || hasSigningMetadata) ||
            string.Equals(response.Code, WorkerResponseCodes.SigningCompleted, StringComparison.Ordinal) &&
                (response.OperationId is null || !hasSigningMetadata) ||
            hasSigningMetadata && response.OperationId is null)
        {
            throw InvalidResponse();
        }

        if (response.HResult is null && (response.HResultSymbol is not null || response.HResultOrigin is not null) ||
            response.HResult is not null && response.DiagnosticPhase is not null && response.HResultOrigin is null ||
            response.NativeCall is null && response.SignerSignEx3Flags is not null ||
            response.NativeCall is not null &&
                (response.SignerSignEx3Flags is null ||
                 !string.Equals(response.HResultOrigin, WorkerHResultOrigins.Native, StringComparison.Ordinal)))
        {
            throw InvalidResponse();
        }

        ValidateAuthoritativeOutcome(response, hasSigningMetadata);
        ValidateDiagnosticRelationship(response);
    }

    private static void ValidateAuthoritativeOutcome(WorkerResponse response, bool hasSigningMetadata)
    {
        bool hasOutcomeContract = response.Outcome is not null || response.Route is not null || response.Failure is not null;
        if (!hasOutcomeContract)
        {
            if (response.OperationId is not null || hasSigningMetadata ||
                string.Equals(response.Code, WorkerResponseCodes.SigningCompleted, StringComparison.Ordinal) ||
                string.Equals(response.Code, WorkerResponseCodes.SkippedExistingSignature, StringComparison.Ordinal))
            {
                throw InvalidResponse();
            }

            return;
        }

        if (response.Outcome is null || response.Route is null || response.OperationId is null || !hasSigningMetadata)
        {
            throw InvalidResponse();
        }

        switch (response.Outcome)
        {
            case WorkerSigningOutcome.Signed:
                if (!response.Success ||
                    !string.Equals(response.Code, WorkerResponseCodes.SigningCompleted, StringComparison.Ordinal) ||
                    response.Failure is not null || response.Route == WorkerExecutionRoute.Skip)
                {
                    throw InvalidResponse();
                }

                break;
            case WorkerSigningOutcome.SkippedExistingSignature:
                if (!response.Success ||
                    !string.Equals(response.Code, WorkerResponseCodes.SkippedExistingSignature, StringComparison.Ordinal) ||
                    response.Route != WorkerExecutionRoute.Skip || response.Failure is not null)
                {
                    throw InvalidResponse();
                }

                break;
            case WorkerSigningOutcome.Failure:
                if (response.Success || response.Route == WorkerExecutionRoute.Skip || response.Failure is null ||
                    !string.Equals(response.Code, FailureCodeFor(response.Failure.Value), StringComparison.Ordinal) ||
                    !IsFailureCompatibleWithRoute(response.Route.Value, response.Failure.Value))
                {
                    throw InvalidResponse();
                }

                break;
            default:
                throw InvalidResponse();
        }

        bool peMetadata = string.Equals(response.Subject, WorkerSubjects.PeImage, StringComparison.Ordinal);
        if (response.Route is WorkerExecutionRoute.ProductPe or WorkerExecutionRoute.SdkSignTool && !peMetadata ||
            response.Route == WorkerExecutionRoute.WindowsSip && peMetadata)
        {
            throw InvalidResponse();
        }
    }

    private static void ValidateProgress(WorkerProgress progress)
    {
        if (progress.ProtocolVersion != Version)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.ProtocolVersionMismatch,
                "The progress protocol version is not supported.");
        }

        if (progress.Phase is not (WorkerProgressPhases.SigningPrimary or
                WorkerProgressPhases.SigningSecondary or
                WorkerProgressPhases.Verifying))
        {
            throw new WorkerProtocolException(WorkerResponseCodes.InvalidRequest, "The progress frame is invalid.");
        }


        ValidateSigningMetadata(
            progress.Subject,
            progress.Capability,
            progress.Engine,
            progress.Verification);
    }

    static WorkerProtocol()
    {
        JsonOptions.Converters.Add(EnumConverter);
    }

    private static bool IsCanonicalAbsolutePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        try
        {
            string canonical = Path.GetFullPath(path);
            return string.Equals(canonical, path, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrEmpty(Path.GetFileName(canonical));
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static void ValidateDiagnosticRelationship(WorkerResponse response)
    {
        switch (response.DiagnosticPhase)
        {
            case null:
                if (response.DiagnosticLeg is not null || response.DigestAlgorithm is not null ||
                    response.AppendSignature is not null || response.NativeCall is not null ||
                    response.SignerSignEx3Flags is not null || response.NativeReasonCode is not null ||
                    response.HResultSymbol is not null || response.HResultOrigin is not null ||
                    response.LegElapsedMilliseconds is not null)
                {
                    throw InvalidResponse();
                }

                break;
            case WorkerDiagnosticPhases.SigningPrimary:
                if (response.DigestAlgorithm is not (WorkerDigestAlgorithms.Sha1 or WorkerDigestAlgorithms.Sha256))
                {
                    throw InvalidResponse();
                }

                ValidateSigningLeg(
                    response,
                    WorkerDiagnosticLegs.Primary,
                    response.DigestAlgorithm,
                    appendSignature: false,
                    failedLegIndex: 0);
                break;
            case WorkerDiagnosticPhases.SigningSecondary:
                ValidateSigningLeg(
                    response,
                    WorkerDiagnosticLegs.Secondary,
                    WorkerDigestAlgorithms.Sha256,
                    appendSignature: true,
                    failedLegIndex: 1);
                break;
            case WorkerDiagnosticPhases.Verifying:
                if (HasSigningLegFields(response) ||
                    string.Equals(response.HResultOrigin, WorkerHResultOrigins.WorkerBridge, StringComparison.Ordinal))
                {
                    throw InvalidResponse();
                }

                break;
            case WorkerDiagnosticPhases.WorkerBridge:
                if (HasSigningLegFields(response) || response.NativeReasonCode is not null ||
                    response.HResult is not null &&
                        !string.Equals(response.HResultOrigin, WorkerHResultOrigins.WorkerBridge, StringComparison.Ordinal))
                {
                    throw InvalidResponse();
                }

                break;
            default:
                throw InvalidResponse();
        }
    }

    private static void ValidateSigningLeg(
        WorkerResponse response,
        string expectedLeg,
        string expectedDigest,
        bool appendSignature,
        int failedLegIndex)
    {
        if (!string.Equals(response.DiagnosticLeg, expectedLeg, StringComparison.Ordinal) ||
            !string.Equals(response.DigestAlgorithm, expectedDigest, StringComparison.Ordinal) ||
            response.AppendSignature != appendSignature ||
            response.FailedLegIndex != failedLegIndex ||
            string.Equals(response.HResultOrigin, WorkerHResultOrigins.WorkerBridge, StringComparison.Ordinal))
        {
            throw InvalidResponse();
        }
    }

    private static bool HasSigningLegFields(WorkerResponse response) =>
        response.FailedLegIndex is not null || response.DiagnosticLeg is not null ||
        response.DigestAlgorithm is not null || response.AppendSignature is not null ||
        response.NativeCall is not null || response.SignerSignEx3Flags is not null ||
        response.LegElapsedMilliseconds is not null;

    private static bool IsLowerHexIdentifier(string? value) => IsLowerHex(value, 32);

    private static bool IsNullableLowerHexIdentifier(string? value) =>
        value is null || IsLowerHexIdentifier(value);

    private static bool IsNullableLowerHex(string? value, int length) => value is null || IsLowerHex(value, length);

    private static bool IsLowerHex(string? value, int length)
    {
        if (value is null || value.Length != length)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsExactFourPartVersion(string? value) =>
        System.Version.TryParse(value, out System.Version? version) &&
        version.Major >= 0 && version.Minor >= 0 && version.Build >= 0 && version.Revision >= 0 &&
        string.Equals(value, version.ToString(4), StringComparison.Ordinal);

    private static bool IsBoundedText(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 256;

    private static bool IsFailureCompatibleWithRoute(
        WorkerExecutionRoute route,
        WorkerFailureCode failure) => route switch
    {
        WorkerExecutionRoute.ProductPe => failure is
            WorkerFailureCode.HandlerFailure or
            WorkerFailureCode.InvalidSigningPlan or
            WorkerFailureCode.SubjectCapabilityMismatch or
            WorkerFailureCode.InvalidStagingOwner or
            WorkerFailureCode.InvalidInput or
            WorkerFailureCode.UnsupportedFileType or
            WorkerFailureCode.CertificateNotFound or
            WorkerFailureCode.CertificateHasNoPrivateKey or
            WorkerFailureCode.ProviderCancelled or
            WorkerFailureCode.TimestampUnavailable or
            WorkerFailureCode.NativeSigningFailed or
            WorkerFailureCode.VerifierDisagreement or
            WorkerFailureCode.OriginalChanged or
            WorkerFailureCode.Cancelled or
            WorkerFailureCode.ExistingSignatureRejected,
        WorkerExecutionRoute.SdkSignTool => failure is
            WorkerFailureCode.InvalidInput or
            WorkerFailureCode.OriginalChanged or
            WorkerFailureCode.Cancelled or
            WorkerFailureCode.SdkCandidateChanged or
            WorkerFailureCode.SdkStartFailed or
            WorkerFailureCode.SdkTimedOut or
            WorkerFailureCode.SdkExitFailed or
            WorkerFailureCode.SdkVerificationFailed,
        WorkerExecutionRoute.WindowsSip => failure is
            WorkerFailureCode.HandlerFailure or
            WorkerFailureCode.InvalidSigningPlan or
            WorkerFailureCode.SubjectCapabilityMismatch or
            WorkerFailureCode.InvalidStagingOwner or
            WorkerFailureCode.InvalidInput or
            WorkerFailureCode.UnsupportedFileType or
            WorkerFailureCode.CertificateNotFound or
            WorkerFailureCode.CertificateHasNoPrivateKey or
            WorkerFailureCode.ProviderCancelled or
            WorkerFailureCode.TimestampUnavailable or
            WorkerFailureCode.NativeSigningFailed or
            WorkerFailureCode.VerifierDisagreement or
            WorkerFailureCode.OriginalChanged or
            WorkerFailureCode.Cancelled or
            WorkerFailureCode.WindowsPowerShellUnavailable or
            WorkerFailureCode.WindowsPowerShellExecutionDenied or
            WorkerFailureCode.WindowsSipUnavailable or
            WorkerFailureCode.PackageIncompatible or
            WorkerFailureCode.CertificateMismatch or
            WorkerFailureCode.ExistingSignatureRejected or
            WorkerFailureCode.InvalidBridgeResponse,
        WorkerExecutionRoute.Skip => false,
        _ => false
    };

    public static string FailureCodeFor(WorkerFailureCode failure) => failure switch
    {
        WorkerFailureCode.HandlerFailure => WorkerResponseCodes.HandlerFailure,
        WorkerFailureCode.InvalidSigningPlan => WorkerResponseCodes.InvalidSigningPlan,
        WorkerFailureCode.SubjectCapabilityMismatch => WorkerResponseCodes.SubjectCapabilityMismatch,
        WorkerFailureCode.InvalidStagingOwner => WorkerResponseCodes.InvalidStagingOwner,
        WorkerFailureCode.InvalidInput => WorkerResponseCodes.InvalidInput,
        WorkerFailureCode.UnsupportedFileType => WorkerResponseCodes.UnsupportedFileType,
        WorkerFailureCode.CertificateNotFound => WorkerResponseCodes.CertificateNotFound,
        WorkerFailureCode.CertificateHasNoPrivateKey => WorkerResponseCodes.CertificateHasNoPrivateKey,
        WorkerFailureCode.ProviderCancelled => WorkerResponseCodes.ProviderCancelled,
        WorkerFailureCode.TimestampUnavailable => WorkerResponseCodes.TimestampUnavailable,
        WorkerFailureCode.NativeSigningFailed => WorkerResponseCodes.NativeSigningFailed,
        WorkerFailureCode.VerifierDisagreement => WorkerResponseCodes.VerifierDisagreement,
        WorkerFailureCode.OriginalChanged => WorkerResponseCodes.OriginalChanged,
        WorkerFailureCode.Cancelled => WorkerResponseCodes.Cancelled,
        WorkerFailureCode.WindowsPowerShellUnavailable => WorkerResponseCodes.WindowsPowerShellUnavailable,
        WorkerFailureCode.WindowsPowerShellExecutionDenied => WorkerResponseCodes.WindowsPowerShellExecutionDenied,
        WorkerFailureCode.WindowsSipUnavailable => WorkerResponseCodes.WindowsSipUnavailable,
        WorkerFailureCode.SecureSipPublicationUnavailable => WorkerResponseCodes.SecureSipPublicationUnavailable,
        WorkerFailureCode.PackageIncompatible => WorkerResponseCodes.PackageIncompatible,
        WorkerFailureCode.CertificateMismatch => WorkerResponseCodes.CertificateMismatch,
        WorkerFailureCode.ExistingSignatureRejected => WorkerResponseCodes.ExistingSignatureRejected,
        WorkerFailureCode.InvalidBridgeResponse => WorkerResponseCodes.InvalidBridgeResponse,
        WorkerFailureCode.SdkCandidateChanged => WorkerResponseCodes.SdkCandidateChanged,
        WorkerFailureCode.SdkStartFailed => WorkerResponseCodes.SdkStartFailed,
        WorkerFailureCode.SdkTimedOut => WorkerResponseCodes.SdkTimedOut,
        WorkerFailureCode.SdkExitFailed => WorkerResponseCodes.SdkExitFailed,
        WorkerFailureCode.SdkVerificationFailed => WorkerResponseCodes.SdkVerificationFailed,
        _ => throw new ArgumentOutOfRangeException(nameof(failure), failure, "Unknown Worker failure.")
    };

    private static bool IsNullableValue(string? value, params string[] allowedValues) =>
        value is null || allowedValues.Contains(value, StringComparer.Ordinal);

    private static bool HasSigningMetadata(
        string? subject,
        string? capability,
        string? engine,
        string? verification) =>
        subject is not null || capability is not null || engine is not null || verification is not null;

    private static void ValidateSigningMetadata(
        string? subject,
        string? capability,
        string? engine,
        string? verification)
    {
        bool peImage = string.Equals(subject, WorkerSubjects.PeImage, StringComparison.Ordinal);
        bool windowsSip = subject is WorkerSubjects.WindowsInstaller or
            WorkerSubjects.Cabinet or
            WorkerSubjects.Catalog or
            WorkerSubjects.AppPackage or
            WorkerSubjects.PowerShellScript or
            WorkerSubjects.WindowsScript;
        bool valid = peImage &&
                string.Equals(capability, WorkerCapabilities.PeImageDualCapable, StringComparison.Ordinal) &&
                string.Equals(engine, WorkerEngines.PeImage, StringComparison.Ordinal) &&
                string.Equals(verification, WorkerVerifications.PeImage, StringComparison.Ordinal) ||
            windowsSip &&
                string.Equals(capability, WorkerCapabilities.WindowsSipSingleOnly, StringComparison.Ordinal) &&
                string.Equals(engine, WorkerEngines.WindowsSip, StringComparison.Ordinal) &&
                string.Equals(verification, WorkerVerifications.WindowsSip, StringComparison.Ordinal);
        if (!valid)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The signing subject, capability, engine, and verification fields are invalid.");
        }
    }

    private static void ValidateRequestNestedFields(byte[] payload)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(
                payload,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                });
            if (!document.RootElement.TryGetProperty("sdkFallback", out JsonElement sdkFallback) ||
                sdkFallback.ValueKind == JsonValueKind.Null)
            {
                return;
            }

            ValidateExactObject(sdkFallback, SdkFallbackFields);
            if (!sdkFallback.TryGetProperty("enabled", out JsonElement enabled) ||
                enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                !sdkFallback.TryGetProperty("candidate", out JsonElement candidate))
            {
                throw InvalidRequest("The SDK fallback object is malformed.");
            }

            if (candidate.ValueKind != JsonValueKind.Null)
            {
                ValidateExactObject(candidate, SdkCandidateFields);
            }
        }
        catch (WorkerProtocolException)
        {
            throw;
        }
        catch (JsonException error)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidRequest,
                "The JSON payload does not match the protocol schema.",
                error);
        }
    }

    private static void ValidateExactObject(JsonElement element, string[] expectedFields)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw InvalidRequest("The nested protocol value must be an object.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!expectedFields.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
            {
                throw InvalidRequest("Unknown, duplicate, and incorrectly cased properties are rejected.");
            }
        }

        if (seen.Count != expectedFields.Length || expectedFields.Any(field => !seen.Contains(field)))
        {
            throw InvalidRequest("The nested protocol object is missing a required property.");
        }
    }

    private static bool IsNullableNativeReasonCode(string? value) => value is null || value is
        "None" or
        "UnsupportedOperatingSystem" or
        "NativeLibraryUnavailable" or
        "MissingNativeExport" or
        "CertificateNotFound" or
        "CertificateHasNoPrivateKey" or
        "TimestampUnavailable" or
        "OperatorCancelled" or
        "NativeSigningFailed" or
        "SecondLegFailed" or
        "VerifierDisagreement" or
        "OriginalChanged" or
        "DestinationExists" or
        "UnsupportedFileType" or
        "UnsupportedKeyAlgorithm" or
        "InvalidInput" or
        "Cancelled";

    private static bool IsNullableHResultSymbol(string? value)
    {
        if (value is null)
        {
            return true;
        }

        if (value.Length is < 1 or > 64 || value[0] is not (>= 'A' and <= 'Z'))
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character is not (>= 'A' and <= 'Z') and not (>= '0' and <= '9') and not '_')
            {
                return false;
            }
        }

        return true;
    }

    private static WorkerProtocolException InvalidResponse() =>
        new(WorkerResponseCodes.InvalidRequest, "The response is invalid.");

    private static WorkerProtocolException InvalidRequest(string message) =>
        new(WorkerResponseCodes.InvalidRequest, message);
}
