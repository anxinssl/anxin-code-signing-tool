using System.Text;
using System.Text.Json;
using CodeSigner.Core.Diagnostics;
using CodeSigner.Core.Worker;

namespace CodeSigner.Core.Evidence;

public static class AllowListEvidenceWriter
{
    private static readonly string[] AllowedFields =
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
        "appendSignature",
        "nativeCall",
        "signerSignEx3Flags",
        "nativeReasonCode",
        "hresultHex",
        "hresultSymbol",
        "hresultOrigin",
        "legElapsedMilliseconds",
        "workerProtocolVersion",
        "workerStderrTail",
        "workerStderrTruncated",
        "failureSummary",
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
        "timestampHost",
        "diagnosticMode",
        "failedLegIndex",
        "status",
        "reasonCode",
        "osVersion",
        "osBuild",
        "applicationVersion",
        "publicCertificateSubject",
        "publicCertificateIssuer",
        "publicCertificateThumbprint",
        "publicCertificateSerialNumber",
        "publicCertificateNotBefore",
        "publicCertificateNotAfter",
        "publicCertificateHasPrivateKey",
        "publicCertificateEnhancedKeyUsages",
        "certificateStoreLocation",
        "certificateStoreName",
        "publicKeyAlgorithm",
        "digestAlgorithm",
        "timestampDigestAlgorithm",
        "hresult",
        "workerHealthState",
        "workerLaunchReason",
        "workerRepairEligible",
        "workerHresult",
        "workerNativeErrorCode",
        "workerExitCode",
        "workerRepairOutcome",
        "workerRepairStarted",
        "workerRepairExitCode",
        "workerRepairNativeErrorCode",
        "workerRepairRestartRequired",
        "workerInstallationStatus",
        "workerInstallationDiagnosticCode",
        "sha256",
        "durationMs",
        "lastRuntimeEvent",
        "lastRuntimeEventTimestampUtc",
        "lastRuntimeEventItemId",
        "lastRuntimeEventProcessId",
        "lastRuntimeEventDetail",
        "fileName",
        "fileFormat",
        "fixtureState",
        "project",
        "package",
        "version",
        "count",
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

    public static async Task WriteAsync(
        Stream destination,
        IReadOnlyDictionary<string, object?> candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(candidate);

        await using Utf8JsonWriter writer = new(destination, new JsonWriterOptions { Indented = false });
        writer.WriteStartObject();
        foreach (string field in AllowedFields)
        {
            if (candidate.TryGetValue(field, out object? value))
            {
                WriteAllowedValue(writer, field, value);
            }
        }

        writer.WriteEndObject();
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        await destination.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private static void WriteAllowedValue(Utf8JsonWriter writer, string field, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNull(field);
                break;
            case string text:
                string? redacted = RedactAllowedString(field, text);
                if (redacted is null)
                {
                    writer.WriteNull(field);
                }
                else
                {
                    writer.WriteString(field, redacted);
                }

                break;
            case bool boolean:
                writer.WriteBoolean(field, boolean);
                break;
            case int integer:
                writer.WriteNumber(field, integer);
                break;
            case long integer:
                writer.WriteNumber(field, integer);
                break;
            case double number when double.IsFinite(number):
                writer.WriteNumber(field, number);
                break;
            case decimal number:
                writer.WriteNumber(field, number);
                break;
            case DateTimeOffset timestamp:
                writer.WriteString(field, timestamp);
                break;
        }
    }

    private static string? RedactAllowedString(string field, string value) => field switch
    {
        "diagnosticLogFileName" or "fileName" => SigningDiagnosticRedactor.RedactFileName(value),
        "detail" or "failureSummary" => SigningDiagnosticRedactor.RedactText(value, 512),
        "workerStderrTail" => SigningDiagnosticRedactor.RedactWorkerStderrTail(
            Encoding.UTF8.GetBytes(value)).Value,
        "providerName" => SigningDiagnosticRedactor.RedactText(value, 256),
        "timestampHost" => RedactTimestampHost(value),
        "responseCode" => WorkerResponseCode(value),
        "subject" or "detectedFormat" => IsOneOf(
            value,
            WorkerSubjects.PeImage,
            WorkerSubjects.WindowsInstaller,
            WorkerSubjects.Cabinet,
            WorkerSubjects.Catalog,
            WorkerSubjects.AppPackage,
            WorkerSubjects.PowerShellScript,
            WorkerSubjects.WindowsScript),
        "capability" => IsOneOf(
            value,
            WorkerCapabilities.PeImageDualCapable,
            WorkerCapabilities.WindowsSipSingleOnly),
        "engine" or "selectedEngine" => IsOneOf(value, WorkerEngines.PeImage, WorkerEngines.WindowsSip),
        "verification" => IsOneOf(value, WorkerVerifications.PeImage, WorkerVerifications.WindowsSip),
        "contentProbeResult" => IsOneOf(value, "validated", "failed", "not_available"),
        "requestedPolicy" or "effectivePolicy" => IsOneOf(value, "single", "dual"),
        "sdkSignToolVersion" => Version.TryParse(value, out Version? parsed) && parsed.ToString() == value
            ? value
            : null,
        "sdkSignToolPathStatus" => IsOneOf(value, "canonical_verified", "not_found", "rejected"),
        "powerShellBridgeAvailability" => IsOneOf(
            value,
            "available",
            "unavailable",
            "execution_denied",
            "unsupported_version"),
        "providerFamily" => IsOneOf(value, "windows_native", "windows_sip", "cng", "csp", "unknown"),
        "structuredStage" => IsOneOf(
            value,
            WorkerDiagnosticPhases.SigningPrimary,
            WorkerDiagnosticPhases.SigningSecondary,
            WorkerDiagnosticPhases.Verifying,
            WorkerDiagnosticPhases.WorkerBridge),
        "hresultClass" or "exitClass" => IsOneOf(value, "success", "failure", "not_available"),
        "finalVerification" => IsOneOf(value, "not_started", "passed", "failed", "not_available"),
        _ => SigningDiagnosticRedactor.RedactText(value)
    };

    private static string? IsOneOf(string value, params string[] allowed) =>
        allowed.Contains(value, StringComparer.Ordinal) ? value : null;

    private static string? WorkerResponseCode(string value) => value is
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

    private static string? RedactTimestampHost(string value)
    {
        string host = value.Trim().ToLowerInvariant();
        if (host.Length is 0 or > 253 || host.IndexOfAny(['/', '\\', '?', '#', ':']) >= 0 ||
            Uri.CheckHostName(host) == UriHostNameType.Unknown)
        {
            return null;
        }

        return SigningDiagnosticRedactor.RedactText(host, 253);
    }
}
