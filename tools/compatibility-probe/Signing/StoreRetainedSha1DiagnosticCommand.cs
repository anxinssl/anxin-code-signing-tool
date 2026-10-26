using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Core.Evidence;
using CodeSigner.Windows.Signing;

namespace CodeSigner.CompatibilityProbe.Signing;

internal static class StoreRetainedSha1DiagnosticCommand
{
    private const string EventName = "store-retained-sha1-diagnostic";
    private const string DiagnosticMode = "store-retained-sha1";

    internal static Task<int> RunAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken) =>
        RunAsync(arguments, output, ExecuteNativeGateAsync, cancellationToken);

    internal static async Task<int> RunAsync(
        string[] arguments,
        Stream output,
        CompatibilityGateOperation operation,
        CancellationToken cancellationToken)
    {
        if (arguments.Length != 7 ||
            string.IsNullOrWhiteSpace(arguments[1]) ||
            string.IsNullOrWhiteSpace(arguments[2]) ||
            !TryParseCertificate(arguments[3], arguments[4], arguments[5], out CertificateReference? certificate) ||
            !TryParseTimestampUri(arguments[6], out Uri? timestampUri))
        {
            return await WriteResultAsync(
                output,
                "failed",
                "InvalidArguments",
                unchecked((int)0x80070057),
                null,
                null,
                null,
                cancellationToken).ConfigureAwait(false);
        }

        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateStoreRetainedSha1Diagnostic(certificate, timestampUri);
        try
        {
            CompatibilityGateResult result = await operation(
                arguments[1],
                arguments[2],
                plan,
                cancellationToken).ConfigureAwait(false);
            return await WriteResultAsync(
                output,
                result.Succeeded ? "passed" : "failed",
                result.ReasonCode.ToString(),
                result.HResult,
                result.OriginalSha256,
                result.OutputSha256,
                result.FailedLegIndex,
                cancellationToken).ConfigureAwait(false);
        }
        catch (PlatformNotSupportedException)
        {
            return await WriteResultAsync(output, "failed", NativeSigningReasonCode.MissingNativeExport.ToString(), unchecked((int)0x8007007F), null, null, null, cancellationToken).ConfigureAwait(false);
        }
        catch (DllNotFoundException exception)
        {
            return await WriteResultAsync(output, "failed", NativeSigningReasonCode.NativeLibraryUnavailable.ToString(), exception.HResult, null, null, null, cancellationToken).ConfigureAwait(false);
        }
        catch (EntryPointNotFoundException exception)
        {
            return await WriteResultAsync(output, "failed", NativeSigningReasonCode.MissingNativeExport.ToString(), exception.HResult, null, null, null, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return await WriteResultAsync(output, "failed", NativeSigningReasonCode.Cancelled.ToString(), unchecked((int)0x800704C7), null, null, null, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return await WriteResultAsync(output, "failed", NativeSigningReasonCode.NativeSigningFailed.ToString(), exception.HResult, null, null, null, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<CompatibilityGateResult> ExecuteNativeGateAsync(
        string input,
        string outputPath,
        CompatibilitySigningPlan plan,
        CancellationToken cancellationToken)
    {
        using Mssign32LegExecutor signer = Mssign32LegExecutor.CreateStoreRetainedSha1Diagnostic();
        CompatibilityGateRunner runner = new(signer, new WinVerifyTrustSignatureVerifier());
        return await runner.RunAsync(input, outputPath, plan, cancellationToken).ConfigureAwait(false);
    }

    private static bool TryParseCertificate(
        string storeLocation,
        string storeName,
        string thumbprint,
        [NotNullWhen(true)] out CertificateReference? certificate)
    {
        StoreLocation? location = storeLocation switch
        {
            "CurrentUser" => StoreLocation.CurrentUser,
            "LocalMachine" => StoreLocation.LocalMachine,
            _ => null
        };
        if (location is null)
        {
            certificate = null;
            return false;
        }

        try
        {
            certificate = CertificateReference.Create(location.Value, storeName, thumbprint);
            return true;
        }
        catch (ArgumentException)
        {
            certificate = null;
            return false;
        }
    }

    private static bool TryParseTimestampUri(string value, [NotNullWhen(true)] out Uri? timestampUri)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out timestampUri) || timestampUri.Scheme is not ("http" or "https"))
        {
            timestampUri = null;
            return false;
        }

        return true;
    }

    private static async Task<int> WriteResultAsync(
        Stream output,
        string status,
        string reasonCode,
        int hresult,
        string? originalHash,
        string? outputHash,
        int? failedLegIndex,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = EventName,
            ["diagnosticMode"] = DiagnosticMode,
            ["failedLegIndex"] = failedLegIndex,
            ["status"] = status,
            ["reasonCode"] = reasonCode,
            ["hresult"] = $"0x{unchecked((uint)hresult):X8}",
            ["sha256"] = outputHash ?? originalHash,
            ["count"] = 1,
            ["digestAlgorithm"] = NativeDigestAlgorithm.Sha1.ToString(),
            ["timestampDigestAlgorithm"] = NativeDigestAlgorithm.Sha256.ToString()
        };
        await AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken).ConfigureAwait(false);
        return status == "passed"
            ? 0
            : reasonCode == "InvalidArguments" ? 64 : 1;
    }
}
