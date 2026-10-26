using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Core.Evidence;
using CodeSigner.Windows.Signing;

namespace CodeSigner.CompatibilityProbe.Signing;

internal delegate Task<CompatibilityGateResult> CompatibilityGateOperation(
    string input,
    string outputPath,
    CompatibilitySigningPlan plan,
    CancellationToken cancellationToken);

internal static class CompatibilitySigningCommands
{
    internal static Task<int> CheckAvailabilityAsync(Stream output, CancellationToken cancellationToken)
    {
        NativeApiAvailability availability = Mssign32AvailabilityProbe.Probe();
        return CheckAvailabilityAsync(output, availability, cancellationToken);
    }

    internal static Task<int> CheckAvailabilityAsync(
        Stream output,
        NativeApiAvailability availability,
        CancellationToken cancellationToken) =>
        WriteResultAsync(
            output,
            "native-availability",
            availability == NativeApiAvailability.Available ? "passed" : "failed",
            availability.ToString(),
            0,
            null,
            null,
            null,
            cancellationToken);

    internal static async Task<int> RunSingleAsync(string[] arguments, Stream output, CancellationToken cancellationToken)
        => await RunSingleAsync(arguments, output, ExecuteNativeGateAsync, cancellationToken).ConfigureAwait(false);

    internal static async Task<int> RunSingleAsync(
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
            return await WriteInvalidArgumentsAsync(output, "single", cancellationToken).ConfigureAwait(false);
        }

        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateSingle(certificate, timestampUri);
        return await ExecuteAsync("single", arguments[1], arguments[2], plan, output, operation, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<int> RunDualAsync(string[] arguments, Stream output, CancellationToken cancellationToken)
        => await RunDualAsync(arguments, output, ExecuteNativeGateAsync, cancellationToken).ConfigureAwait(false);

    internal static async Task<int> RunDualAsync(
        string[] arguments,
        Stream output,
        CompatibilityGateOperation operation,
        CancellationToken cancellationToken)
    {
        if (arguments.Length != 10 ||
            string.IsNullOrWhiteSpace(arguments[1]) ||
            string.IsNullOrWhiteSpace(arguments[2]) ||
            !TryParseCertificate(arguments[3], arguments[4], arguments[5], out CertificateReference? primary) ||
            !TryParseCertificate(arguments[6], arguments[7], arguments[8], out CertificateReference? secondary) ||
            !TryParseTimestampUri(arguments[9], out Uri? timestampUri))
        {
            return await WriteInvalidArgumentsAsync(output, "dual", cancellationToken).ConfigureAwait(false);
        }

        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateDual(primary, secondary, timestampUri);
        return await ExecuteAsync("dual", arguments[1], arguments[2], plan, output, operation, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ExecuteAsync(
        string eventName,
        string input,
        string outputPath,
        CompatibilitySigningPlan plan,
        Stream output,
        CompatibilityGateOperation operation,
        CancellationToken cancellationToken)
    {
        try
        {
            CompatibilityGateResult result = await operation(input, outputPath, plan, cancellationToken).ConfigureAwait(false);
            return await WriteResultAsync(
                output,
                eventName,
                result.Succeeded ? "passed" : "failed",
                result.ReasonCode.ToString(),
                result.HResult,
                result.OriginalSha256,
                result.OutputSha256,
                plan,
                cancellationToken).ConfigureAwait(false);
        }
        catch (PlatformNotSupportedException)
        {
            return await WriteResultAsync(
                output,
                eventName,
                "failed",
                NativeSigningReasonCode.MissingNativeExport.ToString(),
                unchecked((int)0x8007007F),
                null,
                null,
                plan,
                cancellationToken).ConfigureAwait(false);
        }
        catch (DllNotFoundException exception)
        {
            return await WriteResultAsync(
                output,
                eventName,
                "failed",
                NativeSigningReasonCode.NativeLibraryUnavailable.ToString(),
                exception.HResult,
                null,
                null,
                plan,
                cancellationToken).ConfigureAwait(false);
        }
        catch (EntryPointNotFoundException exception)
        {
            return await WriteResultAsync(
                output,
                eventName,
                "failed",
                NativeSigningReasonCode.MissingNativeExport.ToString(),
                exception.HResult,
                null,
                null,
                plan,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return await WriteResultAsync(
                output,
                eventName,
                "failed",
                NativeSigningReasonCode.Cancelled.ToString(),
                unchecked((int)0x800704C7),
                null,
                null,
                plan,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            int hresult = exception.HResult;
            return await WriteResultAsync(
                output,
                eventName,
                "failed",
                NativeSigningReasonCode.NativeSigningFailed.ToString(),
                hresult,
                null,
                null,
                plan,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<CompatibilityGateResult> ExecuteNativeGateAsync(
        string input,
        string outputPath,
        CompatibilitySigningPlan plan,
        CancellationToken cancellationToken)
    {
        using Mssign32LegExecutor signer = Mssign32LegExecutor.Create();
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

    private static Task<int> WriteInvalidArgumentsAsync(Stream output, string eventName, CancellationToken cancellationToken) =>
        WriteResultAsync(output, eventName, "failed", "InvalidArguments", unchecked((int)0x80070057), null, null, null, cancellationToken);

    private static async Task<int> WriteResultAsync(
        Stream output,
        string eventName,
        string status,
        string reasonCode,
        int hresult,
        string? originalHash,
        string? outputHash,
        CompatibilitySigningPlan? plan,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = eventName,
            ["status"] = status,
            ["reasonCode"] = reasonCode,
            ["hresult"] = $"0x{unchecked((uint)hresult):X8}",
            ["sha256"] = outputHash ?? originalHash,
            ["count"] = plan?.Legs.Count,
            ["digestAlgorithm"] = plan is null ? null : string.Join(",", plan.Legs.Select(static leg => leg.FileDigest.ToString())),
            ["timestampDigestAlgorithm"] = plan is null ? null : string.Join(",", plan.Legs.Select(static leg => leg.TimestampDigest.ToString())),
            ["publicCertificateThumbprint"] = plan is null ? null : string.Join(",", plan.Legs.Select(static leg => leg.Certificate.Thumbprint))
        };
        await AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken).ConfigureAwait(false);
        return status switch
        {
            "passed" => 0,
            "blocked" => 20,
            "failed" when reasonCode == "InvalidArguments" => 64,
            "failed" => 1,
            _ => 70
        };
    }
}
