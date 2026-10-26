using System.Security.Cryptography;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Signing;

namespace CodeSigner.CompatibilityProbe.Signing;

internal delegate Task<NativeSigningResult> ProductPeSigningOperation(
    string stagedPath,
    ProductionNativeSigningPlan plan,
    CancellationToken cancellationToken);

internal delegate Task<ProductPeInspection> ProductPeInspectionOperation(
    string path,
    ProductionNativeSigningPlan plan,
    CancellationToken cancellationToken);

internal sealed record ProductPeSignatureInspection(
    int Index,
    string DigestAlgorithm,
    string SignerThumbprint,
    int Rfc3161Count,
    string? Rfc3161DigestAlgorithm,
    bool Rfc3161SignatureBinding);

internal sealed record ProductPeInspection(
    NativeSigningResult Result,
    IReadOnlyList<ProductPeSignatureInspection> Signatures,
    int WinVerifyTrustStatus);

internal static class ProductPeSigningCommands
{
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);
    private const int FailureHResult = unchecked((int)0x80004005);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    internal static Task<int> RunSingleAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken) =>
        RunSigningAsync(
            arguments,
            SigningMode.Single,
            output,
            ExecuteNativeAsync,
            InspectNativeAsync,
            cancellationToken);

    internal static Task<int> RunDualAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken) =>
        RunSigningAsync(
            arguments,
            SigningMode.Dual,
            output,
            ExecuteNativeAsync,
            InspectNativeAsync,
            cancellationToken);

    internal static Task<int> RunSingleAsync(
        string[] arguments,
        Stream output,
        ProductPeSigningOperation signingOperation,
        ProductPeInspectionOperation inspectionOperation,
        CancellationToken cancellationToken) =>
        RunSigningAsync(
            arguments,
            SigningMode.Single,
            output,
            signingOperation,
            inspectionOperation,
            cancellationToken);

    internal static Task<int> RunDualAsync(
        string[] arguments,
        Stream output,
        ProductPeSigningOperation signingOperation,
        ProductPeInspectionOperation inspectionOperation,
        CancellationToken cancellationToken) =>
        RunSigningAsync(
            arguments,
            SigningMode.Dual,
            output,
            signingOperation,
            inspectionOperation,
            cancellationToken);

    internal static Task<int> RunInspectAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken) =>
        RunInspectAsync(arguments, output, InspectNativeAsync, cancellationToken);

    internal static async Task<int> RunInspectAsync(
        string[] arguments,
        Stream output,
        ProductPeInspectionOperation inspectionOperation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inspectionOperation);
        if (arguments.Length != 6 ||
            string.IsNullOrWhiteSpace(arguments[1]) ||
            !File.Exists(arguments[1]) ||
            !TryParseMode(arguments[5], out SigningMode mode) ||
            !TryCreatePlan(mode, arguments[1], arguments[2], arguments[3], arguments[4], out ProductionNativeSigningPlan? plan))
        {
            return await WriteFailureAsync(output, "product-pe-inspect", "InvalidArguments", cancellationToken)
                .ConfigureAwait(false);
        }
        if (plan is null)
        {
            return await WriteFailureAsync(output, "product-pe-inspect", "InvalidArguments", cancellationToken)
                .ConfigureAwait(false);
        }

        string beforeHash;
        try
        {
            beforeHash = await HashAsync(arguments[1], cancellationToken).ConfigureAwait(false);
            ProductPeInspection inspection = await inspectionOperation(arguments[1], plan, cancellationToken)
                .ConfigureAwait(false);
            string afterHash = await HashAsync(arguments[1], cancellationToken).ConfigureAwait(false);
            NativeSigningResult result = string.Equals(beforeHash, afterHash, StringComparison.Ordinal)
                ? inspection.Result
                : NativeSigningResult.Failure(NativeSigningReasonCode.OriginalChanged, FailureHResult);
            return await WriteReceiptAsync(
                output,
                "product-pe-inspect",
                result,
                plan,
                beforeHash,
                afterHash,
                afterHash,
                inspection.Signatures,
                inspection.WinVerifyTrustStatus,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            return await WriteFailureAsync(
                output,
                "product-pe-inspect",
                NativeSigningReasonCode.InvalidInput.ToString(),
                cancellationToken,
                exception.HResult).ConfigureAwait(false);
        }
    }

    private static async Task<int> RunSigningAsync(
        string[] arguments,
        SigningMode mode,
        Stream output,
        ProductPeSigningOperation signingOperation,
        ProductPeInspectionOperation inspectionOperation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signingOperation);
        ArgumentNullException.ThrowIfNull(inspectionOperation);
        string eventName = mode == SigningMode.Single ? "product-pe-single" : "product-pe-dual";
        if (arguments.Length != 7 ||
            string.IsNullOrWhiteSpace(arguments[1]) ||
            string.IsNullOrWhiteSpace(arguments[2]) ||
            !File.Exists(arguments[1]) ||
            !TryCreatePlan(mode, arguments[1], arguments[3], arguments[4], arguments[5], arguments[6], out ProductionNativeSigningPlan? plan))
        {
            return await WriteFailureAsync(output, eventName, "InvalidArguments", cancellationToken)
                .ConfigureAwait(false);
        }
        if (plan is null)
        {
            return await WriteFailureAsync(output, eventName, "InvalidArguments", cancellationToken)
                .ConfigureAwait(false);
        }

        string sourcePath = Path.GetFullPath(arguments[1]);
        string outputPath = Path.GetFullPath(arguments[2]);
        if (string.Equals(sourcePath, outputPath, StringComparison.OrdinalIgnoreCase))
        {
            return await WriteFailureAsync(output, eventName, "InvalidArguments", cancellationToken)
                .ConfigureAwait(false);
        }

        string? attemptDirectory = null;
        FileStream? reservedOutput = null;
        bool outputReserved = false;
        bool outputPublished = false;
        string? sourceHash = null;
        string? stagedHash = null;
        try
        {
            string outputRoot = Path.GetDirectoryName(outputPath)
                ?? throw new InvalidDataException("The output path has no parent directory.");
            Directory.CreateDirectory(outputRoot);
            reservedOutput = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            outputReserved = true;
            attemptDirectory = TransactionalStaging.CreateAttemptDirectory(outputRoot);
            string stagedPath = Path.Combine(attemptDirectory, Path.GetFileName(sourcePath));
            File.Copy(sourcePath, stagedPath, overwrite: false);
            sourceHash = await HashAsync(sourcePath, cancellationToken).ConfigureAwait(false);
            if (PeImageCertificateTable.Read(stagedPath).Records.Count != 0)
            {
                return await WriteReceiptAsync(
                    output,
                    eventName,
                    NativeSigningResult.Failure(NativeSigningReasonCode.InvalidInput, InvalidArgumentHResult),
                    plan,
                    sourceHash,
                    await HashAsync(stagedPath, cancellationToken).ConfigureAwait(false),
                    null,
                    Array.Empty<ProductPeSignatureInspection>(),
                    InvalidArgumentHResult,
                    cancellationToken).ConfigureAwait(false);
            }

            NativeSigningResult signing = await signingOperation(stagedPath, plan, cancellationToken)
                .ConfigureAwait(false);
            stagedHash = await HashAsync(stagedPath, cancellationToken).ConfigureAwait(false);
            string sourceHashAfter = await HashAsync(sourcePath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(sourceHash, sourceHashAfter, StringComparison.Ordinal))
            {
                signing = NativeSigningResult.Failure(NativeSigningReasonCode.OriginalChanged, FailureHResult);
            }

            if (!IsSuccess(signing))
            {
                return await WriteReceiptAsync(
                    output,
                    eventName,
                    NormalizeFailure(signing),
                    plan,
                    sourceHash,
                    stagedHash,
                    null,
                    Array.Empty<ProductPeSignatureInspection>(),
                    signing.HResult,
                    cancellationToken).ConfigureAwait(false);
            }

            ProductPeInspection inspection = await inspectionOperation(stagedPath, plan, cancellationToken)
                .ConfigureAwait(false);
            if (!IsSuccess(inspection.Result))
            {
                return await WriteReceiptAsync(
                    output,
                    eventName,
                    NativeSigningResult.Failure(
                        NativeSigningReasonCode.VerifierDisagreement,
                        inspection.Result.HResult < 0 ? inspection.Result.HResult : FailureHResult),
                    plan,
                    sourceHash,
                    stagedHash,
                    null,
                    inspection.Signatures,
                    inspection.WinVerifyTrustStatus,
                    cancellationToken).ConfigureAwait(false);
            }

            await using (FileStream staged = new(stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                await staged.CopyToAsync(reservedOutput, cancellationToken).ConfigureAwait(false);
            }
            await reservedOutput.FlushAsync(cancellationToken).ConfigureAwait(false);
            reservedOutput.Dispose();
            reservedOutput = null;
            string outputHash = await HashAsync(outputPath, cancellationToken).ConfigureAwait(false);
            string finalSourceHash = await HashAsync(sourcePath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(sourceHash, finalSourceHash, StringComparison.Ordinal))
            {
                return await WriteReceiptAsync(
                    output,
                    eventName,
                    NativeSigningResult.Failure(NativeSigningReasonCode.OriginalChanged, FailureHResult),
                    plan,
                    sourceHash,
                    stagedHash,
                    null,
                    inspection.Signatures,
                    inspection.WinVerifyTrustStatus,
                    cancellationToken).ConfigureAwait(false);
            }
            outputPublished = true;
            return await WriteReceiptAsync(
                output,
                eventName,
                NativeSigningResult.Success(),
                plan,
                sourceHash,
                stagedHash,
                outputHash,
                inspection.Signatures,
                inspection.WinVerifyTrustStatus,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return await WriteReceiptAsync(
                output,
                eventName,
                NativeSigningResult.Failure(NativeSigningReasonCode.Cancelled, unchecked((int)0x800704C7)),
                plan,
                sourceHash,
                stagedHash,
                null,
                Array.Empty<ProductPeSignatureInspection>(),
                unchecked((int)0x800704C7),
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            NativeSigningReasonCode reason = exception is IOException && !outputReserved && File.Exists(outputPath)
                ? NativeSigningReasonCode.DestinationExists
                : NativeSigningReasonCode.InvalidInput;
            return await WriteReceiptAsync(
                output,
                eventName,
                NativeSigningResult.Failure(reason, exception.HResult < 0 ? exception.HResult : FailureHResult),
                plan,
                sourceHash,
                stagedHash,
                null,
                Array.Empty<ProductPeSignatureInspection>(),
                exception.HResult,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            reservedOutput?.Dispose();
            if (!outputPublished && outputReserved && File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
            if (attemptDirectory is not null)
            {
                TransactionalStaging.DeleteAttempt(attemptDirectory);
            }
        }
    }

    private static async Task<NativeSigningResult> ExecuteNativeAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        CancellationToken cancellationToken) =>
        await PeAuthenticodeSigningEngine.Create()
            .ExecuteAsync(stagedPath, plan, cancellationToken)
            .ConfigureAwait(false);

    private static async Task<ProductPeInspection> InspectNativeAsync(
        string path,
        ProductionNativeSigningPlan plan,
        CancellationToken cancellationToken)
    {
        PeImageCertificateTable table = PeImageCertificateTable.Read(path);
        if (table.Records.Count != 1)
        {
            NativeSigningResult invalid = NativeSigningResult.Failure(
                NativeSigningReasonCode.VerifierDisagreement,
                InvalidArgumentHResult);
            return new ProductPeInspection(invalid, Array.Empty<ProductPeSignatureInspection>(), invalid.HResult);
        }

        PeAuthenticodeCmsInspection primary = new AuthenticodeCmsRecordInspector().Inspect(table.Records[0].Content);
        PeAuthenticodeCmsInspection[] logicalSignatures = [primary, .. primary.NestedSignatures];
        ProductPeSignatureInspection[] signatures = logicalSignatures
            .Select(static (signature, index) => new ProductPeSignatureInspection(
                index,
                signature.DigestAlgorithmOid,
                signature.SignerCertificateThumbprint,
                signature.Rfc3161TimestampCount,
                signature.TimestampDigestAlgorithmOid,
                signature.TimestampMessageImprintMatchesSignature))
            .ToArray();
        NativeSigningResult trust = await new WinVerifyTrustSignatureVerifier()
            .VerifyAsync(path, plan, cancellationToken)
            .ConfigureAwait(false);
        return new ProductPeInspection(trust, signatures, trust.HResult);
    }

    private static bool TryCreatePlan(
        SigningMode mode,
        string sourcePath,
        string storeLocation,
        string storeName,
        string thumbprint,
        out ProductionNativeSigningPlan? plan) =>
        TryCreatePlan(mode, sourcePath, storeLocation, storeName, thumbprint, TimestampPolicy.DefaultUri, out plan);

    private static bool TryCreatePlan(
        SigningMode mode,
        string sourcePath,
        string storeLocation,
        string storeName,
        string thumbprint,
        string timestampUri,
        out ProductionNativeSigningPlan? plan)
    {
        plan = null;
        CertificateStoreLocation? location = storeLocation switch
        {
            "CurrentUser" => CertificateStoreLocation.CurrentUser,
            "LocalMachine" => CertificateStoreLocation.LocalMachine,
            _ => null
        };
        if (location is null)
        {
            return false;
        }

        PolicyResult<CertificateRef> certificate = CertificateRef.TryCreate(location.Value, storeName, thumbprint);
        if (!certificate.IsSuccess)
        {
            return false;
        }

        string extension = Path.GetExtension(sourcePath);
        PolicyResult<SigningPlan> corePlan = mode == SigningMode.Single
            ? SigningPlan.TryCreateSingle(certificate.Value, extension, timestampUri)
            : SigningPlan.TryCreateDual(certificate.Value, certificate.Value, extension, timestampUri);
        if (!corePlan.IsSuccess)
        {
            return false;
        }

        plan = ProductionNativeSigningPlan.FromCore(corePlan.Value!);
        return true;
    }

    private static bool TryParseMode(string value, out SigningMode mode)
    {
        mode = value switch
        {
            "single" => SigningMode.Single,
            "dual" => SigningMode.Dual,
            _ => (SigningMode)(-1)
        };
        return Enum.IsDefined(mode);
    }

    private static async Task<int> WriteFailureAsync(
        Stream output,
        string eventName,
        string reasonCode,
        CancellationToken cancellationToken,
        int hResult = InvalidArgumentHResult)
    {
        var receipt = new ProductPeReceipt(
            1,
            eventName,
            "failed",
            reasonCode,
            hResult,
            $"0x{unchecked((uint)hResult):X8}",
            null,
            null,
            null,
            null,
            new ProductPeResult(false, reasonCode, hResult),
            Array.Empty<ProductPeSignatureInspection>(),
            hResult);
        await JsonSerializer.SerializeAsync(output, receipt, JsonOptions, cancellationToken).ConfigureAwait(false);
        await output.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        return 64;
    }

    private static async Task<int> WriteReceiptAsync(
        Stream output,
        string eventName,
        NativeSigningResult result,
        ProductionNativeSigningPlan plan,
        string? sourceHash,
        string? stagedHash,
        string? outputHash,
        IReadOnlyList<ProductPeSignatureInspection> signatures,
        int winVerifyTrustStatus,
        CancellationToken cancellationToken)
    {
        var receipt = new ProductPeReceipt(
            1,
            eventName,
            IsSuccess(result) ? "passed" : "failed",
            result.ReasonCode.ToString(),
            result.HResult,
            $"0x{unchecked((uint)result.HResult):X8}",
            sourceHash,
            stagedHash,
            outputHash,
            new ProductPePlan(
                plan.Mode.ToString(),
                plan.EffectiveMode.ToString(),
                plan.Legs.Select(static leg => new ProductPePlanLeg(
                    leg.FileDigest.ToString(),
                    leg.Append,
                    leg.Certificate.StoreLocation.ToString(),
                    leg.Certificate.StoreName,
                    leg.Certificate.Thumbprint,
                    leg.TimestampUri.Scheme,
                    leg.TimestampUri.Host,
                    leg.TimestampDigest.ToString())).ToArray()),
            new ProductPeResult(result.Succeeded, result.ReasonCode.ToString(), result.HResult),
            signatures,
            winVerifyTrustStatus);
        await JsonSerializer.SerializeAsync(output, receipt, JsonOptions, cancellationToken).ConfigureAwait(false);
        await output.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        return IsSuccess(result) ? 0 : 1;
    }

    private static bool IsSuccess(NativeSigningResult result) =>
        result.Succeeded && result.ReasonCode == NativeSigningReasonCode.None && result.HResult >= 0;

    private static NativeSigningResult NormalizeFailure(NativeSigningResult result) =>
        IsSuccess(result) || result.ReasonCode == NativeSigningReasonCode.None || result.HResult >= 0
            ? NativeSigningResult.Failure(NativeSigningReasonCode.NativeSigningFailed, FailureHResult)
            : result;

    private static bool IsExpectedFailure(Exception exception) => exception is
        IOException or
        UnauthorizedAccessException or
        InvalidDataException or
        ArgumentException or
        CryptographicException or
        System.ComponentModel.Win32Exception or
        System.Security.SecurityException or
        NotSupportedException or
        OverflowException;

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }

    private sealed record ProductPeReceipt(
        int SchemaVersion,
        string Event,
        string Status,
        string ReasonCode,
        int HResult,
        string HResultHex,
        string? SourceSha256,
        string? StagedSha256,
        string? OutputSha256,
        ProductPePlan? Plan,
        ProductPeResult Result,
        IReadOnlyList<ProductPeSignatureInspection> Signatures,
        int WinVerifyTrustStatus);

    private sealed record ProductPePlan(
        string RequestedMode,
        string EffectiveMode,
        IReadOnlyList<ProductPePlanLeg> Legs);

    private sealed record ProductPePlanLeg(
        string DigestAlgorithm,
        bool Append,
        string CertificateStoreLocation,
        string CertificateStoreName,
        string SignerThumbprint,
        string TimestampScheme,
        string TimestampHost,
        string Rfc3161DigestAlgorithm);

    private sealed record ProductPeResult(bool Succeeded, string ReasonCode, int HResult);
}
