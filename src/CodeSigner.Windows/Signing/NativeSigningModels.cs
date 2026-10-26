using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

public enum NativeDigestAlgorithm
{
    Sha1,
    Sha256
}

public sealed record CertificateReference
{
    private CertificateReference(StoreLocation storeLocation, string storeName, string thumbprint)
    {
        StoreLocation = storeLocation;
        StoreName = storeName;
        Thumbprint = thumbprint;
    }

    public StoreLocation StoreLocation { get; }
    public string StoreName { get; }
    public string Thumbprint { get; }

    public static CertificateReference Create(StoreLocation storeLocation, string storeName, string thumbprint)
    {
        if (storeLocation is not StoreLocation.CurrentUser and not StoreLocation.LocalMachine)
        {
            throw new ArgumentOutOfRangeException(nameof(storeLocation));
        }

        if (string.IsNullOrWhiteSpace(storeName))
        {
            throw new ArgumentException("A certificate store name is required.", nameof(storeName));
        }

        string normalized = NormalizeThumbprint(thumbprint);
        return new CertificateReference(storeLocation, storeName, normalized);
    }

    internal static string NormalizeThumbprint(string thumbprint)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);
        string normalized = thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
        if (normalized.Length != 40)
        {
            throw new ArgumentException("A full 20-byte certificate thumbprint is required.", nameof(thumbprint));
        }

        try
        {
            _ = Convert.FromHexString(normalized);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The certificate thumbprint must contain hexadecimal characters only.", nameof(thumbprint), exception);
        }

        return normalized;
    }
}

public sealed record SignatureLeg(
    CertificateReference Certificate,
    NativeDigestAlgorithm FileDigest,
    NativeDigestAlgorithm TimestampDigest,
    Uri TimestampUri,
    bool Append);

public sealed class CompatibilitySigningPlan
{
    private CompatibilitySigningPlan(IReadOnlyList<SignatureLeg> legs)
    {
        Legs = new ReadOnlyCollection<SignatureLeg>(legs.ToArray());
    }

    public IReadOnlyList<SignatureLeg> Legs { get; }

    public static CompatibilitySigningPlan CreateSingle(CertificateReference certificate, Uri timestampUri)
    {
        ValidateTimestampUri(timestampUri);
        return new CompatibilitySigningPlan(
        [
            new SignatureLeg(certificate, NativeDigestAlgorithm.Sha256, NativeDigestAlgorithm.Sha256, timestampUri, Append: false)
        ]);
    }

    public static CompatibilitySigningPlan CreateDual(
        CertificateReference primaryCertificate,
        CertificateReference secondaryCertificate,
        Uri timestampUri)
    {
        ValidateTimestampUri(timestampUri);
        return new CompatibilitySigningPlan(
        [
            new SignatureLeg(primaryCertificate, NativeDigestAlgorithm.Sha1, NativeDigestAlgorithm.Sha256, timestampUri, Append: false),
            new SignatureLeg(secondaryCertificate, NativeDigestAlgorithm.Sha256, NativeDigestAlgorithm.Sha256, timestampUri, Append: true)
        ]);
    }

    internal static CompatibilitySigningPlan CreateStoreRetainedSha1Diagnostic(
        CertificateReference certificate,
        Uri timestampUri)
    {
        ValidateTimestampUri(timestampUri);
        return new CompatibilitySigningPlan(
        [
            new SignatureLeg(certificate, NativeDigestAlgorithm.Sha1, NativeDigestAlgorithm.Sha256, timestampUri, Append: false)
        ]);
    }

    private static void ValidateTimestampUri(Uri timestampUri)
    {
        ArgumentNullException.ThrowIfNull(timestampUri);
        if (!timestampUri.IsAbsoluteUri || timestampUri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("The RFC 3161 timestamp URI must be an absolute HTTP or HTTPS URI.", nameof(timestampUri));
        }
    }
}

public enum NativeSigningReasonCode
{
    None,
    UnsupportedOperatingSystem,
    NativeLibraryUnavailable,
    MissingNativeExport,
    CertificateNotFound,
    CertificateHasNoPrivateKey,
    TimestampUnavailable,
    OperatorCancelled,
    NativeSigningFailed,
    SecondLegFailed,
    VerifierDisagreement,
    OriginalChanged,
    DestinationExists,
    UnsupportedFileType,
    UnsupportedKeyAlgorithm,
    InvalidInput,
    Cancelled
}

public sealed record NativeSigningResult(bool Succeeded, NativeSigningReasonCode ReasonCode, int HResult)
{
    public static NativeSigningResult Success() => new(true, NativeSigningReasonCode.None, 0);

    public static NativeSigningResult Failure(NativeSigningReasonCode reasonCode, int hResult) => new(false, reasonCode, hResult);
}

public sealed record CompatibilityGateResult(
    bool Succeeded,
    NativeSigningReasonCode ReasonCode,
    int HResult,
    string OriginalSha256,
    string? OutputSha256,
    int? FailedLegIndex = null);

public interface INativeSigningLegExecutor
{
    Task<NativeSigningResult> ExecuteAsync(string path, SignatureLeg leg, CancellationToken cancellationToken);
}

public interface INativeSignedFileVerifier
{
    Task<NativeSigningResult> VerifyAsync(string path, CompatibilitySigningPlan plan, CancellationToken cancellationToken);
}
