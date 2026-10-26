using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CoreFileDigestAlgorithm = CodeSigner.Core.Signing.FileDigestAlgorithm;
using CoreSignatureLeg = CodeSigner.Core.Signing.SignatureLeg;
using CoreSigningMode = CodeSigner.Core.Signing.SigningMode;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;

namespace CodeSigner.Windows.Signing;

public enum ProductionSigningError
{
    None,
    InvalidInput,
    UnsupportedFileType,
    CertificateNotFound,
    CertificateHasNoPrivateKey,
    ProviderCancelled,
    TimestampUnavailable,
    NativeSigningFailed,
    VerifierDisagreement,
    OriginalChanged,
    Cancelled
}

public enum ProductionSigningPhase
{
    SigningPrimary,
    SigningSecondary,
    Verifying
}

public enum ProductionSigningNativeCall
{
    SignerSignEx3
}

public enum ProductionHResultOrigin
{
    Native,
    Managed
}

public sealed record ProductionSigningFailureContext(
    ProductionSigningPhase Phase,
    NativeDigestAlgorithm? DigestAlgorithm,
    bool? AppendSignature,
    ProductionSigningNativeCall? NativeCall,
    int? SignerSignEx3Flags,
    NativeSigningReasonCode? NativeReasonCode,
    ProductionHResultOrigin HResultOrigin,
    long? LegElapsedMilliseconds);

public sealed record ProductionSigningReceipt(
    bool Succeeded,
    ProductionSigningError Error,
    int HResult,
    string OriginalSha256,
    string? StagedSha256,
    int? FailedLegIndex = null,
    ProductionSigningFailureContext? Diagnostic = null,
    bool LegacyFallbackAttempted = false);

public sealed class ProductionNativeSigningPlan
{
    private ProductionNativeSigningPlan(
        CoreSigningMode requestedMode,
        CoreSigningMode effectiveMode,
        SigningFormatFamily formatFamily,
        SigningCapability capability,
        SigningEngine engine,
        SigningVerification verification,
        string fileExtension,
        IReadOnlyList<SignatureLeg> legs)
    {
        Mode = requestedMode;
        EffectiveMode = effectiveMode;
        FormatFamily = formatFamily;
        Capability = capability;
        Engine = engine;
        Verification = verification;
        FileExtension = fileExtension;
        Legs = new ReadOnlyCollection<SignatureLeg>(legs.ToArray());
    }

    public CoreSigningMode Mode { get; }

    public CoreSigningMode EffectiveMode { get; }

    public SigningFormatFamily FormatFamily { get; }

    public SigningCapability Capability { get; }

    public SigningEngine Engine { get; }

    public SigningVerification Verification { get; }

    public string FileExtension { get; }

    public IReadOnlyList<SignatureLeg> Legs { get; }

    public static ProductionNativeSigningPlan FromCore(CoreSigningPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.Version != CoreSigningPlan.CurrentVersion ||
            !Enum.IsDefined(plan.RequestedMode) ||
            !Enum.IsDefined(plan.EffectiveMode))
        {
            throw new ArgumentException("The signing plan version or mode is unsupported.", nameof(plan));
        }

        int expectedLegCount = plan.EffectiveMode == CoreSigningMode.Single ? 1 : 2;
        if (plan.Legs.Count != expectedLegCount || !IsFixedExistingSignaturePolicy(plan.ExistingSignatures))
        {
            throw new ArgumentException("The signing plan is not executable by the production signer.", nameof(plan));
        }

        if (plan.Subject.FormatFamily != SigningFormatFamily.PeImage ||
            plan.Subject.Capability != SigningCapability.PeImageDualCapable ||
            plan.Engine != SigningEngine.PeImage ||
            plan.Verification != SigningVerification.PeImage)
        {
            throw new ArgumentException("Only PE-image signing plans are executable by the native PE signer.", nameof(plan));
        }

        var nativeLegs = new List<SignatureLeg>(plan.Legs.Count);
        for (int index = 0; index < plan.Legs.Count; index++)
        {
            CoreSignatureLeg leg = plan.Legs[index];
            ValidateLeg(plan.EffectiveMode, index, leg);
            StoreLocation storeLocation = leg.Certificate.StoreLocation switch
            {
                CertificateStoreLocation.CurrentUser => StoreLocation.CurrentUser,
                CertificateStoreLocation.LocalMachine => StoreLocation.LocalMachine,
                _ => throw new ArgumentException("The certificate store location is unsupported.", nameof(plan))
            };
            CertificateReference certificate = CertificateReference.Create(
                storeLocation,
                leg.Certificate.StoreName,
                leg.Certificate.Thumbprint);
            NativeDigestAlgorithm fileDigest = leg.FileDigest switch
            {
                CoreFileDigestAlgorithm.Sha1 => NativeDigestAlgorithm.Sha1,
                CoreFileDigestAlgorithm.Sha256 => NativeDigestAlgorithm.Sha256,
                _ => throw new ArgumentException("The file digest is unsupported.", nameof(plan))
            };
            nativeLegs.Add(new SignatureLeg(
                certificate,
                fileDigest,
                NativeDigestAlgorithm.Sha256,
                leg.Timestamp.Uri,
                leg.Append));
        }

        return new ProductionNativeSigningPlan(
            plan.RequestedMode,
            plan.EffectiveMode,
            plan.Subject.FormatFamily,
            plan.Subject.Capability,
            plan.Engine,
            plan.Verification,
            plan.Subject.Extension,
            nativeLegs);
    }

    private static void ValidateLeg(CoreSigningMode mode, int index, CoreSignatureLeg leg)
    {
        ArgumentNullException.ThrowIfNull(leg);
        bool expectedAppend = mode == CoreSigningMode.Dual && index == 1;
        CoreFileDigestAlgorithm expectedDigest = mode == CoreSigningMode.Single || index == 1
            ? CoreFileDigestAlgorithm.Sha256
            : CoreFileDigestAlgorithm.Sha1;
        Uri timestampUri = leg.Timestamp.Uri;
        if (leg.Append != expectedAppend ||
            leg.FileDigest != expectedDigest ||
            leg.Timestamp.Protocol != TimestampProtocol.Rfc3161 ||
            leg.Timestamp.TimestampDigest != TimestampDigestAlgorithm.Sha256 ||
            !timestampUri.IsAbsoluteUri ||
            timestampUri.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(timestampUri.UserInfo))
        {
            throw new ArgumentException("A signature leg violates the immutable production signing policy.", nameof(leg));
        }
    }

    private static bool IsFixedExistingSignaturePolicy(ExistingSignaturePolicy policy) =>
        policy.Valid == ExistingSignatureDisposition.Skip &&
        policy.Invalid == ExistingSignatureDisposition.Fail &&
        policy.Untrusted == ExistingSignatureDisposition.Fail &&
        policy.Expired == ExistingSignatureDisposition.Fail &&
        policy.Partial == ExistingSignatureDisposition.Fail &&
        policy.Malformed == ExistingSignatureDisposition.Fail;
}

public interface IProductionSignedFileVerifier
{
    Task<NativeSigningResult> VerifyAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        CancellationToken cancellationToken);
}

public interface IProductionSigningSubjectClassifier
{
    SigningSubject Classify(string path);
}

public sealed class ProductionSigningSubjectClassifier : IProductionSigningSubjectClassifier
{
    public SigningSubject Classify(string path) =>
        SignableSubjectContentClassifier.Classify(path).PolicySubject;
}
