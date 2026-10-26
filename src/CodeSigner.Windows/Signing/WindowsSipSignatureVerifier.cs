using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CoreSignatureLeg = CodeSigner.Core.Signing.SignatureLeg;

namespace CodeSigner.Windows.Signing;

internal sealed class WindowsSipSignatureVerifier : IWindowsSipSignatureVerifier
{
    private readonly IAuthenticodeSignatureInspector signatureInspector;
    private readonly ICertificateStoreMembership certificateStore;
    private readonly ISignableSubjectProbe subjectProbe;

    internal WindowsSipSignatureVerifier(ISignableSubjectProbe subjectProbe)
        : this(
            new AuthenticodeSignatureInspector(),
            new WindowsCertificateStoreMembership(),
            subjectProbe)
    {
    }

    internal WindowsSipSignatureVerifier(
        IAuthenticodeSignatureInspector signatureInspector,
        ICertificateStoreMembership certificateStore,
        ISignableSubjectProbe subjectProbe)
    {
        this.signatureInspector = signatureInspector ?? throw new ArgumentNullException(nameof(signatureInspector));
        this.certificateStore = certificateStore ?? throw new ArgumentNullException(nameof(certificateStore));
        this.subjectProbe = subjectProbe ?? throw new ArgumentNullException(nameof(subjectProbe));
    }

    public WindowsSipVerificationResult VerifySigned(
        string originalPath,
        string stagedPath,
        SigningPlan plan)
    {
        try
        {
            SignableSubject original = subjectProbe.Probe(originalPath);
            SignableSubject staged = subjectProbe.Probe(stagedPath);
            if (!MatchesPlan(original, plan) || !MatchesPlan(staged, plan) ||
                original.SubjectGuid != staged.SubjectGuid)
            {
                return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed);
            }

            AuthenticodeSignatureCountInspection count = signatureInspector.GetSignatureCount(stagedPath);
            AuthenticodeSignatureInspection signature = signatureInspector.InspectSignature(stagedPath, 0);
            CoreSignatureLeg leg = plan.Legs[0];
            CertificateReference certificate = CertificateReference.Create(
                StoreLocation.CurrentUser,
                leg.Certificate.StoreName,
                leg.Certificate.Thumbprint);
            bool signatureValid = count.TrustStatus == 0 &&
                count.SecondarySignatureCount == 0 &&
                signature.TrustStatus == 0 &&
                signature.VerifiedSignatureIndex == 0 &&
                string.Equals(signature.FileDigestAlgorithmOid, AuthenticodeOids.Sha256, StringComparison.Ordinal) &&
                string.Equals(signature.SignerThumbprint, leg.Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase) &&
                certificateStore.ContainsExact(certificate, signature.SignerCertificateDer);
            if (!signatureValid)
            {
                return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed);
            }

            if (plan.Subject.FormatFamily is SigningFormatFamily.PowerShellScript or SigningFormatFamily.WindowsScript &&
                !VerifyScriptContent(originalPath, stagedPath, original.ScriptProfile, staged.ScriptProfile))
            {
                return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed);
            }

            if (plan.Subject.FormatFamily == SigningFormatFamily.AppPackage)
            {
                return VerifyPackagePublisher(stagedPath, signature.SignerCertificateDer);
            }

            return WindowsSipVerificationResult.Success();
        }
        catch (SignableSubjectProbeException exception) when (exception.Error is
            SignableSubjectProbeError.InvalidAppPackage or
            SignableSubjectProbeError.IncompatibleBlockMapHash or
            SignableSubjectProbeError.UnsafePackagePath)
        {
            return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.PackageIncompatible);
        }
        catch (Exception exception) when (exception is
            IOException or
            InvalidDataException or
            CryptographicException or
            UnauthorizedAccessException or
            System.Security.SecurityException or
            ArgumentException)
        {
            return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed);
        }
    }

    public WindowsSipVerificationResult VerifyExisting(
        string originalPath,
        string stagedPath,
        SigningPlan plan)
    {
        try
        {
            SignableSubject original = subjectProbe.Probe(originalPath);
            SignableSubject staged = subjectProbe.Probe(stagedPath);
            AuthenticodeSignatureInspection signature = signatureInspector.InspectSignature(stagedPath, 0);
            return MatchesPlan(original, plan) &&
                MatchesPlan(staged, plan) &&
                original.SubjectGuid == staged.SubjectGuid &&
                signature.TrustStatus == 0
                    ? WindowsSipVerificationResult.Success()
                    : WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed);
        }
        catch (Exception exception) when (exception is
            IOException or
            InvalidDataException or
            CryptographicException or
            UnauthorizedAccessException or
            System.Security.SecurityException or
            ArgumentException)
        {
            return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed);
        }
    }

    private static bool MatchesPlan(SignableSubject subject, SigningPlan plan) =>
        subject.PolicySubject.FormatFamily == plan.Subject.FormatFamily &&
        subject.PolicySubject.Capability == SigningCapability.WindowsSipSingleOnly &&
        string.Equals(subject.PolicySubject.Extension, plan.Subject.Extension, StringComparison.Ordinal);

    private static bool VerifyScriptContent(
        string originalPath,
        string stagedPath,
        ScriptContentProfile? originalProfile,
        ScriptContentProfile? stagedProfile)
    {
        if (originalProfile is null || stagedProfile is null ||
            originalProfile.HasSignatureBlock ||
            !stagedProfile.HasSignatureBlock ||
            originalProfile.Encoding != stagedProfile.Encoding ||
            originalProfile.Newlines != stagedProfile.Newlines ||
            originalProfile.IsEncoded != stagedProfile.IsEncoded)
        {
            return false;
        }

        byte[] original = File.ReadAllBytes(originalPath);
        byte[] staged = File.ReadAllBytes(stagedPath);
        return staged.Length > original.Length && staged.AsSpan(0, original.Length).SequenceEqual(original);
    }

    private static WindowsSipVerificationResult VerifyPackagePublisher(
        string stagedPath,
        byte[] signerCertificateDer)
    {
        string extension = Path.GetExtension(stagedPath).ToLowerInvariant();
        string manifestName = extension is ".appxbundle" or ".msixbundle"
            ? "AppxMetadata/AppxBundleManifest.xml"
            : "AppxManifest.xml";
        using FileStream stream = new(stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using ZipArchive archive = new(stream, ZipArchiveMode.Read, leaveOpen: false);
        ZipArchiveEntry? manifestEntry = archive.GetEntry(manifestName);
        if (manifestEntry is null)
        {
            return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.PackageIncompatible);
        }

        XmlReaderSettings settings = new()
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 4 * 1024 * 1024
        };
        using Stream manifestStream = manifestEntry.Open();
        using XmlReader reader = XmlReader.Create(manifestStream, settings);
        XDocument manifest = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        XElement? identity = manifest.Root?.Elements()
            .FirstOrDefault(element => element.Name.LocalName == "Identity");
        string? publisher = identity?.Attribute("Publisher")?.Value;
        if (string.IsNullOrWhiteSpace(publisher))
        {
            return WindowsSipVerificationResult.Failure(WindowsSipVerificationError.PackageIncompatible);
        }

        using X509Certificate2 signer = X509CertificateLoader.LoadCertificate(signerCertificateDer);
        X500DistinguishedName declaredPublisher = new(publisher);
        return declaredPublisher.RawData.AsSpan().SequenceEqual(signer.SubjectName.RawData)
            ? WindowsSipVerificationResult.Success()
            : WindowsSipVerificationResult.Failure(WindowsSipVerificationError.CertificateMismatch);
    }
}
