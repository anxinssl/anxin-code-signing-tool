using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Signing;

#pragma warning disable CA1720
public enum ExistingSignatureInspectionStatus
{
    Unsigned,
    Valid,
    Invalid,
    Untrusted,
    Expired,
    Partial,
    Malformed,
    FamilyIncompatible
}
#pragma warning restore CA1720

public sealed record ExistingSignatureInspectionResult(
    ExistingSignatureInspectionStatus Status,
    int HResult);

public interface IExistingSignatureInspector
{
    ExistingSignatureInspectionResult Inspect(
        string originalPath,
        string stagedPath,
        SigningPlan plan,
        CancellationToken cancellationToken);
}

public sealed class WindowsExistingSignatureInspector : IExistingSignatureInspector
{
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int TrustETimeStamp = unchecked((int)0x80096005);
    private const int CertEExpired = unchecked((int)0x800B0101);
    private const int CertEValidityPeriodNesting = unchecked((int)0x800B0102);
    private const int CertERevoked = unchecked((int)0x800B010C);
    private const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    private const int CertEChaining = unchecked((int)0x800B010A);
    private const int CertEWrongUsage = unchecked((int)0x800B0110);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);

    private readonly IAuthenticodeSignatureInspector signatureInspector;
    private readonly ISignableSubjectProbe subjectProbe;

    public WindowsExistingSignatureInspector()
        : this(new AuthenticodeSignatureInspector(), new CryptSipSignableSubjectProbe())
    {
    }

    internal WindowsExistingSignatureInspector(
        IAuthenticodeSignatureInspector signatureInspector,
        ISignableSubjectProbe subjectProbe)
    {
        this.signatureInspector = signatureInspector
            ?? throw new ArgumentNullException(nameof(signatureInspector));
        this.subjectProbe = subjectProbe
            ?? throw new ArgumentNullException(nameof(subjectProbe));
    }

    public ExistingSignatureInspectionResult Inspect(
        string originalPath,
        string stagedPath,
        SigningPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(originalPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedPath);
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            StableFileIdentity originalIdentity = ReadIdentity(originalPath);
            StableFileIdentity stagedIdentity = ReadIdentity(stagedPath);
            ExistingSignatureInspectionResult result = InspectCore(
                originalPath,
                stagedPath,
                plan,
                cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return originalIdentity == ReadIdentity(originalPath) &&
                stagedIdentity == ReadIdentity(stagedPath)
                    ? result
                    : Failure(ExistingSignatureInspectionStatus.Malformed, TrustESubjectFormUnknown);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SignableSubjectProbeException)
        {
            return Failure(ExistingSignatureInspectionStatus.FamilyIncompatible, InvalidArgumentHResult);
        }
        catch (Exception exception) when (exception is
            IOException or
            InvalidDataException or
            CryptographicException or
            UnauthorizedAccessException or
            System.Security.SecurityException or
            ArgumentException or
            InvalidOperationException or
            OverflowException or
            System.ComponentModel.Win32Exception)
        {
            return Failure(ExistingSignatureInspectionStatus.Malformed, TrustESubjectFormUnknown);
        }
    }

    private ExistingSignatureInspectionResult InspectCore(
        string originalPath,
        string stagedPath,
        SigningPlan plan,
        CancellationToken cancellationToken)
    {
        SignableSubject original = subjectProbe.Probe(originalPath);
        SignableSubject staged = subjectProbe.Probe(stagedPath);
        if (!MatchesPlan(original, plan) ||
            !MatchesPlan(staged, plan) ||
            original.SubjectGuid != staged.SubjectGuid)
        {
            return Failure(ExistingSignatureInspectionStatus.FamilyIncompatible, InvalidArgumentHResult);
        }

        bool hasStructuralSignature = HasStructuralSignature(stagedPath, staged, plan.Subject.FormatFamily);
        AuthenticodeSignatureCountInspection count = signatureInspector.GetSignatureCount(stagedPath);
        if (count.TrustStatus != 0)
        {
            return count.TrustStatus == TrustENoSignature && !hasStructuralSignature
                ? Failure(ExistingSignatureInspectionStatus.Unsigned, count.TrustStatus)
                : Failure(MapTrustFailure(count.TrustStatus), count.TrustStatus);
        }

        int signatureCount = checked((int)count.SecondarySignatureCount + 1);
        if (signatureCount != plan.Legs.Count)
        {
            return Failure(ExistingSignatureInspectionStatus.Partial, TrustENoSignature);
        }

        for (uint index = 0; index <= count.SecondarySignatureCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AuthenticodeSignatureInspection signature = signatureInspector.InspectSignature(stagedPath, index);
            if (signature.TrustStatus != 0)
            {
                return Failure(MapTrustFailure(signature.TrustStatus), signature.TrustStatus);
            }

            if (signature.VerifiedSignatureIndex != index ||
                !IsCanonicalThumbprint(signature.SignerThumbprint) ||
                signature.SignerCertificateDer.Length == 0)
            {
                return Failure(ExistingSignatureInspectionStatus.Malformed, TrustESubjectFormUnknown);
            }

            CodeSigner.Core.Signing.SignatureLeg expected = plan.Legs[checked((int)index)];
            if (!string.Equals(
                    signature.FileDigestAlgorithmOid,
                    DigestOid(expected.FileDigest),
                    StringComparison.Ordinal) ||
                !HasRequiredTimestamp(signature.Timestamp))
            {
                return Failure(ExistingSignatureInspectionStatus.FamilyIncompatible, InvalidArgumentHResult);
            }
        }

        return new ExistingSignatureInspectionResult(ExistingSignatureInspectionStatus.Valid, 0);
    }

    private static bool HasStructuralSignature(
        string stagedPath,
        SignableSubject staged,
        SigningFormatFamily family)
    {
        if (family == SigningFormatFamily.PeImage)
        {
            PeImageCertificateTable table = PeImageCertificateTable.Read(stagedPath);
            if (table.Records.Count == 0)
            {
                return false;
            }

            if (table.Records.Count != 1)
            {
                throw new InvalidDataException(
                    "A PE existing signature must use the supported single-record representation.");
            }

            return true;
        }

        if (family is SigningFormatFamily.PowerShellScript or SigningFormatFamily.WindowsScript)
        {
            return staged.ScriptProfile?.HasSignatureBlock == true;
        }

        if (family == SigningFormatFamily.AppPackage)
        {
            using FileStream stream = new(stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using System.IO.Compression.ZipArchive archive = new(
                stream,
                System.IO.Compression.ZipArchiveMode.Read,
                leaveOpen: false);
            return archive.GetEntry("AppxSignature.p7x") is not null;
        }

        return false;
    }

    private static ExistingSignatureInspectionStatus MapTrustFailure(int hResult) => hResult switch
    {
        CertEExpired or CertEValidityPeriodNesting or TrustETimeStamp =>
            ExistingSignatureInspectionStatus.Expired,
        CertEUntrustedRoot or CertEChaining or CertEWrongUsage or TrustEExplicitDistrust =>
            ExistingSignatureInspectionStatus.Untrusted,
        TrustENoSignature or TrustESubjectFormUnknown => ExistingSignatureInspectionStatus.Malformed,
        TrustEBadDigest or CertERevoked => ExistingSignatureInspectionStatus.Invalid,
        _ => ExistingSignatureInspectionStatus.Invalid
    };

    private static bool MatchesPlan(SignableSubject subject, SigningPlan plan) =>
        subject.PolicySubject.FormatFamily == plan.Subject.FormatFamily &&
        subject.PolicySubject.Capability == plan.Subject.Capability &&
        string.Equals(subject.PolicySubject.Extension, plan.Subject.Extension, StringComparison.Ordinal);

    private static bool HasRequiredTimestamp(AuthenticodeTimestampInspection timestamp) =>
        timestamp.Kind == AuthenticodeTimestampKind.Rfc3161 &&
        string.Equals(timestamp.MessageImprintAlgorithmOid, AuthenticodeOids.Sha256, StringComparison.Ordinal) &&
        timestamp.CryptographicallyValid &&
        timestamp.ChainValid &&
        timestamp.TimeValid &&
        timestamp.TimestampingEkuValid;

    private static string DigestOid(FileDigestAlgorithm digest) => digest switch
    {
        FileDigestAlgorithm.Sha1 => AuthenticodeOids.Sha1,
        FileDigestAlgorithm.Sha256 => AuthenticodeOids.Sha256,
        _ => throw new InvalidDataException("The planned digest algorithm is unsupported.")
    };

    private static bool IsCanonicalThumbprint(string? value) =>
        value is { Length: 40 } && value.All(static character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static StableFileIdentity ReadIdentity(string path)
    {
        using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        return WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
    }

    private static ExistingSignatureInspectionResult Failure(
        ExistingSignatureInspectionStatus status,
        int hResult) => new(status, hResult < 0 ? hResult : TrustESubjectFormUnknown);
}
