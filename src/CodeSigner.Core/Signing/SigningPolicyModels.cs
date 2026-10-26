using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;

namespace CodeSigner.Core.Signing;

public enum PolicyErrorCode
{
    MalformedJson,
    UnknownField,
    MissingField,
    InvalidFieldType,
    InvalidCertificate,
    InvalidUri,
    UnsupportedFileType,
    InvalidSignatureOrder,
    InvalidAppendSequence,
    InvalidTimestampDigest,
    UnsafePolicy,
    UnsupportedVersion
}

public sealed record PolicyError(PolicyErrorCode Code, string Path, string Message)
{
    public override string ToString() => $"{Code} at {Path}: {Message}";
}

public sealed class PolicyResult<T> where T : class
{
    private PolicyResult(T? value, IReadOnlyList<PolicyError> errors)
    {
        Value = value;
        Errors = errors;
    }

    public bool IsSuccess => Value is not null && Errors.Count == 0;

    public T? Value { get; }

    public IReadOnlyList<PolicyError> Errors { get; }

    internal static PolicyResult<T> Success(T value) =>
        new(value, Array.Empty<PolicyError>());

    internal static PolicyResult<T> Failure(PolicyErrorCode code, string path, string message) =>
        new(null, Array.AsReadOnly([new PolicyError(code, path, message)]));
}

public enum CertificateStoreLocation
{
    CurrentUser,
    LocalMachine
}

public sealed class CertificateRef
{
    private CertificateRef(CertificateStoreLocation storeLocation, string storeName, string thumbprint)
    {
        StoreLocation = storeLocation;
        StoreName = storeName;
        Thumbprint = thumbprint;
    }

    public CertificateStoreLocation StoreLocation { get; }

    public string StoreName { get; }

    public string Thumbprint { get; }

    public static PolicyResult<CertificateRef> TryCreate(
        CertificateStoreLocation storeLocation,
        string? storeName,
        string? thumbprint)
    {
        if (!Enum.IsDefined(storeLocation))
        {
            return PolicyResult<CertificateRef>.Failure(
                PolicyErrorCode.InvalidCertificate,
                "certificate.storeLocation",
                "The certificate store location is unsupported.");
        }

        if (!string.Equals(storeName, "My", StringComparison.Ordinal))
        {
            return PolicyResult<CertificateRef>.Failure(
                PolicyErrorCode.InvalidCertificate,
                "certificate.storeName",
                "Only the exact personal certificate store name 'My' is supported.");
        }

        if (!IsFullSha1Thumbprint(thumbprint))
        {
            return PolicyResult<CertificateRef>.Failure(
                PolicyErrorCode.InvalidCertificate,
                "certificate.thumbprint",
                "A full 40-character hexadecimal certificate thumbprint is required.");
        }

        return PolicyResult<CertificateRef>.Success(
            new CertificateRef(storeLocation, storeName!, thumbprint!.ToUpperInvariant()));
    }

    private static bool IsFullSha1Thumbprint(string? thumbprint)
    {
        if (thumbprint is null || thumbprint.Length != 40)
        {
            return false;
        }

        foreach (char character in thumbprint)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}

public enum FileDigestAlgorithm
{
    Sha1,
    Sha256
}

public enum TimestampProtocol
{
    Rfc3161
}

public enum TimestampDigestAlgorithm
{
    Sha256
}

public sealed class TimestampPolicy
{
    public const string DefaultUri = "http://time.certum.pl";

    private TimestampPolicy(Uri uri)
    {
        Protocol = TimestampProtocol.Rfc3161;
        TimestampDigest = TimestampDigestAlgorithm.Sha256;
        Uri = uri;
    }

    public TimestampProtocol Protocol { get; }

    public TimestampDigestAlgorithm TimestampDigest { get; }

    public Uri Uri { get; }

    public static PolicyResult<TimestampPolicy> TryCreate(string? uri = null)
    {
        string candidate = uri ?? DefaultUri;
        if (!System.Uri.TryCreate(candidate, UriKind.Absolute, out Uri? parsed)
            || (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
            || !string.IsNullOrEmpty(parsed.UserInfo))
        {
            return PolicyResult<TimestampPolicy>.Failure(
                PolicyErrorCode.InvalidUri,
                "timestamp.uri",
                "The timestamp URI must be an absolute HTTP or HTTPS URI without credentials.");
        }

        return PolicyResult<TimestampPolicy>.Success(new TimestampPolicy(parsed));
    }
}

public enum ExistingSignatureStatus
{
    Valid,
    Invalid,
    Untrusted,
    Expired,
    Partial,
    Malformed
}

public enum ExistingSignatureDisposition
{
    Skip,
    Fail
}

public sealed class ExistingSignaturePolicy
{
    private readonly ExistingSignatureDisposition valid;
    private readonly ExistingSignatureDisposition invalid;
    private readonly ExistingSignatureDisposition untrusted;
    private readonly ExistingSignatureDisposition expired;
    private readonly ExistingSignatureDisposition partial;
    private readonly ExistingSignatureDisposition malformed;

    private ExistingSignaturePolicy()
    {
        valid = ExistingSignatureDisposition.Skip;
        invalid = ExistingSignatureDisposition.Fail;
        untrusted = ExistingSignatureDisposition.Fail;
        expired = ExistingSignatureDisposition.Fail;
        partial = ExistingSignatureDisposition.Fail;
        malformed = ExistingSignatureDisposition.Fail;
    }

    public ExistingSignatureDisposition Valid => valid;

    public ExistingSignatureDisposition Invalid => invalid;

    public ExistingSignatureDisposition Untrusted => untrusted;

    public ExistingSignatureDisposition Expired => expired;

    public ExistingSignatureDisposition Partial => partial;

    public ExistingSignatureDisposition Malformed => malformed;

    public ExistingSignatureDisposition For(ExistingSignatureStatus status) => status switch
    {
        ExistingSignatureStatus.Valid => Valid,
        ExistingSignatureStatus.Invalid => Invalid,
        ExistingSignatureStatus.Untrusted => Untrusted,
        ExistingSignatureStatus.Expired => Expired,
        ExistingSignatureStatus.Partial => Partial,
        ExistingSignatureStatus.Malformed => Malformed,
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown signature status.")
    };

    internal static ExistingSignaturePolicy CreateFixed() => new();
}

public enum SigningFormatFamily
{
    PeImage,
    WindowsInstaller,
    Cabinet,
    Catalog,
    AppPackage,
    PowerShellScript,
    WindowsScript
}

public enum SigningCapability
{
    PeImageDualCapable,
    WindowsSipSingleOnly
}

public enum SigningEngine
{
    PeImage,
    WindowsSip
}

public enum SigningVerification
{
    PeImage,
    WindowsSip
}

public sealed class SigningSubject
{
    private const int DosHeaderPeOffset = 0x3c;
    private const int PeSignatureSize = 4;
    private const int CoffHeaderSize = 20;
    private const int OptionalHeaderMagicSize = 2;
    private const int Pe32NumberOfDirectoriesOffset = 92;
    private const int Pe32DirectoriesOffset = 96;
    private const int Pe32PlusNumberOfDirectoriesOffset = 108;
    private const int Pe32PlusDirectoriesOffset = 112;
    private const int AttributeCertificateDirectoryIndex = 4;
    private const int DataDirectorySize = 8;

    private SigningSubject(
        SigningFormatFamily formatFamily,
        string extension,
        SigningCapability capability)
    {
        FormatFamily = formatFamily;
        Extension = extension;
        Capability = capability;
    }

    public SigningFormatFamily FormatFamily { get; }

    public string Extension { get; }

    public SigningCapability Capability { get; }

    public static PolicyResult<SigningSubject> TryCreateForExtension(string? extension)
    {
        if (!TryNormalizeExtension(extension, allowEmpty: false, out string normalized))
        {
            return UnsupportedExtension();
        }

        SigningFormatFamily? formatFamily = FormatForKnownExtension(normalized);
        return formatFamily is null
            ? UnsupportedExtension()
            : PolicyResult<SigningSubject>.Success(Create(formatFamily.Value, normalized));
    }

    public static PolicyResult<SigningSubject> TryClassify(
        string? extension,
        ReadOnlySpan<byte> contentPrefix)
    {
        if (!TryNormalizeExtension(extension, allowEmpty: true, out string normalized))
        {
            return UnsupportedExtension();
        }

        if (IsPeImage(contentPrefix))
        {
            return PolicyResult<SigningSubject>.Success(Create(SigningFormatFamily.PeImage, normalized));
        }

        SigningFormatFamily? formatFamily = FormatForKnownExtension(normalized);
        if (formatFamily is null || formatFamily == SigningFormatFamily.PeImage)
        {
            return UnsupportedExtension();
        }

        return PolicyResult<SigningSubject>.Success(Create(formatFamily.Value, normalized));
    }

    internal static PolicyResult<SigningSubject> TryCreateParsed(
        SigningFormatFamily formatFamily,
        string? extension,
        SigningCapability capability)
    {
        if (!Enum.IsDefined(formatFamily) || !Enum.IsDefined(capability) ||
            !TryNormalizeExtension(
                extension,
                allowEmpty: formatFamily == SigningFormatFamily.PeImage,
                out string normalized))
        {
            return UnsupportedExtension("$.subject.extension");
        }

        if (formatFamily != SigningFormatFamily.PeImage &&
            FormatForKnownExtension(normalized) != formatFamily)
        {
            return UnsupportedExtension("$.subject.extension");
        }

        SigningCapability expectedCapability = CapabilityFor(formatFamily);
        if (capability != expectedCapability)
        {
            return PolicyResult<SigningSubject>.Failure(
                PolicyErrorCode.UnsafePolicy,
                "$.subject.capability",
                "The declared capability does not match the subject format family.");
        }

        return PolicyResult<SigningSubject>.Success(new SigningSubject(formatFamily, normalized, capability));
    }

    private static SigningSubject Create(SigningFormatFamily formatFamily, string extension) =>
        new(formatFamily, extension, CapabilityFor(formatFamily));

    private static SigningCapability CapabilityFor(SigningFormatFamily formatFamily) =>
        formatFamily == SigningFormatFamily.PeImage
            ? SigningCapability.PeImageDualCapable
            : SigningCapability.WindowsSipSingleOnly;

    private static SigningFormatFamily? FormatForKnownExtension(string extension) => extension switch
    {
        ".exe" or ".dll" or ".ocx" or ".cpl" or ".scr" or ".sys" or ".drv" or ".ax" or ".acm" or ".efi" =>
            SigningFormatFamily.PeImage,
        ".msi" or ".msp" or ".msm" => SigningFormatFamily.WindowsInstaller,
        ".cab" => SigningFormatFamily.Cabinet,
        ".cat" => SigningFormatFamily.Catalog,
        ".appx" or ".appxbundle" or ".msix" or ".msixbundle" => SigningFormatFamily.AppPackage,
        ".ps1" or ".psm1" or ".psd1" or ".ps1xml" or ".cdxml" or ".xaml" =>
            SigningFormatFamily.PowerShellScript,
        ".vbs" or ".js" or ".jse" or ".vbe" or ".wsf" => SigningFormatFamily.WindowsScript,
        _ => null
    };

    private static bool TryNormalizeExtension(string? extension, bool allowEmpty, out string normalized)
    {
        normalized = string.Empty;
        if (extension is null || extension.Length > 32 ||
            extension.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, ':']) >= 0)
        {
            return false;
        }

        if (extension.Length == 0)
        {
            return allowEmpty;
        }

        if (extension[0] != '.' || extension.Length == 1 || extension.AsSpan().Contains(' '))
        {
            return false;
        }

        normalized = extension.ToLowerInvariant();
        return true;
    }

    private static bool IsPeImage(ReadOnlySpan<byte> content)
    {
        if (content.Length < DosHeaderPeOffset + sizeof(int) || content[0] != 'M' || content[1] != 'Z')
        {
            return false;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(
            content.Slice(DosHeaderPeOffset, sizeof(int)));
        int optionalHeaderOffset;
        try
        {
            optionalHeaderOffset = checked(peOffset + PeSignatureSize + CoffHeaderSize);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (peOffset < DosHeaderPeOffset + sizeof(int) ||
            optionalHeaderOffset > content.Length - OptionalHeaderMagicSize ||
            content[peOffset] != 'P' || content[peOffset + 1] != 'E' ||
            content[peOffset + 2] != 0 || content[peOffset + 3] != 0)
        {
            return false;
        }

        int coffHeaderOffset = peOffset + PeSignatureSize;
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(content.Slice(coffHeaderOffset, sizeof(ushort)));
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(
            content.Slice(coffHeaderOffset + sizeof(ushort), sizeof(ushort)));
        ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(
            content.Slice(coffHeaderOffset + 16, sizeof(ushort)));
        if (machine == 0 || sectionCount == 0 || optionalHeaderSize < OptionalHeaderMagicSize)
        {
            return false;
        }

        int optionalHeaderEnd;
        try
        {
            optionalHeaderEnd = checked(optionalHeaderOffset + optionalHeaderSize);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (optionalHeaderEnd > content.Length)
        {
            return false;
        }

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(
            content.Slice(optionalHeaderOffset, sizeof(ushort)));
        int numberOfDirectoriesOffset;
        int directoriesOffset;
        switch (magic)
        {
            case 0x10b:
                numberOfDirectoriesOffset = Pe32NumberOfDirectoriesOffset;
                directoriesOffset = Pe32DirectoriesOffset;
                break;
            case 0x20b:
                numberOfDirectoriesOffset = Pe32PlusNumberOfDirectoriesOffset;
                directoriesOffset = Pe32PlusDirectoriesOffset;
                break;
            default:
                return false;
        }

        int certificateDirectoryEnd = directoriesOffset +
            ((AttributeCertificateDirectoryIndex + 1) * DataDirectorySize);
        if (numberOfDirectoriesOffset + sizeof(uint) > optionalHeaderSize ||
            certificateDirectoryEnd > optionalHeaderSize)
        {
            return false;
        }

        uint directoryCount = BinaryPrimitives.ReadUInt32LittleEndian(
            content.Slice(optionalHeaderOffset + numberOfDirectoriesOffset, sizeof(uint)));
        return directoryCount > AttributeCertificateDirectoryIndex;
    }

    private static PolicyResult<SigningSubject> UnsupportedExtension(string path = "subject.extension") =>
        PolicyResult<SigningSubject>.Failure(
            PolicyErrorCode.UnsupportedFileType,
            path,
            "The file does not resolve to an approved signing subject.");
}

public sealed class SignatureLeg
{
    private SignatureLeg(
        CertificateRef certificate,
        FileDigestAlgorithm fileDigest,
        bool append,
        TimestampPolicy timestamp)
    {
        Certificate = certificate;
        FileDigest = fileDigest;
        Append = append;
        Timestamp = timestamp;
    }

    public CertificateRef Certificate { get; }

    public FileDigestAlgorithm FileDigest { get; }

    public bool Append { get; }

    public TimestampPolicy Timestamp { get; }

    internal static SignatureLeg Create(
        CertificateRef certificate,
        FileDigestAlgorithm fileDigest,
        bool append,
        TimestampPolicy timestamp) => new(certificate, fileDigest, append, timestamp);
}

public enum SigningMode
{
    [SuppressMessage("Naming", "CA1720:Identifier contains type name", Justification = "Single is the approved public signing-mode term.")]
    Single,
    Dual
}

public sealed class SigningPlan
{
    public const int CurrentVersion = 2;

    private SigningPlan(
        SigningMode requestedMode,
        SigningMode effectiveMode,
        IReadOnlyList<SignatureLeg> legs,
        SigningSubject subject,
        ExistingSignaturePolicy existingSignatures)
    {
        Version = CurrentVersion;
        RequestedMode = requestedMode;
        EffectiveMode = effectiveMode;
        Legs = legs;
        Subject = subject;
        Engine = subject.Capability == SigningCapability.PeImageDualCapable
            ? SigningEngine.PeImage
            : SigningEngine.WindowsSip;
        Verification = subject.Capability == SigningCapability.PeImageDualCapable
            ? SigningVerification.PeImage
            : SigningVerification.WindowsSip;
        ExistingSignatures = existingSignatures;
    }

    public int Version { get; }

    public SigningMode RequestedMode { get; }

    public SigningMode EffectiveMode { get; }

    public SigningMode Mode => RequestedMode;

    public IReadOnlyList<SignatureLeg> Legs { get; }

    public SigningSubject Subject { get; }

    public SigningEngine Engine { get; }

    public SigningVerification Verification { get; }

    public ExistingSignaturePolicy ExistingSignatures { get; }

    public static PolicyResult<SigningPlan> TryCreateSingle(
        CertificateRef? certificate,
        string extension,
        string? timestampUri = null)
    {
        PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(extension);
        return subject.IsSuccess
            ? TryCreateFactory(SigningMode.Single, certificate, null, subject.Value, timestampUri)
            : CopyFailure<SigningSubject>(subject);
    }

    public static PolicyResult<SigningPlan> TryCreateSingle(
        CertificateRef? certificate,
        SigningSubject? subject,
        string? timestampUri = null) =>
        TryCreateFactory(SigningMode.Single, certificate, null, subject, timestampUri);

    public static PolicyResult<SigningPlan> TryCreateDual(
        CertificateRef? primaryCertificate,
        CertificateRef? secondaryCertificate,
        string extension,
        string? timestampUri = null)
    {
        PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(extension);
        return subject.IsSuccess
            ? TryCreateFactory(SigningMode.Dual, primaryCertificate, secondaryCertificate, subject.Value, timestampUri)
            : CopyFailure<SigningSubject>(subject);
    }

    public static PolicyResult<SigningPlan> TryCreateDual(
        CertificateRef? primaryCertificate,
        CertificateRef? secondaryCertificate,
        SigningSubject? subject,
        string? timestampUri = null) =>
        TryCreateFactory(SigningMode.Dual, primaryCertificate, secondaryCertificate, subject, timestampUri);

    internal static PolicyResult<SigningPlan> TryCreateParsed(
        SigningMode requestedMode,
        SigningMode effectiveMode,
        IReadOnlyList<SignatureLeg> legs,
        SigningSubject subject,
        ExistingSignaturePolicy existingSignatures)
    {
        ArgumentNullException.ThrowIfNull(subject);
        PolicyError? legError = ValidateLegs(requestedMode, effectiveMode, subject.Capability, legs);
        if (legError is not null)
        {
            return PolicyResult<SigningPlan>.Failure(legError.Code, legError.Path, legError.Message);
        }

        ArgumentNullException.ThrowIfNull(existingSignatures);
        return PolicyResult<SigningPlan>.Success(
            new SigningPlan(requestedMode, effectiveMode, Freeze(legs), subject, existingSignatures));
    }

    private static PolicyResult<SigningPlan> TryCreateFactory(
        SigningMode requestedMode,
        CertificateRef? primaryCertificate,
        CertificateRef? secondaryCertificate,
        SigningSubject? subject,
        string? timestampUri)
    {
        if (subject is null)
        {
            return PolicyResult<SigningPlan>.Failure(
                PolicyErrorCode.UnsupportedFileType,
                "subject",
                "A classified signing subject is required.");
        }

        SigningMode effectiveMode = ResolveEffectiveMode(requestedMode, subject.Capability);
        if (primaryCertificate is null ||
            (effectiveMode == SigningMode.Dual && secondaryCertificate is null))
        {
            return PolicyResult<SigningPlan>.Failure(
                PolicyErrorCode.InvalidCertificate,
                "certificate",
                "Every signature leg requires an exact certificate reference.");
        }

        PolicyResult<TimestampPolicy> timestampResult = TimestampPolicy.TryCreate(timestampUri);
        if (!timestampResult.IsSuccess)
        {
            PolicyError error = timestampResult.Errors[0];
            return PolicyResult<SigningPlan>.Failure(error.Code, error.Path, error.Message);
        }

        TimestampPolicy timestamp = timestampResult.Value!;
        List<SignatureLeg> legs =
        [
            SignatureLeg.Create(
                primaryCertificate,
                effectiveMode == SigningMode.Single ? FileDigestAlgorithm.Sha256 : FileDigestAlgorithm.Sha1,
                false,
                timestamp)
        ];
        if (effectiveMode == SigningMode.Dual)
        {
            legs.Add(SignatureLeg.Create(
                secondaryCertificate!,
                FileDigestAlgorithm.Sha256,
                true,
                timestamp));
        }

        return TryCreateParsed(
            requestedMode,
            effectiveMode,
            legs,
            subject,
            ExistingSignaturePolicy.CreateFixed());
    }

    private static PolicyError? ValidateLegs(
        SigningMode requestedMode,
        SigningMode effectiveMode,
        SigningCapability capability,
        IReadOnlyList<SignatureLeg> legs)
    {
        ArgumentNullException.ThrowIfNull(legs);
        if (!Enum.IsDefined(requestedMode) || !Enum.IsDefined(effectiveMode) || !Enum.IsDefined(capability) ||
            effectiveMode != ResolveEffectiveMode(requestedMode, capability) ||
            (effectiveMode == SigningMode.Single && legs.Count != 1) ||
            (effectiveMode == SigningMode.Dual && legs.Count != 2))
        {
            return new PolicyError(
                PolicyErrorCode.InvalidSignatureOrder,
                "$.legs",
                "The signature leg count does not match the effective per-file signing mode.");
        }

        bool appendSequenceIsValid = !legs[0].Append
            && (effectiveMode == SigningMode.Single || legs[1].Append);
        if (!appendSequenceIsValid)
        {
            return new PolicyError(
                PolicyErrorCode.InvalidAppendSequence,
                "$.legs",
                "Only the second leg of a dual plan may append a signature.");
        }

        bool digestSequenceIsValid = effectiveMode == SigningMode.Single
            ? legs[0].FileDigest == FileDigestAlgorithm.Sha256
            : legs[0].FileDigest == FileDigestAlgorithm.Sha1
                && legs[1].FileDigest == FileDigestAlgorithm.Sha256;
        if (!digestSequenceIsValid)
        {
            return new PolicyError(
                PolicyErrorCode.InvalidSignatureOrder,
                "$.legs",
                "The plan digest sequence is not valid for its signing mode.");
        }

        return null;
    }

    private static SigningMode ResolveEffectiveMode(
        SigningMode requestedMode,
        SigningCapability capability) => requestedMode switch
        {
            SigningMode.Single => SigningMode.Single,
            SigningMode.Dual when capability == SigningCapability.PeImageDualCapable => SigningMode.Dual,
            SigningMode.Dual when capability == SigningCapability.WindowsSipSingleOnly => SigningMode.Single,
            _ => throw new ArgumentOutOfRangeException(
                nameof(requestedMode),
                requestedMode,
                "The requested signing mode or capability is unsupported.")
        };

    private static PolicyResult<SigningPlan> CopyFailure<T>(PolicyResult<T> source) where T : class
    {
        PolicyError error = source.Errors[0];
        return PolicyResult<SigningPlan>.Failure(error.Code, error.Path, error.Message);
    }

    private static ReadOnlyCollection<SignatureLeg> Freeze(IReadOnlyList<SignatureLeg> legs) =>
        new ReadOnlyCollection<SignatureLeg>(legs.ToArray());
}
