using CodeSigner.Core.Signing;

namespace CodeSigner.Windows.Files;

public enum SignableFileType
{
    PortableExecutable,
    WindowsInstaller,
    Cabinet,
    Catalog,
    AppPackage,
    PowerShellScript,
    WindowsScript
}

public enum ScriptEncodingKind
{
    Utf8,
    Utf8WithBom,
    Utf16LittleEndian,
    Utf16BigEndian,
    WindowsScriptEncoded
}

public enum ScriptNewlineKind
{
    None,
    CrLf,
    Lf,
    Cr,
    Mixed
}

public sealed record ScriptContentProfile(
    ScriptEncodingKind Encoding,
    ScriptNewlineKind Newlines,
    bool HasSignatureBlock,
    bool IsEncoded);

public sealed record SignableSubject
{
    public SignableSubject(SignableFileType fileType, Guid subjectGuid)
        : this(CreatePolicySubject(fileType), subjectGuid, null)
    {
    }

    public SignableSubject(
        SigningSubject policySubject,
        Guid subjectGuid,
        ScriptContentProfile? scriptProfile)
    {
        PolicySubject = policySubject ?? throw new ArgumentNullException(nameof(policySubject));
        SubjectGuid = subjectGuid;
        ScriptProfile = scriptProfile;
        FileType = ToLegacyFileType(policySubject.FormatFamily);
    }

    public SignableFileType FileType { get; }

    public Guid SubjectGuid { get; }

    public SigningSubject PolicySubject { get; }

    public ScriptContentProfile? ScriptProfile { get; }

    private static SigningSubject CreatePolicySubject(SignableFileType fileType)
    {
        string extension = fileType switch
        {
            SignableFileType.PortableExecutable => ".exe",
            SignableFileType.WindowsInstaller => ".msi",
            SignableFileType.Cabinet => ".cab",
            SignableFileType.Catalog => ".cat",
            SignableFileType.AppPackage => ".appx",
            SignableFileType.PowerShellScript => ".ps1",
            SignableFileType.WindowsScript => ".vbs",
            _ => throw new ArgumentOutOfRangeException(nameof(fileType), fileType, "Unsupported signable file type.")
        };
        PolicyResult<SigningSubject> result = SigningSubject.TryCreateForExtension(extension);
        return result.Value
            ?? throw new InvalidOperationException("The legacy signable file type has no policy subject.");
    }

    private static SignableFileType ToLegacyFileType(SigningFormatFamily family) => family switch
    {
        SigningFormatFamily.PeImage => SignableFileType.PortableExecutable,
        SigningFormatFamily.WindowsInstaller => SignableFileType.WindowsInstaller,
        SigningFormatFamily.Cabinet => SignableFileType.Cabinet,
        SigningFormatFamily.Catalog => SignableFileType.Catalog,
        SigningFormatFamily.AppPackage => SignableFileType.AppPackage,
        SigningFormatFamily.PowerShellScript => SignableFileType.PowerShellScript,
        SigningFormatFamily.WindowsScript => SignableFileType.WindowsScript,
        _ => throw new ArgumentOutOfRangeException(nameof(family), family, "Unsupported signing format family.")
    };
}

public enum SignableSubjectProbeError
{
    UnsupportedExtension,
    MalformedContent,
    ContentTypeMismatch,
    InvalidCompoundFile,
    InvalidCabinet,
    InvalidCatalog,
    InvalidAppPackage,
    UnsafePackagePath,
    IncompatibleBlockMapHash,
    InvalidScriptEncoding,
    InvalidSignatureBlock,
    EncodedScriptUnsupported,
    ContentLimitExceeded,
    SipUnavailable,
    SipSubjectMismatch
}

public sealed class SignableSubjectProbeException : IOException
{
    public SignableSubjectProbeException(
        SignableSubjectProbeError error,
        string message,
        int? nativeErrorCode = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
        NativeErrorCode = nativeErrorCode;
    }

    public SignableSubjectProbeError Error { get; }

    public int? NativeErrorCode { get; }
}

public interface ISignableSubjectProbe
{
    SignableSubject Probe(string path);
}

public sealed record StableFileIdentity(ulong VolumeSerialNumber, string FileId);

public sealed record IntakeFile(
    string OriginalPath,
    string RelativePath,
    string DestinationPath,
    string OutputRoot,
    StableFileIdentity Identity,
    SignableSubject Subject);

public sealed record IntakePlan(string OutputRoot, IReadOnlyList<IntakeFile> Files);

public enum IntakeError
{
    InvalidInput,
    InputNotFound,
    ReparsePoint,
    InputInsideOutputRoot,
    UnsupportedExtension,
    InaccessibleInput,
    NotSignableSubject,
    SipUnavailable,
    DestinationCollision,
    DestinationExists,
    NoSignableInputs
}

public sealed class IntakeValidationException : Exception
{
    public IntakeValidationException(IntakeError error, string message, string? path = null, Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
        Path = path;
    }

    public IntakeError Error { get; }

    public string? Path { get; }
}

public interface IStagedFileSigner
{
    Task SignAsync(string stagedPath, CancellationToken cancellationToken);
}

public interface IStagedFileVerifier
{
    Task VerifyAsync(string stagedPath, CancellationToken cancellationToken);
}

public enum PublishStatus
{
    Published
}

public enum FilePipelineError
{
    InvalidPlan,
    OriginalChanged,
    DestinationCollision,
    StagingUnavailable,
    CleanupFailed,
    SecurePublicationUnavailable,
    OutputSaveFailed
}

public sealed class FilePipelineException : Exception
{
    public FilePipelineException(FilePipelineError error, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
    }

    public FilePipelineError Error { get; }
}

public sealed record PublishReceipt(
    PublishStatus Status,
    string OriginalPath,
    string DestinationPath,
    string OriginalSha256,
    string PublishedSha256,
    string AttemptId);

public sealed record StagingRecoveryReceipt(int RemovedAttemptCount, int SkippedAttemptCount);

internal sealed record TransactionalFilePipelineHooks(
    Action AfterCommit,
    Action<string>? BeforeCommit = null);
