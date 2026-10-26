namespace CodeSigner.CompatibilityProbe.Oracle;

public enum AuthenticodeState
{
    NotSigned,
    Invalid,
    Valid
}

public enum OracleReasonCode
{
    Approved,
    FileMissing,
    NotPortableExecutable,
    AuthenticodeInvalid,
    PublisherMismatch,
    IdentityMismatch,
    VersionNotApproved,
    ProbeFailed
}

public sealed record FileProbeResult(
    bool Exists,
    bool IsPortableExecutable,
    AuthenticodeState SignatureState,
    string? Publisher,
    string? CompanyName,
    string? OriginalFileName,
    string? FileDescription,
    Version? Version,
    string? Sha256)
{
    public static FileProbeResult Missing { get; } = new(
        Exists: false,
        IsPortableExecutable: false,
        SignatureState: AuthenticodeState.NotSigned,
        Publisher: null,
        CompanyName: null,
        OriginalFileName: null,
        FileDescription: null,
        Version: null,
        Sha256: null);
}

public sealed record OracleResolution(
    bool IsApproved,
    OracleReasonCode ReasonCode,
    string FileName,
    string? Sha256,
    string? Publisher,
    string? Version);

public interface IExternalExecutableProbe
{
    FileProbeResult Probe(string path);
}
