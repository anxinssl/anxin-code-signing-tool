namespace CodeSigner.CompatibilityProbe.Oracle;

public sealed class ExternalSignToolResolver(IExternalExecutableProbe probe)
{
    private const string ExpectedPublisher = "Microsoft Corporation";
    private const string ExpectedOriginalFileName = "signtool.exe";
    private static readonly string[] ExpectedDescriptions =
    [
        "File Signing Tool",
        "Authenticode(R) - signing and verifying tool"
    ];
    private static readonly Version MinimumApprovedVersion = new(10, 0, 17763, 0);

    public OracleResolution Resolve(string? configuredPath)
    {
        string fileName = string.IsNullOrWhiteSpace(configuredPath) ? string.Empty : Path.GetFileName(configuredPath);
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return Rejected(OracleReasonCode.FileMissing, fileName);
        }

        FileProbeResult candidate;
        try
        {
            candidate = probe.Probe(configuredPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return Rejected(OracleReasonCode.ProbeFailed, fileName);
        }

        if (!candidate.Exists)
        {
            return Rejected(OracleReasonCode.FileMissing, fileName);
        }

        if (!candidate.IsPortableExecutable)
        {
            return Rejected(OracleReasonCode.NotPortableExecutable, fileName, candidate);
        }

        if (candidate.SignatureState != AuthenticodeState.Valid)
        {
            return Rejected(OracleReasonCode.AuthenticodeInvalid, fileName, candidate);
        }

        if (!string.Equals(candidate.Publisher, ExpectedPublisher, StringComparison.Ordinal)
            || !string.Equals(candidate.CompanyName, ExpectedPublisher, StringComparison.Ordinal))
        {
            return Rejected(OracleReasonCode.PublisherMismatch, fileName, candidate);
        }

        if (!string.Equals(candidate.OriginalFileName, ExpectedOriginalFileName, StringComparison.OrdinalIgnoreCase)
            || !ExpectedDescriptions.Contains(candidate.FileDescription, StringComparer.Ordinal))
        {
            return Rejected(OracleReasonCode.IdentityMismatch, fileName, candidate);
        }

        if (candidate.Version is null
            || candidate.Version.Major != MinimumApprovedVersion.Major
            || candidate.Version < MinimumApprovedVersion)
        {
            return Rejected(OracleReasonCode.VersionNotApproved, fileName, candidate);
        }

        return new OracleResolution(
            IsApproved: true,
            ReasonCode: OracleReasonCode.Approved,
            FileName: fileName,
            Sha256: candidate.Sha256,
            Publisher: candidate.Publisher,
            Version: candidate.Version.ToString());
    }

    private static OracleResolution Rejected(
        OracleReasonCode reasonCode,
        string fileName,
        FileProbeResult? candidate = null) => new(
            IsApproved: false,
            ReasonCode: reasonCode,
            FileName: fileName,
            Sha256: candidate?.Sha256,
            Publisher: candidate?.Publisher,
            Version: candidate?.Version?.ToString());
}
