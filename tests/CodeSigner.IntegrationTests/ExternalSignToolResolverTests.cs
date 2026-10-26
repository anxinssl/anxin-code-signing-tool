using CodeSigner.CompatibilityProbe.Oracle;

namespace CodeSigner.IntegrationTests;

public sealed class ExternalSignToolResolverTests
{
    [Fact]
    public void ResolveRejectsMissingPath()
    {
        ExternalSignToolResolver resolver = new(new StubProbe(FileProbeResult.Missing));

        OracleResolution result = resolver.Resolve("X:/missing/signtool.exe");

        Assert.False(result.IsApproved);
        Assert.Equal(OracleReasonCode.FileMissing, result.ReasonCode);
    }

    [Theory]
    [InlineData(AuthenticodeState.NotSigned, "Microsoft Corporation", "signtool.exe", "File Signing Tool", 10, OracleReasonCode.AuthenticodeInvalid)]
    [InlineData(AuthenticodeState.Valid, "Example Publisher", "signtool.exe", "File Signing Tool", 10, OracleReasonCode.PublisherMismatch)]
    [InlineData(AuthenticodeState.Valid, "Microsoft Corporation", "renamed.exe", "File Signing Tool", 10, OracleReasonCode.IdentityMismatch)]
    [InlineData(AuthenticodeState.Valid, "Microsoft Corporation", "signtool.exe", "Not SignTool", 10, OracleReasonCode.IdentityMismatch)]
    [InlineData(AuthenticodeState.Valid, "Microsoft Corporation", "signtool.exe", "File Signing Tool", 9, OracleReasonCode.VersionNotApproved)]
    public void ResolveRejectsUnapprovedOracle(
        AuthenticodeState signatureState,
        string publisher,
        string originalFileName,
        string description,
        int versionMajor,
        OracleReasonCode expected)
    {
        FileProbeResult probe = new(
            Exists: true,
            IsPortableExecutable: true,
            SignatureState: signatureState,
            Publisher: publisher,
            CompanyName: "Microsoft Corporation",
            OriginalFileName: originalFileName,
            FileDescription: description,
            Version: new Version(versionMajor, 0, 0, 0),
            Sha256: new string('b', 64));
        ExternalSignToolResolver resolver = new(new StubProbe(probe));

        OracleResolution result = resolver.Resolve("C:/sdk/signtool.exe");

        Assert.False(result.IsApproved);
        Assert.Equal(expected, result.ReasonCode);
    }

    [Fact]
    public void ResolveAcceptsOnlyApprovedMicrosoftSignToolContract()
    {
        FileProbeResult probe = new(
            Exists: true,
            IsPortableExecutable: true,
            SignatureState: AuthenticodeState.Valid,
            Publisher: "Microsoft Corporation",
            CompanyName: "Microsoft Corporation",
            OriginalFileName: "signtool.exe",
            FileDescription: "File Signing Tool",
            Version: new Version(10, 0, 26100, 0),
            Sha256: new string('c', 64));
        ExternalSignToolResolver resolver = new(new StubProbe(probe));

        OracleResolution result = resolver.Resolve("C:/sdk/signtool.exe");

        Assert.True(result.IsApproved);
        Assert.Equal(OracleReasonCode.Approved, result.ReasonCode);
        Assert.Equal("signtool.exe", result.FileName);
    }

    [Fact]
    public void ResolveAcceptsCurrentOfficialSdkSignToolIdentity()
    {
        FileProbeResult probe = new(
            Exists: true,
            IsPortableExecutable: true,
            SignatureState: AuthenticodeState.Valid,
            Publisher: "Microsoft Corporation",
            CompanyName: "Microsoft Corporation",
            OriginalFileName: "SIGNTOOL.EXE",
            FileDescription: "Authenticode(R) - signing and verifying tool",
            Version: new Version(10, 0, 26100, 8249),
            Sha256: new string('d', 64));
        ExternalSignToolResolver resolver = new(new StubProbe(probe));

        OracleResolution result = resolver.Resolve("C:/sdk/signtool.exe");

        Assert.True(result.IsApproved);
        Assert.Equal("10.0.26100.8249", result.Version);
    }

    private sealed class StubProbe(FileProbeResult result) : IExternalExecutableProbe
    {
        public FileProbeResult Probe(string path) => result;
    }
}
