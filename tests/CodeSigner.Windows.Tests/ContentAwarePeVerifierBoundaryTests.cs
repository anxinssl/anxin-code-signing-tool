using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class ContentAwarePeVerifierBoundaryTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Theory]
    [InlineData("signed.dll", "valid-unsigned.dll")]
    [InlineData("signed.ocx", "valid-unsigned.ocx")]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidSupportedPeContentReachesSignatureInspection(
        string fileName,
        string fixtureName)
    {
        using TestTree tree = new();
        string path = CopyFixture(tree, fileName, fixtureName);
        var inspector = new CountingInspector();
        WinVerifyTrustSignatureVerifier verifier = new(inspector, new NeverStoreMembership());

        NativeSigningResult result = await verifier.VerifyAsync(
            path,
            CompatibilitySigningPlan.CreateSingle(
                CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
                new Uri("http://time.certum.pl")),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.VerifierDisagreement, result.ReasonCode);
        Assert.Equal(1, inspector.CallCount);
    }

    [Theory]
    [InlineData("malformed.dll", "truncated.dll")]
    [InlineData("malformed.ocx", "malformed.ocx")]
    [Trait("Category", "SigningIntegration")]
    public async Task MalformedSupportedExtensionIsTypedRejectedBeforeSignatureInspection(
        string fileName,
        string fixtureName)
    {
        using TestTree tree = new();
        string path = CopyFixture(tree, fileName, fixtureName);
        var inspector = new CountingInspector();
        WinVerifyTrustSignatureVerifier verifier = new(inspector, new NeverStoreMembership());

        NativeSigningResult result = await verifier.VerifyAsync(
            path,
            CompatibilitySigningPlan.CreateSingle(
                CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
                new Uri("http://time.certum.pl")),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.UnsupportedFileType, result.ReasonCode);
        Assert.Equal(0, inspector.CallCount);
    }

    private static string CopyFixture(TestTree tree, string fileName, string fixtureName)
    {
        string destination = tree.PathOf(fileName);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fixtureName), destination);
        return destination;
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
    }

    private sealed class CountingInspector : IAuthenticodeSignatureInspector
    {
        public int CallCount { get; private set; }

        public AuthenticodeSignatureCountInspection GetSignatureCount(string path)
        {
            CallCount++;
            return new AuthenticodeSignatureCountInspection(unchecked((int)0x800B0100), 0);
        }

        public AuthenticodeSignatureInspection InspectSignature(string path, uint index)
        {
            CallCount++;
            throw new InvalidOperationException("A failed signature count unexpectedly reached signature inspection.");
        }
    }

    private sealed class NeverStoreMembership : ICertificateStoreMembership
    {
        public bool ContainsExact(CertificateReference reference, byte[] certificateDer) =>
            throw new InvalidOperationException("The verifier unexpectedly reached certificate-store inspection.");
    }
}
