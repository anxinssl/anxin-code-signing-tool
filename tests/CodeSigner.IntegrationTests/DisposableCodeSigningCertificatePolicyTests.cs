using System.Security.Cryptography.X509Certificates;
using CodeSigner.CompatibilityProbe.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class DisposableCodeSigningCertificatePolicyTests
{
    [Fact]
    [Trait("Category", "NativeSigning")]
    public void DisposableAuthenticodeSignerIsAnEndEntityCertificate()
    {
        X509BasicConstraintsExtension extension =
            DisposableCodeSigningCertificate.CreateBasicConstraintsExtension();

        Assert.False(extension.CertificateAuthority);
        Assert.False(extension.HasPathLengthConstraint);
        Assert.True(extension.Critical);
    }
}
