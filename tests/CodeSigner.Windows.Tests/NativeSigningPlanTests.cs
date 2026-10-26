using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class NativeSigningPlanTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private static readonly Uri TimestampUri = new("http://time.certum.pl", UriKind.Absolute);

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void SinglePlanHasExactSha256Rfc3161Leg()
    {
        CertificateReference certificate = CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint);

        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateSingle(certificate, TimestampUri);

        SignatureLeg leg = Assert.Single(plan.Legs);
        Assert.Equal(NativeDigestAlgorithm.Sha256, leg.FileDigest);
        Assert.Equal(NativeDigestAlgorithm.Sha256, leg.TimestampDigest);
        Assert.Equal(TimestampUri, leg.TimestampUri);
        Assert.False(leg.Append);
        Assert.Equal(certificate, leg.Certificate);
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void DualPlanIsSha1PrimaryThenSha256Append()
    {
        CertificateReference certificate = CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint);

        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateDual(certificate, certificate, TimestampUri);

        Assert.Collection(
            plan.Legs,
            primary =>
            {
                Assert.Equal(NativeDigestAlgorithm.Sha1, primary.FileDigest);
                Assert.Equal(NativeDigestAlgorithm.Sha256, primary.TimestampDigest);
                Assert.False(primary.Append);
            },
            secondary =>
            {
                Assert.Equal(NativeDigestAlgorithm.Sha256, secondary.FileDigest);
                Assert.Equal(NativeDigestAlgorithm.Sha256, secondary.TimestampDigest);
                Assert.True(secondary.Append);
            });
    }

    [Theory]
    [InlineData("")]
    [InlineData("0011")]
    [InlineData("00112233445566778899AABBCCDDEEFF0011223Z")]
    [Trait("Category", "NativeSigning")]
    public void CertificateReferenceRejectsNonFullThumbprints(string thumbprint)
    {
        Assert.Throws<ArgumentException>(() => CertificateReference.Create(StoreLocation.CurrentUser, "My", thumbprint));
    }
}
