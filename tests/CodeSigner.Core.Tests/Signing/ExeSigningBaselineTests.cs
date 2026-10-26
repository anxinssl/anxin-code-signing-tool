using CodeSigner.Core.Signing;

namespace CodeSigner.Core.Tests.Signing;

public sealed class ExeSigningBaselineTests
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";

    [Fact]
    public void ExeSingleAndDualPlansPreserveTheApprovedSigningContract()
    {
        CertificateRef primary = Certificate(PrimaryThumbprint);
        CertificateRef secondary = Certificate(SecondaryThumbprint);

        SigningPlan single = Success(SigningPlan.TryCreateSingle(primary, ".exe"));
        SigningPlan dual = Success(SigningPlan.TryCreateDual(primary, secondary, ".exe"));

        SignatureLeg singleLeg = Assert.Single(single.Legs);
        Assert.Equal(FileDigestAlgorithm.Sha256, singleLeg.FileDigest);
        Assert.False(singleLeg.Append);
        Assert.Collection(
            dual.Legs,
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha1, leg.FileDigest);
                Assert.False(leg.Append);
            },
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
                Assert.True(leg.Append);
            });
        Assert.All([single, dual], plan =>
        {
            Assert.Equal(SigningFormatFamily.PeImage, plan.Subject.FormatFamily);
            Assert.Equal(SigningCapability.PeImageDualCapable, plan.Subject.Capability);
            Assert.Equal(".exe", plan.Subject.Extension);
            Assert.All(plan.Legs, AssertRfc3161Sha256Timestamp);
        });
    }

    private static CertificateRef Certificate(string thumbprint) =>
        Success(CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", thumbprint));

    private static T Success<T>(PolicyResult<T> result) where T : class
    {
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Errors));
        return Assert.IsType<T>(result.Value);
    }

    private static void AssertRfc3161Sha256Timestamp(SignatureLeg leg)
    {
        Assert.Equal(TimestampProtocol.Rfc3161, leg.Timestamp.Protocol);
        Assert.Equal(TimestampDigestAlgorithm.Sha256, leg.Timestamp.TimestampDigest);
        Assert.Equal("http://time.certum.pl", leg.Timestamp.Uri.OriginalString);
    }
}
