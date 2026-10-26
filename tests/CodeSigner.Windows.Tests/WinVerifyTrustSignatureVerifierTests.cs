using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class WinVerifyTrustSignatureVerifierTests
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
    private static readonly byte[] PrimaryCertificate = [1, 2, 3];
    private static readonly byte[] SecondaryCertificate = [4, 5, 6];

    [Fact]
    public void PublicDefaultVerifierImplementsProductionContract()
    {
        IProductionSignedFileVerifier verifier = new WinVerifyTrustSignatureVerifier();

        Assert.IsType<WinVerifyTrustSignatureVerifier>(verifier);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task DualPlanCharacterizationRequestsPrimaryIndexZeroBeforeSecondaryIndexOne()
    {
        StubInspector inspector = new(
            1,
            CreateInspection(0, AuthenticodeOids.Sha1, PrimaryThumbprint, PrimaryCertificate),
            CreateInspection(1, AuthenticodeOids.Sha256, SecondaryThumbprint, SecondaryCertificate));
        WinVerifyTrustSignatureVerifier verifier = new(
            inspector,
            new StubStoreMembership(PrimaryCertificate, SecondaryCertificate));

        NativeSigningResult result = await verifier.VerifyAsync(
            "signed.exe",
            CreateDualPlan(),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal([0U, 1U], inspector.RequestedIndexes);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task AcceptsExactCountOrderTrustIdentityDigestsAndRfc3161Timestamps()
    {
        StubInspector inspector = new(
            1,
            CreateInspection(0, AuthenticodeOids.Sha1, PrimaryThumbprint, PrimaryCertificate),
            CreateInspection(1, AuthenticodeOids.Sha256, SecondaryThumbprint, SecondaryCertificate));
        StubStoreMembership stores = new(PrimaryCertificate, SecondaryCertificate);
        WinVerifyTrustSignatureVerifier verifier = new(inspector, stores);

        NativeSigningResult result = await verifier.VerifyAsync("signed.exe", CreateDualPlan(), CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal([0U, 1U], inspector.RequestedIndexes);
        Assert.Collection(
            stores.RequestedReferences,
            primary =>
            {
                Assert.Equal(StoreLocation.CurrentUser, primary.StoreLocation);
                Assert.Equal("My", primary.StoreName);
                Assert.Equal(PrimaryThumbprint, primary.Thumbprint);
            },
            secondary =>
            {
                Assert.Equal(StoreLocation.LocalMachine, secondary.StoreLocation);
                Assert.Equal("TrustedPublisher", secondary.StoreName);
                Assert.Equal(SecondaryThumbprint, secondary.Thumbprint);
            });
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsSignatureCountDisagreement()
    {
        StubInspector inspector = new(0, CreateInspection(0, AuthenticodeOids.Sha1, PrimaryThumbprint, PrimaryCertificate));
        WinVerifyTrustSignatureVerifier verifier = new(inspector, new StubStoreMembership(PrimaryCertificate));

        NativeSigningResult result = await verifier.VerifyAsync("signed.exe", CreateDualPlan(), CancellationToken.None);

        AssertVerifierDisagreement(result);
        Assert.Empty(inspector.RequestedIndexes);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsUntrustedSignature()
    {
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha256,
            PrimaryThumbprint,
            PrimaryCertificate) with
        {
            TrustStatus = unchecked((int)0x800B0109)
        };

        NativeSigningResult result = await CreateSingleVerifier(signature).VerifyAsync(
            "signed.exe",
            CreateSinglePlan(),
            CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsWrongVerifiedSignatureIndex()
    {
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha256,
            PrimaryThumbprint,
            PrimaryCertificate) with
        {
            VerifiedSignatureIndex = 1
        };

        NativeSigningResult result = await CreateSingleVerifier(signature).VerifyAsync(
            "signed.exe",
            CreateSinglePlan(),
            CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsWrongFileDigest()
    {
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha1,
            PrimaryThumbprint,
            PrimaryCertificate);

        NativeSigningResult result = await CreateSingleVerifier(signature).VerifyAsync(
            "signed.exe",
            CreateSinglePlan(),
            CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsWrongSignatureOrder()
    {
        StubInspector inspector = new(
            1,
            CreateInspection(0, AuthenticodeOids.Sha256, SecondaryThumbprint, SecondaryCertificate),
            CreateInspection(1, AuthenticodeOids.Sha1, PrimaryThumbprint, PrimaryCertificate));
        WinVerifyTrustSignatureVerifier verifier = new(
            inspector,
            new StubStoreMembership(PrimaryCertificate, SecondaryCertificate));

        NativeSigningResult result = await verifier.VerifyAsync("signed.exe", CreateDualPlan(), CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsWrongSignerThumbprint()
    {
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha256,
            SecondaryThumbprint,
            PrimaryCertificate);

        NativeSigningResult result = await CreateSingleVerifier(signature).VerifyAsync(
            "signed.exe",
            CreateSinglePlan(),
            CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsSignerMissingFromExactPlannedStore()
    {
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha256,
            PrimaryThumbprint,
            PrimaryCertificate);
        WinVerifyTrustSignatureVerifier verifier = new(new StubInspector(0, signature), new StubStoreMembership());

        NativeSigningResult result = await verifier.VerifyAsync("signed.exe", CreateSinglePlan(), CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Theory]
    [InlineData((int)AuthenticodeTimestampKind.Missing, false, AuthenticodeOids.Sha256)]
    [InlineData((int)AuthenticodeTimestampKind.LegacyCounterSignature, true, AuthenticodeOids.Sha256)]
    [InlineData((int)AuthenticodeTimestampKind.Rfc3161, false, AuthenticodeOids.Sha256)]
    [InlineData((int)AuthenticodeTimestampKind.Rfc3161, true, AuthenticodeOids.Sha1)]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsMissingLegacyInvalidOrNonSha256Timestamp(
        int kindValue,
        bool cryptographicallyValid,
        string imprintOid)
    {
        AuthenticodeTimestampInspection timestamp = ValidTimestamp() with
        {
            Kind = (AuthenticodeTimestampKind)kindValue,
            CryptographicallyValid = cryptographicallyValid,
            MessageImprintAlgorithmOid = imprintOid
        };
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha256,
            PrimaryThumbprint,
            PrimaryCertificate) with
        {
            Timestamp = timestamp
        };

        NativeSigningResult result = await CreateSingleVerifier(signature).VerifyAsync(
            "signed.exe",
            CreateSinglePlan(),
            CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Theory]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [Trait("Category", "SigningIntegration")]
    public async Task RejectsInvalidTimestampChainTimeOrEku(bool chainValid, bool timeValid, bool ekuValid)
    {
        AuthenticodeTimestampInspection timestamp = ValidTimestamp() with
        {
            ChainValid = chainValid,
            TimeValid = timeValid,
            TimestampingEkuValid = ekuValid
        };
        AuthenticodeSignatureInspection signature = CreateInspection(
            0,
            AuthenticodeOids.Sha256,
            PrimaryThumbprint,
            PrimaryCertificate) with
        {
            Timestamp = timestamp
        };

        NativeSigningResult result = await CreateSingleVerifier(signature).VerifyAsync(
            "signed.exe",
            CreateSinglePlan(),
            CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task DualVerificationRequiresFirstSignatureToRemainExactAfterAppend()
    {
        AuthenticodeSignatureInspection changedPrimary = CreateInspection(
            0,
            AuthenticodeOids.Sha1,
            SecondaryThumbprint,
            SecondaryCertificate);
        StubInspector inspector = new(
            1,
            changedPrimary,
            CreateInspection(1, AuthenticodeOids.Sha256, SecondaryThumbprint, SecondaryCertificate));
        WinVerifyTrustSignatureVerifier verifier = new(
            inspector,
            new StubStoreMembership(PrimaryCertificate, SecondaryCertificate));

        NativeSigningResult result = await verifier.VerifyAsync("signed.exe", CreateDualPlan(), CancellationToken.None);

        AssertVerifierDisagreement(result);
    }

    private static WinVerifyTrustSignatureVerifier CreateSingleVerifier(AuthenticodeSignatureInspection inspection) =>
        new(new StubInspector(0, inspection), new StubStoreMembership(PrimaryCertificate));

    private static CompatibilitySigningPlan CreateSinglePlan() => CompatibilitySigningPlan.CreateSingle(
        CertificateReference.Create(StoreLocation.CurrentUser, "My", PrimaryThumbprint),
        new Uri("http://time.certum.pl"));

    private static CompatibilitySigningPlan CreateDualPlan() => CompatibilitySigningPlan.CreateDual(
        CertificateReference.Create(StoreLocation.CurrentUser, "My", PrimaryThumbprint),
        CertificateReference.Create(StoreLocation.LocalMachine, "TrustedPublisher", SecondaryThumbprint),
        new Uri("http://time.certum.pl"));

    private static AuthenticodeSignatureInspection CreateInspection(
        uint index,
        string digestOid,
        string thumbprint,
        byte[] certificate) => new(
            TrustStatus: 0,
            VerifiedSignatureIndex: index,
            FileDigestAlgorithmOid: digestOid,
            SignerThumbprint: thumbprint,
            SignerCertificateDer: certificate,
            Timestamp: ValidTimestamp());

    private static AuthenticodeTimestampInspection ValidTimestamp() => new(
        AuthenticodeTimestampKind.Rfc3161,
        AuthenticodeOids.Sha256,
        CryptographicallyValid: true,
        ChainValid: true,
        TimeValid: true,
        TimestampingEkuValid: true);

    private static void AssertVerifierDisagreement(NativeSigningResult result)
    {
        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.VerifierDisagreement, result.ReasonCode);
    }

    private sealed class StubInspector(uint secondarySignatureCount, params AuthenticodeSignatureInspection[] signatures)
        : IAuthenticodeSignatureInspector
    {
        private readonly AuthenticodeSignatureInspection[] signatures = signatures;

        public List<uint> RequestedIndexes { get; } = [];

        public AuthenticodeSignatureCountInspection GetSignatureCount(string path) => new(0, secondarySignatureCount);

        public AuthenticodeSignatureInspection InspectSignature(string path, uint index)
        {
            RequestedIndexes.Add(index);
            return signatures[checked((int)index)];
        }
    }

    private sealed class StubStoreMembership(params byte[][] presentCertificates) : ICertificateStoreMembership
    {
        private readonly byte[][] presentCertificates = presentCertificates;

        public List<CertificateReference> RequestedReferences { get; } = [];

        public bool ContainsExact(CertificateReference reference, byte[] certificateDer)
        {
            RequestedReferences.Add(reference);
            return presentCertificates.Any(candidate => candidate.AsSpan().SequenceEqual(certificateDer));
        }
    }
}
