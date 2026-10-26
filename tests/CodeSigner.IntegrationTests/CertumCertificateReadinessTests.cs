using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CodeSigner.CompatibilityProbe.Signing;
using Xunit.Abstractions;

namespace CodeSigner.IntegrationTests;

public sealed class CertumCertificateReadinessTests(ITestOutputHelper testOutput)
{
    private const string Thumbprint = "134EC6FBED2F01343F1B7325E91E1C1336B2A5A7";
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 2, 0, 0, TimeSpan.Zero);

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task MissingExactCertificateIsBlockedWithoutPrivateKeyAccess()
    {
        FakeCertificateMetadataSource source = new([]);

        (int exitCode, JsonElement receipt) = await RunAsync(source);

        Assert.Equal(20, exitCode);
        Assert.Equal("blocked", receipt.GetProperty("status").GetString());
        Assert.Equal("CertificateNotFound", receipt.GetProperty("reasonCode").GetString());
        Assert.Equal(Thumbprint, receipt.GetProperty("publicCertificateThumbprint").GetString());
        Assert.Equal(1, source.ReadCount);
        testOutput.WriteLine(receipt.GetRawText());
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task WrongEkuCertificateIsBlockedEvenWhenExactAndPrivateKeyAssociated()
    {
        FakeCertificateMetadataSource source = new(
        [
            Candidate(hasPrivateKey: true, ekuOids: ["1.3.6.1.5.5.7.3.1"])
        ]);

        (int exitCode, JsonElement receipt) = await RunAsync(source);

        Assert.Equal(20, exitCode);
        Assert.Equal("blocked", receipt.GetProperty("status").GetString());
        Assert.Equal("CertificateWrongEku", receipt.GetProperty("reasonCode").GetString());
        Assert.Equal(1, source.ReadCount);
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task ExactValidCodeSigningCertificateWithPrivateKeyMetadataIsReady()
    {
        FakeCertificateMetadataSource source = new(
        [
            Candidate(hasPrivateKey: true, ekuOids: [CertificateReadinessCommand.CodeSigningEkuOid])
        ]);

        (int exitCode, JsonElement receipt) = await RunAsync(source);

        Assert.Equal(0, exitCode);
        Assert.Equal("passed", receipt.GetProperty("status").GetString());
        Assert.Equal("CertificateReady", receipt.GetProperty("reasonCode").GetString());
        Assert.Equal("CN=Public Certum Candidate", receipt.GetProperty("publicCertificateSubject").GetString());
        Assert.Equal("CN=Public Certum Issuer", receipt.GetProperty("publicCertificateIssuer").GetString());
        Assert.Equal(Thumbprint, receipt.GetProperty("publicCertificateThumbprint").GetString());
        Assert.Equal(1, source.ReadCount);
    }

    [Theory]
    [InlineData(IneligibleCertificateState.Ambiguous, "CertificateAmbiguous")]
    [InlineData(IneligibleCertificateState.NotYetValid, "CertificateNotYetValid")]
    [InlineData(IneligibleCertificateState.Expired, "CertificateExpired")]
    [InlineData(IneligibleCertificateState.NoPrivateKey, "CertificateHasNoPrivateKey")]
    [Trait("Category", "NativeSigning")]
    public async Task OtherExactCertificateIneligibilityRemainsBlocked(
        IneligibleCertificateState state,
        string expectedReasonCode)
    {
        CertificatePublicMetadata eligible = Candidate(
            hasPrivateKey: state != IneligibleCertificateState.NoPrivateKey,
            ekuOids: [CertificateReadinessCommand.CodeSigningEkuOid],
            notBefore: state == IneligibleCertificateState.NotYetValid ? Now.AddDays(1) : null,
            notAfter: state == IneligibleCertificateState.Expired ? Now.AddDays(-1) : null);
        FakeCertificateMetadataSource source = new(
            state == IneligibleCertificateState.Ambiguous ? [eligible, eligible] : [eligible]);

        (int exitCode, JsonElement receipt) = await RunAsync(source);

        Assert.Equal(20, exitCode);
        Assert.Equal("blocked", receipt.GetProperty("status").GetString());
        Assert.Equal(expectedReasonCode, receipt.GetProperty("reasonCode").GetString());
        Assert.Equal(1, source.ReadCount);
    }

    [Theory]
    [InlineData(StoreFailure.AccessDenied)]
    [InlineData(StoreFailure.Cryptography)]
    [Trait("Category", "NativeSigning")]
    public async Task CertificateStoreInfrastructureFaultIsFailedWithNonBlockedExitCode(StoreFailure failure)
    {
        ICertificateMetadataSource source = new ThrowingCertificateMetadataSource(failure switch
        {
            StoreFailure.AccessDenied => new UnauthorizedAccessException(),
            StoreFailure.Cryptography => new CryptographicException(),
            _ => throw new ArgumentOutOfRangeException(nameof(failure), failure, null)
        });

        (int exitCode, JsonElement receipt) = await RunAsync(source);

        Assert.Equal(1, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal("CertificateStoreUnavailable", receipt.GetProperty("reasonCode").GetString());
        testOutput.WriteLine(receipt.GetRawText());
    }

    private static async Task<(int ExitCode, JsonElement Receipt)> RunAsync(ICertificateMetadataSource source)
    {
        await using MemoryStream output = new();
        int exitCode = await CertificateReadinessCommand.RunAsync(
            ["cert-ready", "CurrentUser", "My", Thumbprint],
            output,
            source,
            Now,
            CancellationToken.None);
        using JsonDocument document = JsonDocument.Parse(Encoding.UTF8.GetString(output.ToArray()));
        return (exitCode, document.RootElement.Clone());
    }

    private static CertificatePublicMetadata Candidate(
        bool hasPrivateKey,
        IReadOnlyList<string> ekuOids,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null) =>
        new(
            StoreLocation.CurrentUser,
            "My",
            Thumbprint,
            "CN=Public Certum Candidate",
            "CN=Public Certum Issuer",
            notBefore ?? Now.AddDays(-1),
            notAfter ?? Now.AddDays(30),
            hasPrivateKey,
            ekuOids);

    private sealed class FakeCertificateMetadataSource(IReadOnlyList<CertificatePublicMetadata> certificates)
        : ICertificateMetadataSource
    {
        public int ReadCount { get; private set; }

        public IReadOnlyList<CertificatePublicMetadata> Read(StoreLocation location, string storeName)
        {
            ReadCount++;
            return certificates;
        }
    }

    private sealed class ThrowingCertificateMetadataSource(Exception exception) : ICertificateMetadataSource
    {
        public IReadOnlyList<CertificatePublicMetadata> Read(StoreLocation location, string storeName) => throw exception;
    }

    public enum IneligibleCertificateState
    {
        Ambiguous,
        NotYetValid,
        Expired,
        NoPrivateKey
    }

    public enum StoreFailure
    {
        AccessDenied,
        Cryptography
    }
}
