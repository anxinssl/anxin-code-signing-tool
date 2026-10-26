using System.Text.Json;
using CodeSigner.CompatibilityProbe.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class SelfSignedCompatibilityGateReceiptTests
{
    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task PendingRootTrustReceiptIncludesExactPublicCertificateFileNameAndThumbprint()
    {
        const string fileName = "CodeSigner-Todo2-0123456789abcdef.cer";
        const string thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
        await using MemoryStream output = new();

        await SelfSignedCompatibilityGate.WriteCertificateCreatedReceiptAsync(
            output,
            fileName,
            thumbprint,
            CancellationToken.None);

        output.Position = 0;
        using JsonDocument receipt = await JsonDocument.ParseAsync(output);
        JsonElement root = receipt.RootElement;
        Assert.Equal("self-signed-certificate-created", root.GetProperty("event").GetString());
        Assert.Equal("pending", root.GetProperty("status").GetString());
        Assert.Equal("AwaitingCurrentUserRootTrust", root.GetProperty("reasonCode").GetString());
        Assert.Equal(thumbprint, root.GetProperty("publicCertificateThumbprint").GetString());
        Assert.Equal(fileName, root.GetProperty("fileName").GetString());
        Assert.Equal(300_000, root.GetProperty("durationMs").GetInt64());
        Assert.Equal("private-key-export-disabled", root.GetProperty("fixtureState").GetString());
    }
}
