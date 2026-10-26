using System.Text;
using System.Text.Json;
using CodeSigner.Core.Evidence;
using CodeSigner.Core.Worker;

namespace CodeSigner.Core.Tests;

public sealed class AllowListEvidenceWriterTests
{
    [Fact]
    public async Task WriteAsyncDropsUnknownAndCredentialFields()
    {
        Dictionary<string, object?> candidate = new(StringComparer.OrdinalIgnoreCase)
        {
            ["event"] = "fixture-manifest",
            ["status"] = "passed",
            ["sha256"] = new string('a', 64),
            ["password"] = "secret-canary-password",
            ["PIN"] = "secret-canary-pin",
            ["api_key"] = "secret-canary-api-key",
            ["providerOutput"] = "secret-canary-provider-output",
            ["unexpected"] = "secret-canary-unknown"
        };
        await using MemoryStream destination = new();

        await AllowListEvidenceWriter.WriteAsync(destination, candidate, CancellationToken.None);

        string json = Encoding.UTF8.GetString(destination.ToArray());
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        Assert.Equal("fixture-manifest", root.GetProperty("event").GetString());
        Assert.Equal("passed", root.GetProperty("status").GetString());
        Assert.Equal(new string('a', 64), root.GetProperty("sha256").GetString());
        Assert.False(root.TryGetProperty("password", out _));
        Assert.False(root.TryGetProperty("PIN", out _));
        Assert.False(root.TryGetProperty("api_key", out _));
        Assert.False(root.TryGetProperty("providerOutput", out _));
        Assert.False(root.TryGetProperty("unexpected", out _));
        Assert.DoesNotContain("secret-canary", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WriteAsyncUsesStableAllowListOrder()
    {
        Dictionary<string, object?> candidate = new()
        {
            ["status"] = "passed",
            ["event"] = "allow-list-demo",
            ["schemaVersion"] = 1
        };
        await using MemoryStream destination = new();

        await AllowListEvidenceWriter.WriteAsync(destination, candidate, CancellationToken.None);

        Assert.Equal("{\"schemaVersion\":1,\"event\":\"allow-list-demo\",\"status\":\"passed\"}\n", Encoding.UTF8.GetString(destination.ToArray()));
    }

    [Fact]
    public async Task WriteAsyncAllowsNonSecretDiagnosticIdentityAndFailedLeg()
    {
        Dictionary<string, object?> candidate = new()
        {
            ["event"] = "store-retained-sha1-diagnostic",
            ["diagnosticMode"] = "store-retained-sha1",
            ["failedLegIndex"] = 0,
            ["providerOutput"] = "secret-canary-provider-output"
        };
        await using MemoryStream destination = new();

        await AllowListEvidenceWriter.WriteAsync(destination, candidate, CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(destination.ToArray());
        Assert.Equal("store-retained-sha1", document.RootElement.GetProperty("diagnosticMode").GetString());
        Assert.Equal(0, document.RootElement.GetProperty("failedLegIndex").GetInt32());
        Assert.False(document.RootElement.TryGetProperty("providerOutput", out _));
    }

    [Fact]
    public async Task WriteAsyncRetainsSecureSipPublicationUnavailableCode()
    {
        Dictionary<string, object?> candidate = new()
        {
            ["event"] = "sip-publication-failure",
            ["responseCode"] = WorkerResponseCodes.SecureSipPublicationUnavailable
        };
        await using MemoryStream destination = new();

        await AllowListEvidenceWriter.WriteAsync(destination, candidate, CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(destination.ToArray());
        Assert.Equal(
            WorkerResponseCodes.SecureSipPublicationUnavailable,
            document.RootElement.GetProperty("responseCode").GetString());
    }
}
