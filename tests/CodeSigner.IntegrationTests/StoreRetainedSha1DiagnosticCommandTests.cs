using System.Text;
using System.Text.Json;
using CodeSigner.CompatibilityProbe.Signing;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class StoreRetainedSha1DiagnosticCommandTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task SuccessUsesExactSha1PlanAndEmitsDiagnosticReceipt()
    {
        CompatibilityGateOperation operation = (_, _, plan, _) =>
        {
            SignatureLeg leg = Assert.Single(plan.Legs);
            Assert.Equal(NativeDigestAlgorithm.Sha1, leg.FileDigest);
            Assert.Equal(NativeDigestAlgorithm.Sha256, leg.TimestampDigest);
            Assert.False(leg.Append);
            return Task.FromResult(new CompatibilityGateResult(true, NativeSigningReasonCode.None, 0, "A", "B"));
        };

        (int exitCode, JsonElement receipt) = await RunAsync(Arguments(), operation);

        Assert.Equal(0, exitCode);
        Assert.Equal("passed", receipt.GetProperty("status").GetString());
        Assert.Equal("store-retained-sha1", receipt.GetProperty("diagnosticMode").GetString());
        Assert.Equal(JsonValueKind.Null, receipt.GetProperty("failedLegIndex").ValueKind);
        Assert.Equal("Sha1", receipt.GetProperty("digestAlgorithm").GetString());
        Assert.Equal("Sha256", receipt.GetProperty("timestampDigestAlgorithm").GetString());
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task NativeFailureIdentifiesDiagnosticModeAndFirstLeg()
    {
        CompatibilityGateOperation operation = (_, _, _, _) => Task.FromResult(
            new CompatibilityGateResult(false, NativeSigningReasonCode.NativeSigningFailed, unchecked((int)0x80090020), "A", null, FailedLegIndex: 0));

        (int exitCode, JsonElement receipt) = await RunAsync(Arguments(), operation);

        Assert.Equal(1, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal("NativeSigningFailed", receipt.GetProperty("reasonCode").GetString());
        Assert.Equal("0x80090020", receipt.GetProperty("hresult").GetString());
        Assert.Equal("store-retained-sha1", receipt.GetProperty("diagnosticMode").GetString());
        Assert.Equal(0, receipt.GetProperty("failedLegIndex").GetInt32());
    }

    [Theory]
    [InlineData(NativeSigningReasonCode.OperatorCancelled)]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable)]
    [Trait("Category", "NativeSigning")]
    public async Task ReturnedNativeLegFailureUsesActualRunnerIndex(NativeSigningReasonCode reasonCode)
    {
        CompatibilityGateOperation operation = (_, _, _, _) => Task.FromResult(
            new CompatibilityGateResult(false, reasonCode, unchecked((int)0x80004005), "A", null, FailedLegIndex: 0));

        (int exitCode, JsonElement receipt) = await RunAsync(Arguments(), operation);

        Assert.Equal(1, exitCode);
        Assert.Equal(reasonCode.ToString(), receipt.GetProperty("reasonCode").GetString());
        Assert.Equal(0, receipt.GetProperty("failedLegIndex").GetInt32());
    }

    [Theory]
    [InlineData(NativeSigningReasonCode.NativeSigningFailed)]
    [InlineData(NativeSigningReasonCode.VerifierDisagreement)]
    [Trait("Category", "NativeSigning")]
    public async Task FailureWithoutRunnerLegIndexIsNeverInferredFromReason(NativeSigningReasonCode reasonCode)
    {
        CompatibilityGateOperation operation = (_, _, _, _) => Task.FromResult(
            new CompatibilityGateResult(false, reasonCode, unchecked((int)0x80004005), "A", null));

        (int exitCode, JsonElement receipt) = await RunAsync(Arguments(), operation);

        Assert.Equal(1, exitCode);
        Assert.Equal(JsonValueKind.Null, receipt.GetProperty("failedLegIndex").ValueKind);
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task OuterIoFailureNeverClaimsAFailedNativeLeg()
    {
        CompatibilityGateOperation operation = (_, _, _, _) => throw new IOException("staging or publish failure");

        (int exitCode, JsonElement receipt) = await RunAsync(Arguments(), operation);

        Assert.Equal(1, exitCode);
        Assert.Equal("NativeSigningFailed", receipt.GetProperty("reasonCode").GetString());
        Assert.Equal(JsonValueKind.Null, receipt.GetProperty("failedLegIndex").ValueKind);
    }

    [Theory]
    [InlineData("", "output.exe")]
    [InlineData("input.exe", "   ")]
    [Trait("Category", "NativeSigning")]
    public async Task InvalidPathIsStructuredAndNeverRunsDiagnostic(string input, string outputPath)
    {
        bool executed = false;
        CompatibilityGateOperation operation = (_, _, _, _) =>
        {
            executed = true;
            return Task.FromResult(new CompatibilityGateResult(true, NativeSigningReasonCode.None, 0, "A", "B"));
        };
        string[] arguments = Arguments();
        arguments[1] = input;
        arguments[2] = outputPath;

        (int exitCode, JsonElement receipt) = await RunAsync(arguments, operation);

        Assert.False(executed);
        Assert.Equal(64, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal("InvalidArguments", receipt.GetProperty("reasonCode").GetString());
    }

    private static string[] Arguments() =>
        ["diagnose-sha1-store-retained", "input.exe", "output.exe", "CurrentUser", "My", Thumbprint, "http://time.certum.pl"];

    private static async Task<(int ExitCode, JsonElement Receipt)> RunAsync(
        string[] arguments,
        CompatibilityGateOperation operation)
    {
        await using MemoryStream output = new();
        int exitCode = await StoreRetainedSha1DiagnosticCommand.RunAsync(
            arguments,
            output,
            operation,
            CancellationToken.None);
        using JsonDocument document = JsonDocument.Parse(Encoding.UTF8.GetString(output.ToArray()));
        return (exitCode, document.RootElement.Clone());
    }
}
