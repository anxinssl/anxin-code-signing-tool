using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodeSigner.CompatibilityProbe.Signing;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class CompatibilitySigningCommandOutcomeTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Theory]
    [InlineData(NativeApiAvailability.UnsupportedOperatingSystem)]
    [InlineData(NativeApiAvailability.LibraryUnavailable)]
    [InlineData(NativeApiAvailability.SignerSignEx3Unavailable)]
    [InlineData(NativeApiAvailability.CleanupExportUnavailable)]
    [Trait("Category", "NativeSigning")]
    public async Task UnavailableNativeApiIsFailedWithNonBlockedExitCode(NativeApiAvailability availability)
    {
        await using MemoryStream output = new();

        int exitCode = await CompatibilitySigningCommands.CheckAvailabilityAsync(
            output,
            availability,
            CancellationToken.None);

        JsonElement receipt = ParseReceipt(output);
        Assert.Equal(1, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal(availability.ToString(), receipt.GetProperty("reasonCode").GetString());
    }

    [Theory]
    [InlineData(NativeSigningReasonCode.UnsupportedOperatingSystem)]
    [InlineData(NativeSigningReasonCode.NativeLibraryUnavailable)]
    [InlineData(NativeSigningReasonCode.MissingNativeExport)]
    [InlineData(NativeSigningReasonCode.CertificateNotFound)]
    [InlineData(NativeSigningReasonCode.CertificateHasNoPrivateKey)]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable)]
    [InlineData(NativeSigningReasonCode.OperatorCancelled)]
    [InlineData(NativeSigningReasonCode.NativeSigningFailed)]
    [InlineData(NativeSigningReasonCode.SecondLegFailed)]
    [InlineData(NativeSigningReasonCode.VerifierDisagreement)]
    [InlineData(NativeSigningReasonCode.OriginalChanged)]
    [InlineData(NativeSigningReasonCode.DestinationExists)]
    [InlineData(NativeSigningReasonCode.InvalidInput)]
    [InlineData(NativeSigningReasonCode.Cancelled)]
    [Trait("Category", "NativeSigning")]
    public async Task EveryUnsuccessfulGateResultIsFailedWithNonBlockedExitCode(NativeSigningReasonCode reasonCode)
    {
        CompatibilityGateResult result = new(false, reasonCode, unchecked((int)0x80004005), "A", null);

        (int exitCode, JsonElement receipt) = await RunSingleAsync(
            (_, _, _, _) => Task.FromResult(result));

        Assert.Equal(1, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal(reasonCode.ToString(), receipt.GetProperty("reasonCode").GetString());
    }

    [Theory]
    [InlineData(RuntimeFailureKind.PlatformUnsupported, NativeSigningReasonCode.MissingNativeExport)]
    [InlineData(RuntimeFailureKind.NativeLibraryUnavailable, NativeSigningReasonCode.NativeLibraryUnavailable)]
    [InlineData(RuntimeFailureKind.NativeExportUnavailable, NativeSigningReasonCode.MissingNativeExport)]
    [Trait("Category", "NativeSigning")]
    public async Task NativeExecutionAvailabilityExceptionIsFailedWithNonBlockedExitCode(
        RuntimeFailureKind failure,
        NativeSigningReasonCode expectedReasonCode)
    {
        (int exitCode, JsonElement receipt) = await RunSingleAsync(
            (_, _, _, _) => Task.FromException<CompatibilityGateResult>(CreateException(failure)));

        Assert.Equal(1, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal(expectedReasonCode.ToString(), receipt.GetProperty("reasonCode").GetString());
    }

    [Theory]
    [InlineData(RuntimeFailureKind.Io)]
    [InlineData(RuntimeFailureKind.Access)]
    [InlineData(RuntimeFailureKind.Cryptography)]
    [Trait("Category", "NativeSigning")]
    public async Task RuntimeIoAccessOrCryptographicExceptionIsFailedWithNonBlockedExitCode(RuntimeFailureKind failure)
    {
        (int exitCode, JsonElement receipt) = await RunSingleAsync(
            (_, _, _, _) => Task.FromException<CompatibilityGateResult>(CreateException(failure)));

        Assert.Equal(1, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal(NativeSigningReasonCode.NativeSigningFailed.ToString(), receipt.GetProperty("reasonCode").GetString());
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task RuntimeCancellationIsFailedWithNonBlockedExitCode()
    {
        (int exitCode, JsonElement receipt) = await RunSingleAsync(
            (_, _, _, _) => Task.FromException<CompatibilityGateResult>(new OperationCanceledException()));

        Assert.Equal(1, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal(NativeSigningReasonCode.Cancelled.ToString(), receipt.GetProperty("reasonCode").GetString());
    }

    [Theory]
    [InlineData("", "output.exe")]
    [InlineData("   ", "output.exe")]
    [InlineData("input.exe", "")]
    [InlineData("input.exe", "   ")]
    [Trait("Category", "NativeSigning")]
    public async Task EmptyOrWhitespaceSigningPathIsStructuredInvalidArgumentsWithoutExecutingGate(
        string input,
        string outputPath)
    {
        bool gateExecuted = false;
        CompatibilityGateOperation operation = (_, _, _, _) =>
        {
            gateExecuted = true;
            return Task.FromResult(new CompatibilityGateResult(true, NativeSigningReasonCode.None, 0, "A", "B"));
        };
        await using MemoryStream output = new();

        int exitCode = await CompatibilitySigningCommands.RunSingleAsync(
            ["single", input, outputPath, "CurrentUser", "My", Thumbprint, "http://time.certum.pl"],
            output,
            operation,
            CancellationToken.None);

        JsonElement receipt = ParseReceipt(output);
        Assert.False(gateExecuted);
        Assert.Equal(64, exitCode);
        Assert.NotEqual(20, exitCode);
        Assert.Equal("failed", receipt.GetProperty("status").GetString());
        Assert.Equal("InvalidArguments", receipt.GetProperty("reasonCode").GetString());
    }

    private static async Task<(int ExitCode, JsonElement Receipt)> RunSingleAsync(CompatibilityGateOperation operation)
    {
        await using MemoryStream output = new();
        int exitCode = await CompatibilitySigningCommands.RunSingleAsync(
            ["single", "input.exe", "output.exe", "CurrentUser", "My", Thumbprint, "http://time.certum.pl"],
            output,
            operation,
            CancellationToken.None);
        return (exitCode, ParseReceipt(output));
    }

    private static JsonElement ParseReceipt(MemoryStream output)
    {
        using JsonDocument document = JsonDocument.Parse(Encoding.UTF8.GetString(output.ToArray()));
        return document.RootElement.Clone();
    }

    private static Exception CreateException(RuntimeFailureKind failure) => failure switch
    {
        RuntimeFailureKind.PlatformUnsupported => new PlatformNotSupportedException(),
        RuntimeFailureKind.NativeLibraryUnavailable => new DllNotFoundException(),
        RuntimeFailureKind.NativeExportUnavailable => new EntryPointNotFoundException(),
        RuntimeFailureKind.Io => new IOException(),
        RuntimeFailureKind.Access => new UnauthorizedAccessException(),
        RuntimeFailureKind.Cryptography => new CryptographicException(),
        _ => throw new ArgumentOutOfRangeException(nameof(failure), failure, null)
    };

    public enum RuntimeFailureKind
    {
        PlatformUnsupported,
        NativeLibraryUnavailable,
        NativeExportUnavailable,
        Io,
        Access,
        Cryptography
    }
}
