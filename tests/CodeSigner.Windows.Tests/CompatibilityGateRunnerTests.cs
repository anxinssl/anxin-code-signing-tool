using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class CompatibilityGateRunnerTests : IDisposable
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private readonly string directory = Path.Combine(Path.GetTempPath(), "CodeSigner-Todo2-" + Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable)]
    [InlineData(NativeSigningReasonCode.CertificateNotFound)]
    [InlineData(NativeSigningReasonCode.OperatorCancelled)]
    [InlineData(NativeSigningReasonCode.SecondLegFailed)]
    [InlineData(NativeSigningReasonCode.VerifierDisagreement)]
    [Trait("Category", "NativeSigning")]
    public async Task FailureNeverMutatesOriginalOrPublishesPartialOutput(NativeSigningReasonCode failure)
    {
        Directory.CreateDirectory(directory);
        string input = Path.Combine(directory, "input.exe");
        string output = Path.Combine(directory, "signed.exe");
        await File.WriteAllBytesAsync(input, [0x4d, 0x5a, 0x01, 0x02]);
        string before = await HashAsync(input);
        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateDual(
            CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
            CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
            new Uri("http://time.certum.pl"));
        StubLegExecutor signer = new(failure);
        StubVerifier verifier = new(failure);
        CompatibilityGateRunner runner = new(signer, verifier);

        CompatibilityGateResult result = await runner.RunAsync(input, output, plan, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(failure, result.ReasonCode);
        int? expectedFailedLeg = failure switch
        {
            NativeSigningReasonCode.VerifierDisagreement => null,
            NativeSigningReasonCode.SecondLegFailed => 1,
            _ => 0
        };
        Assert.Equal(expectedFailedLeg, result.FailedLegIndex);
        Assert.Equal(before, await HashAsync(input));
        Assert.False(File.Exists(output));
        Assert.Empty(Directory.GetFiles(directory, "*.partial-*"));
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task CleanupFailureDoesNotOverwriteReturnedNativeFailureIdentity()
    {
        Directory.CreateDirectory(directory);
        string input = Path.Combine(directory, "input.exe");
        string output = Path.Combine(directory, "signed.exe");
        await File.WriteAllBytesAsync(input, [0x4d, 0x5a, 0x01, 0x02]);
        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateSingle(
            CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
            new Uri("http://time.certum.pl"));
        using LockingFailedLegExecutor signer = new();
        CompatibilityGateRunner runner = new(signer, new StubVerifier(NativeSigningReasonCode.None));

        CompatibilityGateResult result = await runner.RunAsync(input, output, plan, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.TimestampUnavailable, result.ReasonCode);
        Assert.Equal(unchecked((int)0x80072EE7), result.HResult);
        Assert.Equal(0, result.FailedLegIndex);
        Assert.False(File.Exists(output));
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task SuccessPublishesOnlyAfterBothLegsAndIndependentVerification()
    {
        Directory.CreateDirectory(directory);
        string input = Path.Combine(directory, "input.exe");
        string output = Path.Combine(directory, "signed.exe");
        await File.WriteAllBytesAsync(input, [0x4d, 0x5a, 0x01, 0x02]);
        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateDual(
            CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
            CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
            new Uri("http://time.certum.pl"));
        StubLegExecutor signer = new(NativeSigningReasonCode.None);
        StubVerifier verifier = new(NativeSigningReasonCode.None);
        CompatibilityGateRunner runner = new(signer, verifier);

        CompatibilityGateResult result = await runner.RunAsync(input, output, plan, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(2, signer.CallCount);
        Assert.True(verifier.Called);
        Assert.True(File.Exists(output));
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task SingleSignStagingRetainsExeExtensionThroughVerification()
    {
        Directory.CreateDirectory(directory);
        string input = Path.Combine(directory, "input.exe");
        string output = Path.Combine(directory, "signed.exe");
        await File.WriteAllBytesAsync(input, [0x4d, 0x5a, 0x01, 0x02]);
        CompatibilitySigningPlan plan = CompatibilitySigningPlan.CreateSingle(
            CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint),
            new Uri("http://time.certum.pl"));
        StubLegExecutor signer = new(NativeSigningReasonCode.None);
        StubVerifier verifier = new(NativeSigningReasonCode.None);
        CompatibilityGateRunner runner = new(signer, verifier);

        CompatibilityGateResult result = await runner.RunAsync(input, output, plan, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.NotNull(signer.LastPath);
        Assert.Equal(signer.LastPath, verifier.LastPath);
        Assert.NotEqual(output, signer.LastPath);
        Assert.Equal(".exe", Path.GetExtension(signer.LastPath));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task<string> HashAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream));
    }

    private sealed class StubLegExecutor(NativeSigningReasonCode failure) : INativeSigningLegExecutor
    {
        public int CallCount { get; private set; }
        public string? LastPath { get; private set; }

        public Task<NativeSigningResult> ExecuteAsync(string path, SignatureLeg leg, CancellationToken cancellationToken)
        {
            CallCount++;
            LastPath = path;
            NativeSigningReasonCode current = failure switch
            {
                NativeSigningReasonCode.VerifierDisagreement => NativeSigningReasonCode.None,
                NativeSigningReasonCode.SecondLegFailed when CallCount == 1 => NativeSigningReasonCode.None,
                _ => failure
            };
            return Task.FromResult(current == NativeSigningReasonCode.None
                ? NativeSigningResult.Success()
                : NativeSigningResult.Failure(current, unchecked((int)0x80004005)));
        }
    }

    private sealed class StubVerifier(NativeSigningReasonCode failure) : INativeSignedFileVerifier
    {
        public bool Called { get; private set; }
        public string? LastPath { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(string path, CompatibilitySigningPlan plan, CancellationToken cancellationToken)
        {
            Called = true;
            LastPath = path;
            NativeSigningReasonCode current = failure == NativeSigningReasonCode.VerifierDisagreement
                ? failure
                : NativeSigningReasonCode.None;
            return Task.FromResult(current == NativeSigningReasonCode.None
                ? NativeSigningResult.Success()
                : NativeSigningResult.Failure(current, unchecked((int)0x800B0100)));
        }
    }

    private sealed class LockingFailedLegExecutor : INativeSigningLegExecutor, IDisposable
    {
        private FileStream? lockStream;

        public Task<NativeSigningResult> ExecuteAsync(string path, SignatureLeg leg, CancellationToken cancellationToken)
        {
            lockStream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return Task.FromResult(NativeSigningResult.Failure(
                NativeSigningReasonCode.TimestampUnavailable,
                unchecked((int)0x80072EE7)));
        }

        public void Dispose() => lockStream?.Dispose();
    }
}
