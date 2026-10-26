using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Signing;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;
using NativeSignatureLeg = CodeSigner.Windows.Signing.SignatureLeg;

namespace CodeSigner.Windows.Tests;

public sealed class ProductionSigningDiagnosticTests : IDisposable
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
    private const int NoInterfaceHResult = unchecked((int)0x80004002);

    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "CodeSigner-ProductionSigningDiagnostic-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> attempts = [];

    [Theory]
    [InlineData(0, ProductionSigningPhase.SigningPrimary, NativeDigestAlgorithm.Sha1, false, 0)]
    [InlineData(1, ProductionSigningPhase.SigningSecondary, NativeDigestAlgorithm.Sha256, true, 0x1000)]
    [Trait("Category", "SigningIntegration")]
    public async Task NativeLegFailurePreservesExactReceiptContext(
        int failedLegIndex,
        ProductionSigningPhase expectedPhase,
        NativeDigestAlgorithm expectedDigest,
        bool expectedAppend,
        int expectedFlags)
    {
        Attempt attempt = CreateAttempt();
        var observedLegs = new List<NativeSignatureLeg>();
        var signer = new FailingLegExecutor(failedLegIndex, observedLegs);

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(
            signer,
            new SuccessfulVerifier()).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreateDualPlan(),
                CancellationToken.None);

        Assert.False(receipt.Succeeded);
        Assert.Equal(ProductionSigningError.NativeSigningFailed, receipt.Error);
        Assert.Equal(NoInterfaceHResult, receipt.HResult);
        Assert.Equal(failedLegIndex, receipt.FailedLegIndex);
        ProductionSigningFailureContext diagnostic = Assert.IsType<ProductionSigningFailureContext>(receipt.Diagnostic);
        Assert.Equal(expectedPhase, diagnostic.Phase);
        Assert.Equal(expectedDigest, diagnostic.DigestAlgorithm);
        Assert.Equal(expectedAppend, diagnostic.AppendSignature);
        Assert.Equal(ProductionSigningNativeCall.SignerSignEx3, diagnostic.NativeCall);
        Assert.Equal(expectedFlags, diagnostic.SignerSignEx3Flags);
        Assert.Equal(NativeSigningReasonCode.NativeSigningFailed, diagnostic.NativeReasonCode);
        Assert.Equal(ProductionHResultOrigin.Native, diagnostic.HResultOrigin);
        Assert.NotNull(diagnostic.LegElapsedMilliseconds);
        Assert.True(diagnostic.LegElapsedMilliseconds >= 0);

        Assert.Equal(failedLegIndex + 1, observedLegs.Count);
        Assert.Equal(NativeDigestAlgorithm.Sha1, observedLegs[0].FileDigest);
        Assert.False(observedLegs[0].Append);
        if (failedLegIndex == 1)
        {
            Assert.Equal(NativeDigestAlgorithm.Sha256, observedLegs[1].FileDigest);
            Assert.True(observedLegs[1].Append);
        }
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ManagedLegExceptionKeepsLegButDoesNotClaimANativeCall()
    {
        Attempt attempt = CreateAttempt();

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(
            new ThrowingLegExecutor(),
            new SuccessfulVerifier()).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreateDualPlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.NativeSigningFailed, receipt.Error);
        Assert.Equal(0, receipt.FailedLegIndex);
        ProductionSigningFailureContext diagnostic = Assert.IsType<ProductionSigningFailureContext>(receipt.Diagnostic);
        Assert.Equal(ProductionSigningPhase.SigningPrimary, diagnostic.Phase);
        Assert.Equal(NativeDigestAlgorithm.Sha1, diagnostic.DigestAlgorithm);
        Assert.False(diagnostic.AppendSignature);
        Assert.Null(diagnostic.NativeCall);
        Assert.Null(diagnostic.SignerSignEx3Flags);
        Assert.Null(diagnostic.NativeReasonCode);
        Assert.Equal(ProductionHResultOrigin.Managed, diagnostic.HResultOrigin);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task VerifierFailureReportsVerifyingPhaseWithoutLegContext()
    {
        Attempt attempt = CreateAttempt();
        var signer = new FailingLegExecutor(failedLegIndex: null, []);
        var verifier = new FailingVerifier();

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(signer, verifier).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreateDualPlan(),
            CancellationToken.None);

        Assert.False(receipt.Succeeded);
        Assert.Equal(ProductionSigningError.VerifierDisagreement, receipt.Error);
        Assert.Null(receipt.FailedLegIndex);
        ProductionSigningFailureContext diagnostic = Assert.IsType<ProductionSigningFailureContext>(receipt.Diagnostic);
        Assert.Equal(ProductionSigningPhase.Verifying, diagnostic.Phase);
        Assert.Null(diagnostic.DigestAlgorithm);
        Assert.Null(diagnostic.AppendSignature);
        Assert.Null(diagnostic.NativeCall);
        Assert.Null(diagnostic.SignerSignEx3Flags);
        Assert.Equal(NativeSigningReasonCode.VerifierDisagreement, diagnostic.NativeReasonCode);
        Assert.Equal(ProductionHResultOrigin.Native, diagnostic.HResultOrigin);
        Assert.Null(diagnostic.LegElapsedMilliseconds);
    }

    public void Dispose()
    {
        foreach (string attempt in attempts)
        {
            TransactionalStaging.DeleteAttempt(attempt);
        }

        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private Attempt CreateAttempt()
    {
        Directory.CreateDirectory(root);
        string originalPath = Path.Combine(root, Guid.NewGuid().ToString("N") + ".exe");
        File.Copy(
            Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", "valid-unsigned.exe"),
            originalPath);
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        attempts.Add(attemptDirectory);
        string stagedPath = Path.Combine(attemptDirectory, "payload.exe");
        File.Copy(originalPath, stagedPath);
        return new Attempt(originalPath, stagedPath);
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return Assert.IsType<DirectoryInfo>(directory).FullName;
    }

    private static CoreSigningPlan CreateDualPlan()
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", PrimaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.LocalMachine, "My", SecondaryThumbprint).Value);
        return Assert.IsType<CoreSigningPlan>(CoreSigningPlan.TryCreateDual(primary, secondary, ".exe").Value);
    }

    private sealed record Attempt(string OriginalPath, string StagedPath);

    private sealed class FailingLegExecutor(
        int? failedLegIndex,
        List<NativeSignatureLeg> observedLegs) : INativeSigningLegExecutor
    {
        private int callCount;

        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            NativeSignatureLeg leg,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int index = callCount++;
            observedLegs.Add(leg);
            return Task.FromResult(failedLegIndex == index
                ? NativeSigningResult.Failure(NativeSigningReasonCode.NativeSigningFailed, NoInterfaceHResult)
                : NativeSigningResult.Success());
        }
    }

    private sealed class ThrowingLegExecutor : INativeSigningLegExecutor
    {
        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            NativeSignatureLeg leg,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("synthetic managed leg failure");
    }

    private sealed class SuccessfulVerifier : IProductionSignedFileVerifier
    {
        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken) => Task.FromResult(NativeSigningResult.Success());
    }

    private sealed class FailingVerifier : IProductionSignedFileVerifier
    {
        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken) => Task.FromResult(NativeSigningResult.Failure(
                NativeSigningReasonCode.VerifierDisagreement,
                unchecked((int)0x800B0100)));
    }
}
