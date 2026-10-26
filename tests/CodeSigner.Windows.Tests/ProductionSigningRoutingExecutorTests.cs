using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;

namespace CodeSigner.Windows.Tests;

public sealed class ProductionSigningRoutingExecutorTests : IDisposable
{
    private const int NoInterfaceHResult = unchecked((int)0x80004002);
    private const int ManagedExceptionHResult = unchecked((int)0x80131500);
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "CodeSigner-Todo7-Executor-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> attempts = [];

    [Fact]
    public async Task ProductPeSuccessUsesFreshStageAndCommitsOnlyAfterIndependentVerification()
    {
        Attempt attempt = CreateAttempt("product-success");
        byte[] originalBytes = await File.ReadAllBytesAsync(attempt.OriginalPath);
        var engine = new RecordingPeEngine(
            NativeSigningResult.Success(),
            path => File.AppendAllText(path, "|product-pe"));
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var phases = new List<ProductionSigningPhase>();
        using Process owner = Process.GetCurrentProcess();
        ProductionSigningExecutor executor = TestSigningExecutors.Create(engine, verifier);

        ProductionSigningReceipt receipt = await executor.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreateDualPlan(),
            owner.Id,
            owner.StartTime.ToUniversalTime(),
            (phase, _) =>
            {
                phases.Add(phase);
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.True(receipt.Succeeded);
        Assert.False(receipt.LegacyFallbackAttempted);
        Assert.Equal(ProductionSigningError.None, receipt.Error);
        Assert.Equal(
            [
                ProductionSigningPhase.SigningPrimary,
                ProductionSigningPhase.SigningSecondary,
                ProductionSigningPhase.Verifying
            ],
            phases);
        Assert.False(string.Equals(attempt.OriginalPath, engine.StagedPath, StringComparison.OrdinalIgnoreCase));
        Assert.False(string.Equals(attempt.StagedPath, engine.StagedPath, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(engine.StagedPath, verifier.StagedPath);
        Assert.Equal(originalBytes, engine.BytesBeforeMutation);
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(attempt.OriginalPath));
        Assert.EndsWith("|product-pe", await File.ReadAllTextAsync(attempt.StagedPath));
        Assert.Equal(Hash(attempt.OriginalPath), receipt.OriginalSha256);
        Assert.Equal(Hash(attempt.StagedPath), receipt.StagedSha256);
        Assert.False(File.Exists(engine.StagedPath));
    }

    [Fact]
    public async Task ProductPeSuccessReleasesVerifiedCandidateBeforeProductionCommit()
    {
        Attempt attempt = CreateAttempt("production-commit");
        var engine = new RecordingPeEngine(
            NativeSigningResult.Success(),
            path => File.AppendAllText(path, "|product-pe"));
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        ProductionSigningExecutor executor = new(
            engine,
            verifier,
            sdkFallbackExecutor: null,
            sdkFallbackCandidate: null,
            new ProductionSigningSubjectClassifier(),
            LocalStagingFileCommitter.Instance);

        ProductionSigningReceipt receipt = await executor.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreateSinglePlan(),
            CancellationToken.None);

        Assert.True(
            receipt.Succeeded,
            $"Production commit failed with {receipt.Error} / 0x{receipt.HResult:X8}.");
        Assert.Equal(ProductionSigningError.None, receipt.Error);
        Assert.EndsWith("|product-pe", await File.ReadAllTextAsync(attempt.StagedPath));
        Assert.Equal(Hash(attempt.StagedPath), receipt.StagedSha256);
        Assert.False(File.Exists(engine.StagedPath));
    }

    [Fact]
    public async Task VerifiedStrategyPathReplacementBeforeCommitFailsClosedWithoutReplacingOwnedStage()
    {
        Attempt attempt = CreateAttempt("verified-strategy-aba");
        var engine = new RecordingPeEngine(
            NativeSigningResult.Success(),
            path => File.AppendAllText(path, "|verified-product-pe"));
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var classifier = new ReplacingClassifier();
        ProductionSigningExecutor executor = new(
            engine,
            verifier,
            sdkFallbackExecutor: null,
            sdkFallbackCandidate: null,
            subjectClassifier: classifier);

        ProductionSigningReceipt receipt = await executor.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreateSinglePlan(),
            CancellationToken.None);

        string observed = File.ReadAllText(attempt.StagedPath);
        Assert.True(
            receipt.Error == ProductionSigningError.VerifierDisagreement,
            $"Expected verifier-disagreement after the verified path was replaced; observed error={receipt.Error}, succeeded={receipt.Succeeded}, staged={observed}.");
        Assert.Equal(1, engine.CallCount);
        Assert.Equal(1, verifier.CallCount);
        Assert.Equal(attempt.PristineBytes, File.ReadAllBytes(attempt.StagedPath));
        Assert.Equal(3, classifier.CallCount);
    }

    [Fact]
    public async Task SecondaryNoInterfaceFallbackStartsFromPristineBytesAndCannotPublishFailedPeMutation()
    {
        Attempt attempt = CreateAttempt("fallback-success");
        byte[] originalBytes = await File.ReadAllBytesAsync(attempt.OriginalPath);
        var engine = new RecordingPeEngine(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                NoInterfaceHResult),
            path => File.AppendAllText(path, "|failed-product-pe"));
        var fallback = new RecordingSdkFallbackExecutor(
            SdkSignToolFallbackError.None,
            mutateFreshStage: path => File.AppendAllText(path, "|verified-sdk"));
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        ProductionSigningExecutor executor = TestSigningExecutors.Create(
            engine,
            verifier,
            fallback,
            Candidate());

        ProductionSigningReceipt receipt = await executor.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreateDualPlan(),
            CancellationToken.None);

        Assert.True(receipt.Succeeded);
        Assert.False(receipt.LegacyFallbackAttempted);
        Assert.Equal(1, fallback.CallCount);
        Assert.Equal(engine.StagedPath, fallback.FailedStagedPath);
        Assert.False(string.Equals(engine.StagedPath, fallback.FreshStagedPath, StringComparison.OrdinalIgnoreCase));
        Assert.False(string.Equals(attempt.StagedPath, fallback.FreshStagedPath, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(originalBytes, fallback.FreshBytesBeforeMutation);
        Assert.Contains("|failed-product-pe", fallback.FailedStagedText, StringComparison.Ordinal);
        string published = await File.ReadAllTextAsync(attempt.StagedPath);
        Assert.EndsWith("|verified-sdk", published, StringComparison.Ordinal);
        Assert.DoesNotContain("failed-product-pe", published, StringComparison.Ordinal);
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(attempt.OriginalPath));
        Assert.Equal(fallback.FreshStagedPath, verifier.StagedPath);
        Assert.False(File.Exists(engine.StagedPath));
        Assert.False(File.Exists(fallback.FreshStagedPath));
    }

    [Fact]
    public async Task GenericProductPeFailureDoesNotUseSdkFallback()
    {
        Attempt attempt = CreateAttempt("managed-failure-sdk-fallback");
        var engine = new RecordingPeEngine(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.NativeSigningFailed,
                ManagedExceptionHResult));
        var fallback = new RecordingSdkFallbackExecutor(
            SdkSignToolFallbackError.None,
            mutateFreshStage: path => File.AppendAllText(path, "|verified-sdk"));
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        ProductionSigningExecutor executor = TestSigningExecutors.Create(
            engine,
            verifier,
            fallback,
            Candidate());

        ProductionSigningReceipt receipt = await executor.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreateSinglePlan(),
            CancellationToken.None);

        Assert.False(receipt.Succeeded);
        Assert.Equal(ProductionSigningError.NativeSigningFailed, receipt.Error);
        Assert.Equal(0, fallback.CallCount);
        Assert.Equal(attempt.PristineBytes, await File.ReadAllBytesAsync(attempt.StagedPath));
    }

    [Fact]
    public async Task MissingOrInvalidSdkFallbackFailsClosedAndCleansEveryStrategyStage()
    {
        Attempt missing = CreateAttempt("missing-sdk");
        var missingEngine = EligibleFailureEngine();
        var missingVerifier = new RecordingVerifier(NativeSigningResult.Success());
        ProductionSigningReceipt missingReceipt = await TestSigningExecutors.Create(
            missingEngine,
            missingVerifier).ExecuteAsync(
                missing.OriginalPath,
                missing.StagedPath,
                CreateDualPlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.NativeSigningFailed, missingReceipt.Error);
        Assert.Equal(Hash(missing.OriginalPath), missingReceipt.OriginalSha256);
        Assert.Equal(await File.ReadAllBytesAsync(missing.OriginalPath), await File.ReadAllBytesAsync(missing.StagedPath));
        Assert.False(File.Exists(missingEngine.StagedPath));
        Assert.Equal(0, missingVerifier.CallCount);

        Attempt invalid = CreateAttempt("invalid-sdk");
        var invalidEngine = EligibleFailureEngine();
        var invalidFallback = new RecordingSdkFallbackExecutor(SdkSignToolFallbackError.CandidateChanged);
        var invalidVerifier = new RecordingVerifier(NativeSigningResult.Success());
        ProductionSigningReceipt invalidReceipt = await TestSigningExecutors.Create(
            invalidEngine,
            invalidVerifier,
            invalidFallback,
            Candidate()).ExecuteAsync(
                invalid.OriginalPath,
                invalid.StagedPath,
                CreateDualPlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.NativeSigningFailed, invalidReceipt.Error);
        Assert.Equal(Hash(invalid.OriginalPath), invalidReceipt.OriginalSha256);
        Assert.Equal(await File.ReadAllBytesAsync(invalid.OriginalPath), await File.ReadAllBytesAsync(invalid.StagedPath));
        Assert.False(File.Exists(invalidEngine.StagedPath));
        Assert.Null(invalidFallback.FreshStagedPath);
        Assert.Equal(0, invalidVerifier.CallCount);
    }

    [Fact]
    public async Task CancellationOriginalMutationAndVerifierDisagreementNeverCommitProductPeStage()
    {
        Attempt cancelled = CreateAttempt("cancelled");
        var cancellingEngine = new RecordingPeEngine(
            NativeSigningResult.Success(),
            cancelAfterProgress: true);
        ProductionSigningReceipt cancelledReceipt = await TestSigningExecutors.Create(
            cancellingEngine,
            new RecordingVerifier(NativeSigningResult.Success())).ExecuteAsync(
                cancelled.OriginalPath,
                cancelled.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);
        AssertFailureLeavesPublisherPristine(cancelled, cancelledReceipt, ProductionSigningError.Cancelled);
        Assert.False(File.Exists(cancellingEngine.StagedPath));

        Attempt changed = CreateAttempt("original-changed");
        string changedOriginalHash = Hash(changed.OriginalPath);
        var changingEngine = new RecordingPeEngine(
            NativeSigningResult.Success(),
            path =>
            {
                File.AppendAllText(path, "|signed");
                File.AppendAllText(changed.OriginalPath, "|external-change");
            });
        ProductionSigningReceipt changedReceipt = await TestSigningExecutors.Create(
            changingEngine,
            new RecordingVerifier(NativeSigningResult.Success())).ExecuteAsync(
                changed.OriginalPath,
                changed.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);
        Assert.Equal(ProductionSigningError.OriginalChanged, changedReceipt.Error);
        Assert.Equal(changedOriginalHash, changedReceipt.OriginalSha256);
        Assert.Equal(changed.PristineBytes, await File.ReadAllBytesAsync(changed.StagedPath));
        Assert.False(File.Exists(changingEngine.StagedPath));

        Attempt disagreement = CreateAttempt("verifier-disagreement");
        var disagreeingEngine = new RecordingPeEngine(
            NativeSigningResult.Success(),
            path => File.AppendAllText(path, "|unverified"));
        var disagreeingVerifier = new RecordingVerifier(NativeSigningResult.Failure(
            NativeSigningReasonCode.VerifierDisagreement,
            unchecked((int)0x800B0100)));
        ProductionSigningReceipt disagreementReceipt = await TestSigningExecutors.Create(
            disagreeingEngine,
            disagreeingVerifier).ExecuteAsync(
                disagreement.OriginalPath,
                disagreement.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);
        AssertFailureLeavesPublisherPristine(
            disagreement,
            disagreementReceipt,
            ProductionSigningError.VerifierDisagreement);
        Assert.False(File.Exists(disagreeingEngine.StagedPath));
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

    private static void AssertFailureLeavesPublisherPristine(
        Attempt attempt,
        ProductionSigningReceipt receipt,
        ProductionSigningError expectedError)
    {
        Assert.False(receipt.Succeeded);
        Assert.Equal(expectedError, receipt.Error);
        Assert.Equal(Hash(attempt.OriginalPath), receipt.OriginalSha256);
        Assert.Equal(attempt.PristineBytes, File.ReadAllBytes(attempt.StagedPath));
    }

    private Attempt CreateAttempt(string name)
    {
        Directory.CreateDirectory(root);
        byte[] marker = System.Text.Encoding.UTF8.GetBytes(name);
        byte[] image = CreateMinimalPeImage();
        byte[] pristine = new byte[image.Length + marker.Length];
        image.CopyTo(pristine, 0);
        marker.CopyTo(pristine, image.Length);
        string originalPath = Path.Combine(root, name + ".exe");
        File.WriteAllBytes(originalPath, pristine);
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        attempts.Add(attemptDirectory);
        string stagedPath = Path.Combine(attemptDirectory, "payload.exe");
        File.Copy(originalPath, stagedPath);
        return new Attempt(originalPath, stagedPath, pristine);
    }

    private static RecordingPeEngine EligibleFailureEngine() => new(
        NativeSigningResult.Failure(
            NativeSigningReasonCode.UnsupportedKeyAlgorithm,
            NoInterfaceHResult),
        path => File.AppendAllText(path, "|failed-product-pe"));

    private static CoreSigningPlan CreateSinglePlan()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                PrimaryThumbprint).Value);
        return Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateSingle(certificate, ".exe").Value);
    }

    private static CoreSigningPlan CreateDualPlan()
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                PrimaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.LocalMachine,
                "My",
                SecondaryThumbprint).Value);
        return Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateDual(primary, secondary, ".exe").Value);
    }

    private static TrustedSdkSignToolCandidate Candidate() => new(
        Path.Combine(Path.GetTempPath(), "Windows Kits", "10", "bin", "10.0.26100.0", "x64", "signtool.exe"),
        new Version(10, 0, 26100, 0),
        new Version(10, 0, 26100, 0),
        "Microsoft Windows",
        "Microsoft Corporation",
        "Microsoft Windows Operating System",
        new string('A', 64));

    private static string Hash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static byte[] CreateMinimalPeImage()
    {
        const int peOffset = 0x80;
        const int optionalHeaderSize = 0xf0;
        byte[] image = new byte[peOffset + 24 + optionalHeaderSize];
        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3c, sizeof(int)), peOffset);
        image[peOffset] = (byte)'P';
        image[peOffset + 1] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 4, sizeof(ushort)), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 6, sizeof(ushort)), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 20, sizeof(ushort)), optionalHeaderSize);
        int optionalHeader = peOffset + 24;
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(optionalHeader, sizeof(ushort)), 0x20b);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optionalHeader + 108, sizeof(uint)), 16);
        return image;
    }

    private sealed record Attempt(string OriginalPath, string StagedPath, byte[] PristineBytes);

    private sealed class RecordingPeEngine(
        NativeSigningResult result,
        Action<string>? mutateStage = null,
        bool cancelAfterProgress = false) : IPeAuthenticodeSigningEngine
    {
        public int CallCount { get; private set; }

        public string? StagedPath { get; private set; }

        public byte[]? BytesBeforeMutation { get; private set; }

        public Task<NativeSigningResult> ExecuteAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            nint providerWindowHandle,
            CancellationToken cancellationToken) => ExecuteAsync(
                stagedPath,
                plan,
                stagingOwnerPid,
                stagingOwnerStartUtc,
                providerWindowHandle,
                static (_, _) => ValueTask.CompletedTask,
                cancellationToken);

        public async Task<NativeSigningResult> ExecuteAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            nint providerWindowHandle,
            Func<int, CancellationToken, ValueTask> reportLeg,
            CancellationToken cancellationToken)
        {
            CallCount++;
            StagedPath = stagedPath;
            BytesBeforeMutation = await File.ReadAllBytesAsync(stagedPath, cancellationToken);
            for (int index = 0; index < plan.Legs.Count; index++)
            {
                await reportLeg(index, cancellationToken);
            }

            if (cancelAfterProgress)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            mutateStage?.Invoke(stagedPath);
            return result;
        }
    }

    private sealed class ReplacingClassifier : IProductionSigningSubjectClassifier
    {
        private static readonly SigningSubject Subject = SigningSubject.TryCreateForExtension(".exe").Value
            ?? throw new InvalidOperationException("The PE signing subject is unavailable.");

        public int CallCount { get; private set; }

        public SigningSubject Classify(string path)
        {
            CallCount++;
            if (CallCount == 3)
            {
                string moved = path + ".verified";
                File.Move(path, moved);
                File.WriteAllBytes(path, CreateMinimalPeImage());
            }

            return Subject;
        }
    }

    private sealed class RecordingVerifier(NativeSigningResult result) : IProductionSignedFileVerifier
    {
        public int CallCount { get; private set; }

        public string? StagedPath { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            StagedPath = stagedPath;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingSdkFallbackExecutor(
        SdkSignToolFallbackError resultError,
        Action<string>? mutateFreshStage = null) : ITrustedSdkSignToolExecutor
    {
        public int CallCount { get; private set; }

        public string? FailedStagedPath { get; private set; }

        public string? FailedStagedText { get; private set; }

        public string? FreshStagedPath { get; private set; }

        public byte[]? FreshBytesBeforeMutation { get; private set; }

        public Task<SdkSignToolFallbackResult> ExecuteAsync(
            TrustedSdkSignToolCandidate selectedCandidate,
            SdkSignToolFallbackEligibility eligibility,
            string originalPath,
            string failedStagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            FailedStagedPath = failedStagedPath;
            FailedStagedText = File.ReadAllText(failedStagedPath);
            string originalHash = Hash(originalPath);
            if (resultError != SdkSignToolFallbackError.None)
            {
                return Task.FromResult(SdkSignToolFallbackResult.Failure(resultError, originalHash));
            }

            string directory = Path.GetDirectoryName(failedStagedPath)!;
            FreshStagedPath = Path.Combine(directory, $".codesigner-sdk-test-{Guid.NewGuid():N}.exe");
            File.Copy(originalPath, FreshStagedPath);
            FreshBytesBeforeMutation = File.ReadAllBytes(FreshStagedPath);
            mutateFreshStage?.Invoke(FreshStagedPath);
            return Task.FromResult(new SdkSignToolFallbackResult(
                Succeeded: true,
                SdkSignToolFallbackError.None,
                originalHash,
                Hash(FreshStagedPath),
                FreshStagedPath,
                Array.Empty<SdkSignToolInvocationReceipt>()));
        }
    }
}
