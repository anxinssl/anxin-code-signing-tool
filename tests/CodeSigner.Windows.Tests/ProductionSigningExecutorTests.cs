using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Signing;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;
using NativeSignatureLeg = CodeSigner.Windows.Signing.SignatureLeg;

namespace CodeSigner.Windows.Tests;

public sealed class ProductionSigningExecutorTests : IDisposable
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
    private readonly string root = Path.Combine(Path.GetTempPath(), "CodeSigner-Todo6-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> attempts = [];

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void SingleCorePlanCompilesToOneExactImmutableNativeLeg()
    {
        CoreSigningPlan plan = CreateSinglePlan();

        ProductionNativeSigningPlan nativePlan = ProductionNativeSigningPlan.FromCore(plan);

        NativeSignatureLeg leg = Assert.Single(nativePlan.Legs);
        Assert.Equal(System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, leg.Certificate.StoreLocation);
        Assert.Equal("My", leg.Certificate.StoreName);
        Assert.Equal(PrimaryThumbprint, leg.Certificate.Thumbprint);
        Assert.Equal(NativeDigestAlgorithm.Sha256, leg.FileDigest);
        Assert.Equal(NativeDigestAlgorithm.Sha256, leg.TimestampDigest);
        Assert.Equal(new Uri("http://time.certum.pl"), leg.TimestampUri);
        Assert.False(leg.Append);
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSignatureLeg>)nativePlan.Legs).Add(leg));
    }

    [Fact]
    public void PeProjectionCarriesPerFileCapabilityAndRejectsWindowsSipPlan()
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", PrimaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.LocalMachine, "My", SecondaryThumbprint).Value);
        CoreSigningPlan pePlan = Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateDual(primary, secondary, ".dll").Value);
        CoreSigningPlan sipPlan = Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateDual(primary, null, ".msi").Value);

        ProductionNativeSigningPlan projected = ProductionNativeSigningPlan.FromCore(pePlan);

        Assert.Equal(SigningFormatFamily.PeImage, projected.FormatFamily);
        Assert.Equal(SigningCapability.PeImageDualCapable, projected.Capability);
        Assert.Equal(SigningMode.Dual, projected.EffectiveMode);
        Assert.Equal(".dll", projected.FileExtension);
        Assert.Throws<ArgumentException>(() => ProductionNativeSigningPlan.FromCore(sipPlan));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void DualCorePlanPreservesSeparateCertificatesAndTimestampUris()
    {
        string json = $$"""
            {
              "version": 2,
              "requestedMode": "dual",
              "effectiveMode": "dual",
              "legs": [
                {
                  "certificate": { "storeLocation": "currentUser", "storeName": "My", "thumbprint": "{{PrimaryThumbprint}}" },
                  "fileDigest": "sha1",
                  "append": false,
                  "timestamp": { "protocol": "rfc3161", "timestampDigest": "sha256", "uri": "http://time.certum.pl/primary" }
                },
                {
                  "certificate": { "storeLocation": "localMachine", "storeName": "My", "thumbprint": "{{SecondaryThumbprint}}" },
                  "fileDigest": "sha256",
                  "append": true,
                  "timestamp": { "protocol": "rfc3161", "timestampDigest": "sha256", "uri": "https://tsa.example.test/secondary" }
                }
              ],
              "subject": { "formatFamily": "peImage", "extension": ".exe", "capability": "peImageDualCapable" },
              "existingSignatures": { "valid": "skip", "invalid": "fail", "untrusted": "fail", "expired": "fail", "partial": "fail", "malformed": "fail" }
            }
            """;
        CoreSigningPlan plan = Assert.IsType<CoreSigningPlan>(SigningPlanJson.Parse(json).Value);

        ProductionNativeSigningPlan nativePlan = ProductionNativeSigningPlan.FromCore(plan);

        Assert.Collection(
            nativePlan.Legs,
            primary =>
            {
                Assert.Equal(PrimaryThumbprint, primary.Certificate.Thumbprint);
                Assert.Equal(NativeDigestAlgorithm.Sha1, primary.FileDigest);
                Assert.Equal(new Uri("http://time.certum.pl/primary"), primary.TimestampUri);
                Assert.False(primary.Append);
            },
            secondary =>
            {
                Assert.Equal(System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, secondary.Certificate.StoreLocation);
                Assert.Equal(SecondaryThumbprint, secondary.Certificate.Thumbprint);
                Assert.Equal(NativeDigestAlgorithm.Sha256, secondary.FileDigest);
                Assert.Equal(new Uri("https://tsa.example.test/secondary"), secondary.TimestampUri);
                Assert.True(secondary.Append);
            });
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task ExecutesExactLegSequenceThenVerifiesWithoutPublishing()
    {
        Attempt fixture = CreateAttempt("original");
        var events = new List<string>();
        RecordingLegExecutor signer = new(events);
        RecordingProductionVerifier verifier = new(events);
        ProductionSigningExecutor executor = TestSigningExecutors.Create(signer, verifier);

        ProductionSigningReceipt receipt = await executor.ExecuteAsync(
            fixture.OriginalPath,
            fixture.StagedPath,
            CreateDualPlan(),
            CancellationToken.None);

        Assert.True(receipt.Succeeded);
        Assert.True(receipt.LegacyFallbackAttempted);
        Assert.Equal(["sign:Sha1:False", "sign:Sha256:True", "verify:2"], events);
        Assert.Equal(await HashAsync(fixture.OriginalPath), receipt.OriginalSha256);
        Assert.Equal(await HashAsync(fixture.StagedPath), receipt.StagedSha256);
        Assert.Equal(fixture.OriginalBytes, await File.ReadAllBytesAsync(fixture.OriginalPath));
        Assert.False(File.Exists(Path.Combine(root, "published.exe")));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task FailedLegStopsLaterLegAndVerification()
    {
        Attempt fixture = CreateAttempt("original");
        var events = new List<string>();
        RecordingLegExecutor signer = new(events, failAt: 0, NativeSigningReasonCode.TimestampUnavailable);
        RecordingProductionVerifier verifier = new(events);

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(signer, verifier).ExecuteAsync(
            fixture.OriginalPath,
            fixture.StagedPath,
            CreateDualPlan(),
            CancellationToken.None);

        Assert.False(receipt.Succeeded);
        Assert.Equal(ProductionSigningError.TimestampUnavailable, receipt.Error);
        Assert.Equal(0, receipt.FailedLegIndex);
        Assert.Equal(["sign:Sha1:False"], events);
    }

    [Theory]
    [InlineData(NativeSigningReasonCode.CertificateNotFound, ProductionSigningError.CertificateNotFound)]
    [InlineData(NativeSigningReasonCode.CertificateHasNoPrivateKey, ProductionSigningError.CertificateHasNoPrivateKey)]
    [InlineData(NativeSigningReasonCode.OperatorCancelled, ProductionSigningError.ProviderCancelled)]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable, ProductionSigningError.TimestampUnavailable)]
    [InlineData(NativeSigningReasonCode.NativeSigningFailed, ProductionSigningError.NativeSigningFailed)]
    [InlineData(NativeSigningReasonCode.InvalidInput, ProductionSigningError.InvalidInput)]
    [Trait("Category", "SigningIntegration")]
    public async Task NativeFailuresHaveTypedReceipts(NativeSigningReasonCode reason, ProductionSigningError expected)
    {
        Attempt fixture = CreateAttempt("original");
        const int hResult = unchecked((int)0x80004005);
        RecordingLegExecutor signer = new([], failAt: 0, reason, hResult);

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(signer, new RecordingProductionVerifier([])).ExecuteAsync(
            fixture.OriginalPath,
            fixture.StagedPath,
            CreateSinglePlan(),
            CancellationToken.None);

        Assert.Equal(expected, receipt.Error);
        Assert.Equal(hResult, receipt.HResult);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task CancellationStopsBeforeVerificationWithTypedReceipt()
    {
        Attempt fixture = CreateAttempt("original");
        using CancellationTokenSource cancellation = new();
        var events = new List<string>();
        CancellingLegExecutor signer = new(cancellation, events);

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(signer, new RecordingProductionVerifier(events)).ExecuteAsync(
            fixture.OriginalPath,
            fixture.StagedPath,
            CreateDualPlan(),
            cancellation.Token);

        Assert.Equal(ProductionSigningError.Cancelled, receipt.Error);
        Assert.Equal(["sign",], events);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task DirtyStagingAndChangedOriginalFailHashBindingBeforeVerification()
    {
        Attempt dirty = CreateAttempt("original");
        await File.AppendAllTextAsync(dirty.StagedPath, "dirty");
        var dirtyEvents = new List<string>();
        ProductionSigningReceipt dirtyReceipt = await TestSigningExecutors.Create(
            new RecordingLegExecutor(dirtyEvents),
            new RecordingProductionVerifier(dirtyEvents)).ExecuteAsync(
                dirty.OriginalPath,
                dirty.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.OriginalChanged, dirtyReceipt.Error);
        Assert.Empty(dirtyEvents);

        Attempt changed = CreateAttempt("pristine");
        var changedEvents = new List<string>();
        RecordingLegExecutor changingSigner = new(changedEvents, afterSign: () => File.AppendAllText(changed.OriginalPath, "changed"));
        ProductionSigningReceipt changedReceipt = await TestSigningExecutors.Create(
            changingSigner,
            new RecordingProductionVerifier(changedEvents)).ExecuteAsync(
                changed.OriginalPath,
                changed.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.OriginalChanged, changedReceipt.Error);
        Assert.Equal(["sign:Sha256:False"], changedEvents);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task OriginalChangedDuringVerificationFailsPostVerificationHashBinding()
    {
        Attempt fixture = CreateAttempt("pristine");
        var events = new List<string>();
        RecordingProductionVerifier verifier = new(
            events,
            afterVerify: () => File.AppendAllText(fixture.OriginalPath, "changed"));

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(
            new RecordingLegExecutor(events),
            verifier).ExecuteAsync(
                fixture.OriginalPath,
                fixture.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.OriginalChanged, receipt.Error);
        Assert.Equal(["sign:Sha256:False", "verify:1"], events);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task VerifierDisagreementAndMisleadingNativeSuccessFailClosed()
    {
        Attempt disagreement = CreateAttempt("original");
        ProductionSigningReceipt verifierReceipt = await TestSigningExecutors.Create(
            new RecordingLegExecutor([]),
            new RecordingProductionVerifier([], NativeSigningResult.Failure(
                NativeSigningReasonCode.VerifierDisagreement,
                unchecked((int)0x800B0100)))).ExecuteAsync(
                    disagreement.OriginalPath,
                    disagreement.StagedPath,
                    CreateSinglePlan(),
                    CancellationToken.None);
        Assert.Equal(ProductionSigningError.VerifierDisagreement, verifierReceipt.Error);

        Attempt misleading = CreateAttempt("original");
        ProductionSigningReceipt misleadingReceipt = await TestSigningExecutors.Create(
            new FixedLegExecutor(new NativeSigningResult(true, NativeSigningReasonCode.None, unchecked((int)0x80004005))),
            new RecordingProductionVerifier([])).ExecuteAsync(
                misleading.OriginalPath,
                misleading.StagedPath,
                CreateSinglePlan(),
                CancellationToken.None);
        Assert.Equal(ProductionSigningError.NativeSigningFailed, misleadingReceipt.Error);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task InvalidOrNonOwnedPathReturnsInvalidInputWithoutNativeCalls()
    {
        Directory.CreateDirectory(root);
        string original = Path.Combine(root, "original.exe");
        string staged = Path.Combine(root, "unowned.exe");
        await File.WriteAllTextAsync(original, "original");
        File.Copy(original, staged);
        var events = new List<string>();

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(
            new RecordingLegExecutor(events),
            new RecordingProductionVerifier(events)).ExecuteAsync(
                original,
                staged,
                CreateSinglePlan(),
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.InvalidInput, receipt.Error);
        Assert.Empty(events);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task MissingPlanReturnsTypedInvalidInputWithoutNativeCalls()
    {
        Attempt fixture = CreateAttempt("original");
        var events = new List<string>();

        ProductionSigningReceipt receipt = await TestSigningExecutors.Create(
            new RecordingLegExecutor(events),
            new RecordingProductionVerifier(events)).ExecuteAsync(
                fixture.OriginalPath,
                fixture.StagedPath,
                null!,
                CancellationToken.None);

        Assert.Equal(ProductionSigningError.InvalidInput, receipt.Error);
        Assert.Empty(events);
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

    private Attempt CreateAttempt(string content)
    {
        Directory.CreateDirectory(root);
        string original = Path.Combine(root, Guid.NewGuid().ToString("N") + ".exe");
        byte[] marker = Encoding.UTF8.GetBytes(content);
        byte[] originalBytes = new byte[CreateMinimalPeImage().Length + marker.Length];
        CreateMinimalPeImage().CopyTo(originalBytes, 0);
        marker.CopyTo(originalBytes, CreateMinimalPeImage().Length);
        File.WriteAllBytes(original, originalBytes);
        string attempt = TransactionalStaging.CreateAttemptDirectory(root);
        attempts.Add(attempt);
        string staged = Path.Combine(attempt, "payload.exe");
        File.Copy(original, staged);
        return new Attempt(original, staged, originalBytes);
    }

    private static CoreSigningPlan CreateSinglePlan()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", PrimaryThumbprint).Value);
        return Assert.IsType<CoreSigningPlan>(CoreSigningPlan.TryCreateSingle(certificate, ".exe").Value);
    }

    private static CoreSigningPlan CreateDualPlan()
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", PrimaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.LocalMachine, "My", SecondaryThumbprint).Value);
        return Assert.IsType<CoreSigningPlan>(CoreSigningPlan.TryCreateDual(primary, secondary, ".exe").Value);
    }

    private static async Task<string> HashAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream));
    }

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

    private sealed record Attempt(string OriginalPath, string StagedPath, byte[] OriginalBytes);

    private sealed class RecordingLegExecutor(
        List<string> events,
        int? failAt = null,
        NativeSigningReasonCode failure = NativeSigningReasonCode.NativeSigningFailed,
        int hResult = unchecked((int)0x80004005),
        Action? afterSign = null) : INativeSigningLegExecutor
    {
        private int callCount;

        public Task<NativeSigningResult> ExecuteAsync(string path, NativeSignatureLeg leg, CancellationToken cancellationToken)
        {
            int current = callCount++;
            events.Add($"sign:{leg.FileDigest}:{leg.Append}");
            afterSign?.Invoke();
            return Task.FromResult(failAt == current
                ? NativeSigningResult.Failure(failure, hResult)
                : NativeSigningResult.Success());
        }
    }

    private sealed class FixedLegExecutor(NativeSigningResult result) : INativeSigningLegExecutor
    {
        public Task<NativeSigningResult> ExecuteAsync(string path, NativeSignatureLeg leg, CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }

    private sealed class CancellingLegExecutor(CancellationTokenSource cancellation, List<string> events) : INativeSigningLegExecutor
    {
        public Task<NativeSigningResult> ExecuteAsync(string path, NativeSignatureLeg leg, CancellationToken cancellationToken)
        {
            events.Add("sign");
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(NativeSigningResult.Success());
        }
    }

    private sealed class RecordingProductionVerifier(
        List<string> events,
        NativeSigningResult? result = null,
        Action? afterVerify = null) : IProductionSignedFileVerifier
    {
        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            events.Add($"verify:{plan.Legs.Count}");
            afterVerify?.Invoke();
            return Task.FromResult(result ?? NativeSigningResult.Success());
        }
    }
}
