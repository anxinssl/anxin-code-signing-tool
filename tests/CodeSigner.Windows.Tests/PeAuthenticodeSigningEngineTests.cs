using System.Buffers.Binary;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Signing;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;
using NativeSignatureLeg = CodeSigner.Windows.Signing.SignatureLeg;

namespace CodeSigner.Windows.Tests;

public sealed class PeAuthenticodeSigningEngineTests : IDisposable
{
    private static readonly byte[] PrimaryCertificateDer = CreateSyntheticCertificateDer("Primary");
    private static readonly byte[] SecondaryCertificateDer = CreateSyntheticCertificateDer("Secondary");
#pragma warning disable CA5350 // The fake certificate identities mirror Windows SHA-1 thumbprints.
    private static readonly string PrimaryThumbprint = Convert.ToHexString(SHA1.HashData(PrimaryCertificateDer));
    private static readonly string SecondaryThumbprint = Convert.ToHexString(SHA1.HashData(SecondaryCertificateDer));
#pragma warning restore CA5350
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "CodeSigner-PeAuthenticode-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> attempts = [];

    [Theory]
    [InlineData(".exe", false)]
    [InlineData(".exe", true)]
    [InlineData(".dll", false)]
    [InlineData(".dll", true)]
    [InlineData(".sys", false)]
    [InlineData(".sys", true)]
    [InlineData(".efi", false)]
    [InlineData(".efi", true)]
    [Trait("Category", "Authenticode")]
    public async Task SyntheticPeFixturesProduceOneEnvelopeWithOrderedLogicalSignatures(
        string extension,
        bool dual)
    {
        Attempt fixture = CreateAttempt(extension, FixtureBytes("valid-unsigned.exe"));
        byte[] original = File.ReadAllBytes(fixture.StagedPath);
        var cmsSigner = new SyntheticCmsSigner();
        var finalTrust = new RecordingVerifier(NativeSigningResult.Success());
        PeAuthenticodeSigningEngine engine = CreateEngine(cmsSigner, finalTrust);

        NativeSigningResult result = await engine.ExecuteAsync(
            fixture.StagedPath,
            dual ? CreateDualPlan(extension) : CreateSinglePlan(extension),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        PeImageCertificateTable table = PeImageCertificateTable.Read(fixture.StagedPath);
        PeCertificateRecord envelope = Assert.Single(table.Records);
        Assert.Equal(0U, table.TableOffset & 7U);
        Assert.All(table.Records, record =>
        {
            Assert.Equal(0L, record.FileOffset & 7L);
            Assert.Equal(0U, record.AlignedLength & 7U);
            Assert.Equal(record.Content.Length + 8U, record.DeclaredLength);
        });
        var inspector = new AuthenticodeCmsRecordInspector();
        PeAuthenticodeCmsInspection topLevel = inspector.Inspect(envelope.Content);
        PeAuthenticodeCmsInspection[] inspections =
        [
            topLevel,
            .. topLevel.NestedSignatures
        ];
        if (dual)
        {
            Assert.Equal(
                [AuthenticodeOids.Sha1, AuthenticodeOids.Sha256],
                inspections.Select(inspection => inspection.DigestAlgorithmOid));
        }
        else
        {
            Assert.Equal(AuthenticodeOids.Sha256, Assert.Single(inspections).DigestAlgorithmOid);
        }

        Assert.All(inspections, inspection =>
        {
            Assert.Single(inspection.CertificateThumbprints);
            Assert.Equal(1, inspection.Rfc3161TimestampCount);
            Assert.Equal(AuthenticodeOids.Sha256, inspection.TimestampDigestAlgorithmOid);
            Assert.True(inspection.TimestampMessageImprintMatchesSignature);
        });
        Assert.Equal(dual ? 2 : 1, cmsSigner.CallCount);
        Assert.Equal(
            dual
                ? [PrimaryThumbprint, SecondaryThumbprint]
                : [PrimaryThumbprint],
            cmsSigner.CertificateThumbprints);
        Assert.Equal(
            cmsSigner.CertificateThumbprints,
            inspections.SelectMany(inspection => inspection.CertificateThumbprints));
        Assert.Equal(1, finalTrust.CallCount);
        Assert.False(original.AsSpan().SequenceEqual(File.ReadAllBytes(fixture.StagedPath)));
        Assert.False(File.Exists(fixture.DestinationPath));
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("Category", "Authenticode")]
    public async Task UnalignedUnsignedPeIsPaddedBeforeItsAuthenticodeDigestIsCreated(bool dual)
    {
        byte[] input = [.. FixtureBytes("valid-unsigned.exe"), 0x5A];
        Attempt fixture = CreateAttempt(".exe", input);
        var cmsSigner = new SyntheticCmsSigner();
        var finalTrust = new RecordingVerifier(NativeSigningResult.Success());
        PeAuthenticodeSigningEngine engine = CreateEngine(cmsSigner, finalTrust);

        NativeSigningResult result = await engine.ExecuteAsync(
            fixture.StagedPath,
            dual ? CreateDualPlan(".exe") : CreateSinglePlan(".exe"),
            CancellationToken.None);

        Assert.True(
            result.Succeeded,
            $"Reason={result.ReasonCode}; HResult=0x{result.HResult:X8}");
        PeImageCertificateTable table = PeImageCertificateTable.Read(fixture.StagedPath);
        Assert.Equal(0U, table.TableOffset & 7U);
        Assert.Equal(1, finalTrust.CallCount);
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task DualLegDigestsAreComputedFromTheSameUnsignedPeSurface()
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        var digest = new RecordingDigestProvider();
        var signer = new SyntheticCmsSigner();
        var finalTrust = new RecordingVerifier(NativeSigningResult.Success());
        var engine = new PeAuthenticodeSigningEngine(digest, signer, finalTrust);

        NativeSigningResult result = await engine.ExecuteAsync(
            fixture.StagedPath,
            CreateDualPlan(".exe"),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(
            [NativeDigestAlgorithm.Sha1, NativeDigestAlgorithm.Sha256],
            digest.Algorithms.Take(2));
        Assert.Equal([0, 0], digest.CertificateRecordCounts.Take(2));
        Assert.Equal(
            [NativeDigestAlgorithm.Sha1, NativeDigestAlgorithm.Sha256],
            digest.Algorithms.Skip(2));
        Assert.Equal([1, 1], digest.CertificateRecordCounts.Skip(2));
        Assert.Single(PeImageCertificateTable.Read(fixture.StagedPath).Records);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task ProductionCmsWithInMemoryKeysCreatesVerifiableNestedDualEnvelope()
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        using var primaryCertificate = new InMemoryRsaCertificateFixture(
            "CodeSigner In-Memory Primary",
            [0x01]);
        using var secondaryCertificate = new InMemoryRsaCertificateFixture(
            "CodeSigner In-Memory Secondary",
            [0x02]);
        ProductionNativeSigningPlan plan = CreateDualPlan(
            ".exe",
            primaryCertificate.Thumbprint,
            secondaryCertificate.Thumbprint);
        var inspector = new AuthenticodeCmsRecordInspector();
        var timestampClient = new DeterministicTimestampClient();
        var cmsSigner = new WindowsPeAuthenticodeCmsSigner(
            new InMemoryPrivateKeyAcquirer(primaryCertificate, secondaryCertificate),
            new CryptMsgAuthenticodeCmsEncoder(inspector),
            timestampClient,
            inspector);
        var finalWindowsGate = new IndependentInMemoryCmsVerifier(
            inspector,
            new AuthenticodePeImageDigestProvider(),
            primaryCertificate.CertificateDer,
            secondaryCertificate.CertificateDer);
        var verifier = new PeAuthenticodeStructuralVerifier(
            new AuthenticodePeImageDigestProvider(),
            inspector,
            finalWindowsGate);
        var engine = new PeAuthenticodeSigningEngine(
            new AuthenticodePeImageDigestProvider(),
            cmsSigner,
            verifier);

        NativeSigningResult result = await engine.ExecuteAsync(
            fixture.StagedPath,
            plan,
            CancellationToken.None);

        Assert.True(
            result.Succeeded,
            $"Reason={result.ReasonCode}; HResult=0x{result.HResult:X8}; " +
            $"verifierFailure={finalWindowsGate.Failure}");
        Assert.Equal(1, finalWindowsGate.CallCount);
        Assert.True(finalWindowsGate.ContentDigestsValid);
        Assert.True(finalWindowsGate.CmsSignaturesValid);
        Assert.Equal(
            plan.Legs.Select(leg => leg.TimestampUri),
            timestampClient.RequestedUris);
        PeImageCertificateTable table = PeImageCertificateTable.Read(fixture.StagedPath);
        PeAuthenticodeCmsInspection primary = inspector.Inspect(Assert.Single(table.Records).Content);
        PeAuthenticodeCmsInspection secondary = Assert.Single(primary.NestedSignatures);
        PeAuthenticodeCmsInspection[] logicalSignatures = [primary, secondary];
        Assert.Equal(
            [AuthenticodeOids.Sha1, AuthenticodeOids.Sha256],
            logicalSignatures.Select(signature => signature.DigestAlgorithmOid));
        Assert.Equal(
            plan.Legs.Select(leg => leg.Certificate.Thumbprint),
            logicalSignatures.Select(signature => Assert.Single(signature.CertificateThumbprints)));
        Assert.All(logicalSignatures, signature =>
        {
            Assert.Equal(1, signature.Rfc3161TimestampCount);
            Assert.Equal(AuthenticodeOids.Sha256, signature.TimestampDigestAlgorithmOid);
            Assert.True(signature.TimestampMessageImprintMatchesSignature);
        });
        AssertNoWorkFile(fixture.AttemptDirectory);

        string? structuralDumpPath = Environment.GetEnvironmentVariable(
            "CODESIGNER_TASK3_DETERMINISTIC_DUMP");
        if (!string.IsNullOrWhiteSpace(structuralDumpPath))
        {
            var structuralDump = new
            {
                verifier = typeof(PeAuthenticodeStructuralVerifier).FullName,
                result = new
                {
                    result.Succeeded,
                    reasonCode = result.ReasonCode.ToString(),
                    hResult = $"0x{result.HResult:X8}"
                },
                topLevelWinCertificateCount = table.Records.Count,
                logicalSignatureCount = logicalSignatures.Length,
                logicalDigestOrder = logicalSignatures.Select(signature => signature.DigestAlgorithmOid),
                logicalCertificateOrder = logicalSignatures.Select(
                    signature => Assert.Single(signature.CertificateThumbprints)),
                rfc3161TimestampCounts = logicalSignatures.Select(
                    signature => signature.Rfc3161TimestampCount),
                finalWindowsGateCallCount = finalWindowsGate.CallCount,
                repositoryFixtureModified = false,
                disposableStageModified = true,
                certificateStoreAccess = false,
                timestampNetworkAccess = false,
                signingSurface = "ephemeral in-memory keys only"
            };
            File.WriteAllText(
                structuralDumpPath,
                JsonSerializer.Serialize(structuralDump, IndentedJson));
        }

        string? receiptPath = Environment.GetEnvironmentVariable("CODESIGNER_TASK2_REPAIR_QA_PATH");
        if (!string.IsNullOrWhiteSpace(receiptPath))
        {
            var receipt = new
            {
                test = nameof(ProductionCmsWithInMemoryKeysCreatesVerifiableNestedDualEnvelope),
                surface = "production Authenticode CMS encoder with ephemeral in-memory RSA keys",
                topLevelWinCertificateCount = table.Records.Count,
                nestedSignatureCount = primary.NestedSignatures.Count,
                logicalDigestOrder = logicalSignatures.Select(signature => signature.DigestAlgorithmOid),
                plannedCertificateOrderMatched = true,
                plannedTimestampOrderMatched = true,
                contentDigestsValid = finalWindowsGate.ContentDigestsValid,
                cmsSignaturesValid = finalWindowsGate.CmsSignaturesValid,
                privateKeys = "ephemeral in-memory RSACng; not exported or written",
                certificateStoreAccess = false,
                signToolAccess = false,
                providerUiAccess = false,
                timestampNetworkAccess = false
            };
            File.WriteAllText(receiptPath, JsonSerializer.Serialize(receipt, IndentedJson));
        }
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task ProductionCmsSingleSignatureIsNotRejectedByWindowsAsBadDigest()
    {
        const int TrustEBadDigest = unchecked((int)0x80096010);
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        using var certificate = new InMemoryRsaCertificateFixture(
            "CodeSigner In-Memory BAD_DIGEST Regression",
            [0x03]);
        ProductionNativeSigningPlan plan = CreateSinglePlan(".exe", certificate.Thumbprint);
        var inspector = new AuthenticodeCmsRecordInspector();
        var signer = new WindowsPeAuthenticodeCmsSigner(
            new InMemoryPrivateKeyAcquirer(certificate),
            new CryptMsgAuthenticodeCmsEncoder(inspector),
            new DeterministicTimestampClient(),
            inspector);
        var digestProvider = new AuthenticodePeImageDigestProvider();
        byte[] imageDigest = digestProvider.ComputeDigest(
            fixture.StagedPath,
            NativeDigestAlgorithm.Sha256);
        PeCmsCreationResult cms = await signer.CreateAsync(
            plan.Legs[0],
            imageDigest,
            providerWindowHandle: nint.Zero,
            CancellationToken.None);

        Assert.True(cms.Result.Succeeded);
        PeImageCertificateTable.Append(fixture.StagedPath, Assert.IsType<byte[]>(cms.EncodedCms));
        PeImageCertificateTable table = PeImageCertificateTable.Read(fixture.StagedPath);
        PeAuthenticodeCmsInspection current = inspector.Inspect(Assert.Single(table.Records).Content);
        using X509Certificate2 publicCertificate =
            X509CertificateLoader.LoadCertificate(certificate.CertificateDer);
        using RSA publicKey = Assert.IsAssignableFrom<RSA>(publicCertificate.GetRSAPublicKey());
        bool cmsSignatureValid = publicKey.VerifyData(
            current.SignatureInput,
            current.SignatureValue,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        AuthenticodeSignatureCountInspection trust =
            new AuthenticodeSignatureInspector().GetSignatureCount(fixture.StagedPath);

        Assert.True(cmsSignatureValid);
        Assert.Equal(1, current.Rfc3161TimestampCount);
        Assert.True(current.TimestampMessageImprintMatchesSignature);
        Assert.Equal(table.FileLength, checked((long)table.TableOffset + table.TableSize));
        Assert.True(
            trust.TrustStatus != TrustEBadDigest,
            $"Windows rejected the production Authenticode envelope with TRUST_E_BAD_DIGEST " +
            $"(0x{trust.TrustStatus:X8}).");

        string? receiptPath = Environment.GetEnvironmentVariable("CODESIGNER_TASK6_REPAIR2_QA_PATH");
        if (!string.IsNullOrWhiteSpace(receiptPath))
        {
            var receipt = new
            {
                test = nameof(ProductionCmsSingleSignatureIsNotRejectedByWindowsAsBadDigest),
                windowsTrustStatus = $"0x{trust.TrustStatus:X8}",
                trustEBadDigest = false,
                cmsSignatureValid,
                current.Rfc3161TimestampCount,
                current.TimestampMessageImprintMatchesSignature,
                table.TableOffset,
                table.TableSize,
                table.FileLength,
                certificateStoreAccess = false,
                timestampNetworkAccess = false,
                signToolExecutions = 0,
                liveSigningExecutions = 0
            };
            File.WriteAllText(receiptPath, JsonSerializer.Serialize(receipt, IndentedJson));
        }
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task StructuralVerifierRejectsTwoTopLevelRecordsBeforeWindowsTrust()
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        ProductionNativeSigningPlan plan = CreateDualPlan(".exe");
        var digestProvider = new AuthenticodePeImageDigestProvider();
        byte[] primaryDigest = digestProvider.ComputeDigest(
            fixture.StagedPath,
            NativeDigestAlgorithm.Sha1);
        byte[] secondaryDigest = digestProvider.ComputeDigest(
            fixture.StagedPath,
            NativeDigestAlgorithm.Sha256);
        PeImageCertificateTable.Append(
            fixture.StagedPath,
            SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha1,
                primaryDigest,
                includeTimestamp: true,
                certificateDer: PrimaryCertificateDer));
        PeImageCertificateTable.Append(
            fixture.StagedPath,
            SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha256,
                secondaryDigest,
                includeTimestamp: true,
                certificateDer: SecondaryCertificateDer));
        byte[] beforeVerification = File.ReadAllBytes(fixture.StagedPath);
        var finalWindowsGate = new PlanBoundWindowsGate(plan);
        var verifier = new PeAuthenticodeStructuralVerifier(
            digestProvider,
            new AuthenticodeCmsRecordInspector(),
            finalWindowsGate);

        NativeSigningResult result = await verifier.VerifyAsync(
            fixture.StagedPath,
            plan,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.VerifierDisagreement, result.ReasonCode);
        Assert.Equal(0, finalWindowsGate.CallCount);
        Assert.Equal(beforeVerification, File.ReadAllBytes(fixture.StagedPath));
        Assert.False(File.Exists(fixture.DestinationPath));
        WriteMalformedReceipt(
            "two-top-level-records",
            result,
            finalWindowsGate.CallCount,
            beforeVerification,
            File.ReadAllBytes(fixture.StagedPath),
            fixture.DestinationPath);
    }

    [Theory]
    [InlineData("missing-nested")]
    [InlineData("malformed-nested")]
    [InlineData("wrong-digest-order")]
    [InlineData("certificate-mismatch")]
    [InlineData("timestamp-mismatch")]
    [InlineData("malformed-top-level")]
    [InlineData("unrelated-extra-record")]
    [Trait("Category", "Authenticode")]
    public async Task StructuralVerifierRejectsMalformedLogicalLayoutsWithoutWindowsTrust(
        string caseName)
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        ProductionNativeSigningPlan plan = CreateDualPlan(".exe");
        var digestProvider = new AuthenticodePeImageDigestProvider();
        byte[] primaryDigest = digestProvider.ComputeDigest(
            fixture.StagedPath,
            NativeDigestAlgorithm.Sha1);
        byte[] secondaryDigest = digestProvider.ComputeDigest(
            fixture.StagedPath,
            NativeDigestAlgorithm.Sha256);
        byte[] validSecondary = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha256,
            secondaryDigest,
            includeTimestamp: true,
            certificateDer: SecondaryCertificateDer);
        byte[] validPrimary = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha1,
            primaryDigest,
            includeTimestamp: true,
            nestedCms: validSecondary,
            nestedAttributeCount: 1,
            certificateDer: PrimaryCertificateDer);
        byte[] topLevel = caseName switch
        {
            "missing-nested" => SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha1,
                primaryDigest,
                includeTimestamp: true,
                certificateDer: PrimaryCertificateDer),
            "malformed-nested" => SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha1,
                primaryDigest,
                includeTimestamp: true,
                nestedAttributeCount: 1,
                malformedNested: true,
                certificateDer: PrimaryCertificateDer),
            "wrong-digest-order" => SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha256,
                secondaryDigest,
                includeTimestamp: true,
                nestedCms: SyntheticAuthenticodeCms.Create(
                    NativeDigestAlgorithm.Sha1,
                    primaryDigest,
                    includeTimestamp: true,
                    certificateDer: PrimaryCertificateDer),
                nestedAttributeCount: 1,
                certificateDer: SecondaryCertificateDer),
            "certificate-mismatch" => SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha1,
                primaryDigest,
                includeTimestamp: true,
                nestedCms: validSecondary,
                nestedAttributeCount: 1,
                certificateDer: SecondaryCertificateDer),
            "timestamp-mismatch" => SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha1,
                primaryDigest,
                includeTimestamp: false,
                nestedCms: validSecondary,
                nestedAttributeCount: 1,
                certificateDer: PrimaryCertificateDer),
            "malformed-top-level" => [0x30, 0x01, 0x00],
            "unrelated-extra-record" => validPrimary,
            _ => throw new InvalidOperationException("Unknown structural test case.")
        };
        PeImageCertificateTable.Append(fixture.StagedPath, topLevel);
        if (caseName == "unrelated-extra-record")
        {
            PeImageCertificateTable.Append(fixture.StagedPath, validSecondary);
        }

        byte[] beforeVerification = File.ReadAllBytes(fixture.StagedPath);
        var finalWindowsGate = new PlanBoundWindowsGate(plan);
        var verifier = new PeAuthenticodeStructuralVerifier(
            digestProvider,
            new AuthenticodeCmsRecordInspector(),
            finalWindowsGate);

        NativeSigningResult result = await verifier.VerifyAsync(
            fixture.StagedPath,
            plan,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.VerifierDisagreement, result.ReasonCode);
        Assert.True(result.HResult < 0);
        Assert.Equal(0, finalWindowsGate.CallCount);
        Assert.Equal(beforeVerification, File.ReadAllBytes(fixture.StagedPath));
        Assert.False(File.Exists(fixture.DestinationPath));
        WriteMalformedReceipt(
            caseName,
            result,
            finalWindowsGate.CallCount,
            beforeVerification,
            File.ReadAllBytes(fixture.StagedPath),
            fixture.DestinationPath);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public void RetainedSignToolDualSignedSampleHasOneRecordAndWindowsLogicalSha1Sha256Order()
    {
        string path = ReferencePath("pc端签名软件.exe");
        PeImageCertificateTable table = PeImageCertificateTable.Read(path);
        var inspector = new AuthenticodeSignatureInspector();
        AuthenticodeSignatureCountInspection count = inspector.GetSignatureCount(path);
        AuthenticodeSignatureInspection primary = inspector.InspectSignature(path, 0);
        AuthenticodeSignatureInspection secondary = inspector.InspectSignature(path, 1);

        Assert.Single(table.Records);
        Assert.Equal(0, count.TrustStatus);
        Assert.Equal(1U, count.SecondarySignatureCount);
        Assert.Equal(0U, primary.VerifiedSignatureIndex);
        Assert.Equal(AuthenticodeOids.Sha1, primary.FileDigestAlgorithmOid);
        Assert.Equal(1U, secondary.VerifiedSignatureIndex);
        Assert.Equal(AuthenticodeOids.Sha256, secondary.FileDigestAlgorithmOid);

        string? dumpPath = Environment.GetEnvironmentVariable("CODESIGNER_TASK3_KNOWN_GOOD_DUMP");
        if (!string.IsNullOrWhiteSpace(dumpPath))
        {
            var dump = new
            {
                samplePath = path,
                sampleSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                structuralLayout = new
                {
                    topLevelWinCertificateCount = table.Records.Count,
                    logicalSignatureCount = checked((int)count.SecondarySignatureCount + 1),
                    logicalSignatures = new[]
                    {
                        new { index = primary.VerifiedSignatureIndex, digestOid = primary.FileDigestAlgorithmOid },
                        new { index = secondary.VerifiedSignatureIndex, digestOid = secondary.FileDigestAlgorithmOid }
                    }
                },
                productionReaders = new[]
                {
                    typeof(PeImageCertificateTable).FullName,
                    typeof(AuthenticodeSignatureInspector).FullName
                },
                sourceModified = false,
                signingInvoked = false
            };
            File.WriteAllText(dumpPath, JsonSerializer.Serialize(dump, IndentedJson));
        }
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task DisposableDualEnvelopeCanBeObservedAndCleanedForManualQa()
    {
        Directory.CreateDirectory(root);
        string attempt = TransactionalStaging.CreateAttemptDirectory(root);
        string stagedPath = Path.Combine(attempt, "manual-qa.exe");
        int topLevelRecordCount = -1;
        string[] logicalSignerDigestOrder = [];
        bool attemptDirectoryDeleted;
        try
        {
            File.WriteAllBytes(stagedPath, FixtureBytes("valid-unsigned.exe"));
            var signer = new SyntheticCmsSigner();
            var verifier = new RecordingVerifier(NativeSigningResult.Success());
            NativeSigningResult result = await CreateEngine(signer, verifier).ExecuteAsync(
                stagedPath,
                CreateDualPlan(".exe"),
                CancellationToken.None);
            Assert.True(result.Succeeded);

            PeImageCertificateTable table = PeImageCertificateTable.Read(stagedPath);
            topLevelRecordCount = table.Records.Count;
            PeAuthenticodeCmsInspection primary = new AuthenticodeCmsRecordInspector().Inspect(
                Assert.Single(table.Records).Content);
            logicalSignerDigestOrder =
            [
                primary.DigestAlgorithmOid,
                .. primary.NestedSignatures.Select(signature => signature.DigestAlgorithmOid)
            ];
            Assert.Equal(
                [AuthenticodeOids.Sha1, AuthenticodeOids.Sha256],
                logicalSignerDigestOrder);
        }
        finally
        {
            TransactionalStaging.DeleteAttempt(attempt);
            attemptDirectoryDeleted = !Directory.Exists(attempt);
        }

        Assert.True(attemptDirectoryDeleted);
        string? receiptPath = Environment.GetEnvironmentVariable("CODESIGNER_TASK2_MANUAL_QA_PATH");
        if (!string.IsNullOrWhiteSpace(receiptPath))
        {
            var receipt = new
            {
                surface = "disposable deterministic PE/CMS fixture through PeAuthenticodeSigningEngine",
                topLevelRecordCount,
                logicalSignerDigestOrder,
                productReaders = new[]
                {
                    nameof(PeImageCertificateTable),
                    nameof(AuthenticodeCmsRecordInspector)
                },
                cleanup = new
                {
                    fixtureDeleted = !File.Exists(stagedPath),
                    attemptDirectoryDeleted
                },
                storeAccess = false,
                providerAccess = false,
                timestampNetworkAccess = false
            };
            File.WriteAllText(
                receiptPath,
                JsonSerializer.Serialize(receipt, IndentedJson));
        }
    }

    [Theory]
    [InlineData("malformed-nested")]
    [InlineData("duplicate-secondary")]
    [Trait("Category", "Authenticode")]
    public void CmsReaderRejectsMalformedOrDuplicateNestedSecondary(string caseName)
    {
        byte[] digest = new byte[20];
        byte[] secondary = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha256,
            new byte[32],
            includeTimestamp: true);
        byte[] primary = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha1,
            digest,
            includeTimestamp: true,
            nestedCms: secondary,
            nestedAttributeCount: caseName == "duplicate-secondary" ? 2 : 1,
            malformedNested: caseName == "malformed-nested");

        Assert.ThrowsAny<InvalidDataException>(
            () => new AuthenticodeCmsRecordInspector().Inspect(primary));
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public void CmsReaderResolvesSubjectKeyIdentifierToExactEmbeddedSigner()
    {
        byte[] cms = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha256,
            new byte[32],
            includeTimestamp: true,
            certificateDer: PrimaryCertificateDer,
            useSubjectKeyIdentifier: true);

        PeAuthenticodeCmsInspection inspection = new AuthenticodeCmsRecordInspector().Inspect(cms);

        Assert.Equal(PrimaryThumbprint, inspection.SignerCertificateThumbprint);
        Assert.Equal(PrimaryThumbprint, Assert.Single(inspection.CertificateThumbprints));
    }

    [Theory]
    [InlineData("wrong-order")]
    [InlineData("digest-mismatch")]
    [InlineData("malformed-nested")]
    [InlineData("duplicate-secondary")]
    [Trait("Category", "Authenticode")]
    public async Task InvalidLogicalLegEncodingFailsClosedWithoutReplacingStage(string caseName)
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        byte[] before = File.ReadAllBytes(fixture.StagedPath);
        var signer = new SyntheticCmsSigner(
            emittedAlgorithms: caseName == "wrong-order"
                ? [NativeDigestAlgorithm.Sha256, NativeDigestAlgorithm.Sha1]
                : null,
            mismatchedDigestAt: caseName == "digest-mismatch" ? 1 : null,
            preNestedAt: caseName is "malformed-nested" or "duplicate-secondary" ? 0 : null,
            preNestedAttributeCount: caseName == "duplicate-secondary" ? 2 : 1,
            malformedPreNested: caseName == "malformed-nested");
        var finalTrust = new RecordingVerifier(NativeSigningResult.Success());

        NativeSigningResult result = await CreateEngine(signer, finalTrust).ExecuteAsync(
            fixture.StagedPath,
            CreateDualPlan(".exe"),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.InvalidInput, result.ReasonCode);
        Assert.Equal(0, finalTrust.CallCount);
        Assert.Equal(before, File.ReadAllBytes(fixture.StagedPath));
        Assert.Empty(PeImageCertificateTable.Read(fixture.StagedPath).Records);
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task InterruptedDualFixtureGenerationRemovesWorkAndPreservesUnsignedStage()
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        byte[] before = File.ReadAllBytes(fixture.StagedPath);
        var signer = new SyntheticCmsSigner();
        var finalTrust = new RecordingVerifier(NativeSigningResult.Success());
        using var cancellation = new CancellationTokenSource();
        using Process current = Process.GetCurrentProcess();

        NativeSigningResult result = await CreateEngine(signer, finalTrust).ExecuteAsync(
            fixture.StagedPath,
            CreateDualPlan(".exe"),
            current.Id,
            current.StartTime.ToUniversalTime(),
            providerWindowHandle: nint.Zero,
            (legIndex, _) =>
            {
                if (legIndex == 1)
                {
                    cancellation.Cancel();
                }

                return ValueTask.CompletedTask;
            },
            cancellation.Token);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.Cancelled, result.ReasonCode);
        Assert.Equal(1, signer.CallCount);
        Assert.Equal(0, finalTrust.CallCount);
        Assert.Equal(before, File.ReadAllBytes(fixture.StagedPath));
        Assert.Empty(PeImageCertificateTable.Read(fixture.StagedPath).Records);
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Theory]
    [InlineData("dos-header")]
    [InlineData("optional-header")]
    [InlineData("certificate-table")]
    [InlineData("truncated")]
    [Trait("Category", "Authenticode")]
    public async Task MalformedPeStructuresFailBeforeCmsAndLeaveStageUnchanged(string caseName)
    {
        byte[] bytes = caseName switch
        {
            "dos-header" => FixtureBytes("malformed.exe"),
            "optional-header" => CorruptOptionalHeader(FixtureBytes("valid-unsigned.exe")),
            "certificate-table" => CorruptCertificateTable(FixtureBytes("valid-unsigned.exe")),
            "truncated" => "MZ"u8.ToArray(),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName))
        };
        Attempt fixture = CreateAttempt(".exe", bytes);
        byte[] before = File.ReadAllBytes(fixture.StagedPath);
        var cmsSigner = new SyntheticCmsSigner();
        var finalTrust = new RecordingVerifier(NativeSigningResult.Success());

        NativeSigningResult result = await CreateEngine(cmsSigner, finalTrust).ExecuteAsync(
            fixture.StagedPath,
            CreateSinglePlan(".exe"),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.InvalidInput, result.ReasonCode);
        Assert.Equal(0, cmsSigner.CallCount);
        Assert.Equal(0, finalTrust.CallCount);
        Assert.Equal(before, File.ReadAllBytes(fixture.StagedPath));
        Assert.False(File.Exists(fixture.DestinationPath));
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Theory]
    [InlineData("malformed-cms")]
    [InlineData("malformed-timestamp")]
    [InlineData("timestamp-failure")]
    [InlineData("secondary-failure")]
    [InlineData("verifier-failure")]
    [Trait("Category", "Authenticode")]
    public async Task SigningAndVerificationFailuresNeverReplaceStageOrPublish(string caseName)
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        byte[] before = File.ReadAllBytes(fixture.StagedPath);
        var cmsSigner = caseName switch
        {
            "malformed-cms" => new SyntheticCmsSigner(malformedCmsAt: 0),
            "malformed-timestamp" => new SyntheticCmsSigner(invalidTimestampAt: 0),
            "timestamp-failure" => new SyntheticCmsSigner(
                failAt: 0,
                failureReason: NativeSigningReasonCode.TimestampUnavailable,
                failureHResult: unchecked((int)0x80072EE2)),
            "secondary-failure" => new SyntheticCmsSigner(
                failAt: 1,
                failureReason: NativeSigningReasonCode.NativeSigningFailed,
                failureHResult: unchecked((int)0x80004002)),
            "verifier-failure" => new SyntheticCmsSigner(),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName))
        };
        NativeSigningResult trustResult = caseName == "verifier-failure"
            ? NativeSigningResult.Failure(
                NativeSigningReasonCode.VerifierDisagreement,
                unchecked((int)0x800B0100))
            : NativeSigningResult.Success();
        var finalTrust = new RecordingVerifier(trustResult);
        ProductionNativeSigningPlan plan = caseName == "secondary-failure"
            ? CreateDualPlan(".exe")
            : CreateSinglePlan(".exe");

        NativeSigningResult result = await CreateEngine(cmsSigner, finalTrust).ExecuteAsync(
            fixture.StagedPath,
            plan,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(before, File.ReadAllBytes(fixture.StagedPath));
        Assert.Empty(PeImageCertificateTable.Read(fixture.StagedPath).Records);
        Assert.False(File.Exists(fixture.DestinationPath));
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public async Task ExistingCertificateTableAndUnownedPathAreRejectedWithoutMutation()
    {
        Attempt fixture = CreateAttempt(".exe", FixtureBytes("valid-unsigned.exe"));
        var digest = new AuthenticodePeImageDigestProvider();
        byte[] imageDigest = digest.ComputeDigest(fixture.StagedPath, NativeDigestAlgorithm.Sha256);
        PeImageCertificateTable.Append(
            fixture.StagedPath,
            SyntheticAuthenticodeCms.Create(
                NativeDigestAlgorithm.Sha256,
                imageDigest,
                includeTimestamp: true));
        byte[] signedBefore = File.ReadAllBytes(fixture.StagedPath);
        string outside = Path.Combine(root, "outside.exe");
        File.Copy(FixturePath("valid-unsigned.exe"), outside);
        byte[] outsideBefore = File.ReadAllBytes(outside);
        var signer = new SyntheticCmsSigner();
        PeAuthenticodeSigningEngine engine = CreateEngine(
            signer,
            new RecordingVerifier(NativeSigningResult.Success()));

        NativeSigningResult existing = await engine.ExecuteAsync(
            fixture.StagedPath,
            CreateSinglePlan(".exe"),
            CancellationToken.None);
        NativeSigningResult unowned = await engine.ExecuteAsync(
            outside,
            CreateSinglePlan(".exe"),
            CancellationToken.None);

        Assert.Equal(NativeSigningReasonCode.InvalidInput, existing.ReasonCode);
        Assert.Equal(NativeSigningReasonCode.InvalidInput, unowned.ReasonCode);
        Assert.Equal(signedBefore, File.ReadAllBytes(fixture.StagedPath));
        Assert.Equal(outsideBefore, File.ReadAllBytes(outside));
        Assert.Equal(0, signer.CallCount);
        AssertNoWorkFile(fixture.AttemptDirectory);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public void PublicEngineSourceHasNoSdkToolPrivateProviderOrLegacySignerDependency()
    {
        string signingDirectory = Path.Combine(RepositoryRoot(), "src", "CodeSigner.Windows", "Signing");
        string[] engineFiles =
        [
            "PeAuthenticodeCms.cs",
            "PeAuthenticodeInterop.cs",
            "PeAuthenticodeSigningEngine.cs",
            "PeCertificatePrivateKey.cs",
            "PeImageCertificateTable.cs"
        ];
        string source = string.Join(
            Environment.NewLine,
            engineFiles.Select(file => File.ReadAllText(Path.Combine(signingDirectory, file))));

        Assert.DoesNotContain("SIGNER_PROVIDER_INFO", source, StringComparison.Ordinal);
        Assert.DoesNotContain("SignerSignEx3", source, StringComparison.Ordinal);
        Assert.DoesNotContain("signtool.exe", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Windows Kits", source, StringComparison.OrdinalIgnoreCase);
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

    private static PeAuthenticodeSigningEngine CreateEngine(
        IPeAuthenticodeCmsSigner cmsSigner,
        IProductionSignedFileVerifier finalTrust)
    {
        var digest = new AuthenticodePeImageDigestProvider();
        return new PeAuthenticodeSigningEngine(
            digest,
            cmsSigner,
            finalTrust);
    }

    private Attempt CreateAttempt(string extension, byte[] bytes)
    {
        Directory.CreateDirectory(root);
        string attempt = TransactionalStaging.CreateAttemptDirectory(root);
        attempts.Add(attempt);
        string staged = Path.Combine(attempt, "payload" + extension);
        File.WriteAllBytes(staged, bytes);
        return new Attempt(
            attempt,
            staged,
            Path.Combine(root, "published", "payload" + extension));
    }

    private static ProductionNativeSigningPlan CreateSinglePlan(
        string extension,
        string? thumbprint = null)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                thumbprint ?? PrimaryThumbprint).Value);
        CoreSigningPlan plan = Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateSingle(certificate, extension).Value);
        return ProductionNativeSigningPlan.FromCore(plan);
    }

    private static ProductionNativeSigningPlan CreateDualPlan(
        string extension,
        string? primaryThumbprint = null,
        string? secondaryThumbprint = null)
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                primaryThumbprint ?? PrimaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.LocalMachine,
                "My",
                secondaryThumbprint ?? SecondaryThumbprint).Value);
        CoreSigningPlan plan = Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateDual(primary, secondary, extension).Value);
        return ProductionNativeSigningPlan.FromCore(plan);
    }

    private static byte[] CorruptOptionalHeader(byte[] source)
    {
        byte[] bytes = source.ToArray();
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 24), 0xffff);
        return bytes;
    }

    private static byte[] CorruptCertificateTable(byte[] source)
    {
        byte[] bytes = source.ToArray();
        int directoryOffset = CertificateDirectoryFieldOffset(bytes);
        int tableOffset = bytes.Length - 8;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(directoryOffset), checked((uint)tableOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(directoryOffset + 4), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(tableOffset), 4);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(tableOffset + 4), 0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(tableOffset + 6), 0x0002);
        return bytes;
    }

    private static int CertificateDirectoryFieldOffset(byte[] bytes)
    {
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c));
        int optionalOffset = peOffset + 24;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optionalOffset));
        int directoriesOffset = magic == 0x10b ? 96 : 112;
        return optionalOffset + directoriesOffset + (4 * 8);
    }

    private static void AssertNoWorkFile(string attemptDirectory) =>
        Assert.DoesNotContain(
            Directory.GetFiles(attemptDirectory),
            path => Path.GetFileName(path).Contains(".pe-work-", StringComparison.Ordinal));

    private static byte[] FixtureBytes(string fileName) => File.ReadAllBytes(FixturePath(fileName));

    private static string FixturePath(string fileName) =>
        Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fileName);

    private static string ReferencePath(string fileName) =>
        Path.Combine(RepositoryRoot(), "references", "vendor", "binaries", fileName);

    private static void WriteMalformedReceipt(
        string caseName,
        NativeSigningResult result,
        int finalWindowsGateCallCount,
        byte[] beforeVerification,
        byte[] afterVerification,
        string destinationPath)
    {
        string? receiptDirectory = Environment.GetEnvironmentVariable(
            "CODESIGNER_TASK3_MALFORMED_RECEIPT_DIR");
        if (string.IsNullOrWhiteSpace(receiptDirectory))
        {
            return;
        }

        Directory.CreateDirectory(receiptDirectory);
        var receipt = new
        {
            caseName,
            result.Succeeded,
            reasonCode = result.ReasonCode.ToString(),
            hResult = $"0x{result.HResult:X8}",
            finalWindowsGateCallCount,
            beforeSha256 = Convert.ToHexString(SHA256.HashData(beforeVerification)),
            afterSha256 = Convert.ToHexString(SHA256.HashData(afterVerification)),
            stageByteIdentical = beforeVerification.AsSpan().SequenceEqual(afterVerification),
            publicationExists = File.Exists(destinationPath)
        };
        File.WriteAllText(
            Path.Combine(receiptDirectory, caseName + ".json"),
            JsonSerializer.Serialize(receipt, IndentedJson));
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

    internal static byte[] CreateSyntheticCertificateDer(string name)
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN=CodeSigner Synthetic {name}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
            request.PublicKey,
            critical: false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        return certificate.RawData;
    }

    private sealed record Attempt(string AttemptDirectory, string StagedPath, string DestinationPath);

    private sealed class RecordingDigestProvider : IPeImageDigestProvider
    {
        private readonly AuthenticodePeImageDigestProvider inner = new();

        public List<NativeDigestAlgorithm> Algorithms { get; } = [];

        public List<int> CertificateRecordCounts { get; } = [];

        public byte[] ComputeDigest(string path, NativeDigestAlgorithm algorithm)
        {
            Algorithms.Add(algorithm);
            CertificateRecordCounts.Add(PeImageCertificateTable.Read(path).Records.Count);
            return inner.ComputeDigest(path, algorithm);
        }
    }

    private sealed class SyntheticCmsSigner(
        int? failAt = null,
        NativeSigningReasonCode failureReason = NativeSigningReasonCode.NativeSigningFailed,
        int failureHResult = unchecked((int)0x80004005),
        int? malformedCmsAt = null,
        int? invalidTimestampAt = null,
        IReadOnlyList<NativeDigestAlgorithm>? emittedAlgorithms = null,
        int? mismatchedDigestAt = null,
        int? preNestedAt = null,
        int preNestedAttributeCount = 1,
        bool malformedPreNested = false) : IPeAuthenticodeCmsSigner
    {
        public int CallCount { get; private set; }

        public List<string> CertificateThumbprints { get; } = [];

        public Task<PeCmsCreationResult> CreateAsync(
            NativeSignatureLeg leg,
            ReadOnlyMemory<byte> imageDigest,
            nint providerWindowHandle,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int index = CallCount++;
            CertificateThumbprints.Add(leg.Certificate.Thumbprint);
            if (failAt == index)
            {
                return Task.FromResult(PeCmsCreationResult.Failure(failureReason, failureHResult));
            }

            byte[] cms;
            if (malformedCmsAt == index)
            {
                cms = [0x30, 0x01, 0x00];
            }
            else
            {
                byte[] encodedDigest = imageDigest.ToArray();
                if (mismatchedDigestAt == index)
                {
                    encodedDigest[0] ^= 0xff;
                }

                NativeDigestAlgorithm encodedAlgorithm = emittedAlgorithms is not null
                    ? emittedAlgorithms[index]
                    : leg.FileDigest;
                byte[]? preNestedCms = preNestedAt == index
                    ? SyntheticAuthenticodeCms.Create(
                        NativeDigestAlgorithm.Sha256,
                        new byte[32],
                        includeTimestamp: true,
                        certificateDer: SecondaryCertificateDer)
                    : null;
                cms = SyntheticAuthenticodeCms.Create(
                    encodedAlgorithm,
                    encodedDigest,
                    includeTimestamp: true,
                    invalidTimestampDigest: invalidTimestampAt == index,
                    nestedCms: preNestedCms,
                    nestedAttributeCount: preNestedAt == index ? preNestedAttributeCount : 0,
                    malformedNested: preNestedAt == index && malformedPreNested,
                    certificateDer: CertificateDer(leg.Certificate.Thumbprint));
            }

            return Task.FromResult(PeCmsCreationResult.Success(cms));
        }

        private static byte[] CertificateDer(string thumbprint) =>
            string.Equals(thumbprint, PrimaryThumbprint, StringComparison.Ordinal)
                ? PrimaryCertificateDer
                : string.Equals(thumbprint, SecondaryThumbprint, StringComparison.Ordinal)
                    ? SecondaryCertificateDer
                    : throw new InvalidOperationException("The synthetic signer received an unknown certificate.");
    }

    private sealed class RecordingVerifier(NativeSigningResult result) : IProductionSignedFileVerifier
    {
        public int CallCount { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(result);
        }
    }

    private sealed class PlanBoundWindowsGate(ProductionNativeSigningPlan expectedPlan)
        : IProductionSignedFileVerifier
    {
        public int CallCount { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            NativeSigningResult result = ReferenceEquals(plan, expectedPlan) && File.Exists(stagedPath)
                ? NativeSigningResult.Success()
                : NativeSigningResult.Failure(
                    NativeSigningReasonCode.VerifierDisagreement,
                    unchecked((int)0x800B0003));
            return Task.FromResult(result);
        }
    }

    private sealed class DeterministicTimestampClient : IPeRfc3161TimestampClient
    {
        public List<Uri> RequestedUris { get; } = [];

        public Task<PeTimestampResult> GetTimestampAsync(
            Uri timestampUri,
            ReadOnlyMemory<byte> signatureValue,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestedUris.Add(timestampUri);
            return Task.FromResult(PeTimestampResult.Success(
                SyntheticAuthenticodeCms.CreateTimestampToken(signatureValue.Span, invalidDigest: false)));
        }
    }

    private sealed class InMemoryPrivateKeyAcquirer(
        params InMemoryRsaCertificateFixture[] certificates) : IPeCertificatePrivateKeyAcquirer
    {
        public PePrivateKeyAcquisition Acquire(
            CertificateReference reference,
            nint providerWindowHandle)
        {
            Assert.Equal(nint.Zero, providerWindowHandle);
            InMemoryRsaCertificateFixture? certificate = certificates.SingleOrDefault(
                item => string.Equals(item.Thumbprint, reference.Thumbprint, StringComparison.Ordinal));
            return certificate is null
                ? PePrivateKeyAcquisition.Failure(
                    NativeSigningReasonCode.CertificateNotFound,
                    unchecked((int)0x80092004))
                : PePrivateKeyAcquisition.Success(certificate.CreateLease());
        }
    }

    private sealed class InMemoryRsaCertificateFixture : IDisposable
    {
        private static readonly DateTimeOffset NotBefore =
            new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        private static readonly DateTimeOffset NotAfter =
            new(2036, 1, 1, 0, 0, 0, TimeSpan.Zero);
        private readonly RSACng privateKey = new(2048);
        private readonly X509Certificate2 certificate;

        internal InMemoryRsaCertificateFixture(string commonName, byte[] serialNumber)
        {
            CertificateRequest request = new(
                new X500DistinguishedName($"CN={commonName}"),
                privateKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
            using X509Certificate2 publicCertificate = request.Create(
                request.SubjectName,
                X509SignatureGenerator.CreateForRSA(privateKey, RSASignaturePadding.Pkcs1),
                NotBefore,
                NotAfter,
                serialNumber);
            certificate = X509CertificateLoader.LoadCertificate(publicCertificate.RawData);
            CertificateDer = certificate.RawData;
            Thumbprint = certificate.Thumbprint;
        }

        internal byte[] CertificateDer { get; }

        internal string Thumbprint { get; }

        internal PeCertificatePrivateKeyLease CreateLease() => new(
            new SigningCertificateSelection(certificate, storeLease: null),
            privateKey.Key.Handle.DangerousGetHandle(),
            WindowsCertificatePrivateKeyAcquirer.CertificateNcryptKeySpec,
            PePrivateKeyFamily.Cng,
            callerMustFree: false,
            new RejectingPrivateKeyNativeApi());

        public void Dispose()
        {
            certificate.Dispose();
            privateKey.Dispose();
        }
    }

    private sealed class RejectingPrivateKeyNativeApi : ICertificatePrivateKeyNativeApi
    {
        public bool TryAcquire(
            nint certificateContext,
            uint flags,
            nint parameters,
            out nint keyHandle,
            out uint keySpec,
            out bool callerMustFree,
            out int error) => throw new InvalidOperationException("No native key acquisition is permitted.");

        public bool ReleaseCsp(nint keyHandle) =>
            throw new InvalidOperationException("The in-memory key handle is not lease-owned.");

        public int FreeCngKey(nint keyHandle) =>
            throw new InvalidOperationException("The in-memory key handle is not lease-owned.");
    }

    private sealed class IndependentInMemoryCmsVerifier(
        IAuthenticodeCmsRecordInspector inspector,
        IPeImageDigestProvider digestProvider,
        params byte[][] certificateDer) : IProductionSignedFileVerifier
    {
        private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);

        public int CallCount { get; private set; }

        public bool ContentDigestsValid { get; private set; }

        public bool CmsSignaturesValid { get; private set; }

        public string? Failure { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            CallCount++;
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                PeAuthenticodeCmsInspection primary = inspector.Inspect(
                    Assert.Single(PeImageCertificateTable.Read(stagedPath).Records).Content);
                PeAuthenticodeCmsInspection[] signatures =
                [
                    primary,
                    Assert.Single(primary.NestedSignatures)
                ];
                if (signatures.Length != plan.Legs.Count || certificateDer.Length != plan.Legs.Count)
                {
                    Failure = "logical signature or certificate count";
                    return Task.FromResult(CreateFailure());
                }

                for (int index = 0; index < signatures.Length; index++)
                {
                    NativeSignatureLeg leg = plan.Legs[index];
                    PeAuthenticodeCmsInspection signature = signatures[index];
                    byte[] expectedDigest = digestProvider.ComputeDigest(stagedPath, leg.FileDigest);
                    if (!CryptographicOperations.FixedTimeEquals(signature.ImageDigest, expectedDigest))
                    {
                        Failure = $"content digest at leg {index}";
                        return Task.FromResult(CreateFailure());
                    }

                    if (!string.Equals(
                            Assert.Single(signature.CertificateThumbprints),
                            leg.Certificate.Thumbprint,
                            StringComparison.Ordinal))
                    {
                        Failure = $"certificate identity at leg {index}";
                        return Task.FromResult(CreateFailure());
                    }

                    if (signature.Rfc3161TimestampCount != 1 ||
                        !signature.TimestampMessageImprintMatchesSignature)
                    {
                        Failure = $"timestamp binding at leg {index}";
                        return Task.FromResult(CreateFailure());
                    }

                    using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(
                        certificateDer[index]);
                    using RSA publicKey = Assert.IsAssignableFrom<RSA>(certificate.GetRSAPublicKey());
                    HashAlgorithmName hashAlgorithm = leg.FileDigest == NativeDigestAlgorithm.Sha1
                        ? HashAlgorithmName.SHA1
                        : HashAlgorithmName.SHA256;
                    if (!publicKey.VerifyData(
                            signature.SignatureInput,
                            signature.SignatureValue,
                            hashAlgorithm,
                            RSASignaturePadding.Pkcs1))
                    {
                        Failure = $"RSA CMS signature at leg {index}";
                        return Task.FromResult(CreateFailure());
                    }
                }

                ContentDigestsValid = true;
                CmsSignaturesValid = true;
                return Task.FromResult(NativeSigningResult.Success());
            }
            catch (Exception exception) when (exception is InvalidDataException or
                CryptographicException or
                AsnContentException or
                Xunit.Sdk.XunitException)
            {
                Failure = exception.GetType().Name + ": " + exception.Message;
                return Task.FromResult(CreateFailure());
            }
        }

        private static NativeSigningResult CreateFailure() => NativeSigningResult.Failure(
            NativeSigningReasonCode.VerifierDisagreement,
            TrustESubjectFormUnknown);
    }
}

public sealed class PeAuthenticodePrivateKeyTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Theory]
    [InlineData(WindowsCertificatePrivateKeyAcquirer.CertificateNcryptKeySpec, 1)]
    [InlineData(WindowsCertificatePrivateKeyAcquirer.AtSignature, 0)]
    [InlineData(WindowsCertificatePrivateKeyAcquirer.AtKeyExchange, 0)]
    [Trait("Category", "Authenticode")]
    public void DocumentedKeySpecSelectsCngOrCspAndCallerOwnedHandleIsFreedOnce(
        uint keySpec,
        int expectedFamilyValue)
    {
        PePrivateKeyFamily expectedFamily = (PePrivateKeyFamily)expectedFamilyValue;
        X509Certificate2 certificate = CreateRsaCertificate();
        var source = new StubCertificateSource(certificate);
        var native = new StubPrivateKeyNativeApi
        {
            KeyHandle = (nint)1234,
            KeySpec = keySpec,
            CallerMustFree = true
        };
        var acquirer = new WindowsCertificatePrivateKeyAcquirer(source, native);
        nint owner = (nint)5678;

        PePrivateKeyAcquisition result = acquirer.Acquire(Certificate(), owner);

        Assert.True(result.Result.Succeeded);
        PeCertificatePrivateKeyLease lease = Assert.IsType<PeCertificatePrivateKeyLease>(result.Lease);
        Assert.Equal(expectedFamily, lease.Family);
        Assert.Equal(keySpec, lease.KeySpec);
        Assert.Equal(PeRsaPadding.Pkcs1, lease.Padding);
        Assert.Equal(owner, native.WindowHandle);
        Assert.Equal(
            WindowsCertificatePrivateKeyAcquirer.AcquireAllowNcryptKey |
            WindowsCertificatePrivateKeyAcquirer.AcquireCompareKey |
            WindowsCertificatePrivateKeyAcquirer.AcquireWindowHandle,
            native.Flags);

        lease.Dispose();
        lease.Dispose();

        Assert.Equal(expectedFamily == PePrivateKeyFamily.Cng ? 1 : 0, native.CngFreeCount);
        Assert.Equal(expectedFamily == PePrivateKeyFamily.LegacyCsp ? 1 : 0, native.CspReleaseCount);
        Assert.True(source.Selection!.IsDisposed);
    }

    [Theory]
    [InlineData(unchecked((int)0x8009000D), NativeSigningReasonCode.CertificateHasNoPrivateKey)]
    [InlineData(1223, NativeSigningReasonCode.OperatorCancelled)]
    [InlineData(5, NativeSigningReasonCode.NativeSigningFailed)]
    [Trait("Category", "Authenticode")]
    public void CngOrCspAcquisitionErrorsAreTypedAndDisposeCertificate(
        int error,
        NativeSigningReasonCode expectedReason)
    {
        X509Certificate2 certificate = CreateRsaCertificate();
        var source = new StubCertificateSource(certificate);
        var native = new StubPrivateKeyNativeApi { Succeeds = false, Error = error };
        var acquirer = new WindowsCertificatePrivateKeyAcquirer(source, native);

        PePrivateKeyAcquisition result = acquirer.Acquire(Certificate(), nint.Zero);

        Assert.False(result.Result.Succeeded);
        Assert.Equal(expectedReason, result.Result.ReasonCode);
        Assert.Null(result.Lease);
        Assert.True(source.Selection!.IsDisposed);
        Assert.Equal(0, native.CngFreeCount + native.CspReleaseCount);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public void UnsupportedKeyAlgorithmFailsBeforeNativeAcquisition()
    {
        X509Certificate2 certificate = CreateEcdsaCertificate();
        var source = new StubCertificateSource(certificate);
        var native = new StubPrivateKeyNativeApi();
        var acquirer = new WindowsCertificatePrivateKeyAcquirer(source, native);

        PePrivateKeyAcquisition result = acquirer.Acquire(Certificate(), nint.Zero);

        Assert.False(result.Result.Succeeded);
        Assert.Equal(NativeSigningReasonCode.UnsupportedKeyAlgorithm, result.Result.ReasonCode);
        Assert.Equal(0, native.AcquireCount);
        Assert.True(source.Selection!.IsDisposed);
    }

    [Fact]
    [Trait("Category", "Authenticode")]
    public void PublicCryptMsgLayoutsMatchTheInstalledWindowsSdkX64Contract()
    {
        Assert.Equal(40, Marshal.SizeOf<NativeCertificateId>());
        Assert.Equal(168, Marshal.SizeOf<NativeCmsgSignerEncodeInfo>());
        Assert.Equal(64, Marshal.SizeOf<NativeCmsgSignedEncodeInfo>());
        Assert.Equal(24, Marshal.SizeOf<NativeCmsgAddSignerUnauthenticatedAttribute>());
        Assert.Equal(96, Marshal.OffsetOf<NativeCmsgSignerEncodeInfo>(
            nameof(NativeCmsgSignerEncodeInfo.SignerId)).ToInt32());
    }

    private static CertificateReference Certificate() => CertificateReference.Create(
        StoreLocation.CurrentUser,
        "My",
        Thumbprint);

    private static X509Certificate2 CreateRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=CodeSigner Authenticode RSA Fixture",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateEcdsaCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=CodeSigner Authenticode ECDSA Fixture",
            key,
            HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class StubCertificateSource(X509Certificate2 certificate) : ISigningCertificateSource
    {
        public SigningCertificateSelection? Selection { get; private set; }

        public SigningCertificateSelection? Select(
            CertificateReference reference,
            CertificateStoreLifetime storeLifetime)
        {
            Selection = new SigningCertificateSelection(certificate, storeLease: null);
            return Selection;
        }
    }

    private sealed class StubPrivateKeyNativeApi : ICertificatePrivateKeyNativeApi
    {
        public bool Succeeds { get; init; } = true;
        public nint KeyHandle { get; init; } = (nint)123;
        public uint KeySpec { get; init; } = WindowsCertificatePrivateKeyAcquirer.AtSignature;
        public bool CallerMustFree { get; init; }
        public int Error { get; init; }
        public int AcquireCount { get; private set; }
        public int CspReleaseCount { get; private set; }
        public int CngFreeCount { get; private set; }
        public uint Flags { get; private set; }
        public nint WindowHandle { get; private set; }

        public bool TryAcquire(
            nint certificateContext,
            uint flags,
            nint parameters,
            out nint keyHandle,
            out uint keySpec,
            out bool callerMustFree,
            out int error)
        {
            AcquireCount++;
            Flags = flags;
            WindowHandle = parameters == nint.Zero ? nint.Zero : Marshal.ReadIntPtr(parameters);
            keyHandle = Succeeds ? KeyHandle : nint.Zero;
            keySpec = KeySpec;
            callerMustFree = CallerMustFree;
            error = Error;
            return Succeeds;
        }

        public bool ReleaseCsp(nint keyHandle)
        {
            CspReleaseCount++;
            return true;
        }

        public int FreeCngKey(nint keyHandle)
        {
            CngFreeCount++;
            return 0;
        }
    }
}

internal static class SyntheticAuthenticodeCms
{
    private static readonly Asn1Tag ExplicitContent = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag Certificates = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag SubjectKeyIdentifier = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag UnsignedAttributes = new(TagClass.ContextSpecific, 1, isConstructed: true);
    private const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";

    internal static byte[] Create(
        NativeDigestAlgorithm algorithm,
        ReadOnlySpan<byte> imageDigest,
        bool includeTimestamp,
        bool invalidTimestampDigest = false,
        byte[]? nestedCms = null,
        int nestedAttributeCount = 0,
        bool malformedNested = false,
        byte[]? certificateDer = null,
        bool useSubjectKeyIdentifier = false)
    {
        byte[] indirect = AuthenticodeAsn1.EncodeIndirectData(algorithm, imageDigest);
        byte[]? issuerName = null;
        byte[]? signerSubjectKeyIdentifier = null;
        BigInteger serialNumber = BigInteger.One;
        if (certificateDer is not null)
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(certificateDer);
            issuerName = certificate.IssuerName.RawData;
            serialNumber = new BigInteger(
                certificate.GetSerialNumber(),
                isUnsigned: true,
                isBigEndian: false);
            if (useSubjectKeyIdentifier)
            {
                X509Extension extension = certificate.Extensions
                    .Cast<X509Extension>()
                    .Single(value => string.Equals(
                        value.Oid?.Value,
                        "2.5.29.14",
                        StringComparison.Ordinal));
                AsnReader extensionReader = new(extension.RawData, AsnEncodingRules.BER);
                signerSubjectKeyIdentifier = extensionReader.ReadOctetString();
                extensionReader.ThrowIfNotEmpty();
            }
        }
        else if (useSubjectKeyIdentifier)
        {
            throw new ArgumentException(
                "A signer certificate is required for a subject key identifier.",
                nameof(certificateDer));
        }
        byte[] signatureSeed = new byte[imageDigest.Length + 1];
        imageDigest.CopyTo(signatureSeed);
        signatureSeed[^1] = algorithm == NativeDigestAlgorithm.Sha1 ? (byte)1 : (byte)2;
        byte[] signature = SHA256.HashData(signatureSeed);
        string digestOid = AuthenticodeAsn1.DigestOid(algorithm);

        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(AuthenticodeAsn1.SignedDataOid);
        writer.PushSequence(ExplicitContent);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSetOf();
        WriteAlgorithm(writer, digestOid);
        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier(AuthenticodeAsn1.SpcIndirectDataOid);
        writer.PushSequence(ExplicitContent);
        writer.WriteOctetString(indirect);
        writer.PopSequence(ExplicitContent);
        writer.PopSequence();
        if (certificateDer is not null)
        {
            writer.PushSetOf(Certificates);
            writer.WriteEncodedValue(certificateDer);
            writer.PopSetOf(Certificates);
        }

        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteInteger(signerSubjectKeyIdentifier is null ? 1 : 3);
        if (signerSubjectKeyIdentifier is not null)
        {
            writer.WriteOctetString(signerSubjectKeyIdentifier, SubjectKeyIdentifier);
        }
        else
        {
            writer.PushSequence();
            if (issuerName is null)
            {
                writer.PushSequence();
                writer.PopSequence();
            }
            else
            {
                writer.WriteEncodedValue(issuerName);
            }
            writer.WriteInteger(serialNumber);
            writer.PopSequence();
        }
        WriteAlgorithm(writer, digestOid);
        WriteAlgorithm(writer, AuthenticodeAsn1.RsaEncryptionOid);
        writer.WriteOctetString(signature);
        if (includeTimestamp || nestedAttributeCount != 0)
        {
            writer.PushSetOf(UnsignedAttributes);
            if (includeTimestamp)
            {
                writer.PushSequence();
                writer.WriteObjectIdentifier(AuthenticodeOids.Rfc3161CounterSignature);
                writer.PushSetOf();
                writer.WriteEncodedValue(CreateTimestampToken(signature, invalidTimestampDigest));
                writer.PopSetOf();
                writer.PopSequence();
            }

            for (int index = 0; index < nestedAttributeCount; index++)
            {
                writer.PushSequence();
                writer.WriteObjectIdentifier(NestedSignatureOid);
                writer.PushSetOf();
                if (malformedNested)
                {
                    writer.WriteOctetString(ReadOnlySpan<byte>.Empty);
                }
                else
                {
                    writer.WriteEncodedValue(nestedCms ?? throw new InvalidOperationException());
                }

                writer.PopSetOf();
                writer.PopSequence();
            }

            writer.PopSetOf(UnsignedAttributes);
        }

        writer.PopSequence();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(ExplicitContent);
        writer.PopSequence();
        return writer.Encode();
    }

    internal static byte[] CreateTimestampToken(ReadOnlySpan<byte> signature, bool invalidDigest)
    {
        string digestOid = invalidDigest ? AuthenticodeOids.Sha1 : AuthenticodeOids.Sha256;
        byte[] imprint = invalidDigest ? new byte[20] : SHA256.HashData(signature);
        AsnWriter infoWriter = new(AsnEncodingRules.DER);
        infoWriter.PushSequence();
        infoWriter.WriteInteger(1);
        infoWriter.WriteObjectIdentifier("1.2.3.4.5");
        infoWriter.PushSequence();
        WriteAlgorithm(infoWriter, digestOid);
        infoWriter.WriteOctetString(imprint);
        infoWriter.PopSequence();
        infoWriter.WriteInteger(1);
        infoWriter.WriteGeneralizedTime(
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            omitFractionalSeconds: true);
        infoWriter.PopSequence();
        byte[] timestampInfo = infoWriter.Encode();

        AsnWriter tokenWriter = new(AsnEncodingRules.DER);
        tokenWriter.PushSequence();
        tokenWriter.WriteObjectIdentifier(AuthenticodeAsn1.SignedDataOid);
        tokenWriter.PushSequence(ExplicitContent);
        tokenWriter.PushSequence();
        tokenWriter.WriteInteger(1);
        tokenWriter.PushSetOf();
        WriteAlgorithm(tokenWriter, AuthenticodeOids.Sha256);
        tokenWriter.PopSetOf();
        tokenWriter.PushSequence();
        tokenWriter.WriteObjectIdentifier(AuthenticodeAsn1.TimestampInfoOid);
        tokenWriter.PushSequence(ExplicitContent);
        tokenWriter.WriteOctetString(timestampInfo);
        tokenWriter.PopSequence(ExplicitContent);
        tokenWriter.PopSequence();
        tokenWriter.PushSetOf();
        tokenWriter.PopSetOf();
        tokenWriter.PopSequence();
        tokenWriter.PopSequence(ExplicitContent);
        tokenWriter.PopSequence();
        return tokenWriter.Encode();
    }

    private static void WriteAlgorithm(AsnWriter writer, string oid)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        writer.WriteNull();
        writer.PopSequence();
    }
}
