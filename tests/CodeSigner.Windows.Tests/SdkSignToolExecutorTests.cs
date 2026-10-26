using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;

namespace CodeSigner.Windows.Tests;

public sealed class SdkSignToolExecutorTests
{
    private const string PrimaryThumbprint = "1111111111111111111111111111111111111111";
    private const string SecondaryThumbprint = "2222222222222222222222222222222222222222";
    private static readonly byte[] StructuralPrimaryCertificateDer = PeAuthenticodeSigningEngineTests.CreateSyntheticCertificateDer("SDK Primary");
    private static readonly byte[] StructuralSecondaryCertificateDer = PeAuthenticodeSigningEngineTests.CreateSyntheticCertificateDer("SDK Secondary");

    [Fact]
    public async Task ExecutorUsesExactDualArgumentOrderFreshStageAndMandatoryVerifier()
    {
        using Fixture fixture = new();
        ProductionNativeSigningPlan plan = CreateDualPlan();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var locator = new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate));
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var runner = new RecordingRunner((startInfo, _) =>
        {
            string stagedPath = startInfo.ArgumentList[^1];
            File.AppendAllText(stagedPath, ":signed");
            return Exited(
                0,
                $"Successfully signed {stagedPath}; thumbprint={startInfo.ArgumentList[2]}; token=output-canary");
        });
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var executor = new TrustedSdkSignToolExecutor(
            locator,
            verifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            plan,
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.None, result.Error);
        Assert.Equal(stageFactory.CreatedPath, result.FreshStagedPath);
        Assert.Equal(2, locator.RevalidationCount);
        Assert.Equal(2, runner.StageBytesBeforeInvocations.Count);
        Assert.Equal(fixture.PristineBytes, runner.StageBytesBeforeInvocations[0]);
        Assert.Equal(fixture.FailedBytes, File.ReadAllBytes(fixture.FailedStagedPath));
        Assert.Equal(fixture.PristineBytes, File.ReadAllBytes(fixture.OriginalPath));
        Assert.Equal(1, verifier.CallCount);
        Assert.Equal(stageFactory.CreatedPath, verifier.StagedPath);
        Assert.Same(plan, verifier.Plan);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(fixture.PristineBytes)),
            result.OriginalSha256);

        Assert.Collection(
            runner.Starts,
            first => AssertStart(
                first,
                candidate.Path,
                [
                    "sign",
                    "/sha1", PrimaryThumbprint,
                    "/s", "My",
                    "/fd", "sha1",
                    "/tr", plan.Legs[0].TimestampUri.AbsoluteUri,
                    "/td", "sha256",
                    stageFactory.CreatedPath!
                ]),
            second => AssertStart(
                second,
                candidate.Path,
                [
                    "sign",
                    "/sha1", SecondaryThumbprint,
                    "/s", "My",
                    "/sm",
                    "/fd", "sha256",
                    "/tr", plan.Legs[1].TimestampUri.AbsoluteUri,
                    "/td", "sha256",
                    "/as",
                    stageFactory.CreatedPath!
                ]));
        Assert.Collection(
            result.Invocations,
            first =>
            {
                Assert.Equal(NativeDigestAlgorithm.Sha1, first.FileDigest);
                Assert.False(first.Append);
                Assert.Equal(0, first.ExitCode);
                Assert.DoesNotContain(stageFactory.CreatedPath!, first.StandardOutput, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(PrimaryThumbprint, first.StandardOutput, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("output-canary", first.StandardOutput, StringComparison.Ordinal);
                Assert.Contains("[REDACTED", first.StandardOutput, StringComparison.Ordinal);
            },
            second =>
            {
                Assert.Equal(NativeDigestAlgorithm.Sha256, second.FileDigest);
                Assert.True(second.Append);
            });
    }

    [Fact]
    public async Task ExecutorAcceptsOneTopLevelRecordWithNestedDualThroughSharedStructuralVerifier()
    {
        using Fixture fixture = new();
        byte[] unsignedPe = FixtureBytes("valid-unsigned.exe");
        File.WriteAllBytes(fixture.OriginalPath, unsignedPe);
        string primaryThumbprint = CertificateThumbprint(StructuralPrimaryCertificateDer);
        string secondaryThumbprint = CertificateThumbprint(StructuralSecondaryCertificateDer);
        ProductionNativeSigningPlan plan = CreateDualPlan(primaryThumbprint, secondaryThumbprint);
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var locator = new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate));
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var digestProvider = new AuthenticodePeImageDigestProvider();
        var runner = new RecordingRunner((startInfo, index) =>
        {
            if (index == 1)
            {
                AppendStructuralLayout(
                    startInfo.ArgumentList[^1],
                    nestedSecondary: true,
                    extraTopLevel: false);
            }

            return Exited(0, "signed");
        });
        var finalWindowsGate = new PlanBoundWindowsGate(plan);
        var structuralVerifier = new PeAuthenticodeStructuralVerifier(
            digestProvider,
            new AuthenticodeCmsRecordInspector(),
            finalWindowsGate);
        var executor = new TrustedSdkSignToolExecutor(
            locator,
            structuralVerifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            plan,
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        string freshStage = Assert.IsType<string>(result.FreshStagedPath);
        PeAuthenticodeCmsInspection primary = new AuthenticodeCmsRecordInspector().Inspect(
            Assert.Single(PeImageCertificateTable.Read(freshStage).Records).Content);
        PeAuthenticodeCmsInspection secondary = Assert.Single(primary.NestedSignatures);
        Assert.Equal(
            [AuthenticodeOids.Sha1, AuthenticodeOids.Sha256],
            new[] { primary.DigestAlgorithmOid, secondary.DigestAlgorithmOid });
        Assert.Equal(1, finalWindowsGate.CallCount);
        Assert.Equal(unsignedPe, File.ReadAllBytes(fixture.OriginalPath));
        Assert.Equal(fixture.FailedBytes, File.ReadAllBytes(fixture.FailedStagedPath));
    }

    [Theory]
    [InlineData("two-top-level-records")]
    [InlineData("missing-nested")]
    public async Task ExecutorRejectsMalformedDualLayoutAndDeletesFreshStage(string caseName)
    {
        using Fixture fixture = new();
        byte[] unsignedPe = FixtureBytes("valid-unsigned.exe");
        File.WriteAllBytes(fixture.OriginalPath, unsignedPe);
        ProductionNativeSigningPlan plan = CreateDualPlan(
            CertificateThumbprint(StructuralPrimaryCertificateDer),
            CertificateThumbprint(StructuralSecondaryCertificateDer));
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var runner = new RecordingRunner((startInfo, index) =>
        {
            if (index == 1)
            {
                AppendStructuralLayout(
                    startInfo.ArgumentList[^1],
                    nestedSecondary: false,
                    extraTopLevel: caseName == "two-top-level-records");
            }

            return Exited(0, "Successfully signed and verified");
        });
        var finalWindowsGate = new PlanBoundWindowsGate(plan);
        var structuralVerifier = new PeAuthenticodeStructuralVerifier(
            new AuthenticodePeImageDigestProvider(),
            new AuthenticodeCmsRecordInspector(),
            finalWindowsGate);
        var executor = new TrustedSdkSignToolExecutor(
            new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate)),
            structuralVerifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            plan,
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.VerifierDisagreement, result.Error);
        Assert.Null(result.FreshStagedPath);
        Assert.Null(result.StagedSha256);
        Assert.Equal(0, finalWindowsGate.CallCount);
        Assert.NotNull(stageFactory.CreatedPath);
        Assert.False(File.Exists(stageFactory.CreatedPath));
        Assert.Equal(unsignedPe, File.ReadAllBytes(fixture.OriginalPath));
        Assert.Equal(fixture.FailedBytes, File.ReadAllBytes(fixture.FailedStagedPath));
    }

    [Fact]
    public async Task ExecutorRunsSingleSha256OnceWithoutAppend()
    {
        using Fixture fixture = new();
        ProductionNativeSigningPlan plan = CreateSinglePlan();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var runner = new RecordingRunner((startInfo, _) =>
        {
            File.AppendAllText(startInfo.ArgumentList[^1], ":signed");
            return Exited(0, "signed");
        });
        var executor = new TrustedSdkSignToolExecutor(
            new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate)),
            new RecordingVerifier(NativeSigningResult.Success()),
            runner,
            new RecordingStageFactory(fixture.Root),
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            plan,
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        InvocationStart start = Assert.Single(runner.Starts);
        Assert.Contains("sha256", start.Arguments);
        Assert.DoesNotContain("sha1", start.Arguments);
        Assert.DoesNotContain("/as", start.Arguments);
    }

    [Fact]
    public async Task ExitZeroAndMisleadingSuccessOutputCannotBypassVerifier()
    {
        using Fixture fixture = new();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var verifier = new RecordingVerifier(NativeSigningResult.Failure(
            NativeSigningReasonCode.VerifierDisagreement,
            unchecked((int)0x800B0100)));
        var executor = new TrustedSdkSignToolExecutor(
            new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate)),
            verifier,
            new RecordingRunner((startInfo, _) =>
            {
                File.AppendAllText(startInfo.ArgumentList[^1], ":forged-success");
                return Exited(0, "Successfully signed and verified");
            }),
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateSinglePlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.VerifierDisagreement, result.Error);
        Assert.Equal(1, verifier.CallCount);
        Assert.NotNull(stageFactory.CreatedPath);
        Assert.False(File.Exists(stageFactory.CreatedPath));
    }

    [Fact]
    public async Task DirectProviderFailureThenSignToolNonzeroLeavesNoFallbackStage()
    {
        using Fixture fixture = new();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var runner = new RecordingRunner((_, index) =>
            index == 0 ? Exited(0, "primary complete") : Exited(7, "timestamp failed"));
        var executor = new TrustedSdkSignToolExecutor(
            new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate)),
            verifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateDualPlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.ProcessFailed, result.Error);
        Assert.Equal(2, runner.Starts.Count);
        Assert.Equal(0, verifier.CallCount);
        Assert.False(File.Exists(stageFactory.CreatedPath));
        Assert.Equal(fixture.PristineBytes, File.ReadAllBytes(fixture.OriginalPath));
    }

    [Fact]
    public async Task StaleCandidateIsRejectedImmediatelyBeforeProcessUse()
    {
        using Fixture fixture = new();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var locator = new RecordingLocator(_ => SdkSignToolDiscoveryResult.Rejected(
            SdkSignToolRejectionReason.CandidateChanged,
            candidate.Path));
        var runner = new RecordingRunner((_, _) => Exited(0, "unused"));
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var executor = new TrustedSdkSignToolExecutor(
            locator,
            verifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateSinglePlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.CandidateChanged, result.Error);
        Assert.Equal(1, locator.RevalidationCount);
        Assert.Empty(runner.Starts);
        Assert.Equal(0, verifier.CallCount);
        Assert.False(File.Exists(stageFactory.CreatedPath));
    }

    [Fact]
    public async Task ExactCandidateIsRevalidatedOnceImmediatelyBeforeEachProcessStart()
    {
        using Fixture fixture = new();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var events = new List<string>();
        var locator = new RecordingLocator(
            _ =>
            {
                events.Add("revalidate");
                return SdkSignToolDiscoveryResult.Available(candidate);
            },
            launchCandidate =>
            {
                events.Add("launch-lease");
                return SdkSignToolLaunchLeaseResult.Available(
                    new RecordingLaunchLease(launchCandidate));
            });
        var runner = new RecordingRunner((_, _) =>
        {
            events.Add("start");
            return Exited(0, "signed");
        });
        var executor = new TrustedSdkSignToolExecutor(
            locator,
            new RecordingVerifier(NativeSigningResult.Success()),
            runner,
            new RecordingStageFactory(fixture.Root),
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateSinglePlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(["revalidate", "launch-lease", "start"], events);
        Assert.Equal(1, locator.LaunchLeaseCount);
        File.Delete(Assert.IsType<string>(result.FreshStagedPath));
    }

    [Fact]
    public async Task CandidateReboundAfterRevalidationNeverReachesProcessRunner()
    {
        using Fixture fixture = new();
        using CanonicalSdkTree sdkTree = new();
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            sdkTree.Locator.Discover().Candidate);
        var locator = new RebindingLocator(sdkTree.Locator, sdkTree.SignToolPath);
        var runner = new RecordingRunner((_, _) => Exited(0, "replacement started"));
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var executor = new TrustedSdkSignToolExecutor(
            locator,
            verifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateSinglePlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.CandidateChanged, result.Error);
        Assert.Equal(1, locator.RevalidationCount);
        Assert.Equal(1, locator.LaunchLeaseCount);
        Assert.Empty(runner.Starts);
        Assert.Equal(0, verifier.CallCount);
        Assert.False(File.Exists(stageFactory.CreatedPath));
    }

    [Fact]
    public async Task LaunchLeaseRemainsHeldThroughoutRunnerBoundaryAndReleasesAfterward()
    {
        using Fixture fixture = new();
        using CanonicalSdkTree sdkTree = new();
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            sdkTree.Locator.Discover().Candidate);
        bool mutationDeniedInsideRunner = false;
        var runner = new RecordingRunner((startInfo, _) =>
        {
            Assert.Equal(candidate.Path, startInfo.FileName);
            Assert.ThrowsAny<IOException>(() =>
                File.Move(candidate.Path, $"{candidate.Path}.inside-runner"));
            Assert.ThrowsAny<IOException>(() =>
                File.WriteAllBytes(candidate.Path, [0x4D, 0x5A, 0xDE, 0xAD]));
            mutationDeniedInsideRunner = true;
            return Exited(1, "mutation denied");
        });
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var executor = new TrustedSdkSignToolExecutor(
            sdkTree.Locator,
            verifier,
            runner,
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateSinglePlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(SdkSignToolFallbackError.ProcessFailed, result.Error);
        Assert.True(mutationDeniedInsideRunner);
        Assert.Single(runner.Starts);
        Assert.Equal(0, verifier.CallCount);
        Assert.False(File.Exists(stageFactory.CreatedPath));
        File.Move(candidate.Path, $"{candidate.Path}.after-runner");
        Assert.False(File.Exists(candidate.Path));
    }

    [Theory]
    [InlineData(NativeSigningReasonCode.Cancelled, unchecked((int)0x800704C7))]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable, unchecked((int)0x80072EE7))]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable, unchecked((int)0x80004002))]
    [InlineData(NativeSigningReasonCode.InvalidInput, unchecked((int)0x80070057))]
    [InlineData(NativeSigningReasonCode.InvalidInput, unchecked((int)0x80004002))]
    [InlineData(NativeSigningReasonCode.VerifierDisagreement, unchecked((int)0x800B0100))]
    [InlineData(NativeSigningReasonCode.VerifierDisagreement, unchecked((int)0x80004002))]
    [InlineData(NativeSigningReasonCode.Cancelled, unchecked((int)0x80004002))]
    [InlineData(NativeSigningReasonCode.NativeSigningFailed, unchecked((int)0x80004005))]
    public void FallbackEligibilityRejectsCancellationTimestampInputTrustAndGenericFailures(
        NativeSigningReasonCode reason,
        int hResult)
    {
        bool allowed = SdkSignToolFallbackEligibility.TryCreate(
            NativeSigningResult.Failure(reason, hResult),
            out SdkSignToolFallbackEligibility? eligibility);

        Assert.False(allowed);
        Assert.Null(eligibility);
    }

    [Theory]
    [InlineData(SdkSignToolProcessOutcome.StartFailed, SdkSignToolFallbackError.ProcessStartFailed)]
    [InlineData(SdkSignToolProcessOutcome.TimedOut, SdkSignToolFallbackError.TimedOut)]
    [InlineData(SdkSignToolProcessOutcome.Cancelled, SdkSignToolFallbackError.Cancelled)]
    public async Task FailedProcessDoesNotVerifyOrRetainFreshStage(
        SdkSignToolProcessOutcome processOutcome,
        SdkSignToolFallbackError expectedError)
    {
        using Fixture fixture = new();
        TrustedSdkSignToolCandidate candidate = Candidate(fixture.SignToolPath);
        var stageFactory = new RecordingStageFactory(fixture.Root);
        var verifier = new RecordingVerifier(NativeSigningResult.Success());
        var executor = new TrustedSdkSignToolExecutor(
            new RecordingLocator(_ => SdkSignToolDiscoveryResult.Available(candidate)),
            verifier,
            new RecordingRunner((_, _) => new SdkSignToolProcessResult(
                processOutcome,
                ExitCode: null,
                StandardOutput: string.Empty,
                StandardError: string.Empty,
                StandardOutputTruncated: false,
                StandardErrorTruncated: false)),
            stageFactory,
            TimeSpan.FromSeconds(5));

        SdkSignToolFallbackResult result = await executor.ExecuteAsync(
            candidate,
            Eligibility(),
            fixture.OriginalPath,
            fixture.FailedStagedPath,
            CreateSinglePlan(),
            Environment.ProcessId,
            Process.GetCurrentProcess().StartTime.ToUniversalTime(),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(expectedError, result.Error);
        Assert.Equal(0, verifier.CallCount);
        Assert.False(File.Exists(stageFactory.CreatedPath));
    }

    [Fact]
    public async Task DefaultStageFactoryCopiesPristineOriginalBesideOwnedFailedStage()
    {
        string root = Directory.CreateTempSubdirectory("codesigner-sdk-stage-").FullName;
        string? attempt = null;
        string? fresh = null;
        try
        {
            byte[] pristine = [1, 2, 3, 4, 5];
            string original = Path.Combine(root, "original.exe");
            File.WriteAllBytes(original, pristine);
            using Process current = Process.GetCurrentProcess();
            attempt = TransactionalStaging.CreateAttemptDirectory(root);
            string failed = Path.Combine(attempt, "failed.exe");
            File.WriteAllBytes(failed, [9, 9, 9]);
            var factory = new SdkSignToolPristineStageFactory();

            fresh = await factory.CreatePristineAsync(
                original,
                failed,
                current.Id,
                current.StartTime.ToUniversalTime(),
                CancellationToken.None);

            Assert.Equal(Path.GetFullPath(attempt), Path.GetDirectoryName(Path.GetFullPath(fresh)));
            Assert.NotEqual(Path.GetFullPath(failed), Path.GetFullPath(fresh));
            Assert.Equal(pristine, File.ReadAllBytes(fresh));
            Assert.Equal([9, 9, 9], File.ReadAllBytes(failed));
        }
        finally
        {
            if (fresh is not null)
            {
                File.Delete(fresh);
            }

            if (attempt is not null)
            {
                TransactionalStaging.DeleteAttempt(attempt);
            }

            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void AssertStart(InvocationStart actual, string expectedFileName, string[] expectedArguments)
    {
        Assert.Equal(expectedFileName, actual.FileName);
        Assert.Equal(expectedArguments, actual.Arguments);
        Assert.Equal(string.Empty, actual.ArgumentsProperty);
        Assert.False(actual.UseShellExecute);
        Assert.True(actual.RedirectStandardOutput);
        Assert.True(actual.RedirectStandardError);
        Assert.True(actual.CreateNoWindow);
    }

    private static SdkSignToolFallbackEligibility Eligibility()
    {
        Assert.True(SdkSignToolFallbackEligibility.TryCreate(
            NativeSigningResult.Failure(
                NativeSigningReasonCode.NativeSigningFailed,
                SdkSignToolFallbackEligibility.NoInterfaceHResult),
            out SdkSignToolFallbackEligibility? eligibility));
        return Assert.IsType<SdkSignToolFallbackEligibility>(eligibility);
    }

    private static SdkSignToolProcessResult Exited(int exitCode, string stdout) => new(
        SdkSignToolProcessOutcome.Exited,
        exitCode,
        stdout,
        StandardError: string.Empty,
        StandardOutputTruncated: false,
        StandardErrorTruncated: false);

    private static ProductionNativeSigningPlan CreateSinglePlan()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", PrimaryThumbprint).Value);
        CoreSigningPlan plan = Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateSingle(certificate, ".exe").Value);
        return ProductionNativeSigningPlan.FromCore(plan);
    }

    private static ProductionNativeSigningPlan CreateDualPlan() =>
        CreateDualPlan(PrimaryThumbprint, SecondaryThumbprint);

    private static ProductionNativeSigningPlan CreateDualPlan(
        string primaryThumbprint,
        string secondaryThumbprint)
    {
        CertificateRef primary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", primaryThumbprint).Value);
        CertificateRef secondary = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.LocalMachine, "My", secondaryThumbprint).Value);
        CoreSigningPlan plan = Assert.IsType<CoreSigningPlan>(
            CoreSigningPlan.TryCreateDual(primary, secondary, ".exe").Value);
        return ProductionNativeSigningPlan.FromCore(plan);
    }

    private static string CertificateThumbprint(byte[] certificateDer)
    {
#pragma warning disable CA5350
        return Convert.ToHexString(SHA1.HashData(certificateDer));
#pragma warning restore CA5350
    }

    private static byte[] FixtureBytes(string fileName)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        DirectoryInfo repository = Assert.IsType<DirectoryInfo>(directory);
        return File.ReadAllBytes(Path.Combine(
            repository.FullName,
            "tests",
            "fixtures",
            "generated",
            fileName));
    }

    private static void AppendStructuralLayout(
        string stagedPath,
        bool nestedSecondary,
        bool extraTopLevel)
    {
        var digestProvider = new AuthenticodePeImageDigestProvider();
        byte[] primaryDigest = digestProvider.ComputeDigest(
            stagedPath,
            NativeDigestAlgorithm.Sha1);
        byte[] secondaryDigest = digestProvider.ComputeDigest(
            stagedPath,
            NativeDigestAlgorithm.Sha256);
        byte[] primaryCms = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha1,
            primaryDigest,
            includeTimestamp: true,
            certificateDer: StructuralPrimaryCertificateDer);
        byte[] secondaryCms = SyntheticAuthenticodeCms.Create(
            NativeDigestAlgorithm.Sha256,
            secondaryDigest,
            includeTimestamp: true,
            certificateDer: StructuralSecondaryCertificateDer);
        if (nestedSecondary)
        {
            primaryCms = PeAuthenticodeCmsEnvelope.CreateDual(
                primaryCms,
                primaryDigest,
                CertificateThumbprint(StructuralPrimaryCertificateDer),
                secondaryCms,
                secondaryDigest,
                CertificateThumbprint(StructuralSecondaryCertificateDer));
        }

        PeImageCertificateTable.Append(stagedPath, primaryCms);
        if (extraTopLevel)
        {
            PeImageCertificateTable.Append(stagedPath, secondaryCms);
        }
    }

    private static TrustedSdkSignToolCandidate Candidate(string path) => new(
        Path.GetFullPath(path),
        new Version(10, 0, 26100, 0),
        new Version(10, 0, 26100, 7463),
        "Microsoft Corporation",
        "Microsoft Corporation",
        "Microsoft® Windows® Operating System",
        new string('A', 64));

    private sealed class Fixture : IDisposable
    {
        public Fixture()
        {
            Root = Directory.CreateTempSubdirectory("codesigner-sdk-executor-").FullName;
            PristineBytes = [0x4D, 0x5A, 1, 2, 3, 4];
            FailedBytes = [0x4D, 0x5A, 9, 9, 9, 9];
            OriginalPath = Path.Combine(Root, "original.exe");
            FailedStagedPath = Path.Combine(Root, "failed.exe");
            SignToolPath = Path.Combine(Root, "sdk", "signtool.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(SignToolPath)!);
            File.WriteAllBytes(OriginalPath, PristineBytes);
            File.WriteAllBytes(FailedStagedPath, FailedBytes);
            File.WriteAllBytes(SignToolPath, [0x4D, 0x5A]);
        }

        public string Root { get; }
        public byte[] PristineBytes { get; }
        public byte[] FailedBytes { get; }
        public string OriginalPath { get; }
        public string FailedStagedPath { get; }
        public string SignToolPath { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class CanonicalSdkTree : IDisposable
    {
        public CanonicalSdkTree()
        {
            Root = Directory.CreateTempSubdirectory("codesigner-sdk-launch-").FullName;
            SignToolPath = Path.Combine(
                Root,
                "Windows Kits",
                "10",
                "bin",
                "10.0.26100.0",
                "x64",
                "signtool.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(SignToolPath)!);
            File.WriteAllBytes(SignToolPath, [0x4D, 0x5A, 1, 2, 3, 4]);
            Locator = new TrustedSdkSignToolLocator(
                new CanonicalSdkFileSystem(Root),
                new WindowsTrustedSdkSignToolCandidateValidator(new HashingSdkInspector()));
        }

        public string Root { get; }

        public string SignToolPath { get; }

        public TrustedSdkSignToolLocator Locator { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class CanonicalSdkFileSystem(string root) : ITrustedSdkSignToolFileSystem
    {
        public string ProgramFilesX86 => root;

        public string GetFullPath(string path) => Path.GetFullPath(path);

        public bool DirectoryExists(string path) => Directory.Exists(path);

        public bool FileExists(string path) => File.Exists(path);

        public IEnumerable<string> EnumerateDirectories(string path) =>
            Directory.EnumerateDirectories(path, "*", SearchOption.TopDirectoryOnly);

        public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
    }

    private sealed class HashingSdkInspector : ISdkSignToolExecutableInspector
    {
        public SdkSignToolExecutableInspection Inspect(string path)
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return new SdkSignToolExecutableInspection(
                PeMachine: 0x8664,
                WindowsTrustValid: true,
                WindowsTrustedSdkSignToolCandidateValidator.ExpectedPublisher,
                WindowsTrustedSdkSignToolCandidateValidator.ExpectedCompanyName,
                WindowsTrustedSdkSignToolCandidateValidator.ExpectedProductName,
                OriginalFileName: "SIGNTOOL.EXE",
                FileDescription: "Authenticode(R) - signing and verifying tool",
                ProductVersion: new Version(10, 0, 26100, 7463),
                Convert.ToHexString(SHA256.HashData(stream)));
        }
    }

    private sealed class RebindingLocator(
        TrustedSdkSignToolLocator locator,
        string candidatePath) : ITrustedSdkSignToolLocator, ITrustedSdkSignToolLaunchLeaseProvider
    {
        private bool rebound;

        public int RevalidationCount { get; private set; }

        public int LaunchLeaseCount { get; private set; }

        public SdkSignToolDiscoveryResult Discover() => locator.Discover();

        public SdkSignToolDiscoveryResult Revalidate(TrustedSdkSignToolCandidate candidate)
        {
            RevalidationCount++;
            SdkSignToolDiscoveryResult result = locator.Revalidate(candidate);
            if (result.IsAvailable && !rebound)
            {
                File.Move(candidatePath, $"{candidatePath}.validated");
                File.WriteAllBytes(candidatePath, [0x4D, 0x5A, 0xDE, 0xAD]);
                rebound = true;
            }

            return result;
        }

        public SdkSignToolLaunchLeaseResult AcquireLaunchLease(TrustedSdkSignToolCandidate candidate)
        {
            LaunchLeaseCount++;
            return locator.AcquireLaunchLease(candidate);
        }
    }

    private sealed class RecordingLocator(
        Func<int, SdkSignToolDiscoveryResult> result,
        Func<TrustedSdkSignToolCandidate, SdkSignToolLaunchLeaseResult>? launch = null)
        : ITrustedSdkSignToolLocator, ITrustedSdkSignToolLaunchLeaseProvider
    {
        public int RevalidationCount { get; private set; }

        public int LaunchLeaseCount { get; private set; }

        public SdkSignToolDiscoveryResult Discover() => throw new InvalidOperationException("Discovery is not used by Worker fallback.");

        public SdkSignToolDiscoveryResult Revalidate(TrustedSdkSignToolCandidate candidate)
        {
            RevalidationCount++;
            return result(RevalidationCount);
        }

        public SdkSignToolLaunchLeaseResult AcquireLaunchLease(TrustedSdkSignToolCandidate candidate)
        {
            LaunchLeaseCount++;
            return launch?.Invoke(candidate) ??
                SdkSignToolLaunchLeaseResult.Available(new RecordingLaunchLease(candidate));
        }
    }

    private sealed class RecordingLaunchLease(TrustedSdkSignToolCandidate candidate)
        : ITrustedSdkSignToolLaunchLease
    {
        public TrustedSdkSignToolCandidate Candidate { get; } = candidate;

        public StableFileIdentity Identity { get; } = new(0, "RECORDING-LEASE");

        public string Sha256 => Candidate.Sha256;

        public void Dispose()
        {
        }
    }

    private sealed class RecordingStageFactory(string root) : ISdkSignToolPristineStageFactory
    {
        public string? CreatedPath { get; private set; }

        public Task<string> CreatePristineAsync(
            string originalPath,
            string failedStagedPath,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CreatedPath = Path.Combine(root, $"fresh-{Guid.NewGuid():N}{Path.GetExtension(originalPath)}");
            File.Copy(originalPath, CreatedPath, overwrite: false);
            return Task.FromResult(CreatedPath);
        }

        public void Delete(string path) => File.Delete(path);
    }

    private sealed class RecordingRunner(Func<ProcessStartInfo, int, SdkSignToolProcessResult> result)
        : ITrustedSdkSignToolProcessRunner
    {
        public List<InvocationStart> Starts { get; } = [];
        public List<byte[]> StageBytesBeforeInvocations { get; } = [];

        public Task<SdkSignToolProcessResult> RunAsync(
            ProcessStartInfo startInfo,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StageBytesBeforeInvocations.Add(File.ReadAllBytes(startInfo.ArgumentList[^1]));
            Starts.Add(new InvocationStart(
                startInfo.FileName,
                startInfo.ArgumentList.ToArray(),
                startInfo.Arguments,
                startInfo.UseShellExecute,
                startInfo.RedirectStandardOutput,
                startInfo.RedirectStandardError,
                startInfo.CreateNoWindow));
            return Task.FromResult(result(startInfo, Starts.Count - 1));
        }
    }

    private sealed record InvocationStart(
        string FileName,
        string[] Arguments,
        string ArgumentsProperty,
        bool UseShellExecute,
        bool RedirectStandardOutput,
        bool RedirectStandardError,
        bool CreateNoWindow);

    private sealed class RecordingVerifier(NativeSigningResult result) : IProductionSignedFileVerifier
    {
        public int CallCount { get; private set; }
        public string? StagedPath { get; private set; }
        public ProductionNativeSigningPlan? Plan { get; private set; }

        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            StagedPath = stagedPath;
            Plan = plan;
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
            bool matches = ReferenceEquals(plan, expectedPlan) &&
                File.Exists(stagedPath) &&
                PeImageCertificateTable.Read(stagedPath).Records.Count == 1;
            return Task.FromResult(matches
                ? NativeSigningResult.Success()
                : NativeSigningResult.Failure(
                    NativeSigningReasonCode.VerifierDisagreement,
                    unchecked((int)0x800B0003)));
        }
    }
}
