using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class WindowsPowerShellSipBridgeCompatibilityTests : IDisposable
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const int FailureHResult = unchecked((int)0x80004005);
    private static readonly Guid ScriptSubjectGuid = new("603bcc1f-4b59-4e08-b724-d2c6297ef351");
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "codesigner-sip-compatibility-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task CompatibilityBridgeUsesExactSystemPowerShellAndStructuredSingleSha256Leg()
    {
        Attempt attempt = CreateAttempt("payload.ps1", "Write-Output 'test'\r\n");
        byte[] originalBytes = File.ReadAllBytes(attempt.OriginalPath);
        SigningPlan plan = CreatePlan(SigningMode.Dual, ".ps1");
        var runner = new FakeProcessRunner
        {
            MutateStagedFile = true,
            ResponseJson = SuccessResponse()
        };
        var verifier = new FakeSipVerifier();
        var replacer = new RecordingAtomicFileReplacer();
        WindowsPowerShellSipBridge bridge = CreateBridge(runner, verifier: verifier, replacer: replacer);

        WindowsSipSigningResult result = await bridge.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan,
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            reportProgress: null,
            CancellationToken.None);

        Assert.True(
            result.Succeeded,
            $"{result.Error}; replaceCalls={replacer.CallCount}; work={runner.ObservedTargetPath}; workExists={File.Exists(runner.ObservedTargetPath)}; staged={File.ReadAllText(attempt.StagedPath)}");
        Assert.Equal(WindowsSipSigningError.None, result.Error);
        Assert.False(result.SkippedExistingSignature);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, verifier.SignedCallCount);
        Assert.Equal(1, replacer.CallCount);
        Assert.Equal(1, replacer.AtomicReplaceCount);
        Assert.Equal(runner.ObservedTargetPath, replacer.SourcePath);
        Assert.Equal(attempt.StagedPath, replacer.DestinationPath);
        ProcessStartInfo startInfo = Assert.IsType<ProcessStartInfo>(runner.StartInfo);
        Assert.Equal(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            startInfo.FileName);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.RedirectStandardInput);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Equal(ProcessWindowStyle.Hidden, startInfo.WindowStyle);
        Assert.Equal(
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WindowsPowerShellSipCommand.SignAndVerify],
            startInfo.ArgumentList);
        Assert.DoesNotContain(startInfo.ArgumentList, argument =>
            argument.Contains("ExecutionPolicy", StringComparison.OrdinalIgnoreCase) ||
            argument.Contains("pwsh", StringComparison.OrdinalIgnoreCase) ||
            argument.Contains("signtool", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(attempt.StagedPath, WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.DoesNotContain(Thumbprint, WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("Set-AuthenticodeSignature", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("PSVersionTable.PSVersion.Major -ne 5", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("[Console]::In.Read", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("[Console]::Out.Write", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("$requestProperties = @($request.PSObject.Properties)", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("$requestProperties.Count -ne $expectedProperties.Count", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.DoesNotContain("$request.PSObject.Properties.Count -ne $expectedProperties.Count", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.DoesNotContain("request.json", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("response.json", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CODESIGNER_SIP_REQUEST", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.DoesNotContain("CODESIGNER_SIP_RESPONSE", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.DoesNotContain("-split", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("switch", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.OrdinalIgnoreCase);

        using JsonDocument request = JsonDocument.Parse(Assert.IsType<string>(runner.RequestJson));
        JsonElement rootElement = request.RootElement;
        Assert.Equal(1, rootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("signAndVerify", rootElement.GetProperty("operation").GetString());
        string workPath = Assert.IsType<string>(rootElement.GetProperty("stagedPath").GetString());
        Assert.NotEqual(attempt.StagedPath, workPath);
        Assert.NotEqual(attempt.OriginalPath, workPath);
        Assert.Equal(Path.GetExtension(attempt.StagedPath), Path.GetExtension(workPath));
        Assert.Equal(Path.GetDirectoryName(attempt.StagedPath), Path.GetDirectoryName(Path.GetDirectoryName(workPath)));
        Assert.True(runner.WorkFileExistedDuringRun);
        Assert.Equal("powerShellScript", rootElement.GetProperty("formatFamily").GetString());
        Assert.Equal("CurrentUser", rootElement.GetProperty("certificateStoreLocation").GetString());
        Assert.Equal("My", rootElement.GetProperty("certificateStoreName").GetString());
        Assert.Equal(Thumbprint, rootElement.GetProperty("certificateThumbprint").GetString());
        Assert.Equal("sha256", rootElement.GetProperty("fileDigest").GetString());
        Assert.False(rootElement.GetProperty("appendSignature").GetBoolean());
        Assert.Equal("rfc3161", rootElement.GetProperty("timestampProtocol").GetString());
        Assert.Equal("sha256", rootElement.GetProperty("timestampDigest").GetString());
        Assert.Equal("skip", rootElement.GetProperty("existingValid").GetString());
        Assert.Equal("fail", rootElement.GetProperty("existingInvalid").GetString());
        Assert.False(rootElement.TryGetProperty("legs", out _));
        Assert.Equal(SigningMode.Single, plan.EffectiveMode);
        Assert.Single(plan.Legs);
        Assert.Equal(FileDigestAlgorithm.Sha256, plan.Legs[0].FileDigest);
        Assert.False(plan.Legs[0].Append);
        Assert.DoesNotContain(startInfo.Environment.Keys, key =>
            key.Contains("CODESIGNER_SIP_REQUEST", StringComparison.Ordinal) ||
            key.Contains("CODESIGNER_SIP_RESPONSE", StringComparison.Ordinal));
        Assert.True(runner.StandardInputClosed);
        Assert.True(runner.NoProtocolFilesDuringRun);
        Assert.Equal(Encoding.UTF8.GetByteCount(runner.RequestJson), runner.StandardInputBytes);
        Assert.Equal(Encoding.UTF8.GetByteCount(SuccessResponse()), runner.StandardOutputBytes);
        byte[] publishedBytes = File.ReadAllBytes(attempt.StagedPath);
        Assert.True(publishedBytes.AsSpan().StartsWith(originalBytes));
        Assert.True(publishedBytes.Length > originalBytes.Length);
        Assert.Equal(originalBytes, File.ReadAllBytes(attempt.OriginalPath));
    }

    [Fact]
    public async Task ExistingValidSkipVerifiesPrivateIdentityAndPerformsNoAtomicReplace()
    {
        Attempt attempt = CreateAttempt("already-signed.ps1", "Write-Output existing\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        string stagedHash = await HashAsync(attempt.StagedPath);
        var runner = new FakeProcessRunner { ResponseJson = ExistingValidResponse() };
        var verifier = new FakeSipVerifier();
        var replacer = new RecordingAtomicFileReplacer();

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            verifier: verifier,
            replacer: replacer).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreatePlan(SigningMode.Single, ".ps1"),
                attempt.OwnerPid,
                attempt.OwnerStartUtc,
                null,
                CancellationToken.None);

        Assert.True(result.Succeeded, result.Error.ToString());
        Assert.True(result.SkippedExistingSignature);
        Assert.Equal(1, verifier.ExistingCallCount);
        Assert.Equal(0, verifier.SignedCallCount);
        Assert.Equal(0, replacer.CallCount);
        Assert.NotEqual(attempt.StagedPath, runner.ObservedTargetPath);
        Assert.Equal(runner.ObservedTargetPath, verifier.ObservedStagedPath);
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
        Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
    }

    [Theory]
    [InlineData("process")]
    [InlineData("response")]
    [InlineData("verification")]
    [InlineData("replace")]
    public async Task FailureAfterWorkCopyCreationNeverChangesOriginalOrCanonicalStage(string failurePoint)
    {
        Attempt attempt = CreateAttempt($"{failurePoint}.ps1", "Write-Output failure\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        string stagedHash = await HashAsync(attempt.StagedPath);
        var runner = new FakeProcessRunner
        {
            MutateStagedFile = failurePoint is not "process",
            ResponseJson = failurePoint switch
            {
                "process" => FailureResponse("processFailed"),
                "response" => "{malformed",
                _ => SuccessResponse()
            },
            ProcessResult = new WindowsPowerShellProcessResult(failurePoint == "process" ? 1 : 0)
        };
        var verifier = new FakeSipVerifier
        {
            Result = failurePoint == "verification"
                ? WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed)
                : WindowsSipVerificationResult.Success()
        };
        var replacer = new RecordingAtomicFileReplacer { ThrowOnReplace = failurePoint == "replace" };

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            verifier: verifier,
            replacer: replacer).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreatePlan(SigningMode.Single, ".ps1"),
                attempt.OwnerPid,
                attempt.OwnerStartUtc,
                null,
                CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
        Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
        Assert.Equal(failurePoint == "replace" ? 1 : 0, replacer.CallCount);
    }

    [Theory]
    [InlineData("work")]
    [InlineData("request-directory")]
    [InlineData("canonical")]
    [InlineData("original")]
    public async Task ChildBoundaryIdentityRacesFailWithoutPublishing(string race)
    {
        Attempt attempt = CreateAttempt($"{race}.ps1", "Write-Output race\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        string stagedHash = await HashAsync(attempt.StagedPath);
        var runner = new FakeProcessRunner
        {
            MutateStagedFile = true,
            ResponseJson = SuccessResponse(),
            BeforeReturn = workPath => ApplyChildBoundaryRace(race, attempt, workPath)
        };
        var replacer = new RecordingAtomicFileReplacer();

        WindowsSipSigningResult result = await CreateBridge(runner, replacer: replacer).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(0, replacer.CallCount);
        if (race == "canonical")
        {
            Assert.Equal("replacement canonical identity\r\n", File.ReadAllText(attempt.StagedPath));
        }
        else
        {
            Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
        }

        if (race != "original")
        {
            Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
        }
    }

    [Fact]
    public async Task VerifierTimingRaceCannotOverwriteAConcurrentCanonicalStage()
    {
        Attempt attempt = CreateAttempt("verifier-race.ps1", "Write-Output stable\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        const string concurrent = "concurrent canonical stage\r\n";
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        var verifier = new FakeSipVerifier
        {
            DuringVerification = _ => ReplaceWithText(attempt.StagedPath, concurrent)
        };
        var replacer = new RecordingAtomicFileReplacer();

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            verifier: verifier,
            replacer: replacer).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreatePlan(SigningMode.Single, ".ps1"),
                attempt.OwnerPid,
                attempt.OwnerStartUtc,
                null,
                CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(0, replacer.CallCount);
        Assert.Equal(concurrent, File.ReadAllText(attempt.StagedPath));
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
    }

    [Fact]
    public async Task ReplaceBoundaryRaceIsRejectedBeforeAtomicCommit()
    {
        Attempt attempt = CreateAttempt("replace-race.ps1", "Write-Output stable\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        const string concurrent = "replace boundary canonical stage\r\n";
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        var replacer = new RecordingAtomicFileReplacer
        {
            BeforeValidation = (_, destinationPath) => ReplaceWithText(destinationPath, concurrent)
        };

        WindowsSipSigningResult result = await CreateBridge(runner, replacer: replacer).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(1, replacer.CallCount);
        Assert.Equal(0, replacer.AtomicReplaceCount);
        Assert.Equal(concurrent, File.ReadAllText(attempt.StagedPath));
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
    }

    [Fact]
    public async Task StagingOwnershipMutationBeforeCommitReturnsTypedFailureWithoutPublication()
    {
        Attempt attempt = CreateAttempt("ownership-race.ps1", "Write-Output stable\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        string stagedHash = await HashAsync(attempt.StagedPath);
        string manifestPath = Path.Combine(
            Path.GetDirectoryName(attempt.StagedPath)!,
            TransactionalStaging.ManifestFileName);
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        var verifier = new FakeSipVerifier
        {
            DuringVerification = _ => File.WriteAllText(manifestPath, "{}", new UTF8Encoding(false))
        };
        var replacer = new RecordingAtomicFileReplacer();

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            verifier: verifier,
            replacer: replacer).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreatePlan(SigningMode.Single, ".ps1"),
                attempt.OwnerPid,
                attempt.OwnerStartUtc,
                null,
                CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(WindowsSipSigningError.ProcessFailed, result.Error);
        Assert.Equal(0, replacer.CallCount);
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
        Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
    }

    [Fact]
    public async Task WorkFileIsWriteLockedThroughoutParentVerification()
    {
        Attempt attempt = CreateAttempt("locked.ps1", "Write-Output locked\r\n");
        string stagedHash = await HashAsync(attempt.StagedPath);
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        var verifier = new FakeSipVerifier
        {
            Result = WindowsSipVerificationResult.Failure(WindowsSipVerificationError.VerificationFailed),
            DuringVerification = workPath =>
            {
                Assert.Throws<IOException>(() => File.AppendAllText(workPath, "forbidden"));
            }
        };
        var replacer = new RecordingAtomicFileReplacer();

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            verifier: verifier,
            replacer: replacer).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreatePlan(SigningMode.Single, ".ps1"),
                attempt.OwnerPid,
                attempt.OwnerStartUtc,
                null,
                CancellationToken.None);

        Assert.Equal(WindowsSipSigningError.VerificationFailed, result.Error);
        Assert.Equal(0, replacer.CallCount);
        Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
    }

    [Fact]
    public async Task WorkIdentityReplacementDuringVerificationFailsWithoutPublication()
    {
        Attempt attempt = CreateAttempt("work-verifier-race.ps1", "Write-Output locked\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        string stagedHash = await HashAsync(attempt.StagedPath);
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        var verifier = new FakeSipVerifier
        {
            DuringVerification = workPath => ReplaceWithText(workPath, "replacement verifier work\r\n")
        };
        var replacer = new RecordingAtomicFileReplacer();

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            verifier: verifier,
            replacer: replacer).ExecuteAsync(
                attempt.OriginalPath,
                attempt.StagedPath,
                CreatePlan(SigningMode.Single, ".ps1"),
                attempt.OwnerPid,
                attempt.OwnerStartUtc,
                null,
                CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(WindowsSipSigningError.VerificationFailed, result.Error);
        Assert.Equal(0, replacer.CallCount);
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
        Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
    }

    [Fact]
    public async Task LargePackageWorkCopyUsesBoundedStreamingPolicy()
    {
        const long packageBytes = 64L * 1024 * 1024;
        Attempt attempt = CreateLargeAttempt("large.msix", packageBytes);
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        long allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);

        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".msix"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        long allocated = GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore;
        Assert.True(result.Succeeded, result.Error.ToString());
        Assert.True(allocated < packageBytes / 2, $"Allocated {allocated} bytes for a {packageBytes}-byte package.");
        Assert.Equal(packageBytes + Encoding.UTF8.GetByteCount("# SIG # synthetic-test-only\r\n"), new FileInfo(attempt.StagedPath).Length);
        Assert.DoesNotContain("XDocument", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("maximumManifestBytes", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("maximumBlockMapBytes", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
        Assert.Contains("XmlReader", WindowsPowerShellSipCommand.SignAndVerify, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScriptPublicationPreservesEveryOriginalByteAndNewlineBeforeSignature()
    {
        byte[] scriptBytes = [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("one\r\ntwo\nthree\rfour")];
        Attempt attempt = CreateAttempt("bytes.ps1", scriptBytes);
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };

        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.True(result.Succeeded, result.Error.ToString());
        Assert.True(File.ReadAllBytes(attempt.StagedPath).AsSpan().StartsWith(scriptBytes));
        Assert.Equal(scriptBytes, File.ReadAllBytes(attempt.OriginalPath));
    }

    [Theory]
    [Trait("Category", "MockFolderIntake")]
    [InlineData(false, "plain", SigningMode.Single)]
    [InlineData(true, "plain", SigningMode.Single)]
    [InlineData(false, "copies", SigningMode.Single)]
    [InlineData(true, "copies", SigningMode.Single)]
    [InlineData(false, "copies", SigningMode.Dual)]
    [InlineData(true, "copies", SigningMode.Dual)]
    [InlineData(false, "source-directory", SigningMode.Single)]
    [InlineData(true, "source-directory", SigningMode.Single)]
    [InlineData(false, "output-directory", SigningMode.Single)]
    [InlineData(true, "output-directory", SigningMode.Single)]
    [InlineData(true, "nested", SigningMode.Single)]
    [InlineData(true, "nested", SigningMode.Dual)]
    public async Task FileAndFolderIntakePublishLiteralCopyNamesWithoutChangingSigningPlan(
        bool importFolder,
        string layout,
        SigningMode requestedMode)
    {
        string inputRoot = Path.Combine(root, layout == "source-directory" ? "\u8f93\u5165 (1)" : "\u8f93\u5165");
        string outputRoot = Path.Combine(root, layout == "output-directory" ? "\u8f93\u51fa (2)" : "\u8f93\u51fa");
        string[] relativePaths = Enumerable.Range(5, 3).Select(index =>
        {
            string name = layout is "copies" or "nested"
                ? $"Anxin-Certificate-Signing-Tool-1.0.32-win-x64 - \u526f\u672c ({index}) - \u526f\u672c.msi"
                : $"installer-{index}.msi";
            return layout == "nested" && index > 5
                ? Path.Combine("\u5b50\u76ee\u5f55 (3)", $"level-{index}", name)
                : name;
        }).ToArray();
        byte[] originalBytes = Encoding.UTF8.GetBytes("synthetic installer fixture; not a real MSI\r\n");
        foreach (string relativePath in relativePaths)
        {
            string path = Path.Combine(inputRoot, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, originalBytes);
        }

        var planner = new IntakePlanner(new StubSubjectProbe(CreateSubject));
        var admittedFiles = new List<IntakeFile>();
        if (importFolder)
        {
            IntakePlan folderPlan = await planner.CreateAsync([inputRoot], true, outputRoot, CancellationToken.None);
            admittedFiles.AddRange(folderPlan.Files);
        }
        else
        {
            foreach (string relativePath in relativePaths)
            {
                IntakePlan filePlan = await planner.CreateAsync(
                    [Path.Combine(inputRoot, relativePath)], false, outputRoot, CancellationToken.None);
                admittedFiles.Add(Assert.Single(filePlan.Files));
            }
        }

        var intake = new IntakePlan(outputRoot, admittedFiles);
        Assert.Equal(3, intake.Files.Count);
        SigningPlan plan = CreatePlan(requestedMode, ".msi");
        string planBefore = SigningPlanJson.Serialize(plan);
        using Process owner = Process.GetCurrentProcess();
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        var bridgeVerifier = new FakeSipVerifier();
        WindowsPowerShellSipBridge bridge = CreateBridge(runner, verifier: bridgeVerifier);

        foreach (IntakeFile file in intake.Files)
        {
            var signer = new BridgeFixtureSigner(bridge, file.OriginalPath, plan, owner);
            var publisher = new TransactionalFilePublisher(signer, new SyntheticFixtureVerifier(originalBytes));
            PublishReceipt receipt = await publisher.PublishAsync(file, CancellationToken.None);

            Assert.Equal(PublishStatus.Published, receipt.Status);
            Assert.Equal(Path.Combine(outputRoot, file.RelativePath), receipt.DestinationPath);
            Assert.Contains(file.RelativePath, relativePaths);
            Assert.Equal(originalBytes, File.ReadAllBytes(file.OriginalPath));
            Assert.Equal(receipt.OriginalSha256, Convert.ToHexString(SHA256.HashData(originalBytes)));
            Assert.Equal(receipt.PublishedSha256, await HashAsync(file.DestinationPath));
            Assert.Equal(planBefore, SigningPlanJson.Serialize(plan));
            Assert.Equal(SigningMode.Single, plan.EffectiveMode);
            Assert.Single(plan.Legs);
            Assert.Equal(FileDigestAlgorithm.Sha256, plan.Legs[0].FileDigest);
            Assert.False(plan.Legs[0].Append);
            Assert.DoesNotContain(file.OriginalPath, runner.StartInfo!.ArgumentList);
            Assert.DoesNotContain(runner.StartInfo.ArgumentList, argument => argument.Contains(file.RelativePath, StringComparison.Ordinal));
        }

        Assert.Equal(3, runner.CallCount);
        Assert.Equal(3, bridgeVerifier.SignedCallCount);
        Assert.Equal(3, Directory.GetFiles(outputRoot, "*.msi", SearchOption.AllDirectories).Length);
        Assert.Empty(Directory.GetDirectories(outputRoot, ".codesigner-staging-*", SearchOption.AllDirectories));
    }

    [Theory]
    [Trait("Category", "MockFolderIntake")]
    [InlineData("relative")]
    [InlineData("noncanonical")]
    [InlineData("same-file")]
    [InlineData("missing")]
    [InlineData("extension")]
    [InlineData("owner")]
    [InlineData("unowned-stage")]
    public async Task LiteralCopyNamesDoNotBypassCanonicalOwnershipOrPlanGuards(string invalidCase)
    {
        Attempt attempt = CreateAttempt("installer (5).msi", "synthetic MSI fixture");
        string originalPath = invalidCase switch
        {
            "relative" => Path.GetFileName(attempt.OriginalPath),
            "noncanonical" => Path.Combine(Path.GetDirectoryName(attempt.OriginalPath)!, ".", Path.GetFileName(attempt.OriginalPath)),
            "same-file" => attempt.StagedPath,
            "missing" => Path.Combine(Path.GetDirectoryName(attempt.OriginalPath)!, "missing (6).msi"),
            _ => attempt.OriginalPath
        };
        string stagedPath = attempt.StagedPath;
        if (invalidCase == "unowned-stage")
        {
            stagedPath = Path.Combine(root, "unowned (5).msi");
            File.Copy(attempt.OriginalPath, stagedPath);
        }

        byte[] originalBytes = File.ReadAllBytes(attempt.OriginalPath);
        byte[] stagedBytes = File.ReadAllBytes(stagedPath);
        var runner = new FakeProcessRunner { MutateStagedFile = true, ResponseJson = SuccessResponse() };
        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            originalPath,
            stagedPath,
            CreatePlan(SigningMode.Single, invalidCase == "extension" ? ".ps1" : ".msi"),
            invalidCase == "owner" ? 0 : attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.Equal(WindowsSipSigningError.InvalidInput, result.Error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(originalBytes, File.ReadAllBytes(attempt.OriginalPath));
        Assert.Equal(stagedBytes, File.ReadAllBytes(stagedPath));
    }

    [Theory]
    [InlineData("payload;whoami.ps1")]
    [InlineData("payload$(whoami).ps1")]
    [InlineData("payload&whoami.ps1")]
    public async Task CompatibilityBridgeRejectsInjectionShapedPathsBeforeProcess(string fileName)
    {
        Attempt attempt = CreateAttempt(fileName, "Write-Output test\r\n");
        var runner = new FakeProcessRunner { ResponseJson = SuccessResponse() };
        WindowsPowerShellSipBridge bridge = CreateBridge(runner);

        WindowsSipSigningResult result = await bridge.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            reportProgress: null,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(WindowsSipSigningError.InvalidInput, result.Error);
        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public async Task CompatibilityBridgeRejectsInjectionShapedTimestampArgumentBeforeProcess()
    {
        Attempt attempt = CreateAttempt("timestamp.ps1", "Write-Output test\r\n");
        var runner = new FakeProcessRunner { ResponseJson = SuccessResponse() };
        WindowsPowerShellSipBridge bridge = CreateBridge(runner);

        WindowsSipSigningResult result = await bridge.ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1", "https://tsa.example.test/%24%28whoami%29"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.Equal(WindowsSipSigningError.InvalidInput, result.Error);
        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public async Task CompatibilityBridgeDistinguishesMissingDeniedAndUnavailableSip()
    {
        Attempt attempt = CreateAttempt("payload.ps1", "Write-Output test\r\n");
        SigningPlan plan = CreatePlan(SigningMode.Single, ".ps1");
        var missingEnvironment = new FakeWindowsPowerShellEnvironment { ExecutableExists = false };
        var unusedRunner = new FakeProcessRunner();
        WindowsSipSigningResult missing = await CreateBridge(unusedRunner, missingEnvironment).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan,
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        var deniedRunner = new FakeProcessRunner
        {
            ProcessResult = new WindowsPowerShellProcessResult(
                -1,
                WindowsPowerShellProcessStartFailure.ExecutionDenied)
        };
        WindowsSipSigningResult denied = await CreateBridge(deniedRunner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan,
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        var sipRunner = new FakeProcessRunner();
        var unavailableProbe = new StubSubjectProbe(_ => throw new SignableSubjectProbeException(
            SignableSubjectProbeError.SipUnavailable,
            "synthetic unavailable SIP"));
        WindowsSipSigningResult unavailableSip = await CreateBridge(
            sipRunner,
            subjectProbe: unavailableProbe).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan,
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.Equal(WindowsSipSigningError.PowerShellUnavailable, missing.Error);
        Assert.Equal(0, unusedRunner.CallCount);
        Assert.Equal(WindowsSipSigningError.ExecutionDenied, denied.Error);
        Assert.Equal(1, deniedRunner.CallCount);
        Assert.Equal(WindowsSipSigningError.SipUnavailable, unavailableSip.Error);
        Assert.Equal(0, sipRunner.CallCount);
    }

    [Theory]
    [InlineData("unsupported.xaml")]
    [InlineData("unsupported.jse")]
    [InlineData("unsupported.vbe")]
    public async Task CompatibilityBridgeRejectsUnsupportedScriptHandlerWithoutGenericFallback(string fileName)
    {
        Attempt attempt = CreateAttempt(fileName, "synthetic script fixture");
        var runner = new FakeProcessRunner();
        var unavailableProbe = new StubSubjectProbe(_ => throw new SignableSubjectProbeException(
            SignableSubjectProbeError.SipUnavailable,
            "synthetic unsupported handler"));

        WindowsSipSigningResult result = await CreateBridge(
            runner,
            subjectProbe: unavailableProbe).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, Path.GetExtension(fileName)),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.Equal(WindowsSipSigningError.SipUnavailable, result.Error);
        Assert.Equal(0, runner.CallCount);
    }

    [Theory]
    [InlineData("packageIncompatible", WindowsSipSigningError.PackageIncompatible)]
    [InlineData("certificateMismatch", WindowsSipSigningError.CertificateMismatch)]
    [InlineData("providerCancelled", WindowsSipSigningError.ProviderCancelled)]
    [InlineData("timestampUnavailable", WindowsSipSigningError.TimestampUnavailable)]
    [InlineData("verificationFailed", WindowsSipSigningError.VerificationFailed)]
    [InlineData("existingSignatureRejected", WindowsSipSigningError.ExistingSignatureRejected)]
    public async Task CompatibilityBridgeMapsStructuredFailureResponses(
        string resultCode,
        WindowsSipSigningError expectedError)
    {
        Attempt attempt = CreateAttempt("payload.msi", "synthetic installer fixture");
        var runner = new FakeProcessRunner
        {
            ProcessResult = new WindowsPowerShellProcessResult(1),
            ResponseJson = FailureResponse(resultCode)
        };

        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Dual, ".msi"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(expectedError, result.Error);
        Assert.Equal(FailureHResult, result.HResult);
    }

    [Fact]
    public async Task CompatibilityBridgeRejectsMalformedAndIncompleteSuccessJson()
    {
        Attempt malformedAttempt = CreateAttempt("malformed.ps1", "Write-Output malformed\r\n");
        var malformedRunner = new FakeProcessRunner { ResponseJson = "{not-json" };
        WindowsSipSigningResult malformed = await CreateBridge(malformedRunner).ExecuteAsync(
            malformedAttempt.OriginalPath,
            malformedAttempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            malformedAttempt.OwnerPid,
            malformedAttempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Attempt incompleteAttempt = CreateAttempt("incomplete.ps1", "Write-Output incomplete\r\n");
        var incompleteRunner = new FakeProcessRunner
        {
            MutateStagedFile = true,
            ResponseJson = SuccessResponse(timestampProtocol: null)
        };
        var verifier = new FakeSipVerifier();
        WindowsSipSigningResult incomplete = await CreateBridge(incompleteRunner, verifier: verifier).ExecuteAsync(
            incompleteAttempt.OriginalPath,
            incompleteAttempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            incompleteAttempt.OwnerPid,
            incompleteAttempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.Equal(WindowsSipSigningError.MalformedResponse, malformed.Error);
        Assert.Equal(WindowsSipSigningError.VerificationFailed, incomplete.Error);
        Assert.Equal(0, verifier.SignedCallCount);
    }

    [Theory]
    [MemberData(nameof(InvalidStandardOutputCases))]
    public async Task CompatibilityBridgeRejectsNonCanonicalStandardOutput(string output)
    {
        Attempt attempt = CreateAttempt("invalid-output.ps1", "Write-Output invalid\r\n");
        var runner = new FakeProcessRunner
        {
            ResponseJson = output,
            ProcessResult = new WindowsPowerShellProcessResult(0)
        };

        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(WindowsSipSigningError.MalformedResponse, result.Error);
    }

    [Fact]
    public async Task CompatibilityBridgeIgnoresStaleBridgeFilesAndCannotRedirectPipedRequest()
    {
        Attempt attempt = CreateAttempt("immutable.ps1", "Write-Output immutable\r\n");
        string redirectedPath = Path.Combine(root, "redirected.ps1");
        File.WriteAllText(redirectedPath, "must remain unchanged\r\n", new UTF8Encoding(false));
        string redirectedBefore = File.ReadAllText(redirectedPath);
        var runner = new FakeProcessRunner
        {
            MutateStagedFile = true,
            ResponseJson = SuccessResponse(),
            ReplaceBridgeProtocolFiles = true,
            RedirectedPath = redirectedPath
        };
        SigningPlan plan = CreatePlan(SigningMode.Single, ".ps1");

        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan,
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);

        Assert.True(result.Succeeded, result.Error.ToString());
        Assert.NotEqual(attempt.StagedPath, runner.ObservedTargetPath);
        Assert.Equal(Path.GetExtension(attempt.StagedPath), Path.GetExtension(runner.ObservedTargetPath));
        Assert.Equal(Thumbprint, runner.ObservedThumbprint);
        Assert.Equal(plan.Legs[0].Timestamp.Uri.AbsoluteUri, runner.ObservedTimestampUri);
        Assert.Equal(redirectedBefore, File.ReadAllText(redirectedPath));
        Assert.True(runner.NoProtocolFilesAfterRun);
    }

    [Fact]
    public async Task SystemRunnerWritesAndClosesStandardInputAndRedactsBoundedStandardError()
    {
        const string input = "immutable-stdin-sentinel";
        const string stderrSentinel = "PRIVATE-STDERR-SENTINEL";
        ProcessStartInfo startInfo = CreateDeterministicPowerShellStartInfo(
            "$value = [Console]::In.ReadToEnd(); [Console]::Out.Write($value); [Console]::Error.Write('" +
            stderrSentinel + "')");
        string qaDirectory = Path.Combine(root, "manual-qa-runner");
        Directory.CreateDirectory(qaDirectory);
        startInfo.WorkingDirectory = qaDirectory;
        string requestPath = Path.Combine(qaDirectory, "request.json");
        string responsePath = Path.Combine(qaDirectory, "response.json");
        Assert.False(File.Exists(requestPath));
        Assert.False(File.Exists(responsePath));
        var runner = new SystemWindowsPowerShellProcessRunner();

        WindowsPowerShellProcessResult result = await runner.RunAsync(
            startInfo,
            input,
            CancellationToken.None);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(input, Encoding.UTF8.GetString(Assert.IsType<byte[]>(result.StandardOutput)));
        Assert.False(result.StandardOutputLimitExceeded);
        Assert.True(result.StandardErrorBytes > 0);
        Assert.False(result.StandardErrorLimitExceeded);
        Assert.DoesNotContain(stderrSentinel, result.StandardErrorDiagnostic, StringComparison.Ordinal);
        Assert.Equal("StandardErrorRedacted", result.StandardErrorDiagnostic);
        Assert.False(File.Exists(requestPath));
        Assert.False(File.Exists(responsePath));
    }

    [Fact]
    public async Task SystemRunnerCancellationTerminatesHungChildAndCleansPipesRepeatedly()
    {
        var runner = new SystemWindowsPowerShellProcessRunner();
        Stopwatch elapsed = Stopwatch.StartNew();

        for (int iteration = 0; iteration < 3; iteration++)
        {
            ProcessStartInfo startInfo = CreateDeterministicPowerShellStartInfo(
                "Start-Sleep -Seconds 30");
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.RunAsync(
                startInfo,
                new string('X', 128 * 1024),
                cancellation.Token));
        }

        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task SystemRunnerBoundsBothOutputPipesAndNeverReturnsRawStandardError()
    {
        ProcessStartInfo startInfo = CreateDeterministicPowerShellStartInfo(
            "[Console]::Out.Write(('O' * 40000)); [Console]::Error.Write(('PRIVATE' * 7000))");
        var runner = new SystemWindowsPowerShellProcessRunner();

        WindowsPowerShellProcessResult result = await runner.RunAsync(
            startInfo,
            standardInput: null,
            CancellationToken.None);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(32 * 1024, Assert.IsType<byte[]>(result.StandardOutput).Length);
        Assert.True(result.StandardOutputLimitExceeded);
        Assert.Equal(8 * 1024 + 1, result.StandardErrorBytes);
        Assert.True(result.StandardErrorLimitExceeded);
        Assert.Equal("StandardErrorRedacted", result.StandardErrorDiagnostic);
        Assert.DoesNotContain("PRIVATE", result.StandardErrorDiagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompatibilityBridgeCancellationClosesInputAndRemovesStaleProtocolFiles()
    {
        Attempt attempt = CreateAttempt("cancelled.ps1", "Write-Output cancellation\r\n");
        string originalHash = await HashAsync(attempt.OriginalPath);
        string stagedHash = await HashAsync(attempt.StagedPath);
        string redirectedPath = Path.Combine(root, "cancel-redirected.ps1");
        File.WriteAllText(redirectedPath, "must remain unchanged\r\n", new UTF8Encoding(false));
        var runner = new FakeProcessRunner
        {
            ReplaceBridgeProtocolFiles = true,
            RedirectedPath = redirectedPath,
            WaitForCancellation = true
        };
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        WindowsSipSigningResult result = await CreateBridge(runner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            cancellation.Token);

        Assert.Equal(WindowsSipSigningError.Cancelled, result.Error);
        Assert.True(runner.StandardInputClosed);
        Assert.True(runner.NoProtocolFilesAfterRun);
        Assert.Equal("must remain unchanged\r\n", File.ReadAllText(redirectedPath));
        Assert.Equal(originalHash, await HashAsync(attempt.OriginalPath));
        Assert.Equal(stagedHash, await HashAsync(attempt.StagedPath));
    }

    [Fact]
    public async Task PowerShellCommandRejectsMalformedDuplicateUnknownMissingTrailingDeepAndOversizedRequests()
    {
        Attempt attempt = CreateAttempt("request-validation.ps1", "Write-Output validation\r\n");
        var captureRunner = new FakeProcessRunner { ResponseJson = SuccessResponse() };
        WindowsSipSigningResult captureResult = await CreateBridge(captureRunner).ExecuteAsync(
            attempt.OriginalPath,
            attempt.StagedPath,
            CreatePlan(SigningMode.Single, ".ps1"),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            null,
            CancellationToken.None);
        Assert.True(captureResult.Succeeded, captureResult.Error.ToString());
        string valid = Assert.IsType<string>(captureRunner.RequestJson);
        using JsonDocument document = JsonDocument.Parse(valid);
        Dictionary<string, object?> fields = document.RootElement.EnumerateObject().ToDictionary(
            property => property.Name,
            property => JsonSerializer.Deserialize<object?>(property.Value.GetRawText()));
        var missing = new Dictionary<string, object?>(fields, StringComparer.Ordinal);
        missing.Remove("timestampUri");
        var unknown = new Dictionary<string, object?>(fields, StringComparer.Ordinal)
        {
            ["unexpected"] = true
        };
        string duplicate = valid.Replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            StringComparison.Ordinal);
        string excessiveDepth = "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}";
        string[] invalidRequests =
        [
            "{not-json",
            JsonSerializer.Serialize(missing),
            JsonSerializer.Serialize(unknown),
            duplicate,
            valid + valid,
            valid + " trailing",
            excessiveDepth,
            new string(' ', 32 * 1024 + 1) + valid
        ];
        string executable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        var runner = new SystemWindowsPowerShellProcessRunner();

        for (int invalidIndex = 0; invalidIndex < invalidRequests.Length; invalidIndex++)
        {
            string invalidRequest = invalidRequests[invalidIndex];
            ProcessStartInfo startInfo = WindowsPowerShellSipBridge.CreateStartInfo(
                executable,
                Path.GetDirectoryName(attempt.StagedPath)!);
            WindowsPowerShellProcessResult result = await runner.RunAsync(
                startInfo,
                invalidRequest,
                CancellationToken.None);

            Assert.Equal(1, result.ExitCode);
            Assert.False(result.StandardOutputLimitExceeded);
            using JsonDocument response = JsonDocument.Parse(Assert.IsType<byte[]>(result.StandardOutput));
            Assert.True(
                string.Equals("invalidInput", response.RootElement.GetProperty("resultCode").GetString(), StringComparison.Ordinal),
                $"Malformed request case {invalidIndex} was not classified as invalid input.");
            Assert.DoesNotContain(Thumbprint, result.StandardErrorDiagnostic, StringComparison.Ordinal);
        }
    }

    public static TheoryData<string> InvalidStandardOutputCases()
    {
        string success = SuccessResponse();
        using JsonDocument document = JsonDocument.Parse(success);
        Dictionary<string, object?> fields = document.RootElement.EnumerateObject().ToDictionary(
            property => property.Name,
            property => JsonSerializer.Deserialize<object?>(property.Value.GetRawText()));
        var missing = new Dictionary<string, object?>(fields, StringComparer.Ordinal);
        missing.Remove("cmsVerified");
        var unknown = new Dictionary<string, object?>(fields, StringComparer.Ordinal)
        {
            ["unexpected"] = true
        };
        string duplicate = success.Replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            StringComparison.Ordinal);
        string excessiveDepth = "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}";

        return new TheoryData<string>
        {
            "",
            "{not-json",
            JsonSerializer.Serialize(missing),
            JsonSerializer.Serialize(unknown),
            duplicate,
            success + success,
            success + " trailing",
            excessiveDepth,
            new string(' ', 32 * 1024) + success
        };
    }

    [Fact]
    public async Task CompatibilityReadinessProbeUsesOnlyFixedWindowsPowerShell51Command()
    {
        var runner = new FakeProcessRunner();
        WindowsPowerShellBridgeReadinessProbe probe = new(
            new FakeWindowsPowerShellEnvironment(),
            runner);

        WindowsPowerShellBridgeReadiness readiness = await probe.ProbeAsync(CancellationToken.None);

        Assert.Equal(WindowsPowerShellBridgeStatus.Available, readiness.Status);
        Assert.Equal("5.1", readiness.Version);
        Assert.Equal(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            readiness.ExecutablePath);
        ProcessStartInfo startInfo = Assert.IsType<ProcessStartInfo>(runner.StartInfo);
        Assert.Equal(
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WindowsPowerShellSipCommand.Probe],
            startInfo.ArgumentList);
        Assert.DoesNotContain(startInfo.ArgumentList, argument =>
            argument.Contains("ExecutionPolicy", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CompatibilityVerifierRequiresExactSha256SignerAndDefersTimestampTrustToWindowsSip()
    {
        Attempt attempt = CreateAttempt("verified.msi", "synthetic installer fixture");
        SigningPlan plan = CreatePlan(SigningMode.Single, ".msi");
        AuthenticodeTimestampInspection exactTimestamp = new(
            AuthenticodeTimestampKind.Rfc3161,
            AuthenticodeOids.Sha256,
            CryptographicallyValid: true,
            ChainValid: true,
            TimeValid: true,
            TimestampingEkuValid: true);
        var inspector = new StubSignatureInspector
        {
            Inspection = new AuthenticodeSignatureInspection(
                0,
                0,
                AuthenticodeOids.Sha256,
                Thumbprint,
                [1, 2, 3],
                exactTimestamp)
        };
        WindowsSipSignatureVerifier verifier = new(
            inspector,
            new AcceptingCertificateStoreMembership(),
            new StubSubjectProbe(CreateSubject));

        WindowsSipVerificationResult exact = verifier.VerifySigned(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan);
        inspector.Inspection = inspector.Inspection with { FileDigestAlgorithmOid = AuthenticodeOids.Sha1 };
        WindowsSipVerificationResult sha1 = verifier.VerifySigned(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan);
        inspector.Inspection = inspector.Inspection with
        {
            FileDigestAlgorithmOid = AuthenticodeOids.Sha256,
            SignerThumbprint = new string('A', 40)
        };
        WindowsSipVerificationResult wrongSigner = verifier.VerifySigned(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan);
        inspector.Inspection = inspector.Inspection with
        {
            SignerThumbprint = Thumbprint,
            Timestamp = exactTimestamp with { Kind = AuthenticodeTimestampKind.LegacyCounterSignature }
        };
        WindowsSipVerificationResult legacyTimestamp = verifier.VerifySigned(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan);
        inspector.Inspection = inspector.Inspection with
        {
            Timestamp = exactTimestamp with { MessageImprintAlgorithmOid = AuthenticodeOids.Sha1 }
        };
        WindowsSipVerificationResult sha1Timestamp = verifier.VerifySigned(
            attempt.OriginalPath,
            attempt.StagedPath,
            plan);

        Assert.True(exact.Succeeded);
        Assert.Equal(WindowsSipVerificationError.VerificationFailed, sha1.Error);
        Assert.Equal(WindowsSipVerificationError.VerificationFailed, wrongSigner.Error);
        Assert.True(legacyTimestamp.Succeeded);
        Assert.True(sha1Timestamp.Succeeded);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static WindowsPowerShellSipBridge CreateBridge(
        FakeProcessRunner runner,
        FakeWindowsPowerShellEnvironment? environment = null,
        ISignableSubjectProbe? subjectProbe = null,
        FakeSipVerifier? verifier = null,
        IWindowsSipAtomicFileReplacer? replacer = null) => new(
        runner,
        environment ?? new FakeWindowsPowerShellEnvironment(),
        subjectProbe ?? new StubSubjectProbe(CreateSubject),
        verifier ?? new FakeSipVerifier(),
        replacer ?? new RecordingAtomicFileReplacer());

    private Attempt CreateAttempt(string fileName, string content)
        => CreateAttempt(fileName, new UTF8Encoding(false).GetBytes(content));

    private Attempt CreateAttempt(string fileName, byte[] content)
    {
        Directory.CreateDirectory(root);
        string itemRoot = Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(itemRoot);
        string originalPath = Path.Combine(itemRoot, fileName);
        File.WriteAllBytes(originalPath, content);
        string stagingRoot = Path.Combine(itemRoot, "output");
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(stagingRoot);
        string stagedPath = Path.Combine(attemptDirectory, fileName);
        File.Copy(originalPath, stagedPath);
        using Process owner = Process.GetCurrentProcess();
        return new Attempt(
            originalPath,
            stagedPath,
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero));
    }

    private Attempt CreateLargeAttempt(string fileName, long length)
    {
        Directory.CreateDirectory(root);
        string itemRoot = Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(itemRoot);
        string originalPath = Path.Combine(itemRoot, fileName);
        using (FileStream stream = new(originalPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.SetLength(length);
        }

        string stagingRoot = Path.Combine(itemRoot, "output");
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(stagingRoot);
        string stagedPath = Path.Combine(attemptDirectory, fileName);
        File.Copy(originalPath, stagedPath);
        using Process owner = Process.GetCurrentProcess();
        return new Attempt(
            originalPath,
            stagedPath,
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero));
    }

    private static async Task<string> HashAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream));
    }

    private static void ApplyChildBoundaryRace(string race, Attempt attempt, string workPath)
    {
        if (race == "work")
        {
            ReplaceWithText(workPath, "replacement work identity\r\n");
            return;
        }

        if (race == "request-directory")
        {
            string bridgeDirectory = Assert.IsType<string>(Path.GetDirectoryName(workPath));
            Directory.Delete(bridgeDirectory, recursive: true);
            Directory.CreateDirectory(bridgeDirectory);
            File.WriteAllText(workPath, "replacement directory identity\r\n", new UTF8Encoding(false));
            return;
        }

        if (race == "canonical")
        {
            ReplaceWithText(attempt.StagedPath, "replacement canonical identity\r\n");
            return;
        }

        Assert.Equal("original", race);
        ReplaceWithText(attempt.OriginalPath, "replacement original identity\r\n");
    }

    private static void ReplaceWithText(string destinationPath, string content)
    {
        string replacementPath = Path.Combine(
            Path.GetDirectoryName(destinationPath)!,
            $"replacement-{Guid.NewGuid():N}{Path.GetExtension(destinationPath)}");
        File.WriteAllText(replacementPath, content, new UTF8Encoding(false));
        File.Replace(replacementPath, destinationPath, destinationBackupFileName: null);
    }

    private static SigningPlan CreatePlan(
        SigningMode mode,
        string extension,
        string? timestampUri = null)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return mode == SigningMode.Single
            ? Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, extension, timestampUri).Value)
            : Assert.IsType<SigningPlan>(SigningPlan.TryCreateDual(certificate, null, extension, timestampUri).Value);
    }

    private static SignableSubject CreateSubject(string path)
    {
        SigningSubject policySubject = Assert.IsType<SigningSubject>(
            SigningSubject.TryCreateForExtension(Path.GetExtension(path)).Value);
        ScriptContentProfile? profile = policySubject.FormatFamily is
            SigningFormatFamily.PowerShellScript or SigningFormatFamily.WindowsScript
                ? new ScriptContentProfile(
                    ScriptEncodingKind.Utf8,
                    ScriptNewlineKind.CrLf,
                    HasSignatureBlock: false,
                    IsEncoded: false)
                : null;
        return new SignableSubject(policySubject, ScriptSubjectGuid, profile);
    }

    private static string SuccessResponse(string? timestampProtocol = "rfc3161") => JsonSerializer.Serialize(
        new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["resultCode"] = "signed",
            ["hresult"] = 0,
            ["signatureStatus"] = "Valid",
            ["fileDigest"] = "sha256",
            ["signerThumbprint"] = Thumbprint,
            ["timestampProtocol"] = timestampProtocol,
            ["timestampDigest"] = "sha256",
            ["cmsVerified"] = true,
            ["subjectVerified"] = true,
            ["contentVerified"] = true,
            ["existingSignatureDisposition"] = "signed"
        });

    private static string ExistingValidResponse() => JsonSerializer.Serialize(
        new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["resultCode"] = "existingSignatureValid",
            ["hresult"] = 0,
            ["signatureStatus"] = "Valid",
            ["fileDigest"] = null,
            ["signerThumbprint"] = null,
            ["timestampProtocol"] = null,
            ["timestampDigest"] = null,
            ["cmsVerified"] = true,
            ["subjectVerified"] = true,
            ["contentVerified"] = true,
            ["existingSignatureDisposition"] = "skip"
        });

    private static string FailureResponse(string resultCode) => JsonSerializer.Serialize(
        new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["resultCode"] = resultCode,
            ["hresult"] = FailureHResult,
            ["signatureStatus"] = null,
            ["fileDigest"] = null,
            ["signerThumbprint"] = null,
            ["timestampProtocol"] = null,
            ["timestampDigest"] = null,
            ["cmsVerified"] = false,
            ["subjectVerified"] = false,
            ["contentVerified"] = false,
            ["existingSignatureDisposition"] = null
        });

    private static ProcessStartInfo CreateDeterministicPowerShellStartInfo(string command)
    {
        string executable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        ProcessStartInfo startInfo = WindowsPowerShellSipBridge.CreateStartInfo(
            executable,
            Environment.CurrentDirectory);
        startInfo.ArgumentList[startInfo.ArgumentList.Count - 1] = command;
        return startInfo;
    }

    private sealed record Attempt(
        string OriginalPath,
        string StagedPath,
        int OwnerPid,
        DateTimeOffset OwnerStartUtc);

    private sealed class FakeProcessRunner : IWindowsPowerShellProcessRunner
    {
        private string? bridgeWorkingDirectory;

        public int CallCount { get; private set; }

        public ProcessStartInfo? StartInfo { get; private set; }

        public string? RequestJson { get; private set; }

        public string? ResponseJson { get; init; }

        public bool MutateStagedFile { get; init; }

        public bool ReplaceBridgeProtocolFiles { get; init; }

        public bool WaitForCancellation { get; init; }

        public string? RedirectedPath { get; init; }

        public Action<string>? BeforeReturn { get; init; }

        public string? ObservedTargetPath { get; private set; }

        public string? ObservedThumbprint { get; private set; }

        public string? ObservedTimestampUri { get; private set; }

        public bool WorkFileExistedDuringRun { get; private set; }

        public int StandardInputBytes { get; private set; }

        public int StandardOutputBytes { get; private set; }

        public bool StandardInputClosed { get; private set; }

        public bool NoProtocolFilesDuringRun { get; private set; }

        public bool NoProtocolFilesAfterRun => bridgeWorkingDirectory is not null &&
            !File.Exists(Path.Combine(bridgeWorkingDirectory, "request.json")) &&
            !File.Exists(Path.Combine(bridgeWorkingDirectory, "response.json"));

        public WindowsPowerShellProcessResult ProcessResult { get; init; } = new(0);

        public async Task<WindowsPowerShellProcessResult> RunAsync(
            ProcessStartInfo startInfo,
            string? standardInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            StartInfo = startInfo;
            bridgeWorkingDirectory = startInfo.WorkingDirectory;
            RequestJson = standardInput;
            StandardInputBytes = standardInput is null ? 0 : Encoding.UTF8.GetByteCount(standardInput);
            StandardInputClosed = true;
            string requestPath = Path.Combine(startInfo.WorkingDirectory, "request.json");
            string responsePath = Path.Combine(startInfo.WorkingDirectory, "response.json");
            NoProtocolFilesDuringRun = !File.Exists(requestPath) && !File.Exists(responsePath);
            if (ReplaceBridgeProtocolFiles)
            {
                string redirected = Assert.IsType<string>(RedirectedPath);
                File.WriteAllText(requestPath, "{\"stagedPath\":" + JsonSerializer.Serialize(redirected) + "}");
                File.WriteAllText(responsePath, "{\"resultCode\":\"signed\"}");
            }

            if (standardInput is not null)
            {
                using JsonDocument request = JsonDocument.Parse(standardInput);
                ObservedTargetPath = Assert.IsType<string>(request.RootElement.GetProperty("stagedPath").GetString());
                ObservedThumbprint = Assert.IsType<string>(request.RootElement.GetProperty("certificateThumbprint").GetString());
                ObservedTimestampUri = Assert.IsType<string>(request.RootElement.GetProperty("timestampUri").GetString());
                WorkFileExistedDuringRun = File.Exists(ObservedTargetPath);
                if (MutateStagedFile)
                {
                    File.AppendAllText(ObservedTargetPath, "# SIG # synthetic-test-only\r\n", new UTF8Encoding(false));
                }

                BeforeReturn?.Invoke(ObservedTargetPath);
            }

            byte[] output = ResponseJson is null ? [] : Encoding.UTF8.GetBytes(ResponseJson);
            StandardOutputBytes = output.Length;
            if (WaitForCancellation)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            return ProcessResult with { StandardOutput = output };
        }
    }

    private sealed class BridgeFixtureSigner(
        WindowsPowerShellSipBridge bridge,
        string originalPath,
        SigningPlan plan,
        Process owner) : IStagedFileSigner
    {
        public async Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            WindowsSipSigningResult result = await bridge.ExecuteAsync(
                originalPath,
                stagedPath,
                plan,
                owner.Id,
                new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
                null,
                cancellationToken);
            Assert.True(result.Succeeded, $"Bridge rejected fixture: {result.Error}; HRESULT=0x{result.HResult:X8}");
        }
    }

    private sealed class SyntheticFixtureVerifier(byte[] originalBytes) : IStagedFileVerifier
    {
        public Task VerifyAsync(string stagedPath, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] expected = [.. originalBytes, .. Encoding.UTF8.GetBytes("# SIG # synthetic-test-only\r\n")];
            Assert.Equal(expected, File.ReadAllBytes(stagedPath));
            return Task.CompletedTask;
        }
    }

    private sealed class FakeWindowsPowerShellEnvironment : IWindowsPowerShellEnvironment
    {
        public bool IsWindows { get; init; } = true;

        public string WindowsDirectory { get; init; } = "C:\\Windows";

        public bool ExecutableExists { get; init; } = true;

        public bool FileExists(string path) => ExecutableExists;

        public FileAttributes GetAttributes(string path) => FileAttributes.Normal;
    }

    private sealed class StubSubjectProbe(Func<string, SignableSubject> probe) : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => probe(path);
    }

    private sealed class FakeSipVerifier : IWindowsSipSignatureVerifier
    {
        public int SignedCallCount { get; private set; }

        public int ExistingCallCount { get; private set; }

        public WindowsSipVerificationResult Result { get; init; } = WindowsSipVerificationResult.Success();

        public Action<string>? DuringVerification { get; init; }

        public string? ObservedStagedPath { get; private set; }

        public WindowsSipVerificationResult VerifySigned(
            string originalPath,
            string stagedPath,
            SigningPlan plan)
        {
            SignedCallCount++;
            ObservedStagedPath = stagedPath;
            DuringVerification?.Invoke(stagedPath);
            return Result;
        }

        public WindowsSipVerificationResult VerifyExisting(
            string originalPath,
            string stagedPath,
            SigningPlan plan)
        {
            ExistingCallCount++;
            ObservedStagedPath = stagedPath;
            DuringVerification?.Invoke(stagedPath);
            return Result;
        }
    }

    private sealed class RecordingAtomicFileReplacer : IWindowsSipAtomicFileReplacer
    {
        public int CallCount { get; private set; }

        public string? SourcePath { get; private set; }

        public string? DestinationPath { get; private set; }

        public bool ThrowOnReplace { get; init; }

        public int AtomicReplaceCount { get; private set; }

        public Action<string, string>? BeforeValidation { get; init; }

        public bool TryReplace(
            string sourcePath,
            WindowsSipFileIdentity expectedSourceIdentity,
            string expectedSourceSha256,
            string destinationPath,
            WindowsSipFileIdentity expectedDestinationIdentity,
            string expectedDestinationSha256)
        {
            CallCount++;
            SourcePath = sourcePath;
            DestinationPath = destinationPath;
            BeforeValidation?.Invoke(sourcePath, destinationPath);
            if (ThrowOnReplace)
            {
                throw new IOException("Synthetic atomic replacement failure.");
            }

            var systemReplacer = new SystemWindowsSipAtomicFileReplacer();
            bool replaced = systemReplacer.TryReplace(
                sourcePath,
                expectedSourceIdentity,
                expectedSourceSha256,
                destinationPath,
                expectedDestinationIdentity,
                expectedDestinationSha256);
            if (replaced)
            {
                AtomicReplaceCount++;
            }

            return replaced;
        }
    }

    private sealed class StubSignatureInspector : IAuthenticodeSignatureInspector
    {
        public AuthenticodeSignatureInspection Inspection { get; set; } = null!;

        public AuthenticodeSignatureCountInspection GetSignatureCount(string path) => new(0, 0);

        public AuthenticodeSignatureInspection InspectSignature(string path, uint index) => Inspection;
    }

    private sealed class AcceptingCertificateStoreMembership : ICertificateStoreMembership
    {
        public bool ContainsExact(CertificateReference reference, byte[] certificateDer) => true;
    }
}

public sealed class WindowsPowerShellSipWorkerTests : IDisposable
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private const int FailureHResult = unchecked((int)0x80004005);
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "codesigner-sip-worker-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task WorkerRoutesSipPlanToBridgeWithoutCreatingPeComponents()
    {
        Attempt attempt = CreateAttempt();
        SigningPlan plan = CreatePlan();
        var bridge = new FakeWorkerSipBridge(WindowsSipSigningResult.Success(
            new string('A', 64),
            new string('B', 64)));
        int nativeFactoryCalls = 0;
        int verifierFactoryCalls = 0;
        IStreamingWorkerCommandHandler handler = CreateHandler(
            () =>
            {
                nativeFactoryCalls++;
                throw new InvalidOperationException("PE signing must not run for a SIP subject.");
            },
            () =>
            {
                verifierFactoryCalls++;
                throw new InvalidOperationException("PE verification must not run for a SIP subject.");
            },
            () => bridge);
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.SignBatch,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(plan),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            OperationId);
        var progress = new List<WorkerProgress>();

        WorkerResponse response = await handler.HandleAsync(
            request,
            (item, _) =>
            {
                progress.Add(item);
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.True(response.Success);
        Assert.Equal(WorkerResponseCodes.SigningCompleted, response.Code);
        Assert.Equal(WorkerExecutionRoute.WindowsSip, response.Route);
        Assert.Equal(1, bridge.CallCount);
        Assert.True(bridge.Disposed);
        SigningPlan bridgedPlan = Assert.IsType<SigningPlan>(bridge.Plan);
        Assert.Equal(SigningMode.Single, bridgedPlan.EffectiveMode);
        Assert.Equal(SigningEngine.WindowsSip, bridgedPlan.Engine);
        Assert.Equal(SigningCapability.WindowsSipSingleOnly, bridgedPlan.Subject.Capability);
        Assert.Equal(0, nativeFactoryCalls);
        Assert.Equal(0, verifierFactoryCalls);
        Assert.Equal(
            [WorkerProgressPhases.SigningPrimary, WorkerProgressPhases.Verifying],
            progress.Select(item => item.Phase));
    }

    [Fact]
    public async Task WorkerConvertsUnexpectedSipBridgeExceptionToTypedFailure()
    {
        Attempt attempt = CreateAttempt();
        SigningPlan plan = CreatePlan();
        IStreamingWorkerCommandHandler handler = CreateHandler(
            () => throw new InvalidOperationException("PE signing must not run for a SIP subject."),
            () => throw new InvalidOperationException("PE verification must not run for a SIP subject."),
            () => throw new InvalidOperationException("Synthetic SIP bridge failure."));
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.SignBatch,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(plan),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            OperationId);

        WorkerResponse response = await handler.HandleAsync(
            request,
            static (_, _) => ValueTask.CompletedTask,
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
        Assert.Equal(WorkerExecutionRoute.WindowsSip, response.Route);
        Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
        Assert.NotEqual(FailureHResult, response.HResult);
    }

    [Theory]
    [InlineData(true, WorkerResponseCodes.Cancelled, WorkerFailureCode.Cancelled)]
    public async Task WorkerFailsSipClosedBeforeEveryFactoryAndPreservesOriginalAndStage(
        bool cancellationRequested,
        string expectedCode,
        WorkerFailureCode expectedFailure)
    {
        Attempt attempt = CreateAttempt();
        SigningPlan plan = CreatePlan();
        byte[] originalBefore = await File.ReadAllBytesAsync(attempt.OriginalPath);
        byte[] stagedBefore = await File.ReadAllBytesAsync(attempt.StagedPath);
        int nativeFactoryCalls = 0;
        int verifierFactoryCalls = 0;
        int sipFactoryCalls = 0;
        IStreamingWorkerCommandHandler handler = CreateHandler(
            () =>
            {
                nativeFactoryCalls++;
                throw new InvalidOperationException("PE signing must not run for a SIP subject.");
            },
            () =>
            {
                verifierFactoryCalls++;
                throw new InvalidOperationException("PE verification must not run for a SIP subject.");
            },
            () =>
            {
                sipFactoryCalls++;
                throw new InvalidOperationException("SIP signing must fail before bridge construction.");
            });
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.SignBatch,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(plan),
            attempt.OwnerPid,
            attempt.OwnerStartUtc,
            OperationId);
        var progress = new List<WorkerProgress>();
        using var cancellation = new CancellationTokenSource();
        if (cancellationRequested)
        {
            cancellation.Cancel();
        }

        WorkerResponse response = await handler.HandleAsync(
            request,
            (item, _) =>
            {
                progress.Add(item);
                return ValueTask.CompletedTask;
            },
            cancellation.Token);

        Assert.False(response.Success);
        Assert.False(response.LegacyFallbackAttempted);
        Assert.Equal(expectedCode, response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.WindowsSip, response.Route);
        Assert.Equal(expectedFailure, response.Failure);
        Assert.Equal(WorkerCapabilities.WindowsSipSingleOnly, response.Capability);
        Assert.Equal(WorkerEngines.WindowsSip, response.Engine);
        Assert.Equal(WorkerVerifications.WindowsSip, response.Verification);
        Assert.Equal(0, nativeFactoryCalls);
        Assert.Equal(0, verifierFactoryCalls);
        Assert.Equal(0, sipFactoryCalls);
        Assert.Empty(progress);
        Assert.Equal(originalBefore, await File.ReadAllBytesAsync(attempt.OriginalPath));
        Assert.Equal(stagedBefore, await File.ReadAllBytesAsync(attempt.StagedPath));

        using var frame = new MemoryStream();
        await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);
        frame.Position = 0;
        Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(frame, CancellationToken.None));
    }

    [Theory]
    [InlineData(WindowsSipSigningError.PowerShellUnavailable, WorkerResponseCodes.WindowsPowerShellUnavailable)]
    [InlineData(WindowsSipSigningError.ExecutionDenied, WorkerResponseCodes.WindowsPowerShellExecutionDenied)]
    [InlineData(WindowsSipSigningError.SipUnavailable, WorkerResponseCodes.WindowsSipUnavailable)]
    [InlineData(WindowsSipSigningError.PackageIncompatible, WorkerResponseCodes.PackageIncompatible)]
    [InlineData(WindowsSipSigningError.CertificateMismatch, WorkerResponseCodes.CertificateMismatch)]
    [InlineData(WindowsSipSigningError.ProviderCancelled, WorkerResponseCodes.ProviderCancelled)]
    [InlineData(WindowsSipSigningError.TimestampUnavailable, WorkerResponseCodes.TimestampUnavailable)]
    [InlineData(WindowsSipSigningError.VerificationFailed, WorkerResponseCodes.VerifierDisagreement)]
    [InlineData(WindowsSipSigningError.MalformedResponse, WorkerResponseCodes.InvalidBridgeResponse)]
    public async Task WorkerMapsEverySipBridgeFailureToAnExactOutcome(
        WindowsSipSigningError error,
        string expectedCode)
    {
        Type handlerType = LoadHandlerType();
        MethodInfo map = Assert.IsAssignableFrom<MethodInfo>(handlerType.GetMethod(
            "FromSipResult",
            BindingFlags.NonPublic | BindingFlags.Static));
        WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(CreatePlan());
        WindowsSipSigningResult result = WindowsSipSigningResult.Failure(
            error,
            FailureHResult,
            new string('A', 64));

        WorkerResponse response = Assert.IsType<WorkerResponse>(map.Invoke(
            null,
            [result, OperationId, contract]));

        Assert.False(response.Success);
        Assert.Equal(expectedCode, response.Code);
        Assert.Equal(WorkerDiagnosticPhases.WorkerBridge, response.DiagnosticPhase);
        Assert.Equal(WorkerHResultOrigins.WorkerBridge, response.HResultOrigin);
        Assert.Equal(WorkerCapabilities.WindowsSipSingleOnly, response.Capability);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.WindowsSip, response.Route);
        Assert.NotNull(response.Failure);

        using var frame = new MemoryStream();
        await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);
        frame.Position = 0;
        Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(frame, CancellationToken.None));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private Attempt CreateAttempt()
    {
        Directory.CreateDirectory(root);
        string originalPath = Path.Combine(root, Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(originalPath, "Write-Output test\r\n", new UTF8Encoding(false));
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(Path.Combine(root, "output"));
        string stagedPath = Path.Combine(attemptDirectory, "payload.ps1");
        File.Copy(originalPath, stagedPath);
        using Process owner = Process.GetCurrentProcess();
        return new Attempt(
            originalPath,
            stagedPath,
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero));
    }

    private static SigningPlan CreatePlan()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return Assert.IsType<SigningPlan>(SigningPlan.TryCreateDual(certificate, null, ".ps1").Value);
    }

    private static IStreamingWorkerCommandHandler CreateHandler(
        Func<INativeSigningLegExecutor> signerFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<IWindowsSipSigningBridge> bridgeFactory)
    {
        Type handlerType = LoadHandlerType();
        return Assert.IsAssignableFrom<IStreamingWorkerCommandHandler>(Activator.CreateInstance(
            handlerType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args:
            [
                signerFactory,
                verifierFactory,
                bridgeFactory,
                (Func<IExistingSignatureInspector>)(() => new UnsignedExistingSignatureInspector()),
                (Action<WorkerProcessIdentity, WorkerProcessIdentity>)((_, _) => { })
            ],
            culture: null));
    }

    private static Type LoadHandlerType()
    {
        Assembly workerAssembly = Assembly.LoadFrom(WorkerAssemblyPath());
        return workerAssembly.GetType(
            "CodeSigner.Worker.ProductionSigningWorkerCommandHandler",
            throwOnError: true)!;
    }

    private static string WorkerAssemblyPath() => Path.Combine(
        FindRepositoryRoot(),
        "src",
        "CodeSigner.Worker",
        "bin",
#if DEBUG
        "Debug",
#else
        "Release",
#endif
        "net10.0-windows",
        "win-x64",
        "CodeSigner.Worker.dll");

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
    }

    private static async Task<string> HashAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream));
    }

    private sealed record Attempt(
        string OriginalPath,
        string StagedPath,
        int OwnerPid,
        DateTimeOffset OwnerStartUtc);

    private sealed class UnsignedExistingSignatureInspector : IExistingSignatureInspector
    {
        public ExistingSignatureInspectionResult Inspect(
            string originalPath,
            string stagedPath,
            SigningPlan plan,
            CancellationToken cancellationToken) => new(ExistingSignatureInspectionStatus.Unsigned, 0);
    }

    private sealed class FakeWorkerSipBridge(WindowsSipSigningResult result)
        : IWindowsSipSigningBridge, IDisposable
    {
        public int CallCount { get; private set; }

        public SigningPlan? Plan { get; private set; }

        public bool Disposed { get; private set; }

        public async Task<WindowsSipSigningResult> ExecuteAsync(
            string originalPath,
            string stagedPath,
            SigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            Func<WindowsSipSigningPhase, CancellationToken, ValueTask>? reportProgress,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            Plan = plan;
            if (reportProgress is not null)
            {
                await reportProgress(WindowsSipSigningPhase.Signing, cancellationToken);
                await reportProgress(WindowsSipSigningPhase.Verifying, cancellationToken);
            }

            return result;
        }

        public void Dispose() => Disposed = true;
    }
}
