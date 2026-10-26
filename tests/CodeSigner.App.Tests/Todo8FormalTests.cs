using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class Todo8FormalTests
{
    [Fact]
    [Trait("Category", "Todo8Formal")]
    public async Task WorkbenchContractCoversTheContentAwareSigningWorkflow()
    {
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var readiness = new TestReadinessAdapter(BlockedSnapshot());
        var intake = new TestIntakeAdapter();
        var batch = new TestBatchAdapter();
        var shell = new TestOperatorShell();
        await using var viewModel = batch.CreateWithDeterministicProgressContext(() => new SigningWorkbenchViewModel(
            readiness,
            intake,
            batch,
            shell,
            new HealthyWorkerHealthService(),
            new UnusedWorkerRepairService(),
            static _ => ValueTask.FromResult(true)));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();

        AssertCommandsAreExposed(viewModel);
        Assert.False(viewModel.CanSign);
        Assert.Equal("请选择一个签名文件项目", viewModel.SignDisabledReason);
        Assert.Equal("AddFilesButton", viewModel.FocusTargetAutomationId);

        readiness.Snapshot = ReadySnapshot(primary, secondary);
        await viewModel.RefreshCommand.ExecuteAsync(null);
        Assert.Equal(2, viewModel.Certificates.Count);

        string original = "C:\\release\\\u53d1\u5e03 \u7248\u672c\\" + new string('x', 160) + ".dll";
        string outputRoot = "C:\\release\\\u5df2\u7b7e\u540d \u8f93\u51fa";
        string destination = Path.Combine(outputRoot, Path.GetFileName(original));
        intake.Plan = new IntakePlan(
            outputRoot,
            [new IntakeFile(
                original,
                Path.GetFileName(original),
                destination,
                outputRoot,
                new StableFileIdentity(7, "FILE-7"),
                new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()))]);

        viewModel.OutputRoot = outputRoot;
        await viewModel.QueueFilesAsync([original]);
        await WaitForDetectionCountAsync(intake, 1);
        Assert.Equal(1, intake.AdmissionCount);
        Assert.Equal(1, intake.DetectionCount);
        await viewModel.ReplanOutputRootAsync(outputRoot);
        Assert.Equal(1, intake.CallCount);
        Assert.Equal(0, batch.RunCount);
        Assert.Single(viewModel.Rows);
        Assert.Equal(outputRoot, viewModel.OutputRoot);
        Assert.Equal(original, viewModel.Rows[0].FullPath);
        Assert.Equal(SigningFormatFamily.PeImage, viewModel.Rows[0].FormatFamily);
        Assert.Equal(SigningEngine.PeImage, viewModel.Rows[0].Engine);
        Assert.Equal(string.Empty, viewModel.InputError);

        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        viewModel.SelectedMode = SigningMode.Single;
        SigningPlan singlePlan = viewModel.BuildSigningPlan();
        Assert.Equal(SigningMode.Single, singlePlan.Mode);
        Assert.Single(singlePlan.Legs);
        Assert.Equal(FileDigestAlgorithm.Sha256, singlePlan.Legs[0].FileDigest);
        Assert.Equal(primary.Thumbprint, singlePlan.Legs[0].Certificate.Thumbprint);

        viewModel.SelectedMode = SigningMode.Dual;
        viewModel.SecondaryCertificate = viewModel.Certificates[1];
        SigningPlan dualPlan = viewModel.BuildSigningPlan();
        Assert.Equal(SigningMode.Dual, dualPlan.Mode);
        Assert.Collection(
            dualPlan.Legs,
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha1, leg.FileDigest);
                Assert.False(leg.Append);
            },
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
                Assert.True(leg.Append);
            });

        Assert.False(viewModel.ApplySettings("ftp://timestamp.invalid", 30));
        Assert.Equal("请输入不带凭据的绝对 HTTP 或 HTTPS 时间戳 URI", viewModel.SettingsValidationError);
        Assert.Equal("SettingsTimestampUri", viewModel.FocusTargetAutomationId);
        Assert.True(viewModel.ApplySettings("https://timestamp.example.test", 30));
        Assert.Equal(30, viewModel.DiagnosticRetentionDays);

        viewModel.OutputRoot = string.Empty;
        Assert.False(viewModel.CanSign);
        Assert.Equal("选择有效的输出目录", viewModel.SignDisabledReason);
        Assert.Equal("OutputRootTextBox", viewModel.FocusTargetAutomationId);
        viewModel.OutputRoot = outputRoot;
        Assert.True(viewModel.CanSign);

        var observedProgress = new List<(string State, int Percent)>();
        var observedAttempts = new List<ExecutionAttemptContext>();
        batch.AfterProgress = update =>
        {
            observedAttempts.Add(update.Attempt);
            observedProgress.Add((ProgressStateText(update.State), ProgressPercent(update.State)));
        };
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            batch.Emit(request.ItemId, BatchItemState.SigningPrimary);
            batch.Emit(request.ItemId, BatchItemState.SigningSecondary);
            batch.Emit(request.ItemId, BatchItemState.Verifying);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                Receipt(request, BatchItemState.Failed, BatchResultCode.WorkerFailure, unchecked((int)0x80004005)));
        };

        await viewModel.SignAsync();
        Assert.Equal(1, batch.RunCount);
        Assert.Contains(("正在主签名", 30), observedProgress);
        Assert.Contains(("正在辅助签名", 60), observedProgress);
        Assert.Contains(("正在验证", 85), observedProgress);
        Assert.NotEmpty(observedAttempts);
        Assert.All(observedAttempts, attempt => Assert.Same(observedAttempts[0], attempt));
        Assert.Equal("失败", viewModel.Rows[0].StateText);
        Assert.Equal("QueueRow_1", viewModel.FocusTargetAutomationId);
        Assert.True(viewModel.RetryCommand.CanExecute(null));

        batch.ResumeBehavior = () =>
        {
            BatchItemRequest request = Assert.Single(batch.LastRequests);
            batch.Emit(request.ItemId, BatchItemState.Ready);
            batch.Emit(request.ItemId, BatchItemState.SigningPrimary);
            batch.Emit(request.ItemId, BatchItemState.SigningSecondary);
            batch.Emit(request.ItemId, BatchItemState.Verifying);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Published,
                Receipt(request, BatchItemState.Published, BatchResultCode.Published, 0));
        };

        await viewModel.RetryAsync();
        Assert.Equal(1, batch.ResumeCount);
        Assert.Equal("已发布", viewModel.Rows[0].StateText);
        Assert.Equal(100, viewModel.Rows[0].ProgressPercent);
        Assert.Equal(100, viewModel.AggregateProgressPercent);
        Assert.Equal("SummaryRegion", viewModel.FocusTargetAutomationId);

        viewModel.OpenOutputCommand.Execute(null);
        Assert.Equal(outputRoot, shell.OpenedFolder);
        batch.RuntimeEventLogPath = "C:\\diagnostics\\CodeSigner-runtime.jsonl";
        batch.LastRuntimeEvent = new SigningRuntimeEvent(
            1,
            DateTimeOffset.Parse("2026-07-21T08:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
            SigningRuntimeEventNames.PublishDone,
            "item-1",
            1234,
            null);
        await ((IAsyncCommand)viewModel.ExportDiagnosticsCommand).ExecuteAsync(null);
        Assert.Equal(1, shell.ExportCount);
        Assert.Equal(30, shell.LastRetentionDays);
        Assert.Equal("C:\\diagnostics\\CodeSigner-diagnostics.json", viewModel.LastDiagnosticsPath);
        Assert.Equal(Path.GetFileName(batch.RuntimeEventLogPath), shell.LastDiagnostics!["diagnosticLogFileName"]);
        Assert.False(shell.LastDiagnostics.ContainsKey("runtimeEventLogPath"));
        Assert.Equal(SigningRuntimeEventNames.PublishDone, shell.LastDiagnostics["event"]);
        Assert.DoesNotContain(original, shell.LastDiagnostics!.Values.OfType<string>());
    }

    [Theory]
    [InlineData("library.dll", SignableFileType.PortableExecutable, SigningFormatFamily.PeImage, SigningEngine.PeImage)]
    [InlineData("package.msi", SignableFileType.WindowsInstaller, SigningFormatFamily.WindowsInstaller, SigningEngine.WindowsSip)]
    [Trait("Category", "Todo8Formal")]
    public async Task ValidSupportedInputIsQueuedFromTheContentAwareIntakePlan(
        string fileName,
        SignableFileType fileType,
        SigningFormatFamily expectedFamily,
        SigningEngine expectedEngine)
    {
        string original = Path.Combine("C:\\release", fileName);
        string outputRoot = "C:\\release\\signed";
        var intake = new TestIntakeAdapter
        {
            Plan = new IntakePlan(
                outputRoot,
                [new IntakeFile(
                    original,
                    fileName,
                    Path.Combine(outputRoot, fileName),
                    outputRoot,
                    new StableFileIdentity(9, "FILE-9"),
                    new SignableSubject(fileType, Guid.NewGuid()))])
        };
        var batch = new TestBatchAdapter();
        await using var viewModel = new SigningWorkbenchViewModel(
            new TestReadinessAdapter(BlockedSnapshot()),
            intake,
            batch,
            new TestOperatorShell(),
            new HealthyWorkerHealthService(),
            new UnusedWorkerRepairService(),
            static _ => ValueTask.FromResult(true));

        viewModel.OutputRoot = outputRoot;
        await viewModel.QueueFilesAsync([original]);
        await WaitForDetectionCountAsync(intake, 1);

        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        Assert.Equal(1, intake.AdmissionCount);
        Assert.Equal(1, intake.DetectionCount);
        Assert.Equal(0, batch.RunCount);
        Assert.Equal(original, row.FullPath);
        Assert.Equal(expectedFamily, row.FormatFamily);
        Assert.Equal(expectedEngine, row.Engine);
        Assert.Equal(string.Empty, viewModel.InputError);
        Assert.Equal(outputRoot, viewModel.OutputRoot);

        await viewModel.SetCurrentItemAsync(row.ItemId);
        await viewModel.SetCurrentItemAsync(row.ItemId);
        Assert.Equal(1, intake.DetectionCount);
    }

    private static async Task WaitForDetectionCountAsync(TestIntakeAdapter intake, int expected)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (intake.DetectionCount < expected)
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    [Fact]
    [Trait("Category", "Todo8Formal")]
    public async Task WorkbenchExportPreservesLastRuntimeEventFinalVerification()
    {
        var batch = new TestBatchAdapter
        {
            LastRuntimeEvent = new SigningRuntimeEvent(
                3,
                DateTimeOffset.Parse("2026-07-29T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
                SigningRuntimeEventNames.PublishDone,
                "item-final-verification",
                4321,
                null,
                FinalVerification: "passed")
        };
        var shell = new TestOperatorShell();
        await using var viewModel = new SigningWorkbenchViewModel(
            new TestReadinessAdapter(BlockedSnapshot()),
            new TestIntakeAdapter(),
            batch,
            shell,
            new HealthyWorkerHealthService(),
            new UnusedWorkerRepairService(),
            static _ => ValueTask.FromResult(true));

        await ((IAsyncCommand)viewModel.ExportDiagnosticsCommand).ExecuteAsync(null);

        Assert.Equal("passed", shell.LastDiagnostics!["finalVerification"]);
    }

    [Theory]
    [InlineData(".exe", SignableFileType.PortableExecutable, false)]
    [InlineData(".msi", SignableFileType.WindowsInstaller, false)]
    public async Task WorkbenchExportUsesWorkerReceiptRoutingAndExplicitLegacyTelemetryWithoutSecrets(
        string extension,
        SignableFileType fileType,
        bool legacyFallbackAttempted)
    {
        const string stderrSecret = "workbench-stderr-secret-731";
        bool pe = fileType == SignableFileType.PortableExecutable;
        string fileName = "payload" + extension;
        string original = Path.Combine("C:\\release", fileName);
        string outputRoot = "C:\\release\\signed";
        var readiness = new TestReadinessAdapter(ReadySnapshot(Certificate('A', "CN=Release SHA256")));
        var intake = new TestIntakeAdapter
        {
            Plan = new IntakePlan(
                outputRoot,
                [new IntakeFile(
                    original,
                    fileName,
                    Path.Combine(outputRoot, fileName),
                    outputRoot,
                    new StableFileIdentity(8, "FILE-8"),
                    new SignableSubject(fileType, Guid.NewGuid()))])
        };
        var batch = new TestBatchAdapter();
        var shell = new TestOperatorShell();
        await using var viewModel = new SigningWorkbenchViewModel(
            readiness,
            intake,
            batch,
            shell,
            new HealthyWorkerHealthService(),
            new UnusedWorkerRepairService(),
            static _ => ValueTask.FromResult(true),
            new FixedSdkSignToolReadinessState(SdkSignToolDiscoveryResult.Available(SdkCandidate())));
        await viewModel.QueueFilesAndWaitAsync([original]);
        await WaitForDetectionCountAsync(intake, 1);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        Assert.Equal(QueueItemDetectionState.Supported, row.DetectionState);
        Assert.Same(row, viewModel.CurrentItem);
        WorkerResponse response = CreateRoutingFailureResponse(pe, legacyFallbackAttempted);
        row.Apply(
            BatchItemState.Failed,
            new BatchItemReceipt(
                row.ItemId,
                BatchItemState.Failed,
                BatchResultCode.WorkerFailure,
                original,
                Path.Combine(outputRoot, fileName),
                new string('a', 64),
                null,
                "ATTEMPT-8",
                4321,
                unchecked((int)0x80004005),
                SigningDiagnostic: response,
                WorkerStderrTail: $"--pin {stderrSecret}"));
        await viewModel.RefreshSdkSignToolCommand.ExecuteAsync(null);
        Assert.True(viewModel.SdkSignToolAvailable);

        await ((IAsyncCommand)viewModel.ExportDiagnosticsCommand).ExecuteAsync(null);

        IReadOnlyDictionary<string, object?> diagnostics = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(
            shell.LastDiagnostics);
        Assert.Equal(response.Subject, diagnostics["detectedFormat"]);
        Assert.Equal(response.Engine, diagnostics["selectedEngine"]);
        Assert.Equal(response.Engine, diagnostics["engine"]);
        Assert.Equal(pe ? "windows_native" : "windows_sip", diagnostics["providerFamily"]);
        Assert.Equal(legacyFallbackAttempted, diagnostics["legacyFallbackAttempt"]);
        string json = JsonSerializer.Serialize(diagnostics);
        Assert.DoesNotContain(stderrSecret, json, StringComparison.Ordinal);
    }

    private static WorkerResponse CreateRoutingFailureResponse(bool pe, bool legacyFallbackAttempted) => new(
        WorkerProtocol.Version,
        Success: false,
        pe ? WorkerResponseCodes.NativeSigningFailed : WorkerResponseCodes.WindowsSipUnavailable,
        HResult: unchecked((int)0x80004005),
        FailedLegIndex: pe ? 0 : null,
        OriginalSha256: new string('a', 64),
        OperationId: "0123456789abcdef0123456789abcdef",
        DiagnosticId: "fedcba9876543210fedcba9876543210",
        DiagnosticPhase: pe ? WorkerDiagnosticPhases.SigningPrimary : WorkerDiagnosticPhases.WorkerBridge,
        DiagnosticLeg: pe ? WorkerDiagnosticLegs.Primary : null,
        DigestAlgorithm: pe ? WorkerDigestAlgorithms.Sha256 : null,
        AppendSignature: pe ? false : null,
        NativeReasonCode: pe ? NativeSigningReasonCode.NativeSigningFailed.ToString() : null,
        HResultOrigin: pe ? WorkerHResultOrigins.Native : WorkerHResultOrigins.WorkerBridge,
        Subject: pe ? WorkerSubjects.PeImage : WorkerSubjects.WindowsInstaller,
        Capability: pe ? WorkerCapabilities.PeImageDualCapable : WorkerCapabilities.WindowsSipSingleOnly,
        Engine: pe ? WorkerEngines.PeImage : WorkerEngines.WindowsSip,
        Verification: pe ? WorkerVerifications.PeImage : WorkerVerifications.WindowsSip,
        LegacyFallbackAttempted: legacyFallbackAttempted);

    private static void AssertCommandsAreExposed(SigningWorkbenchViewModel viewModel)
    {
        Assert.NotNull(viewModel.AddFilesCommand);
        Assert.NotNull(viewModel.AddFolderCommand);
        Assert.NotNull(viewModel.RemoveCommand);
        Assert.NotNull(viewModel.RefreshCommand);
        Assert.NotNull(viewModel.RetryCommand);
        Assert.NotNull(viewModel.OpenOutputCommand);
        Assert.NotNull(viewModel.ExportDiagnosticsCommand);
        Assert.NotNull(viewModel.SignCommand);
        Assert.NotNull(viewModel.CancelCommand);
        Assert.NotNull(viewModel.SettingsCommand);
    }

    private static EligibleCertificate Certificate(char thumbprintCharacter, string subject) => new(
        StoreLocation.CurrentUser,
        "My",
        new string(thumbprintCharacter, 40),
        subject,
        "CN=Issuing CA",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddYears(1),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private static TrustedSdkSignToolCandidate SdkCandidate() => new(
        Path.GetFullPath("C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe"),
        new Version(10, 0, 26100, 0),
        new Version(10, 0, 26100, 7463),
        "Microsoft Corporation",
        "Microsoft Corporation",
        "Microsoft Windows Operating System",
        new string('A', 64));

    private static ReadinessSnapshot ReadySnapshot(params EligibleCertificate[] certificates) => new(
        new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
        NativeApiAvailability.Available,
        new SimplySignInstallation(
            SimplySignInstallationStatus.Installed,
            "{A}",
            "{B}",
            "SimplySign Desktop",
            "Certum",
            "9.2.14.61"),
        new CertificateCatalog(
            CertificateAvailabilityStatus.CertificateAvailable,
            certificates,
            [new CertificateStoreDiagnostic(StoreLocation.CurrentUser, "My", CertificateStoreReadStatus.Success)]),
        new TimestampConfiguration(TimestampConfigurationStatus.Configured, new Uri(TimestampPolicy.DefaultUri)),
        ProviderAuthorizationStatus.AuthorizationUnknown);

    private static ReadinessSnapshot BlockedSnapshot() => new(
        new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
        NativeApiAvailability.Available,
        new SimplySignInstallation(
            SimplySignInstallationStatus.NotInstalled,
            "{A}",
            null,
            null,
            null,
            null),
        new CertificateCatalog(CertificateAvailabilityStatus.Unavailable, [], []),
        new TimestampConfiguration(TimestampConfigurationStatus.Configured, new Uri(TimestampPolicy.DefaultUri)),
        ProviderAuthorizationStatus.AuthorizationUnknown);

    private static string ProgressStateText(BatchItemState state) => state switch
    {
        BatchItemState.SigningPrimary => "正在主签名",
        BatchItemState.SigningSecondary => "正在辅助签名",
        BatchItemState.Verifying => "正在验证",
        BatchItemState.Failed => "失败",
        _ => state.ToString()
    };

    private static int ProgressPercent(BatchItemState state) => state switch
    {
        BatchItemState.SigningPrimary => 30,
        BatchItemState.SigningSecondary => 60,
        BatchItemState.Verifying => 85,
        _ => 100
    };

    private static BatchItemReceipt Receipt(
        BatchItemRequest request,
        BatchItemState state,
        BatchResultCode code,
        int hResult) => new(
            request.ItemId,
            state,
            code,
            request.File.OriginalPath,
            request.File.DestinationPath,
            state == BatchItemState.Published ? new string('1', 64) : null,
            state == BatchItemState.Published ? new string('2', 64) : null,
            state == BatchItemState.Published ? "ATTEMPT-1" : null,
            1234,
            hResult);

    private sealed class HealthyWorkerHealthService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
    }

    private sealed class UnusedWorkerRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Worker repair is not used by this test.");

        public void Dispose()
        {
        }
    }

    private sealed class TestReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public ReadinessSnapshot Snapshot { get; set; } = snapshot;

        public ReadinessSnapshot Probe(Uri timestampUri) => Snapshot;
    }

    private sealed class FixedSdkSignToolReadinessState(SdkSignToolDiscoveryResult result)
        : ISdkSignToolReadinessState
    {
        public SdkSignToolDiscoveryResult Current => result;

        public SdkSignToolDiscoveryResult Refresh() => result;
    }

    private sealed class TestIntakeAdapter : IIntakeAdapter
    {
        private string[] admittedInputs = [];

        public int AdmissionCount { get; private set; }

        public int DetectionCount { get; private set; }

        public int CallCount { get; private set; }

        public IntakePlan? Plan { get; set; }

        public IntakeValidationException? Exception { get; set; }

        public Task<QueuedSourceAdmissionResult> AdmitAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AdmissionCount++;
            admittedInputs = inputs.ToArray();
            if (Exception is not null)
            {
                throw Exception;
            }

            QueuedSource[] sources = admittedInputs.Select((path, index) => new QueuedSource(
                path,
                Path.GetFileName(path),
                new StableFileIdentity((ulong)(index + 1), path))).ToArray();
            return Task.FromResult(new QueuedSourceAdmissionResult(sources, []));
        }

        public Task<QueuedSourceDetectionResult> DetectAsync(
            QueuedSource source,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DetectionCount++;
            IntakeFile planned = Assert.Single((Plan ?? throw new InvalidOperationException(
                "The test intake plan was not configured.")).Files, file =>
                    string.Equals(file.OriginalPath, source.CanonicalPath, StringComparison.OrdinalIgnoreCase));
            var detected = new DetectedQueuedSource(
                source,
                planned.Subject,
                new SourceFingerprint(source.Identity, 0, DateTime.UnixEpoch, new string('A', 64)));
            return Task.FromResult(new QueuedSourceDetectionResult(
                QueuedSourceDetectionStatus.Supported,
                detected,
                Error: null));
        }

        public Task<IntakeFile> PlanOutputAsync(
            DetectedQueuedSource detectedSource,
            string outputRoot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            IntakeFile planned = Assert.Single((Plan ?? throw new InvalidOperationException(
                "The test intake plan was not configured.")).Files, file =>
                    string.Equals(file.OriginalPath, detectedSource.Source.CanonicalPath, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(planned with
            {
                OutputRoot = outputRoot,
                DestinationPath = Path.Combine(outputRoot, planned.RelativePath),
                Identity = detectedSource.Source.Identity,
                Subject = detectedSource.Subject
            });
        }

        public Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
            DetectedQueuedSource detectedSource,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new QueuedSourceDetectionResult(
                QueuedSourceDetectionStatus.Supported,
                detectedSource,
                Error: null));
        }
    }

    private sealed class TestBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

        public string? RuntimeEventLogPath { get; set; }

        public SigningRuntimeEvent? LastRuntimeEvent { get; set; }

        public int RunCount { get; private set; }

        public int ResumeCount { get; private set; }

        public int CancelCount { get; private set; }

        public IReadOnlyList<BatchItemRequest> LastRequests { get; private set; } = [];

        public Func<IReadOnlyList<BatchItemRequest>, BatchProgressUpdate>? RunBehavior { get; set; }

        public Func<BatchProgressUpdate>? ResumeBehavior { get; set; }

        public Action<BatchProgressUpdate>? AfterProgress { get; set; }

        private SynchronizationContext? progressContext;

        private ExecutionAttemptContext? activeAttempt;

        public async Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            RunCount++;
            IReadOnlyList<BatchItemRequest> requests = [request];
            LastRequests = requests;
            BatchProgressUpdate final = RunBehavior?.Invoke(requests)
                ?? throw new InvalidOperationException("The test batch run was not configured.");
            await WaitForProgressDrainAsync(cancellationToken).ConfigureAwait(false);
            return final;
        }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            ExecutionAttemptContext attempt,
            CancellationToken cancellationToken)
        {
            activeAttempt = attempt;
            try
            {
                return RunAsync(request, cancellationToken);
            }
            finally
            {
                activeAttempt = null;
            }
        }

        public async Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            ResumeCount++;
            Assert.True(retryFailed);
            BatchProgressUpdate final = ResumeBehavior?.Invoke()
                ?? throw new InvalidOperationException("The test batch resume was not configured.");
            await WaitForProgressDrainAsync(cancellationToken).ConfigureAwait(false);
            return final;
        }

        public Task<BatchProgressUpdate> ResumeAsync(
            ExecutionAttemptContext attempt,
            bool retryFailed,
            CancellationToken cancellationToken)
        {
            activeAttempt = attempt;
            try
            {
                return ResumeAsync(attempt.ItemId, retryFailed, cancellationToken);
            }
            finally
            {
                activeAttempt = null;
            }
        }

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken)
        {
            CancelCount++;
            return Task.CompletedTask;
        }

        public BatchProgressUpdate Emit(
            string itemId,
            BatchItemState state,
            BatchItemReceipt? receipt = null)
        {
            ExecutionAttemptContext attempt = activeAttempt ??
                throw new InvalidOperationException("The test batch progress must be emitted within an execution attempt.");
            var update = new BatchProgressUpdate(attempt, state, receipt);
            ProgressChanged?.Invoke(this, new BatchProgressChangedEventArgs(update));
            AfterProgress?.Invoke(update);
            return update;
        }

        private Task WaitForProgressDrainAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (progressContext is null)
            {
                return Task.CompletedTask;
            }

            if (progressContext is ProgressDrainContext deterministicContext)
            {
                deterministicContext.Drain();
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }

            if (SynchronizationContext.Current == progressContext)
            {
                return Task.CompletedTask;
            }

            progressContext.Send(_ => { }, null);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public T CreateWithDeterministicProgressContext<T>(Func<T> factory)
        {
            ArgumentNullException.ThrowIfNull(factory);
            SynchronizationContext? previous = SynchronizationContext.Current;
            progressContext = new ProgressDrainContext();
            SynchronizationContext.SetSynchronizationContext(progressContext);
            try
            {
                return factory();
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(previous);
            }
        }

        private sealed class ProgressDrainContext : SynchronizationContext
        {
            private readonly Queue<(SendOrPostCallback Callback, object? State)> pending = new();

            public override void Post(SendOrPostCallback callback, object? state)
            {
                lock (pending)
                {
                    pending.Enqueue((callback, state));
                }
            }

            public void Drain()
            {
                while (true)
                {
                    (SendOrPostCallback Callback, object? State) work;
                    lock (pending)
                    {
                        if (pending.Count == 0)
                        {
                            return;
                        }

                        work = pending.Dequeue();
                    }

                    SynchronizationContext? previous = Current;
                    SetSynchronizationContext(this);
                    try
                    {
                        work.Callback(work.State);
                    }
                    finally
                    {
                        SetSynchronizationContext(previous);
                    }
                }
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class TestOperatorShell : IOperatorShell
    {
        public string? OpenedFolder { get; private set; }

        public int ExportCount { get; private set; }

        public int LastRetentionDays { get; private set; }

        public IReadOnlyDictionary<string, object?>? LastDiagnostics { get; private set; }

        public void OpenFolder(string path) => OpenedFolder = path;

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken)
        {
            ExportCount++;
            LastDiagnostics = diagnostics;
            LastRetentionDays = retentionDays;
            return Task.FromResult("C:\\diagnostics\\CodeSigner-diagnostics.json");
        }
    }
}
