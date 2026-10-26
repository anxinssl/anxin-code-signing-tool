using System.IO;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using Xunit.Abstractions;

namespace CodeSigner.App.Tests;

public sealed class SignButtonAvailabilityRecoveryTests(ITestOutputHelper output)
{
    public static TheoryData<AvailabilityCase, bool, string, string> AvailabilityCases => new()
    {
        { AvailabilityCase.Busy, false, "签名正在进行中", "AddFilesButton" },
        { AvailabilityCase.EmptyWithoutReadiness, false, "请选择一个签名文件项目", "AddFilesButton" },
        { AvailabilityCase.InputErrorWithoutPendingWork, false, "请选择一个签名文件项目", "AddFilesButton" },
        { AvailabilityCase.CompletedOnly, false, "当前签名文件项目已完成", "QueueRow_1" },
        { AvailabilityCase.MissingReadiness, false, "尚未检查就绪状态", "RefreshButton" },
        { AvailabilityCase.UnsupportedWorkstation, false, "此 Windows 计算机不受支持", "ReadinessWorkstation" },
        { AvailabilityCase.PeWithoutNativeApi, false, "Windows 签名 API 不可用", "ReadinessNativeApi" },
        { AvailabilityCase.SipWithoutPowerShellBridge, false, "Windows 签名处理程序不可用", "ReadinessNativeApi" },
        { AvailabilityCase.MixedWithoutNativeApi, false, "Windows 签名 API 不可用", "ReadinessNativeApi" },
        { AvailabilityCase.MixedWithoutPowerShellBridge, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.SimplySignMissing, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.CertificateCatalogMissing, false, "没有可用的代码签名证书", "ReadinessCertificates" },
        { AvailabilityCase.TimestampInvalid, false, "时间戳 URI 无效", "TimestampStatus" },
        { AvailabilityCase.FailedWithPendingWork, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.PausedWithoutPendingWork, false, "签名前请重试、移除失败、暂停或已取消的签名文件项目", "QueueRow_1" },
        { AvailabilityCase.PausedTimestampWithoutPendingWork, false, "签名前请重试、移除失败、暂停或已取消的签名文件项目", "QueueRow_1" },
        { AvailabilityCase.CancelledWithoutPendingWork, false, "签名前请重试、移除失败、暂停或已取消的签名文件项目", "QueueRow_1" },
        { AvailabilityCase.PrimaryCertificateMissing, false, "选择主签名证书", "PrimaryCertificateCombo" },
        { AvailabilityCase.SecondaryCertificateMissingForPendingPe, false, "选择 SHA-256 辅助签名证书", "SecondaryCertificateCombo" },
        { AvailabilityCase.InvalidOutputRoot, false, "选择有效的输出目录", "OutputRootTextBox" },
        { AvailabilityCase.StaleOutputPlan, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.ValidSipWithoutNativeApi, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.ValidPeWithoutPowerShellBridge, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.PublishedPeWithPendingSipNeedsNoSecondary, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.SkippedPeWithPendingSipNeedsNoSecondary, true, string.Empty, "AddFilesButton" },
        { AvailabilityCase.ValidPendingWorkWithInputError, true, string.Empty, "AddFilesButton" }
    };

    [Fact]
    public async Task RefreshValidationRefreshesSignCommandAndWorkerAndSdkStateDoNotGateAvailability()
    {
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            ReadySnapshot(),
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Missing));
        var states = new List<string>();
        int commandInvalidations = 0;
        viewModel.SignCommand.CanExecuteChanged += (_, _) => commandInvalidations++;

        Assert.True(viewModel.ApplySettings(
            viewModel.TimestampUri.AbsoluteUri,
            viewModel.DiagnosticRetentionDays));
        await QueuePendingAsync(viewModel, ".exe");
        Capture("ready");

        viewModel.OutputRoot = string.Empty;
        Capture("invalid-output");

        viewModel.OutputRoot = @"C:\matrix\out";
        Capture("recovered-output");

        await viewModel.InitializeAsync();
        Capture("unhealthy-worker-sdk-unavailable");

        Assert.True(commandInvalidations >= 2);
        Assert.Equal(
            [
                "ready:True:True::AddFilesButton",
                "invalid-output:False:False:选择有效的输出目录:OutputRootTextBox",
                "recovered-output:True:True::OutputRootTextBox",
                "unhealthy-worker-sdk-unavailable:True:True::WorkerRecoveryRegion"
            ],
            states);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.False(viewModel.SdkSignToolAvailable);
        output.WriteLine(string.Join(" | ", states));

        void Capture(string phase)
        {
            states.Add($"{phase}:{viewModel.CanSign}:{viewModel.SignCommand.CanExecute(null)}:" +
                $"{viewModel.SignDisabledReason}:{viewModel.FocusTargetAutomationId}");
        }
    }

    [Theory]
    [MemberData(nameof(AvailabilityCases))]
    public async Task SignAvailabilityMatchesThePendingWorkMatrix(
        AvailabilityCase availabilityCase,
        bool expectedEnabled,
        string expectedReason,
        string expectedFocus)
    {
        ReadinessSnapshot readiness = ReadinessFor(availabilityCase);
        var batch = new TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            readiness,
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy),
            batch);
        Task? activeSigning = null;

        try
        {
            await PrepareCaseAsync(availabilityCase, viewModel, batch);
            if (availabilityCase == AvailabilityCase.Busy)
            {
                activeSigning = viewModel.SignAsync();
                await batch.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await viewModel.SignAsync();
            }
            else if (!expectedEnabled)
            {
                await viewModel.SignAsync();
            }

            Assert.Equal(expectedEnabled, viewModel.CanSign);
            Assert.Equal(viewModel.CanSignQueue, viewModel.SignCommand.CanExecute(null));
            Assert.Equal(expectedReason, viewModel.SignDisabledReason);
            Assert.Equal(expectedFocus, viewModel.FocusTargetAutomationId);
        }
        finally
        {
            batch.CancelPendingRun();
            if (activeSigning is not null)
            {
                await activeSigning;
            }
        }
    }

    private static async Task PrepareCaseAsync(
        AvailabilityCase availabilityCase,
        SigningWorkbenchViewModel viewModel,
        TestBatchAdapter batch)
    {
        if (availabilityCase == AvailabilityCase.EmptyWithoutReadiness)
        {
            return;
        }

        if (availabilityCase == AvailabilityCase.InputErrorWithoutPendingWork)
        {
            await viewModel.QueueFilesAsync([]);
            return;
        }

        if (availabilityCase == AvailabilityCase.MissingReadiness)
        {
            await QueuePendingAsync(viewModel, ".exe");
            return;
        }

        Assert.True(viewModel.ApplySettings(
            viewModel.TimestampUri.AbsoluteUri,
            viewModel.DiagnosticRetentionDays));

        switch (availabilityCase)
        {
            case AvailabilityCase.Busy:
                await QueuePendingAsync(viewModel, ".exe");
                batch.BlockNextRun();
                return;
            case AvailabilityCase.CompletedOnly:
                await QueuePendingAsync(viewModel, ".exe");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.Published);
                return;
            case AvailabilityCase.MixedWithoutNativeApi:
            case AvailabilityCase.MixedWithoutPowerShellBridge:
                await QueuePendingAsync(viewModel, ".exe", ".msi");
                return;
            case AvailabilityCase.SipWithoutPowerShellBridge:
            case AvailabilityCase.ValidSipWithoutNativeApi:
                await QueuePendingAsync(viewModel, ".msi");
                return;
            case AvailabilityCase.FailedWithPendingWork:
                await QueuePendingAsync(viewModel, ".exe", ".msi");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.Failed);
                await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);
                return;
            case AvailabilityCase.PausedWithoutPendingWork:
                await QueuePendingAsync(viewModel, ".exe");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.PausedProvider);
                return;
            case AvailabilityCase.PausedTimestampWithoutPendingWork:
                await QueuePendingAsync(viewModel, ".exe");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.PausedTimestamp);
                return;
            case AvailabilityCase.CancelledWithoutPendingWork:
                await QueuePendingAsync(viewModel, ".exe");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.Cancelled);
                return;
            case AvailabilityCase.PrimaryCertificateMissing:
                await QueuePendingAsync(viewModel, ".exe");
                viewModel.PrimaryCertificate = null;
                return;
            case AvailabilityCase.SecondaryCertificateMissingForPendingPe:
                await QueuePendingAsync(viewModel, ".exe");
                viewModel.SelectedMode = SigningMode.Dual;
                return;
            case AvailabilityCase.PublishedPeWithPendingSipNeedsNoSecondary:
                await QueuePendingAsync(viewModel, ".exe", ".msi");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.Published);
                await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);
                viewModel.SelectedMode = SigningMode.Dual;
                return;
            case AvailabilityCase.SkippedPeWithPendingSipNeedsNoSecondary:
                await QueuePendingAsync(viewModel, ".exe", ".msi");
                TestBatchAdapter.Emit(viewModel.Rows[0], BatchItemState.SkippedAlreadySigned);
                await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);
                viewModel.SelectedMode = SigningMode.Dual;
                return;
            case AvailabilityCase.InvalidOutputRoot:
                await QueuePendingAsync(viewModel, ".exe");
                viewModel.OutputRoot = string.Empty;
                return;
            case AvailabilityCase.StaleOutputPlan:
                await QueuePendingAsync(viewModel, ".exe");
                viewModel.OutputRoot = @"C:\matrix\different-output";
                await viewModel.InvalidateCurrentPreflightAsync();
                return;
            case AvailabilityCase.ValidPendingWorkWithInputError:
                await QueuePendingAsync(viewModel, ".exe");
                await viewModel.QueueFilesAsync([]);
                return;
            default:
                await QueuePendingAsync(viewModel, ".exe");
                return;
        }
    }

    internal static async Task QueuePendingAsync(
        SigningWorkbenchViewModel viewModel,
        params string[] extensions)
    {
        await viewModel.ReplanOutputRootAsync(viewModel.OutputRoot);
        await viewModel.QueueFilesAsync(extensions.Select((extension, index) =>
            $@"C:\matrix\item-{index + 1}{extension}").ToArray());
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (viewModel.Rows.Count != extensions.Length ||
               viewModel.Rows.Any(row => row.DetectionState is
                   QueueItemDetectionState.Pending or QueueItemDetectionState.Running) ||
               viewModel.CurrentItem?.PreflightState is
                   QueueItemPreflightState.Unplanned or QueueItemPreflightState.Planning)
        {
            await Task.Delay(10, cancellation.Token);
        }
    }

    internal static CurrentFocusState CaptureCurrentFocusState(
        SigningWorkbenchViewModel viewModel,
        QueueItemViewModel current) => new(
            viewModel.CanSign,
            viewModel.SignCommand.CanExecute(null),
            viewModel.RetryCommand.CanExecute(null),
            viewModel.SignDisabledReason,
            viewModel.FocusTargetAutomationId,
            viewModel.CurrentFileStatusText,
            current.PreflightState,
            current.PreflightIssue?.FocusTargetAutomationId,
            current.PreflightIssue?.RecoveryAction);

    private static ReadinessSnapshot ReadinessFor(AvailabilityCase availabilityCase) => availabilityCase switch
    {
        AvailabilityCase.UnsupportedWorkstation => ReadySnapshot(
            workstationStatus: WorkstationSupportStatus.Unsupported),
        AvailabilityCase.PeWithoutNativeApi or AvailabilityCase.MixedWithoutNativeApi or
            AvailabilityCase.ValidSipWithoutNativeApi => ReadySnapshot(
                nativeApi: NativeApiAvailability.LibraryUnavailable),
        AvailabilityCase.SipWithoutPowerShellBridge or AvailabilityCase.MixedWithoutPowerShellBridge or
            AvailabilityCase.ValidPeWithoutPowerShellBridge => ReadySnapshot(
                bridgeStatus: WindowsPowerShellBridgeStatus.Unavailable),
        AvailabilityCase.SimplySignMissing => ReadySnapshot(
            simplySignStatus: SimplySignInstallationStatus.NotInstalled),
        AvailabilityCase.CertificateCatalogMissing => ReadySnapshot(
            certificateStatus: CertificateAvailabilityStatus.Unavailable),
        AvailabilityCase.TimestampInvalid => ReadySnapshot(
            timestampStatus: TimestampConfigurationStatus.Invalid),
        _ => ReadySnapshot()
    };

    internal static SigningWorkbenchViewModel CreateViewModel(
        ReadinessSnapshot readiness,
        WorkerLaunchDiagnostic workerDiagnostic,
        IBatchAdapter? batch = null)
    {
        var viewModel = new SigningWorkbenchViewModel(
            new FixedReadinessAdapter(readiness),
            new FixedIntakeAdapter(),
            batch ?? new NoopBatchAdapter(),
            new NoopOperatorShell(),
            new FixedWorkerHealthService(workerDiagnostic),
            new NoopWorkerRepairService(),
            static _ => ValueTask.FromResult(true));
        viewModel.OutputRoot = @"C:\matrix\out";
        if (readiness.CertificateCatalog.Certificates.Count > 0)
        {
            viewModel.PrimaryCertificate = new CertificateOptionViewModel(
                readiness.CertificateCatalog.Certificates[0]);
        }
        return viewModel;
    }

    internal static ReadinessSnapshot ReadySnapshot(
        WorkstationSupportStatus workstationStatus = WorkstationSupportStatus.Supported,
        NativeApiAvailability nativeApi = NativeApiAvailability.Available,
        SimplySignInstallationStatus simplySignStatus = SimplySignInstallationStatus.Installed,
        CertificateAvailabilityStatus certificateStatus = CertificateAvailabilityStatus.CertificateAvailable,
        TimestampConfigurationStatus timestampStatus = TimestampConfigurationStatus.Configured,
        WindowsPowerShellBridgeStatus bridgeStatus = WindowsPowerShellBridgeStatus.Available) => new(
        new WorkstationReadiness(workstationStatus, "None"),
        nativeApi,
        new SimplySignInstallation(
            simplySignStatus,
            "{A}",
            "{B}",
            "SimplySign Desktop",
            "Certum",
            "9.2.14.61"),
        new CertificateCatalog(
            certificateStatus,
            certificateStatus == CertificateAvailabilityStatus.CertificateAvailable
                ? [Certificate('A'), Certificate('B')]
                : [],
            [new CertificateStoreDiagnostic(StoreLocation.CurrentUser, "My", CertificateStoreReadStatus.Success)]),
        new TimestampConfiguration(
            timestampStatus,
            timestampStatus == TimestampConfigurationStatus.Configured ? new Uri(TimestampPolicy.DefaultUri) : null),
        ProviderAuthorizationStatus.AuthorizationUnknown,
        new WindowsPowerShellBridgeReadiness(
            bridgeStatus,
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "5.1",
            "None"));

    private static EligibleCertificate Certificate(char thumbprint) => new(
        StoreLocation.CurrentUser,
        "My",
        new string(thumbprint, 40),
        $"CN=Matrix-{thumbprint}",
        "CN=Matrix Issuing CA",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddDays(1),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private sealed class FixedReadinessAdapter(ReadinessSnapshot readiness) : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => readiness;
    }

    private sealed class FixedIntakeAdapter : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            string root = outputRoot ?? @"C:\matrix\out";
            IntakeFile[] files = inputs.Select((input, index) =>
            {
                PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(Path.GetExtension(input));
                Assert.True(subject.IsSuccess);
                return new IntakeFile(
                    input,
                    Path.GetFileName(input),
                    Path.Combine(root, Path.GetFileName(input)),
                    root,
                    new StableFileIdentity((ulong)(index + 1), input),
                    new SignableSubject(subject.Value!, Guid.NewGuid(), null));
            }).ToArray();
            return Task.FromResult(new IntakePlan(root, files));
        }
    }

    private sealed class NoopBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken) =>
            Task.FromException<BatchProgressUpdate>(new InvalidOperationException("Run is not configured."));

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken) =>
            Task.FromException<BatchProgressUpdate>(new InvalidOperationException("Resume is not configured."));

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    internal sealed class TestBatchAdapter : IBatchAdapter
    {
        private EventHandler<BatchProgressChangedEventArgs>? progressChanged;
        private TaskCompletionSource<BatchProgressUpdate>? pendingRun;

        public TaskCompletionSource RunStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int OperationCalls { get; private set; }

        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add => progressChanged += value;
            remove => progressChanged -= value;
        }

        public void BlockNextRun() => pendingRun = new TaskCompletionSource<BatchProgressUpdate>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            OperationCalls++;
            RunStarted.TrySetResult();
            return pendingRun?.Task ??
                Task.FromException<BatchProgressUpdate>(new InvalidOperationException("Run is not configured."));
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            OperationCalls++;
            return Task.FromException<BatchProgressUpdate>(new InvalidOperationException("Resume is not configured."));
        }

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken)
        {
            OperationCalls++;
            return Task.CompletedTask;
        }

        public static void Emit(QueueItemViewModel row, BatchItemState state) => row.Apply(state, receipt: null);

        public void CancelPendingRun() => pendingRun?.TrySetCanceled();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoopOperatorShell : IOperatorShell
    {
        public void OpenFolder(string path)
        {
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken) => Task.FromResult(string.Empty);
    }

    private sealed class FixedWorkerHealthService(WorkerLaunchDiagnostic diagnostic) : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(diagnostic);
    }

    private sealed class NoopWorkerRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            Task.FromException<WorkerRepairResult>(new InvalidOperationException("Repair is not configured."));

        public void Dispose()
        {
        }
    }

    public enum AvailabilityCase
    {
        Busy,
        EmptyWithoutReadiness,
        InputErrorWithoutPendingWork,
        CompletedOnly,
        MissingReadiness,
        UnsupportedWorkstation,
        PeWithoutNativeApi,
        SipWithoutPowerShellBridge,
        MixedWithoutNativeApi,
        MixedWithoutPowerShellBridge,
        SimplySignMissing,
        CertificateCatalogMissing,
        TimestampInvalid,
        FailedWithPendingWork,
        PausedWithoutPendingWork,
        PausedTimestampWithoutPendingWork,
        CancelledWithoutPendingWork,
        PrimaryCertificateMissing,
        SecondaryCertificateMissingForPendingPe,
        InvalidOutputRoot,
        StaleOutputPlan,
        ValidSipWithoutNativeApi,
        ValidPeWithoutPowerShellBridge,
        PublishedPeWithPendingSipNeedsNoSecondary,
        SkippedPeWithPendingSipNeedsNoSecondary,
        ValidPendingWorkWithInputError
    }

    internal sealed record CurrentFocusState(
        bool CanSign,
        bool SignCommandEnabled,
        bool RetryCommandEnabled,
        string SignDisabledReason,
        string FocusTargetAutomationId,
        string CurrentFileStatusText,
        QueueItemPreflightState PreflightState,
        string? IssueFocusTargetAutomationId,
        PreflightRecoveryAction? RecoveryAction);
}

public sealed class CurrentItemFocusArbitrationTests
{
    [Fact]
    public async Task RejectedIntakeKeepsReadyCurrentItemFocusAndRecoveryState()
    {
        var batch = new SignButtonAvailabilityRecoveryTests.TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = SignButtonAvailabilityRecoveryTests.CreateViewModel(
            SignButtonAvailabilityRecoveryTests.ReadySnapshot(),
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy),
            batch);

        Assert.True(viewModel.ApplySettings(
            viewModel.TimestampUri.AbsoluteUri,
            viewModel.DiagnosticRetentionDays));
        await SignButtonAvailabilityRecoveryTests.QueuePendingAsync(viewModel, ".exe");

        QueueItemViewModel current = Assert.IsType<QueueItemViewModel>(viewModel.CurrentItem);
        Assert.Equal(QueueItemPreflightState.Ready, current.PreflightState);
        Assert.Null(current.PreflightIssue);
        SignButtonAvailabilityRecoveryTests.CurrentFocusState before =
            SignButtonAvailabilityRecoveryTests.CaptureCurrentFocusState(viewModel, current);

        await viewModel.QueueFilesAsync([]);

        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal("请至少选择一个支持的签名文件", viewModel.InputError);
        Assert.Equal(QueueItemPreflightState.Ready, current.PreflightState);
        Assert.Null(current.PreflightIssue);
        Assert.Equal(before, SignButtonAvailabilityRecoveryTests.CaptureCurrentFocusState(viewModel, current));
        Assert.NotEqual("InputError", viewModel.FocusTargetAutomationId);
        Assert.Equal(0, batch.OperationCalls);
    }

    [Fact]
    public async Task RejectedIntakeWithoutCurrentItemUsesInputErrorFocus()
    {
        var batch = new SignButtonAvailabilityRecoveryTests.TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = SignButtonAvailabilityRecoveryTests.CreateViewModel(
            SignButtonAvailabilityRecoveryTests.ReadySnapshot(),
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy),
            batch);

        await viewModel.QueueFilesAsync([]);

        Assert.Null(viewModel.CurrentItem);
        Assert.Empty(viewModel.Rows);
        Assert.Equal("请至少选择一个支持的签名文件", viewModel.InputError);
        Assert.Equal("InputError", viewModel.FocusTargetAutomationId);
        Assert.False(viewModel.CanSign);
        Assert.False(viewModel.RetryCommand.CanExecute(null));
        Assert.Equal(0, batch.OperationCalls);
    }
}
