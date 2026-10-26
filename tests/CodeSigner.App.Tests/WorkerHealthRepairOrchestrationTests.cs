using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Core.Evidence;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class WorkerHealthRepairOrchestrationTests
{
    public static TheoryData<WorkerLaunchReason, bool, string> WorkerRecoveryCopy => new()
    {
        {
            WorkerLaunchReason.Missing,
            true,
            "未找到 CodeSigner.Worker.exe。可使用“修复 Worker”重新安装 Worker 组件。"
        },
        {
            WorkerLaunchReason.InvalidImage,
            true,
            "CodeSigner.Worker.exe 文件无效或不支持当前 Windows x64。可使用“修复 Worker”重新安装 Worker 组件。"
        },
        {
            WorkerLaunchReason.VersionMismatch,
            true,
            "Worker 与应用版本不一致。可使用“修复 Worker”重新安装匹配的 Worker 组件。"
        },
        {
            WorkerLaunchReason.AccessDenied,
            false,
            "Windows 拒绝启动 Worker。请检查安装目录访问权限或安全策略，然后重新检测。"
        },
        {
            WorkerLaunchReason.StartFailed,
            false,
            "Worker 无法启动。请重新检测；若仍失败，请导出诊断信息。"
        },
        {
            WorkerLaunchReason.UserMismatch,
            false,
            "Worker 与当前应用不属于同一 Windows 用户。请使用当前用户重新启动应用。"
        },
        {
            WorkerLaunchReason.SessionMismatch,
            false,
            "Worker 与当前应用不在同一 Windows 会话。请在当前会话中重新启动应用。"
        },
        {
            WorkerLaunchReason.MissingUserSid,
            false,
            "无法确认 Worker 的 Windows 用户身份。请重新登录 Windows 后再试。"
        },
        {
            WorkerLaunchReason.Timeout,
            false,
            "Worker 健康检查超时。请重新检测；若仍超时，请导出诊断信息。"
        },
        {
            WorkerLaunchReason.Crashed,
            false,
            "Worker 在启动或通信期间退出。请重新检测并导出诊断信息。"
        },
        {
            WorkerLaunchReason.ProtocolMismatch,
            false,
            "Worker 通信协议与当前应用不兼容。请安装匹配版本的 CodeSigner。"
        },
        {
            WorkerLaunchReason.InvalidFrame,
            false,
            "Worker 返回了无效响应。请重新检测并导出诊断信息。"
        }
    };

    [Fact]
    public async Task LoadedInitializationTransitionsFromUnknownThroughCheckingToHealthy()
    {
        var probeCompletion = new TaskCompletionSource<WorkerLaunchDiagnostic>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new TestWorkerHealthService(_ => probeCompletion.Task);
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health);

        Assert.Equal(WorkerHealthState.Unknown, viewModel.WorkerHealthState);
        Assert.False(viewModel.CanSign);

        Task initialization = viewModel.InitializeAsync();

        Assert.Equal(WorkerHealthState.Checking, viewModel.WorkerHealthState);
        Assert.False(viewModel.CanSign);
        probeCompletion.SetResult(Diagnostic(WorkerLaunchReason.Healthy));
        await initialization;

        Assert.Equal(WorkerHealthState.Healthy, viewModel.WorkerHealthState);
        Assert.Equal(WorkerLaunchReason.Healthy, viewModel.WorkerDiagnostic?.Reason);
        Assert.Equal(1, health.CallCount);
    }

    public static TheoryData<WorkerLaunchReason, bool> UnhealthyReasons => new()
    {
        { WorkerLaunchReason.Missing, true },
        { WorkerLaunchReason.InvalidImage, true },
        { WorkerLaunchReason.VersionMismatch, true },
        { WorkerLaunchReason.AccessDenied, false },
        { WorkerLaunchReason.StartFailed, false },
        { WorkerLaunchReason.UserMismatch, false },
        { WorkerLaunchReason.SessionMismatch, false },
        { WorkerLaunchReason.MissingUserSid, false },
        { WorkerLaunchReason.Timeout, false },
        { WorkerLaunchReason.Crashed, false },
        { WorkerLaunchReason.ProtocolMismatch, false },
        { WorkerLaunchReason.InvalidFrame, false }
    };

    [Theory]
    [MemberData(nameof(UnhealthyReasons))]
    public async Task LoadedInitializationMapsEveryUnhealthyReason(
        WorkerLaunchReason reason,
        bool repairEligible)
    {
        var health = new TestWorkerHealthService(Diagnostic(reason));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health);

        await viewModel.InitializeAsync();

        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Equal(reason, viewModel.WorkerDiagnostic?.Reason);
        Assert.False(viewModel.CanSign);
        Assert.Equal(repairEligible, viewModel.RepairWorkerCommand.CanExecute(null));
    }

    [Fact]
    public async Task ManualWorkerRefreshKeepsPayloadOnlyRepairEligibilityBoundary()
    {
        WorkerLaunchDiagnostic missing = Diagnostic(WorkerLaunchReason.Missing);
        WorkerLaunchDiagnostic accessDenied = Diagnostic(WorkerLaunchReason.AccessDenied);
        var health = new TestWorkerHealthService(missing, accessDenied);
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health);

        await viewModel.InitializeAsync();

        Assert.Same(missing, viewModel.WorkerDiagnostic);
        Assert.True(viewModel.RepairWorkerCommand.CanExecute(null));
        Assert.True(viewModel.RefreshWorkerCommand.CanExecute(null));

        await viewModel.RefreshWorkerHealthAsync();

        Assert.Same(accessDenied, viewModel.WorkerDiagnostic);
        Assert.False(viewModel.RepairWorkerCommand.CanExecute(null));
        Assert.True(viewModel.RefreshWorkerCommand.CanExecute(null));
        Assert.Equal(2, health.CallCount);
    }

    [Fact]
    public async Task ManualWorkerRefreshClearsPreviousMsiOutcomeBeforeShowingFreshReason()
    {
        var health = new TestWorkerHealthService(
            Diagnostic(WorkerLaunchReason.Missing),
            Diagnostic(WorkerLaunchReason.AccessDenied),
            Diagnostic(WorkerLaunchReason.Timeout));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: health,
            repair: new TestWorkerRepairService(SuccessResult()));

        await viewModel.InitializeAsync();
        await viewModel.RepairWorkerAsync();
        Assert.Equal(WorkerRepairOutcome.Succeeded, viewModel.LastWorkerRepairOutcome);
        Assert.Contains("重新检测仍未通过", viewModel.WorkerRecoveryMessage, StringComparison.Ordinal);

        await viewModel.RefreshWorkerHealthAsync();

        Assert.Equal(WorkerLaunchReason.Timeout, viewModel.WorkerDiagnostic?.Reason);
        Assert.Null(viewModel.LastWorkerRepairOutcome);
        Assert.Equal(
            "Worker 健康检查超时。请重新检测；若仍超时，请导出诊断信息。",
            viewModel.WorkerRecoveryMessage);
    }

    [Theory]
    [MemberData(nameof(WorkerRecoveryCopy))]
    public async Task EveryUnhealthyReasonHasExactChineseRecoveryCopy(
        WorkerLaunchReason reason,
        bool repairOffered,
        string expectedCopy)
    {
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: new TestWorkerHealthService(Diagnostic(reason)));

        await viewModel.InitializeAsync();

        Assert.True(viewModel.IsWorkerRecoveryVisible);
        Assert.Equal(repairOffered, viewModel.IsWorkerRepairOffered);
        Assert.Equal(expectedCopy, viewModel.WorkerRecoveryMessage);
        Assert.Equal("WorkerRecoveryRegion", viewModel.FocusTargetAutomationId);
        Assert.Contains(expectedCopy, viewModel.WorkerRecoveryAutomationName, StringComparison.Ordinal);
        if (!repairOffered)
        {
            Assert.DoesNotContain("修复 Worker", viewModel.WorkerRecoveryMessage, StringComparison.Ordinal);
            Assert.DoesNotContain("重新安装 Worker 组件", viewModel.WorkerRecoveryMessage, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task UnhealthyWorkerExportUsesTypedAllowListedFieldsAndNeverReportsNoFault()
    {
        var shell = new TestOperatorShell();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Missing)),
            shell: shell);
        await viewModel.InitializeAsync();

        await viewModel.ExportDiagnosticsCommand.ExecuteAsync(null);

        IReadOnlyDictionary<string, object?> diagnostics = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(
            shell.LastDiagnostics);
        Assert.NotEqual("无故障", diagnostics["status"]);
        Assert.Equal("missing", diagnostics["reasonCode"]);
        Assert.Equal("Unhealthy", diagnostics["workerHealthState"]);
        Assert.Equal("missing", diagnostics["workerLaunchReason"]);
        Assert.Equal(true, diagnostics["workerRepairEligible"]);
        Assert.DoesNotContain(diagnostics.Keys, key =>
            key.Contains("sourcePath", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("originalPath", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("repairLogPath", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            diagnostics.Values.OfType<string>(),
            value => value.Contains(@"C:\release", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task FailedMsiOutcomeAppearsInRecoveryCopyAndTypedExportWithoutLogPath()
    {
        var shell = new TestOperatorShell();
        var repair = new TestWorkerRepairService(FailedResult(WorkerRepairOutcome.SourceUnavailable));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Missing)),
            repair: repair,
            shell: shell);
        await viewModel.InitializeAsync();

        await viewModel.RepairWorkerAsync();
        await viewModel.ExportDiagnosticsCommand.ExecuteAsync(null);

        Assert.Equal(
            "安装维护文件缺失，Worker 未修复。请使用本版本 EXE 安装包重新安装工具。",
            viewModel.WorkerRecoveryMessage);
        Assert.Equal("WorkerRecoveryRegion", viewModel.FocusTargetAutomationId);
        IReadOnlyDictionary<string, object?> diagnostics = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(
            shell.LastDiagnostics);
        Assert.Equal("source_unavailable", diagnostics["workerRepairOutcome"]);
        Assert.Equal(1612, diagnostics["workerRepairExitCode"]);
        Assert.Equal(true, diagnostics["workerRepairStarted"]);
        Assert.False(diagnostics.ContainsKey("workerRepairLogPath"));
        Assert.False(diagnostics.ContainsKey("sourcePath"));
        Assert.False(diagnostics.ContainsKey("originalPath"));
        Assert.DoesNotContain(@"C:\repair logs\worker.log", diagnostics.Values.OfType<string>());
    }

    [Fact]
    public async Task ExportDiagnosticsSerializesTypedWorkerAndFailedMsiFieldsToFinalJson()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        string outputPath = Path.Combine(evidenceDirectory, "worker-diagnostics-serialized.json");
        var shell = new SerializingTestOperatorShell(outputPath);
        var repair = new TestWorkerRepairService(FailedResult(WorkerRepairOutcome.SourceUnavailable));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Missing)),
            repair: repair,
            shell: shell);

        await viewModel.InitializeAsync();
        await viewModel.RepairWorkerAsync();
        await viewModel.ExportDiagnosticsCommand.ExecuteAsync(null);

        Assert.Equal(outputPath, viewModel.LastDiagnosticsPath);
        Assert.Equal(1, shell.ExportCount);
        Assert.True(File.Exists(outputPath));
        string json = await File.ReadAllTextAsync(outputPath);
        Assert.False(string.IsNullOrWhiteSpace(json));
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        Assert.Equal(3, root.GetProperty("schemaVersion").GetInt32());
        Assert.NotEqual("无故障", root.GetProperty("status").GetString());
        Assert.Equal("missing", root.GetProperty("reasonCode").GetString());
        Assert.Equal("Unhealthy", root.GetProperty("workerHealthState").GetString());
        Assert.Equal("missing", root.GetProperty("workerLaunchReason").GetString());
        Assert.True(root.GetProperty("workerRepairEligible").GetBoolean());
        Assert.Equal("source_unavailable", root.GetProperty("workerRepairOutcome").GetString());
        Assert.Equal(1612, root.GetProperty("workerRepairExitCode").GetInt32());
        Assert.True(root.GetProperty("workerRepairStarted").GetBoolean());
        Assert.False(root.TryGetProperty("sourcePath", out _));
        Assert.False(root.TryGetProperty("originalPath", out _));
        Assert.False(root.TryGetProperty("repairLogPath", out _));
        Assert.DoesNotContain("SHOULD_BE_DROPPED", json, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\release\secret\package.exe", json, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\repair logs\worker.log", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenInstallationDirectoryUsesApplicationBaseDirectory()
    {
        var shell = new TestOperatorShell();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.AccessDenied)),
            shell: shell);
        await viewModel.InitializeAsync();

        viewModel.OpenInstallationDirectoryCommand.Execute(null);

        Assert.Equal(Path.GetFullPath(AppContext.BaseDirectory), shell.OpenedFolder);
    }

    [Fact]
    public async Task BatchLaunchFailureUpdatesTheSameWorkerHealthState()
    {
        var health = new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Healthy));
        var batch = new TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, batch: batch);
        await PrepareSignableAsync(viewModel);
        Assert.True(viewModel.CanSign);
        WorkerLaunchDiagnostic missing = Diagnostic(WorkerLaunchReason.Missing);
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                Receipt(request, BatchResultCode.WorkerLaunchFailed, missing));
        };

        await viewModel.SignAsync();

        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Same(missing, viewModel.WorkerDiagnostic);
        Assert.False(viewModel.CanSign);
        Assert.Equal(1, batch.RunCount);
        Assert.Equal("WorkerRecoveryRegion", viewModel.FocusTargetAutomationId);
        Assert.Contains("未找到 CodeSigner.Worker.exe", viewModel.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeclinedRepairPreservesQueueAndSettingsWithoutCallingRepairOrProbe()
    {
        var health = new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Missing));
        var repair = new TestWorkerRepairService(SuccessResult());
        var confirmation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: health,
            repair: repair,
            confirmation: _ => new ValueTask<bool>(confirmation.Task));
        await PrepareSignableAsync(viewModel);
        Assert.True(viewModel.ApplySettings("https://timestamp.example.test", 90));
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        Task pendingRepair = viewModel.RepairWorkerAsync();
        Assert.Equal(WorkerHealthState.Repairing, viewModel.WorkerHealthState);
        Assert.False(viewModel.CanClose);
        Assert.False(viewModel.RefreshCommand.CanExecute(null));
        Assert.False(viewModel.RefreshWorkerCommand.CanExecute(null));
        confirmation.SetResult(false);
        await pendingRepair;

        Assert.Equal(WorkerRepairOutcome.ConfirmationDeclined, viewModel.LastWorkerRepairOutcome);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Equal(WorkerLaunchReason.Missing, viewModel.WorkerDiagnostic?.Reason);
        Assert.Equal(0, repair.CallCount);
        Assert.Equal(1, health.CallCount);
        Assert.Same(row, Assert.Single(viewModel.Rows));
        Assert.Equal(new Uri("https://timestamp.example.test"), viewModel.TimestampUri);
        Assert.Equal(90, viewModel.DiagnosticRetentionDays);
    }

    [Fact]
    public async Task RepairIsSerializedAndBlocksCloseAndRefreshWithoutBlockingSignOrClearingUserWork()
    {
        WorkerLaunchDiagnostic missing = Diagnostic(WorkerLaunchReason.Missing);
        var health = new TestWorkerHealthService(missing);
        var repairCompletion = new TaskCompletionSource<WorkerRepairResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var repair = new TestWorkerRepairService(_ => repairCompletion.Task);
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, repair: repair);
        await PrepareSignableAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        Task firstRepair = viewModel.RepairWorkerAsync();
        await repair.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(WorkerHealthState.Repairing, viewModel.WorkerHealthState);
        Assert.False(viewModel.CanClose);
        Assert.True(viewModel.CanSign);
        Assert.True(viewModel.SignCommand.CanExecute(null));
        Assert.False(viewModel.RefreshCommand.CanExecute(null));
        Assert.False(viewModel.RefreshWorkerCommand.CanExecute(null));
        Assert.False(viewModel.RepairWorkerCommand.CanExecute(null));
        Assert.True(viewModel.IsWorkerRecoveryVisible);
        Assert.True(viewModel.IsWorkerRepairOffered);
        Assert.Equal(
            "正在修复 Worker。Windows 安装程序完成后将自动重新检测。",
            viewModel.WorkerRecoveryMessage);

        await viewModel.RepairWorkerAsync();
        await viewModel.RefreshWorkerHealthAsync();
        Assert.Equal(1, repair.CallCount);
        Assert.Equal(1, health.CallCount);

        repairCompletion.SetResult(FailedResult(WorkerRepairOutcome.InstallerBusy));
        await firstRepair;

        Assert.True(viewModel.CanClose);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Same(missing, viewModel.WorkerDiagnostic);
        Assert.Same(row, Assert.Single(viewModel.Rows));
    }

    [Fact]
    public async Task SuccessfulMsiRepairProbesHealthyAndNeverStartsOrRetriesSigning()
    {
        var health = new TestWorkerHealthService(
            Diagnostic(WorkerLaunchReason.Missing),
            Diagnostic(WorkerLaunchReason.Healthy));
        var repair = new TestWorkerRepairService(SuccessResult());
        var batch = new TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: health,
            repair: repair,
            batch: batch);
        await PrepareSignableAsync(viewModel);
        Assert.True(viewModel.ApplySettings("https://timestamp.example.test", 90));
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        await viewModel.RepairWorkerAsync();

        Assert.Equal(WorkerRepairOutcome.Succeeded, viewModel.LastWorkerRepairOutcome);
        Assert.Equal(WorkerHealthState.Healthy, viewModel.WorkerHealthState);
        Assert.Equal(WorkerLaunchReason.Healthy, viewModel.WorkerDiagnostic?.Reason);
        Assert.True(viewModel.CanSign);
        Assert.Equal(2, health.CallCount);
        Assert.Equal(1, repair.CallCount);
        Assert.Equal(0, batch.RunCount);
        Assert.Equal(0, batch.ResumeCount);
        Assert.Same(row, Assert.Single(viewModel.Rows));
        Assert.Equal(new Uri("https://timestamp.example.test"), viewModel.TimestampUri);
        Assert.Equal(90, viewModel.DiagnosticRetentionDays);
    }

    [Fact]
    public async Task SuccessfulMsiRepairWithFailedProbeKeepsRecoveryAvailableAndNeverAutoSigns()
    {
        var health = new TestWorkerHealthService(
            Diagnostic(WorkerLaunchReason.Missing),
            Diagnostic(WorkerLaunchReason.Timeout));
        var repair = new TestWorkerRepairService(SuccessResult());
        var batch = new TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: health,
            repair: repair,
            batch: batch);
        await PrepareSignableAsync(viewModel);

        await viewModel.RepairWorkerAsync();

        Assert.Equal(WorkerRepairOutcome.Succeeded, viewModel.LastWorkerRepairOutcome);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Equal(WorkerLaunchReason.Timeout, viewModel.WorkerDiagnostic?.Reason);
        Assert.True(viewModel.CanSign);
        Assert.Equal(2, health.CallCount);
        Assert.Equal(0, batch.RunCount);
        Assert.Equal(0, batch.ResumeCount);
    }

    [Fact]
    public async Task FailedMsiRepairDoesNotProbeOrSign()
    {
        var health = new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Missing));
        var repair = new TestWorkerRepairService(FailedResult(WorkerRepairOutcome.SourceUnavailable));
        var batch = new TestBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: health,
            repair: repair,
            batch: batch);
        await PrepareSignableAsync(viewModel);

        await viewModel.RepairWorkerAsync();

        Assert.Equal(WorkerRepairOutcome.SourceUnavailable, viewModel.LastWorkerRepairOutcome);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Equal(1, health.CallCount);
        Assert.Equal(0, batch.RunCount);
        Assert.Equal(0, batch.ResumeCount);
    }

    [Fact]
    public async Task UacCancellationKeepsTheOriginalUnhealthyDiagnosticWithoutProbing()
    {
        WorkerLaunchDiagnostic missing = Diagnostic(WorkerLaunchReason.Missing);
        var health = new TestWorkerHealthService(missing);
        var repair = new TestWorkerRepairService(FailedResult(WorkerRepairOutcome.UacCancelled));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, repair: repair);
        await viewModel.InitializeAsync();

        await viewModel.RepairWorkerAsync();

        Assert.Equal(WorkerRepairOutcome.UacCancelled, viewModel.LastWorkerRepairOutcome);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Same(missing, viewModel.WorkerDiagnostic);
        Assert.Equal(1, health.CallCount);
        Assert.Equal(1, repair.CallCount);
    }

    [Fact]
    public async Task DisposalWaitsForActiveRepairWithoutCancellingIt()
    {
        var health = new TestWorkerHealthService(
            Diagnostic(WorkerLaunchReason.Missing),
            Diagnostic(WorkerLaunchReason.Healthy));
        var repairCompletion = new TaskCompletionSource<WorkerRepairResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var repair = new TestWorkerRepairService(_ => repairCompletion.Task);
        SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, repair: repair);
        await viewModel.InitializeAsync();

        Task activeRepair = viewModel.RepairWorkerAsync();
        await repair.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task disposal = viewModel.DisposeAsync().AsTask();

        Assert.False(disposal.IsCompleted);
        Assert.False(repair.LastCancellationToken.CanBeCanceled);
        repairCompletion.SetResult(SuccessResult());
        await activeRepair;
        await disposal;

        Assert.Equal(2, health.CallCount);
        Assert.Equal(1, repair.DisposeCount);
    }

    private static SigningWorkbenchViewModel CreateViewModel(
        TestWorkerHealthService? health = null,
        TestWorkerRepairService? repair = null,
        TestBatchAdapter? batch = null,
        IOperatorShell? shell = null,
        Func<CancellationToken, ValueTask<bool>>? confirmation = null)
    {
        var viewModel = new SigningWorkbenchViewModel(
            new TestReadinessAdapter(ReadySnapshot(Certificate())),
            new TestIntakeAdapter(),
            batch ?? new TestBatchAdapter(),
            shell ?? new TestOperatorShell(),
            health ?? new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Healthy)),
            repair ?? new TestWorkerRepairService(SuccessResult()),
            confirmation ?? (static _ => ValueTask.FromResult(true)));

        Assert.True(viewModel.ApplySettings(
            viewModel.TimestampUri.AbsoluteUri,
            viewModel.DiagnosticRetentionDays));
        return viewModel;
    }

    private static async Task PrepareSignableAsync(SigningWorkbenchViewModel viewModel)
    {
        await viewModel.InitializeAsync();
        await viewModel.ReplanOutputRootAsync(@"C:\release\out");
        await viewModel.QueueFilesAndWaitAsync([@"C:\release\package.exe"]);
    }

    private static string ResolveEvidenceDirectory()
    {
        string? configured = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured);
        }

        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(
            directory.FullName,
            "artifacts",
            "evidence",
            "worker-launch-diagnostics-repair",
            "task-6",
            "current",
            "fix-2");
    }

    private static WorkerLaunchDiagnostic Diagnostic(WorkerLaunchReason reason) =>
        WorkerLaunchDiagnosticMapper.ForReason(reason);

    private static WorkerRepairResult SuccessResult() =>
        RepairResult(WorkerRepairOutcome.Succeeded, exitCode: 0, started: true);

    private static WorkerRepairResult FailedResult(WorkerRepairOutcome outcome) =>
        RepairResult(outcome, ExitCodeFor(outcome), started: true);

    private static int? ExitCodeFor(WorkerRepairOutcome outcome) => outcome switch
    {
        WorkerRepairOutcome.SourceUnavailable => 1612,
        WorkerRepairOutcome.InstallerBusy => 1618,
        _ => 1618
    };

    private static WorkerRepairResult RepairResult(
        WorkerRepairOutcome outcome,
        int? exitCode,
        bool started) =>
        new(
            outcome,
            new CodeSignerInstallation(
                CodeSignerInstallationStatus.Installed,
                CodeSignerInstallationProbe.ObservedUpgradeCode,
                "{11111111-1111-1111-1111-111111111111}",
                CodeSignerInstallationProbe.ObservedProductName,
                CodeSignerInstallationProbe.ObservedPublisher,
                "1.0.0"),
            @"C:\repair logs\worker.log",
            exitCode,
            null,
            started);

    private static EligibleCertificate Certificate() => new(
        StoreLocation.CurrentUser,
        "My",
        new string('A', 40),
        "CN=Release",
        "CN=Issuing CA",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddYears(1),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

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

    private static BatchItemReceipt Receipt(
        BatchItemRequest request,
        BatchResultCode code,
        WorkerLaunchDiagnostic diagnostic) =>
        new(
            request.ItemId,
            BatchItemState.Failed,
            code,
            request.File.OriginalPath,
            request.File.DestinationPath,
            null,
            null,
            null,
            null,
            diagnostic.HResult,
            diagnostic);

    private sealed class TestWorkerHealthService : IWorkerHealthService
    {
        private readonly Queue<Func<CancellationToken, Task<WorkerLaunchDiagnostic>>> results;

        public TestWorkerHealthService(params WorkerLaunchDiagnostic[] results)
            : this(results.Select(result =>
                new Func<CancellationToken, Task<WorkerLaunchDiagnostic>>(_ => Task.FromResult(result))).ToArray())
        {
        }

        public TestWorkerHealthService(Func<CancellationToken, Task<WorkerLaunchDiagnostic>> result)
            : this([result])
        {
        }

        private TestWorkerHealthService(
            IEnumerable<Func<CancellationToken, Task<WorkerLaunchDiagnostic>>> results) =>
            this.results = new Queue<Func<CancellationToken, Task<WorkerLaunchDiagnostic>>>(results);

        public int CallCount { get; private set; }

        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            return results.Dequeue()(cancellationToken);
        }
    }

    private sealed class TestWorkerRepairService : IWorkerRepairService
    {
        private readonly Func<CancellationToken, Task<WorkerRepairResult>> behavior;

        public TestWorkerRepairService(WorkerRepairResult result)
            : this(_ => Task.FromResult(result))
        {
        }

        public TestWorkerRepairService(Func<CancellationToken, Task<WorkerRepairResult>> behavior) =>
            this.behavior = behavior;

        public int CallCount { get; private set; }

        public int DisposeCount { get; private set; }

        public CancellationToken LastCancellationToken { get; private set; }

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            LastCancellationToken = cancellationToken;
            Started.TrySetResult();
            return behavior(cancellationToken);
        }

        public void Dispose() => DisposeCount++;
    }

    private sealed class TestReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => snapshot;
    }

    private sealed class TestIntakeAdapter : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            string original = Assert.Single(inputs);
            string destinationRoot = outputRoot ?? @"C:\release\signed";
            return Task.FromResult(new IntakePlan(
                destinationRoot,
                [new IntakeFile(
                    original,
                    Path.GetFileName(original),
                    Path.Combine(destinationRoot, Path.GetFileName(original)),
                    destinationRoot,
                    new StableFileIdentity(7, "FILE-7"),
                    new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()))]));
        }
    }

    private sealed class TestBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

        public int RunCount { get; private set; }

        public int ResumeCount { get; private set; }

        public Func<IReadOnlyList<BatchItemRequest>, BatchProgressUpdate>? RunBehavior { get; set; }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            RunCount++;
            IReadOnlyList<BatchItemRequest> requests = [request];
            return Task.FromResult(RunBehavior?.Invoke(requests)
                ?? throw new InvalidOperationException("The test batch run was not configured."));
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            ResumeCount++;
            throw new InvalidOperationException("The test batch resume was not configured.");
        }

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public BatchProgressUpdate Emit(
            string itemId,
            BatchItemState state,
            BatchItemReceipt? receipt = null)
        {
            var update = new BatchProgressUpdate(itemId, state, receipt);
            ProgressChanged?.Invoke(this, new BatchProgressChangedEventArgs(update));
            return update;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class TestOperatorShell : IOperatorShell
    {
        public string? OpenedFolder { get; private set; }

        public IReadOnlyDictionary<string, object?>? LastDiagnostics { get; private set; }

        public void OpenFolder(string path)
        {
            OpenedFolder = path;
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken)
        {
            LastDiagnostics = diagnostics;
            return Task.FromResult(@"C:\diagnostics\worker.json");
        }
    }

    private sealed class SerializingTestOperatorShell(string outputPath) : IOperatorShell
    {
        public int ExportCount { get; private set; }

        public void OpenFolder(string path)
        {
        }

        public async Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken)
        {
            var candidate = new Dictionary<string, object?>(diagnostics, StringComparer.Ordinal)
            {
                ["sourcePath"] = @"C:\release\secret\package.exe",
                ["originalPath"] = @"C:\release\secret\package.exe",
                ["repairLogPath"] = @"C:\repair logs\worker.log",
                ["password"] = "SHOULD_BE_DROPPED",
                ["privateKey"] = "SHOULD_BE_DROPPED",
                ["pin"] = "SHOULD_BE_DROPPED"
            };
            await using FileStream stream = new(
                outputPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Read);
            await AllowListEvidenceWriter.WriteAsync(stream, candidate, cancellationToken);
            ExportCount++;
            return outputPath;
        }
    }
}
