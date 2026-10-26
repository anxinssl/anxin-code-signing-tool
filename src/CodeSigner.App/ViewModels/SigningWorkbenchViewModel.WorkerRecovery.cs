using System.IO;
using CodeSigner.App.Services;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    public Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        lock (startupTaskSync)
        {
            if (startupTask is not null)
            {
                return startupTask;
            }

            if (disposeRequested != 0)
            {
                return Task.CompletedTask;
            }

            cancellationToken.ThrowIfCancellationRequested();
            startupTask = InitializeCoreAsync(startupProbeCancellation.Token);
            return startupTask;
        }
    }

    private async Task InitializeCoreAsync(CancellationToken cancellationToken)
    {
        await RefreshSdkSignToolReadinessAsync(cancellationToken);
        await workerOperationGate.WaitAsync(cancellationToken);
        try
        {
            long observationId = StartWorkerObservation();
            TrySetWorkerHealth(observationId, WorkerHealthState.Checking, workerDiagnostic);
            WorkerLaunchDiagnostic diagnostic = await ProbeWorkerAsync(cancellationToken);
            ApplyWorkerDiagnostic(observationId, diagnostic);
        }
        finally
        {
            workerOperationGate.Release();
        }
    }

    public async Task RefreshReadinessAsync(CancellationToken cancellationToken = default)
    {
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.ReadinessRefresh, CurrentItem);
        if (audit is null)
        {
            return;
        }

        if (!CanRefreshWorker)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
            return;
        }

        SetReadinessRefreshing(true);
        try
        {
            RefreshEnvironmentReadiness();
            await RefreshSdkSignToolReadinessAsync(cancellationToken);
            bool refreshed = await RefreshWorkerHealthCoreAsync(cancellationToken);
            EndActionAudit(
                audit,
                refreshed ? QueueAuditOutcomes.Completed : QueueAuditOutcomes.Rejected,
                refreshed ? null : QueueAuditReasons.Busy);
        }
        catch (OperationCanceledException)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
            throw;
        }
        finally
        {
            SetReadinessRefreshing(false);
        }
    }

    public async Task RefreshWorkerHealthAsync(CancellationToken cancellationToken = default)
    {
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.ReadinessRefresh, CurrentItem);
        if (audit is null)
        {
            return;
        }

        try
        {
            bool refreshed = await RefreshWorkerHealthCoreAsync(cancellationToken);
            EndActionAudit(
                audit,
                refreshed ? QueueAuditOutcomes.Completed : QueueAuditOutcomes.Rejected,
                refreshed ? null : QueueAuditReasons.Busy);
        }
        catch (OperationCanceledException)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
            throw;
        }
    }

    private async Task<bool> RefreshWorkerHealthCoreAsync(CancellationToken cancellationToken)
    {
        if (!CanRefreshWorker || !workerOperationGate.Wait(0, CancellationToken.None))
        {
            return false;
        }

        try
        {
            long observationId = StartWorkerObservation();
            // A manual Probe is a fresh observation; do not let a previous MSI
            // result override the newly reported launch reason.
            LastWorkerRepairResult = null;
            LastWorkerRepairOutcome = null;
            TrySetWorkerHealth(observationId, WorkerHealthState.Checking, workerDiagnostic);
            WorkerLaunchDiagnostic diagnostic = await ProbeWorkerAsync(cancellationToken);
            ApplyWorkerDiagnostic(observationId, diagnostic);
            return true;
        }
        finally
        {
            workerOperationGate.Release();
        }
    }

    public async Task RepairWorkerAsync()
    {
        if (!CanRepairWorker || !workerOperationGate.Wait(0, CancellationToken.None))
        {
            return;
        }

        try
        {
            if (!CanRepairWorker)
            {
                return;
            }

            WorkerLaunchDiagnostic? diagnosticBeforeRepair = WorkerDiagnostic;
            long observationBeforeRepair = Volatile.Read(ref latestWorkerObservationId);
            TrySetWorkerHealth(
                observationBeforeRepair,
                WorkerHealthState.Repairing,
                diagnosticBeforeRepair);

            bool confirmed;
            try
            {
                confirmed = await workerRepairConfirmation(CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                confirmed = false;
            }

            if (!confirmed)
            {
                LastWorkerRepairResult = null;
                LastWorkerRepairOutcome = WorkerRepairOutcome.ConfirmationDeclined;
                RestoreWorkerHealthIfCurrent(observationBeforeRepair, diagnosticBeforeRepair);
                return;
            }

            LastWorkerRepairResult = null;
            LastWorkerRepairOutcome = null;

            WorkerRepairResult result;
            try
            {
                result = await workerRepairService.RepairAsync(CancellationToken.None);
            }
            catch (Exception error) when (error is InvalidOperationException or IOException or UnauthorizedAccessException)
            {
                LastWorkerRepairOutcome = WorkerRepairOutcome.UnknownExitCode;
                RestoreWorkerHealthIfCurrent(observationBeforeRepair, diagnosticBeforeRepair);
                return;
            }

            LastWorkerRepairResult = result;
            LastWorkerRepairOutcome = result.Outcome;
            if (!result.Succeeded)
            {
                RestoreWorkerHealthIfCurrent(observationBeforeRepair, diagnosticBeforeRepair);
                return;
            }

            long postRepairObservationId = StartWorkerObservation();
            WorkerLaunchDiagnostic postRepairDiagnostic = await ProbeWorkerAsync(CancellationToken.None);
            ApplyWorkerDiagnostic(postRepairObservationId, postRepairDiagnostic);
        }
        finally
        {
            workerOperationGate.Release();
        }
    }

    private async Task<WorkerLaunchDiagnostic> ProbeWorkerAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await workerHealthService.ProbeAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            return WorkerLaunchDiagnosticMapper.FromException(error);
        }
    }

    private long StartWorkerObservation()
    {
        lock (workerObservationSync)
        {
            long observationId = ++nextWorkerObservationId;
            Volatile.Write(ref latestWorkerObservationId, observationId);
            return observationId;
        }
    }

    private bool IsLatestWorkerObservation(long observationId) =>
        observationId != 0 && observationId == Volatile.Read(ref latestWorkerObservationId);

    private bool ApplyWorkerDiagnostic(long observationId, WorkerLaunchDiagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        return TrySetWorkerHealth(
            observationId,
            diagnostic.Reason == WorkerLaunchReason.Healthy
                ? WorkerHealthState.Healthy
                : WorkerHealthState.Unhealthy,
            diagnostic);
    }

    private bool TrySetWorkerHealth(
        long observationId,
        WorkerHealthState state,
        WorkerLaunchDiagnostic? diagnostic)
    {
        WorkerHealthState previousState;
        bool stateChanged;
        bool diagnosticChanged;
        lock (workerObservationSync)
        {
            if (observationId == 0 || observationId != latestWorkerObservationId)
            {
                return false;
            }

            previousState = workerHealthState;
            stateChanged = workerHealthState != state;
            diagnosticChanged = !EqualityComparer<WorkerLaunchDiagnostic?>.Default.Equals(
                workerDiagnostic,
                diagnostic);
            workerHealthState = state;
            workerDiagnostic = diagnostic;
        }

        return PublishWorkerHealthChanges(
            observationId,
            previousState,
            state,
            stateChanged,
            diagnosticChanged);
    }

    private void RestoreWorkerHealthIfCurrent(
        long observationBeforeRepair,
        WorkerLaunchDiagnostic? diagnosticBeforeRepair)
    {
        TrySetWorkerHealth(
            observationBeforeRepair,
            WorkerHealthState.Unhealthy,
            diagnosticBeforeRepair);
    }

    private bool PublishWorkerHealthChanges(
        long observationId,
        WorkerHealthState previousState,
        WorkerHealthState state,
        bool stateChanged,
        bool diagnosticChanged)
    {
        if (!stateChanged && !diagnosticChanged)
        {
            return true;
        }

        if (stateChanged &&
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(WorkerHealthState)))
        {
            return false;
        }

        if (diagnosticChanged &&
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(WorkerDiagnostic)))
        {
            return false;
        }

        if (!NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(CanRepairWorker)) ||
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(CanRefreshWorker)) ||
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(CanClose)) ||
            !NotifyWorkerRecoveryPresentationChanged(observationId))
        {
            return false;
        }

        RefreshValidation();
        if (!IsLatestWorkerObservation(observationId))
        {
            return false;
        }

        if (IsWorkerRecoveryVisible)
        {
            StatusMessage = WorkerRecoveryMessage;
            if (!IsLatestWorkerObservation(observationId))
            {
                return false;
            }

            ReadinessAnnouncement = WorkerRecoveryAutomationName;
            if (!IsLatestWorkerObservation(observationId))
            {
                return false;
            }

            FocusTargetAutomationId = "WorkerRecoveryRegion";
        }
        else if (state == WorkerHealthState.Healthy &&
                 previousState is WorkerHealthState.Unhealthy or WorkerHealthState.Repairing)
        {
            StatusMessage = "Worker 检测通过，可以继续签名。";
            if (!IsLatestWorkerObservation(observationId))
            {
                return false;
            }

            ReadinessAnnouncement = StatusMessage;
            if (!IsLatestWorkerObservation(observationId))
            {
                return false;
            }

            FocusTargetAutomationId = Rows.Count > 0 ? "SignButton" : "AddFilesButton";
        }

        return IsLatestWorkerObservation(observationId);
    }

    private bool NotifyWorkerRecoveryPresentationChanged(long observationId = 0)
    {
        if (!NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(IsWorkerRecoveryVisible)) ||
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(IsWorkerRepairOffered)) ||
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(WorkerRecoveryMessage)) ||
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(WorkerRecoveryAutomationName)) ||
            !NotifyWorkerPropertyChangedIfCurrent(observationId, nameof(WorkerRecoveryHelpText)))
        {
            return false;
        }

        OpenInstallationDirectoryCommand.RaiseCanExecuteChanged();
        return observationId == 0 || IsLatestWorkerObservation(observationId);
    }

    private bool NotifyWorkerPropertyChangedIfCurrent(long observationId, string propertyName)
    {
        if (observationId != 0 && !IsLatestWorkerObservation(observationId))
        {
            return false;
        }

        OnPropertyChanged(propertyName);
        return observationId == 0 || IsLatestWorkerObservation(observationId);
    }

    private string FormatWorkerRecoveryMessage()
    {
        if (WorkerHealthState == WorkerHealthState.Repairing)
        {
            return "正在修复 Worker。Windows 安装程序完成后将自动重新检测。";
        }

        string launchReason = FormatWorkerLaunchReason(WorkerDiagnostic?.Reason);
        return LastWorkerRepairOutcome switch
        {
            null => launchReason,
            WorkerRepairOutcome.Succeeded =>
                $"Worker 组件已重新安装，但重新检测仍未通过。{launchReason}",
            WorkerRepairOutcome.SucceededRestartRequired =>
                $"Worker 修复已完成且 Windows 要求重启；重新检测仍未通过。{launchReason}",
            WorkerRepairOutcome.Busy => "Worker 修复已在进行，未启动第二次修复。",
            WorkerRepairOutcome.ConfirmationDeclined => "已取消 Worker 修复，安装未更改。",
            WorkerRepairOutcome.UacCancelled => "已取消 Windows 用户帐户控制（UAC），Worker 未修复。",
            WorkerRepairOutcome.SourceUnavailable =>
                "安装维护文件缺失，Worker 未修复。请使用本版本 EXE 安装包重新安装工具。",
            WorkerRepairOutcome.InstallerBusy =>
                "安装维护程序正忙或组件被占用，Worker 未修复。请稍后重试。",
            WorkerRepairOutcome.Fatal =>
                "安装维护程序修复 Worker 失败。请关闭工具后重新运行本版本 EXE 安装包。",
            WorkerRepairOutcome.UnknownExitCode =>
                "安装维护程序返回未知结果，无法确认 Worker 是否已修复。",
            WorkerRepairOutcome.ProductNotInstalled =>
                "未找到与当前工具匹配的安装记录，请使用本版本 EXE 安装包重新安装。",
            WorkerRepairOutcome.AmbiguousProduct =>
                "检测到多个 CodeSigner 安装记录，未启动 Worker 修复。",
            WorkerRepairOutcome.ProductAdvertised =>
                "安装尚未完成，无法修复 Worker。请重新运行安装包。",
            WorkerRepairOutcome.MalformedProduct =>
                "CodeSigner 安装记录无效，未启动 Worker 修复。",
            WorkerRepairOutcome.WindowsInstallerUnavailable =>
                "安装维护程序不可用，无法修复 Worker。",
            _ => "Worker 修复结果无效。请导出诊断信息。"
        };
    }

    private string FormatWorkerRecoveryHelpText()
    {
        WorkerLaunchDiagnostic? diagnostic = WorkerDiagnostic;
        if (diagnostic is null)
        {
            return WorkerRecoveryMessage;
        }

        string eligibility = diagnostic.RepairEligible
            ? "此故障可使用“修复 Worker”重新安装 Worker 组件。"
            : "此故障不支持自动修复，请使用本版本 EXE 安装包重新安装。";
        return $"{WorkerRecoveryMessage} 原因代码：{diagnostic.ReasonCode}。{eligibility}";
    }

    private static string FormatWorkerLaunchReason(WorkerLaunchReason? reason) => reason switch
    {
        WorkerLaunchReason.Missing =>
            "未找到 CodeSigner.Worker.exe。可使用“修复 Worker”重新安装 Worker 组件。",
        WorkerLaunchReason.InvalidImage =>
            "CodeSigner.Worker.exe 文件无效或不支持当前 Windows x64。可使用“修复 Worker”重新安装 Worker 组件。",
        WorkerLaunchReason.VersionMismatch =>
            "Worker 与应用版本不一致。可使用“修复 Worker”重新安装匹配的 Worker 组件。",
        WorkerLaunchReason.AccessDenied =>
            "Windows 拒绝启动 Worker。请检查安装目录访问权限或安全策略，然后重新检测。",
        WorkerLaunchReason.StartFailed =>
            "Worker 无法启动。请重新检测；若仍失败，请导出诊断信息。",
        WorkerLaunchReason.UserMismatch =>
            "Worker 与当前应用不属于同一 Windows 用户。请使用当前用户重新启动应用。",
        WorkerLaunchReason.SessionMismatch =>
            "Worker 与当前应用不在同一 Windows 会话。请在当前会话中重新启动应用。",
        WorkerLaunchReason.MissingUserSid =>
            "无法确认 Worker 的 Windows 用户身份。请重新登录 Windows 后再试。",
        WorkerLaunchReason.Timeout =>
            "Worker 健康检查超时。请重新检测；若仍超时，请导出诊断信息。",
        WorkerLaunchReason.Crashed =>
            "Worker 在启动或通信期间退出。请重新检测并导出诊断信息。",
        WorkerLaunchReason.ProtocolMismatch =>
            "Worker 通信协议与当前应用不兼容。请安装匹配版本的 CodeSigner。",
        WorkerLaunchReason.InvalidFrame =>
            "Worker 返回了无效响应。请重新检测并导出诊断信息。",
        WorkerLaunchReason.Healthy => "Worker 检测通过。",
        null => "Worker 不可用。请重新检测并导出诊断信息。",
        _ => "Worker 状态无效。请导出诊断信息。"
    };

    private void OpenInstallationDirectory() =>
        operatorShell.OpenFolder(Path.GetFullPath(AppContext.BaseDirectory));
}
