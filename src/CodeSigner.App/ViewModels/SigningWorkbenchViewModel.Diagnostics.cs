using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private async Task ExportDiagnosticsCoreAsync()
    {
        QueueItemViewModel? failed = Rows.FirstOrDefault(row => row.State is
            BatchItemState.Failed or BatchItemState.PausedProvider or BatchItemState.PausedTimestamp);
        SigningRuntimeEvent? lastRuntimeEvent = batchAdapter.LastRuntimeEvent;
        WorkerResponse? signingResponse = failed?.Receipt?.SigningDiagnostic;
        SigningRuntimeDiagnostic? fallbackDiagnostic = signingResponse is WorkerResponse response
            ? SigningRuntimeDiagnostic.FromWorkerResponse(
                response,
                failed?.Receipt?.WorkerStderrTail,
                failed?.Receipt?.WorkerStderrTruncated ?? false)
            : failed?.Receipt?.LaunchDiagnostic is WorkerLaunchDiagnostic launchDiagnostic
                ? SigningRuntimeDiagnostic.FromWorkerLaunchDiagnostic(launchDiagnostic)
                : null;
        SigningRuntimeEvent runtimeEvent = lastSigningDiagnosticEvent ??
            batchAdapter.LastDiagnosticRuntimeEvent ??
            lastRuntimeEvent ??
            SigningRuntimeEventLog.CreateEvent(
                "workbench-diagnostics",
                failed?.ItemId,
                failed?.Receipt?.WorkerProcessId,
                failed?.DetailText,
                fallbackDiagnostic);
        var diagnostics = new Dictionary<string, object?>(
            SigningDiagnosticExportProjection.Create(
                runtimeEvent,
                new SigningDiagnosticExportContext(
                DiagnosticLogPath: batchAdapter.RuntimeEventLogPath,
                VerificationState: VerificationState(failed?.Receipt?.SigningDiagnostic),
                TimestampUri: timestampUri,
                DetectedFormat: signingResponse?.Subject ?? WorkerSubject(failed?.FormatFamily),
                ContentProbeResult: failed is null ? null : SigningDiagnosticVocabulary.ValidatedContentProbe,
                RequestedPolicy: DiagnosticPolicy(failed?.RequestedMode),
                EffectivePolicy: DiagnosticPolicy(failed?.EffectiveMode),
                SelectedEngine: signingResponse?.Engine ?? WorkerEngine(failed?.Engine),
                LegacyFallbackAttempt: signingResponse?.LegacyFallbackAttempted,
                SdkSignToolAvailable: sdkSignToolDiscovery.IsAvailable,
                SdkSignToolVersion: sdkSignToolDiscovery.Candidate?.ProductVersion.ToString(),
                SdkSignToolPathStatus: SdkSignToolPathStatus(),
                PowerShellBridgeAvailability: PowerShellBridgeAvailability(),
                ProviderFamily: ProviderFamily(signingResponse?.Engine ?? WorkerEngine(failed?.Engine)),
                StructuredStage: signingResponse?.DiagnosticPhase ?? runtimeEvent.DiagnosticPhase,
                HResultClass: DiagnosticResultClass(signingResponse?.HResult ?? runtimeEvent.HResult),
                ExitClass: DiagnosticExitClass(runtimeEvent.WorkerExitCode),
                FinalVerification: VerificationState(signingResponse))),
            StringComparer.Ordinal)
        {
            ["status"] = WorkerHealthState == WorkerHealthState.Healthy ? "healthy" : "worker_unhealthy",
            ["reasonCode"] = WorkerDiagnostic?.ReasonCode,
            ["workerHealthState"] = WorkerHealthState.ToString(),
            ["workerLaunchReason"] = WorkerDiagnostic?.ReasonCode,
            ["workerRepairEligible"] = WorkerDiagnostic?.RepairEligible,
            ["workerHresult"] = WorkerDiagnostic?.HResult,
            ["workerNativeErrorCode"] = WorkerDiagnostic?.NativeErrorCode,
            ["workerExitCode"] = WorkerDiagnostic?.ExitCode ?? runtimeEvent.WorkerExitCode,
            ["workerRepairOutcome"] = FormatWorkerRepairOutcome(LastWorkerRepairOutcome),
            ["workerRepairStarted"] = LastWorkerRepairResult?.Started,
            ["workerRepairExitCode"] = LastWorkerRepairResult?.ExitCode,
            ["workerRepairNativeErrorCode"] = LastWorkerRepairResult?.NativeErrorCode,
            ["workerRepairRestartRequired"] = LastWorkerRepairResult?.RestartRequired,
            ["workerInstallationStatus"] = LastWorkerRepairResult?.Installation.Status.ToString(),
            ["workerInstallationDiagnosticCode"] = LastWorkerRepairResult?.Installation.DiagnosticCode
        };
        try
        {
            LastDiagnosticsPath = await operatorShell.ExportDiagnosticsAsync(
                diagnostics,
                DiagnosticRetentionDays,
                CancellationToken.None);
            StatusMessage = $"诊断信息已导出：{LastDiagnosticsPath}";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            StatusMessage = "诊断信息无法导出到本地诊断文件夹";
            FocusTargetAutomationId = "SummaryRegion";
        }
    }

    private static string? VerificationState(WorkerResponse? response) => response?.DiagnosticPhase switch
    {
        WorkerDiagnosticPhases.Verifying => "failed",
        WorkerDiagnosticPhases.SigningPrimary or WorkerDiagnosticPhases.SigningSecondary => "not_started",
        WorkerDiagnosticPhases.WorkerBridge => "not_started",
        _ => null
    };

    private static string? WorkerSubject(SigningFormatFamily? format) => format switch
    {
        SigningFormatFamily.PeImage => WorkerSubjects.PeImage,
        SigningFormatFamily.WindowsInstaller => WorkerSubjects.WindowsInstaller,
        SigningFormatFamily.Cabinet => WorkerSubjects.Cabinet,
        SigningFormatFamily.Catalog => WorkerSubjects.Catalog,
        SigningFormatFamily.AppPackage => WorkerSubjects.AppPackage,
        SigningFormatFamily.PowerShellScript => WorkerSubjects.PowerShellScript,
        SigningFormatFamily.WindowsScript => WorkerSubjects.WindowsScript,
        _ => null
    };

    private static string? WorkerEngine(SigningEngine? engine) => engine switch
    {
        SigningEngine.PeImage => WorkerEngines.PeImage,
        SigningEngine.WindowsSip => WorkerEngines.WindowsSip,
        _ => null
    };

    private static string? DiagnosticPolicy(SigningMode? mode) => mode switch
    {
        SigningMode.Single => "single",
        SigningMode.Dual => "dual",
        _ => null
    };

    private string SdkSignToolPathStatus() => sdkSignToolDiscovery.Status switch
    {
        SdkSignToolDiscoveryStatus.Available => "canonical_verified",
        SdkSignToolDiscoveryStatus.Rejected => "rejected",
        _ => "not_found"
    };

    private string? PowerShellBridgeAvailability() => readiness?.PowerShellBridge?.Status switch
    {
        WindowsPowerShellBridgeStatus.Available => "available",
        WindowsPowerShellBridgeStatus.Unavailable => "unavailable",
        WindowsPowerShellBridgeStatus.ExecutionDenied => "execution_denied",
        WindowsPowerShellBridgeStatus.UnsupportedVersion => "unsupported_version",
        _ => null
    };

    private static string ProviderFamily(string? engine) => engine switch
    {
        WorkerEngines.PeImage => "windows_native",
        WorkerEngines.WindowsSip => "windows_sip",
        _ => "unknown"
    };

    private static string DiagnosticResultClass(int? value) => value switch
    {
        null => "not_available",
        < 0 => "failure",
        _ => "success"
    };

    private static string DiagnosticExitClass(int? value) => value switch
    {
        null => "not_available",
        0 => "success",
        _ => "failure"
    };

    private static string? FormatWorkerRepairOutcome(WorkerRepairOutcome? outcome) => outcome switch
    {
        null => null,
        WorkerRepairOutcome.Succeeded => "succeeded",
        WorkerRepairOutcome.SucceededRestartRequired => "succeeded_restart_required",
        WorkerRepairOutcome.Busy => "busy",
        WorkerRepairOutcome.ConfirmationDeclined => "confirmation_declined",
        WorkerRepairOutcome.UacCancelled => "uac_cancelled",
        WorkerRepairOutcome.SourceUnavailable => "source_unavailable",
        WorkerRepairOutcome.InstallerBusy => "installer_busy",
        WorkerRepairOutcome.Fatal => "fatal",
        WorkerRepairOutcome.UnknownExitCode => "unknown_exit_code",
        WorkerRepairOutcome.ProductNotInstalled => "product_not_installed",
        WorkerRepairOutcome.AmbiguousProduct => "ambiguous_product",
        WorkerRepairOutcome.ProductAdvertised => "product_advertised",
        WorkerRepairOutcome.MalformedProduct => "malformed_product",
        WorkerRepairOutcome.WindowsInstallerUnavailable => "windows_installer_unavailable",
        _ => "invalid"
    };

    private void OpenOutput()
    {
        if (!HasValidOutputRoot())
        {
            OutputError = "选择有效的输出目录";
            FocusTargetAutomationId = "OutputRootTextBox";
            return;
        }

        operatorShell.OpenFolder(OutputRoot);
    }

    private void OpenLogDirectory()
    {
        try
        {
            operatorShell.OpenFolder(SigningRuntimeEventLog.DefaultDiagnosticsRoot);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            StatusMessage = "无法打开日志目录：日志目录路径无效。";
            FocusTargetAutomationId = "SummaryRegion";
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or DirectoryNotFoundException or IOException)
        {
            StatusMessage = "无法打开日志目录：无法创建或访问日志目录。";
            FocusTargetAutomationId = "SummaryRegion";
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            StatusMessage = "无法打开日志目录：无法启动文件资源管理器。";
            FocusTargetAutomationId = "SummaryRegion";
        }
    }
}
