using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private void RefreshValidation(bool moveFocus = false)
    {
        ScheduleCurrentPreflight();
        BlockingReason blocking = FirstBlocking();
        SignDisabledReason = blocking.Reason ?? string.Empty;
        OnPropertyChanged(nameof(CurrentFileStatusText));
        if (moveFocus)
        {
            FocusTargetAutomationId = blocking.FocusTarget ?? "AddFilesButton";
        }

        OnPropertyChanged(nameof(CanSign));
        RefreshCommands();
    }

    private void ScheduleCurrentPreflight()
    {
        if (auditIncomplete || disposeRequested != 0 || queueCancellation?.IsCancellationRequested == true)
        {
            return;
        }

        QueueItemViewModel? current = CurrentItem;
        if (current is null ||
            current.State != BatchItemState.Pending ||
            current.DetectionState != QueueItemDetectionState.Supported ||
            current.SourceIntegrityState != QueueItemSourceIntegrityState.Current ||
            current.DetectedSource is null ||
            !IsCommittedOutputRootCurrent() ||
            current.PreflightState is not (QueueItemPreflightState.Unplanned or QueueItemPreflightState.Stale))
        {
            return;
        }

        _ = InvalidateCurrentPreflightAsync();
    }

    private string FormatCurrentFileStatusText()
    {
        QueueItemViewModel? current = CurrentItem;
        if (current is null || current.State != BatchItemState.Pending)
        {
            return SignDisabledReason;
        }

        return current.PreflightState switch
        {
            QueueItemPreflightState.Checking => "正在检查当前文件",
            QueueItemPreflightState.Ready => "当前文件检查就绪",
            QueueItemPreflightState.Blocked => FormatBlockedCurrentFile(current),
            _ => "当前文件尚未检查"
        };
    }

    private static string FormatBlockedCurrentFile(QueueItemViewModel current)
    {
        QueueItemPreflightIssue? issue = current.PreflightIssue;
        string reason = string.IsNullOrWhiteSpace(issue?.Message)
            ? "当前文件检查未通过"
            : issue.Message;
        return $"{reason}。解决方法：{FormatRecoveryPrompt(issue?.RecoveryAction ?? PreflightRecoveryAction.None)}";
    }

    private static string FormatRecoveryPrompt(PreflightRecoveryAction action) => action switch
    {
        PreflightRecoveryAction.OutputRoot => "选择其他输出目录",
        PreflightRecoveryAction.PrimaryCertificate => "选择主签名证书",
        PreflightRecoveryAction.SecondaryCertificate => "选择 SHA-256 辅助签名证书",
        PreflightRecoveryAction.TimestampSettings => "打开签名设置并检查时间戳地址",
        PreflightRecoveryAction.DiagnosticsAccess => "打开日志目录并恢复审计日志",
        PreflightRecoveryAction.RefreshReadiness => "刷新就绪状态",
        PreflightRecoveryAction.RepairReadiness => "刷新或修复运行环境",
        PreflightRecoveryAction.RemoveAndReAdd => "从队列移除当前文件后重新添加",
        _ => "检查当前文件状态"
    };

    private BlockingReason FirstBlocking(bool allowQueueExecution = false)
    {
        if (auditIncomplete)
        {
            return new("审计日志不可用，请先恢复审计日志", "OpenLogDirectoryButton");
        }

        if (isBusy || (queueCancellation is not null && !allowQueueExecution))
        {
            return new("签名正在进行中", "CancelButton");
        }

        QueueItemViewModel? current = CurrentItem;
        if (current is null)
        {
            return new("请选择一个签名文件项目", Rows.Count == 0 ? "AddFilesButton" : "QueueGrid");
        }

        if (current.State != BatchItemState.Pending)
        {
            return IsRetainedProblem(current)
                ? RetainedProblemBlocking(current)
                : new("当前签名文件项目已完成", current.AutomationId);
        }

        if (current.DetectionState is QueueItemDetectionState.Pending or QueueItemDetectionState.Running)
        {
            return new("正在检测当前签名文件项目", current.AutomationId);
        }

        if (current.DetectionState != QueueItemDetectionState.Supported)
        {
            return new("当前签名文件项目格式检测未通过", current.AutomationId);
        }

        if (current.SourceIntegrityState == QueueItemSourceIntegrityState.Unavailable)
        {
            return new("签名文件不存在", current.AutomationId);
        }

        if (current.SourceIntegrityState == QueueItemSourceIntegrityState.Changed)
        {
            return new("原始文件在签名期间发生变更", current.AutomationId);
        }

        if (!HasValidOutputRoot())
        {
            return new("选择有效的输出目录", "OutputRootTextBox");
        }

        if (current.PreflightState == QueueItemPreflightState.Checking)
        {
            return new("正在检查当前签名文件项目", current.AutomationId);
        }

        if (current.PreflightState == QueueItemPreflightState.Blocked)
        {
            return new(
                string.IsNullOrWhiteSpace(current.PreflightIssue?.Message)
                    ? "当前签名文件项目检查未通过"
                    : current.PreflightIssue.Message,
                string.IsNullOrWhiteSpace(current.PreflightIssue?.FocusTargetAutomationId)
                    ? current.AutomationId
                    : current.PreflightIssue.FocusTargetAutomationId);
        }

        if (current.PreflightState is QueueItemPreflightState.Unchecked or QueueItemPreflightState.Stale)
        {
            return new("当前签名文件项目尚未检查", current.AutomationId);
        }

        if (readiness is null)
        {
            return new("尚未检查就绪状态", "RefreshButton");
        }

        if (readiness.Workstation.Status != WorkstationSupportStatus.Supported)
        {
            return new("此 Windows 计算机不受支持", "ReadinessWorkstation");
        }

        if (current.Capability == SigningCapability.PeImageDualCapable &&
            readiness.NativeApi != NativeApiAvailability.Available)
        {
            return new("Windows 签名 API 不可用", "ReadinessNativeApi");
        }

        if (current.Capability != SigningCapability.PeImageDualCapable &&
            readiness.PowerShellBridge?.Status != WindowsPowerShellBridgeStatus.Available)
        {
            return new("Windows PowerShell 5.1 签名桥不可用", "ReadinessNativeApi");
        }

        if (readiness.CertificateCatalog.Status != CertificateAvailabilityStatus.CertificateAvailable)
        {
            return new("没有可用的代码签名证书", "ReadinessCertificates");
        }

        if (readiness.Timestamp.Status != TimestampConfigurationStatus.Configured)
        {
            return new("时间戳 URI 无效", "TimestampStatus");
        }

        if (PrimaryCertificate is null)
        {
            return new("选择主签名证书", "PrimaryCertificateCombo");
        }

        if (SelectedMode == SigningMode.Dual &&
            current.Capability == SigningCapability.PeImageDualCapable &&
            SecondaryCertificate is null)
        {
            return new("选择 SHA-256 辅助签名证书", "SecondaryCertificateCombo");
        }

        if (!current.HasOutputPlan(outputGeneration))
        {
            return new("验证输出目录是否适用于已添加的签名文件项目", "OutputRootTextBox");
        }

        return new(null, null);
    }

    private static bool IsRetainedProblem(QueueItemViewModel row) => row.State is
        BatchItemState.Failed or
        BatchItemState.PausedProvider or
        BatchItemState.PausedTimestamp or
        BatchItemState.Cancelled;

    private static BlockingReason RetainedProblemBlocking(QueueItemViewModel row) =>
        new("签名前请重试、移除失败、暂停或已取消的签名文件项目", row.AutomationId);

    private bool CanRetry() => !auditIncomplete && !IsBusy &&
        CurrentItem?.RetainedRequest is not null &&
        CurrentItem.State is BatchItemState.Failed or BatchItemState.PausedProvider or BatchItemState.PausedTimestamp;

    private bool CanRemoveSelected() => !auditIncomplete && !IsBusy &&
        Rows.Any(row => row.IsSelected && IsRemovable(row));

    private bool CanRemoveQueueItem(object? parameter) =>
        !auditIncomplete && !IsBusy && parameter is QueueItemViewModel row &&
        IsRemovable(row) && Rows.Contains(row);

    private static bool IsRemovable(QueueItemViewModel row) => row.State is
        BatchItemState.Pending or
        BatchItemState.Failed or
        BatchItemState.PausedProvider or
        BatchItemState.PausedTimestamp or
        BatchItemState.Cancelled or
        BatchItemState.Published or
        BatchItemState.SkippedAlreadySigned;

    private bool HasValidOutputRoot()
    {
        if (string.IsNullOrWhiteSpace(OutputRoot) || !Path.IsPathFullyQualified(OutputRoot))
        {
            return false;
        }

        try
        {
            return string.Equals(Path.GetFullPath(OutputRoot), OutputRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private void SetInputError(string message)
    {
        SetInputError(message, null, null);
    }

    private void SetInputError(string message, IntakeSource? source, IntakeError? error)
    {
        bool hasCurrentItem = CurrentItem is not null;
        inputErrorSource = source;
        inputErrorKind = error;
        InputError = message;
        StatusMessage = message;
        if (!hasCurrentItem)
        {
            FocusTargetAutomationId = "InputError";
        }

        RefreshValidation(moveFocus: hasCurrentItem);
    }

    private void ClearInputError()
    {
        bool clearsInputErrorFocus = !string.IsNullOrEmpty(InputError) ||
            string.Equals(FocusTargetAutomationId, "InputError", StringComparison.Ordinal);
        inputErrorSource = null;
        inputErrorKind = null;
        InputError = string.Empty;
        if (clearsInputErrorFocus)
        {
            RefreshValidation(moveFocus: true);
        }
    }

    private void ClearInputErrorFor(IntakeSource source)
    {
        if (inputErrorSource is null || IsSameIntakeSource(inputErrorSource, source))
        {
            ClearInputError();
        }
    }

    private void RefreshCommands()
    {
        ((AsyncCommand)AddFilesCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)AddFolderCommand).RaiseCanExecuteChanged();
        RemoveCommand.RaiseCanExecuteChanged();
        RemoveQueueItemCommand.RaiseCanExecuteChanged();
        ((AsyncCommand)RefreshCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)RefreshWorkerCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)RefreshSdkSignToolCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)RepairWorkerCommand).RaiseCanExecuteChanged();
        OpenOutputCommand.RaiseCanExecuteChanged();
        OpenInstallationDirectoryCommand.RaiseCanExecuteChanged();
        SettingsCommand.RaiseCanExecuteChanged();
        ((AsyncCommand)RetryCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)SignCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)CancelCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)ExportDiagnosticsCommand).RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanSign));
        OnPropertyChanged(nameof(CanSignQueue));
        OnPropertyChanged(nameof(QueueSignDisabledReason));
        OnPropertyChanged(nameof(QueueStatusText));
        OnPropertyChanged(nameof(SignButtonText));
    }

    private static IReadOnlyCollection<string> ToPaths(object? parameter) => parameter switch
    {
        IReadOnlyCollection<string> paths => paths,
        IEnumerable<string> paths => paths.ToArray(),
        string path => [path],
        _ => []
    };

    private static string ToSinglePath(object? parameter) => parameter as string ?? string.Empty;

    private static string SafeFileName(string? path)
    {
        try
        {
            string? fileName = Path.GetFileName(path);
            return string.IsNullOrEmpty(fileName) ? "无效输入" : fileName;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return "无效输入";
        }
    }

    private static string FormatIntakeError(IntakeValidationException exception)
    {
        string suffix = exception.Path is null ? string.Empty : $"：{SafeFileName(exception.Path)}";
        return exception.Error switch
        {
            IntakeError.UnsupportedExtension => $"不支持的签名文件类型{suffix}",
            IntakeError.NotSignableSubject => $"文件内容不是可签名的受支持格式{suffix}",
            IntakeError.DestinationExists => $"目标文件已存在，请选择其他输出目录{suffix}",
            IntakeError.DestinationCollision => $"多个签名文件输入解析到同一目标路径{suffix}",
            IntakeError.InputInsideOutputRoot => $"签名文件不能位于输出目录内{suffix}",
            IntakeError.ReparsePoint => $"不接受重解析点的签名文件导入{suffix}",
            IntakeError.InaccessibleInput => $"签名文件无法访问{suffix}",
            IntakeError.InputNotFound => $"签名文件不存在{suffix}",
            IntakeError.NoSignableInputs => "文件夹中不包含可接受的签名文件",
            IntakeError.SipUnavailable => $"Windows 签名处理程序不可用{suffix}",
            _ => $"签名文件输入无效{suffix}"
        };
    }

    private static string Identity(EligibleCertificate certificate) =>
        $"{certificate.StoreLocation}|{certificate.StoreName}|{certificate.Thumbprint}";

    private sealed record BlockingReason(string? Reason, string? FocusTarget);

}
