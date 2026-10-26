using System.Collections.ObjectModel;
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
    public CertificateOptionViewModel? PrimaryCertificate
    {
        get => primaryCertificate;
        set
        {
            if (ReferenceEquals(primaryCertificate, value))
            {
                return;
            }

            ActionAudit? audit = BeginActionAudit(QueueAuditActions.PrimaryCertificateRoleChange, CurrentItem);
            if (audit is null)
            {
                return;
            }

            if (IsBusy)
            {
                EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
                return;
            }

            if (SetProperty(ref primaryCertificate, value))
            {
                RefreshValidation();
            }

            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
    }

    public CertificateOptionViewModel? SecondaryCertificate
    {
        get => secondaryCertificate;
        set
        {
            if (ReferenceEquals(secondaryCertificate, value))
            {
                return;
            }

            ActionAudit? audit = BeginActionAudit(QueueAuditActions.SecondaryCertificateRoleChange, CurrentItem);
            if (audit is null)
            {
                return;
            }

            if (IsBusy)
            {
                EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
                return;
            }

            if (SetProperty(ref secondaryCertificate, value))
            {
                RefreshValidation();
            }

            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
    }

    public SigningMode SelectedMode
    {
        get => selectedMode;
        set
        {
            if (selectedMode == value)
            {
                return;
            }

            ActionAudit? audit = BeginActionAudit(QueueAuditActions.ModeChange, CurrentItem);
            if (audit is null)
            {
                return;
            }

            if (IsBusy)
            {
                EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
                return;
            }

            if (!Enum.IsDefined(value))
            {
                EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.InvalidState);
                throw new ArgumentOutOfRangeException(nameof(value), value, "未知签名模式");
            }

            if (SetProperty(ref selectedMode, value))
            {
                foreach (QueueItemViewModel row in Rows)
                {
                    row.UpdateSigningMode(value);
                }

                OnPropertyChanged(nameof(IsSingleMode));
                OnPropertyChanged(nameof(IsDualMode));
                RefreshValidation();
            }

            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
    }

    public bool IsSingleMode
    {
        get => SelectedMode == SigningMode.Single;
        set
        {
            if (value)
            {
                SelectedMode = SigningMode.Single;
            }
        }
    }

    public bool IsDualMode
    {
        get => SelectedMode == SigningMode.Dual;
        set
        {
            if (value)
            {
                SelectedMode = SigningMode.Dual;
            }
        }
    }

    public string OutputRoot
    {
        get => outputRoot;
        set
        {
            string candidate = value ?? string.Empty;
            if (string.Equals(outputRoot, candidate, StringComparison.Ordinal))
            {
                return;
            }

            ActionAudit? audit = BeginActionAudit(QueueAuditActions.OutputReplan, CurrentItem);
            if (audit is null)
            {
                return;
            }

            if (IsBusy)
            {
                EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
                return;
            }

            if (SetProperty(ref outputRoot, candidate))
            {
                OutputError = HasValidOutputRoot()
                    ? string.Empty
                    : "选择有效的输出目录";
                if (!string.IsNullOrEmpty(OutputError))
                {
                    FocusTargetAutomationId = "OutputRootTextBox";
                }

                RefreshValidation();
            }

            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
    }

    public string InputError
    {
        get => inputError;
        private set => SetProperty(ref inputError, value);
    }

    public string OutputError
    {
        get => outputError;
        private set => SetProperty(ref outputError, value);
    }

    public string SettingsValidationError
    {
        get => settingsValidationError;
        private set => SetProperty(ref settingsValidationError, value);
    }

    public string SignDisabledReason
    {
        get => signDisabledReason;
        private set => SetProperty(ref signDisabledReason, value);
    }

    public string CurrentFileStatusText => FormatCurrentFileStatusText();

    public string FocusTargetAutomationId
    {
        get => focusTargetAutomationId;
        private set => SetProperty(ref focusTargetAutomationId, value);
    }

    public string StatusMessage
    {
        get => statusMessage;
        private set
        {
            if (SetProperty(ref statusMessage, value))
            {
                OnPropertyChanged(nameof(QueueStatusText));
            }
        }
    }

    public string ReadinessAnnouncement
    {
        get => readinessAnnouncement;
        private set => SetProperty(ref readinessAnnouncement, value);
    }

    public string LastDiagnosticsPath
    {
        get => lastDiagnosticsPath;
        private set => SetProperty(ref lastDiagnosticsPath, value);
    }

    public int AggregateProgressPercent
    {
        get => aggregateProgressPercent;
        private set => SetProperty(ref aggregateProgressPercent, value);
    }

    public bool IsBusy
    {
        get => isBusy || queueCancellation is not null;
        private set
        {
            if (SetProperty(ref isBusy, value))
            {
                NotifyBusyStateChanged();
            }
        }
    }

    public string SignButtonText => IsBusy ? "签名中……" :
        Rows.Count(row => row.State == BatchItemState.Pending) > 1 ? "批量签名" : "签名";

    public Uri TimestampUri => timestampUri;

    public int DiagnosticRetentionDays => diagnosticRetentionDays;

    public bool SdkSignToolAvailable => sdkSignToolDiscovery.IsAvailable;

    public TrustedSdkSignToolCandidate? SdkSignToolCandidate => sdkSignToolDiscovery.Candidate;

    public string SdkSignToolStatusText => sdkSignToolDiscovery.Status switch
    {
        SdkSignToolDiscoveryStatus.Available =>
            $"SDK 兼容备用可用；SDK 兼容备用已启用；SDK {sdkSignToolDiscovery.Candidate!.SdkVersion}；" +
                $"路径已验证：{sdkSignToolDiscovery.Candidate.Path}",
        SdkSignToolDiscoveryStatus.Rejected =>
            $"Windows SDK 签名工具不可用：{FormatSdkSignToolRejection(sdkSignToolDiscovery.RejectionReason)}",
        _ => "未检测到 Windows SDK 签名工具"
    };

    public WorkerHealthState WorkerHealthState => workerHealthState;

    public WorkerLaunchDiagnostic? WorkerDiagnostic => workerDiagnostic;

    public WorkerRepairResult? LastWorkerRepairResult
    {
        get => lastWorkerRepairResult;
        private set
        {
            if (SetProperty(ref lastWorkerRepairResult, value))
            {
                NotifyWorkerRecoveryPresentationChanged();
            }
        }
    }

    public WorkerRepairOutcome? LastWorkerRepairOutcome
    {
        get => lastWorkerRepairOutcome;
        private set
        {
            if (SetProperty(ref lastWorkerRepairOutcome, value))
            {
                NotifyWorkerRecoveryPresentationChanged();
            }
        }
    }

    public bool IsWorkerRecoveryVisible =>
        WorkerHealthState is WorkerHealthState.Unhealthy or WorkerHealthState.Repairing;

    public bool IsWorkerRepairOffered =>
        IsWorkerRecoveryVisible && WorkerDiagnostic?.RepairEligible == true;

    public string WorkerRecoveryMessage => FormatWorkerRecoveryMessage();

    public string WorkerRecoveryAutomationName => $"Worker 恢复。{WorkerRecoveryMessage}";

    public string WorkerRecoveryHelpText => FormatWorkerRecoveryHelpText();

    public bool CanRepairWorker => disposeRequested == 0 &&
        !auditIncomplete &&
        !IsBusy &&
        WorkerHealthState == WorkerHealthState.Unhealthy &&
        WorkerDiagnostic?.RepairEligible == true;

    public bool CanRefreshWorker => disposeRequested == 0 &&
        !auditIncomplete &&
        !IsBusy &&
        WorkerHealthState != WorkerHealthState.Repairing;

    public bool CanClose => WorkerHealthState != WorkerHealthState.Repairing;

    public bool CanSign => string.IsNullOrEmpty(SignDisabledReason);

    public string WorkstationStatus => WorkstationPresentation;

    public string NativeApiStatus =>
        PendingEnvironmentText("签名环境待检查", "正在检查签名环境") ??
        (
        $"PE 双重签名{(readiness?.NativeApi == NativeApiAvailability.Available ? "可用" : "不可用")}；" +
        $"Windows 单次签名{(readiness?.PowerShellBridge?.Status == WindowsPowerShellBridgeStatus.Available ? "可用" : "不可用")}");

    public string PowerShellBridgeStatus => PendingEnvironmentText("签名环境待检查", "正在检查签名环境") ??
        (readiness?.PowerShellBridge?.Status switch
    {
        WindowsPowerShellBridgeStatus.Available => "Windows PowerShell 5.1 签名桥可用",
        WindowsPowerShellBridgeStatus.ExecutionDenied => "Windows PowerShell 5.1 签名桥被系统策略阻止",
        WindowsPowerShellBridgeStatus.UnsupportedVersion => "Windows PowerShell 版本不受支持",
        _ => "Windows PowerShell 5.1 签名桥不可用"
    });

    public string SimplySignStatus => readiness?.SimplySign.Status == SimplySignInstallationStatus.Installed
        ? $"SimplySign 已安装（{readiness.SimplySign.Version ?? "版本未知"}）"
        : "SimplySign 未安装";

    public string CertificateStatus => readinessRefreshing ? "正在读取证书…" : readiness is null
        ? environmentCheckAttempted ? "证书读取失败，请重试" : "尚未刷新证书"
        : readiness.CertificateCatalog.Status == CertificateAvailabilityStatus.CertificateAvailable
            ? $"已读取 {readiness.CertificateCatalog.Certificates.Count} 张代码签名证书"
            : "未发现可用证书";

    public string CertificatePreparationHint =>
        readiness?.CertificateCatalog.Status == CertificateAvailabilityStatus.Unavailable
            ? "未发现可用的代码签名证书。云证书请检查 SimplySign 等对应客户端的登录状态；硬件 UKey 请检查 SafeNet 等驱动是否识别到设备和证书，然后重新刷新。"
            : "云证书请先登录对应客户端；硬件 UKey 请先插入设备并确认驱动已识别。准备完成后，点击“刷新证书”，读取到有效证书后再签名。";

    public string TimestampStatus => PendingEnvironmentText("时间戳配置待检查", "正在检查时间戳配置") ??
        (readiness?.Timestamp.Status == TimestampConfigurationStatus.Configured
        ? "时间戳已配置"
        : "时间戳配置无效");
}
