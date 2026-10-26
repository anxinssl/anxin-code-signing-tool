using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.ViewModels;

public enum QueueItemPreflightState
{
    Unplanned,
    Planning,
    Ready,
    Blocked,
    Stale,
    Unchecked = Unplanned,
    Checking = Planning
}

public enum QueueItemDetectionState
{
    Pending,
    Running,
    Supported,
    Blocked,
    Faulted,
    Cancelled
}

public enum QueueItemSourceIntegrityState
{
    Current,
    Unavailable,
    Changed
}

public enum QueueItemPreflightIssueCode
{
    AuditLogUnavailable,
    SourceUnavailable,
    SourceChanged,
    UnsupportedFormat,
    OutputUnavailable,
    WorkstationUnavailable,
    SigningCapabilityUnavailable,
    ProviderUnavailable,
    CertificateUnavailable,
    TimestampUnavailable
}

public sealed record QueueItemPreflightIssue(
    QueueItemPreflightIssueCode Code,
    string DetailCode,
    string Message = "",
    string FocusTargetAutomationId = "",
    PreflightRecoveryAction RecoveryAction = PreflightRecoveryAction.None);

public sealed class QueueItemViewModel : ObservableObject
{
    private IntakeFile? currentIntakeFile;
    private DetectedQueuedSource? detectedSource;
    private QueueItemDetectionState detectionState;
    private QueueItemSourceIntegrityState sourceIntegrityState = QueueItemSourceIntegrityState.Current;
    private BatchItemState state = BatchItemState.Pending;
    private QueueItemPreflightState preflightState;
    private QueueItemPreflightIssue? preflightIssue;
    private int progressPercent;
    private string resultText = string.Empty;
    private string detailText = string.Empty;
    private bool isSelected;
    private int? hResult;
    private BatchItemReceipt? receipt;
    private BatchItemRequest? retainedRequest;
    private SigningMode requestedMode = SigningMode.Single;

    public QueueItemViewModel(string itemId, IntakeFile file)
        : this(itemId, new QueuedSource(file.OriginalPath, file.Identity), file)
    {
    }

    public QueueItemViewModel(string itemId, QueuedSource source, IntakeFile? currentIntakeFile = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        ItemId = itemId;
        Source = source ?? throw new ArgumentNullException(nameof(source));
        this.currentIntakeFile = currentIntakeFile;
        detectionState = currentIntakeFile is null
            ? QueueItemDetectionState.Pending
            : QueueItemDetectionState.Supported;
        DetectionGeneration = currentIntakeFile is null ? 0 : 1;
        preflightState = currentIntakeFile is null
            ? QueueItemPreflightState.Unplanned
            : QueueItemPreflightState.Ready;
    }

    public string ItemId { get; }

    public QueuedSource Source { get; }

    public IntakeFile? CurrentIntakeFile => currentIntakeFile;

    public DetectedQueuedSource? DetectedSource => detectedSource;

    public IntakeFile File => currentIntakeFile ??
        throw new InvalidOperationException("The queue item does not have a current intake file.");

    public string FullPath => Source.CanonicalPath;

    public string DisplayName => Source.RelativePath;

    public string DestinationPath => currentIntakeFile?.DestinationPath ?? string.Empty;

    public SigningFormatFamily FormatFamily => RequiredSubject.FormatFamily;

    public SigningFormatFamily DetectedFormatFamily => FormatFamily;

    public SigningCapability Capability => RequiredSubject.Capability;

    public SigningEngine Engine => Capability == SigningCapability.PeImageDualCapable
        ? SigningEngine.PeImage
        : SigningEngine.WindowsSip;

    public SigningEngine SelectedEngineKind => Engine;

    public SigningVerification Verification => Capability == SigningCapability.PeImageDualCapable
        ? SigningVerification.PeImage
        : SigningVerification.WindowsSip;

    public SigningMode RequestedMode => requestedMode;

    public SigningMode EffectiveMode => requestedMode == SigningMode.Dual &&
        Capability == SigningCapability.PeImageDualCapable
            ? SigningMode.Dual
            : SigningMode.Single;

    public SigningMode EffectiveSigningMode => EffectiveMode;

    public string FormatText => CurrentSubject is SigningSubject subject
        ? FormatFor(subject.FormatFamily)
        : DetectionPlaceholder;

    public string DetectedFormat => FormatText;

    public string EngineText => CurrentSubject is not null
        ? EngineFor(Engine, EffectiveMode)
        : DetectionPlaceholder;

    public string SelectedEngine => EngineText;

    public string EffectivePolicyText => CurrentSubject is null
        ? DetectionPlaceholder
        : EffectiveMode == SigningMode.Dual
            ? "SHA-1 + SHA-256"
            : "SHA-256";

    public string EffectivePolicy => EffectivePolicyText;

    public string PolicyText => EffectivePolicyText;

    public string AutomationId => $"QueueRow_{ItemId}";

    public string RemoveAutomationId => $"{AutomationId}_Remove";

    public BatchItemState State
    {
        get => state;
        private set => SetProperty(ref state, value);
    }

    public string StateText => FormatState(State);

    public QueueItemDetectionState DetectionState
    {
        get => detectionState;
        private set => SetProperty(ref detectionState, value);
    }

    public QueueItemSourceIntegrityState SourceIntegrityState
    {
        get => sourceIntegrityState;
        private set => SetProperty(ref sourceIntegrityState, value);
    }

    public string DetectionStateText => DetectionTextFor(DetectionState);

    public string SourceStateText => SourceIntegrityState switch
    {
        QueueItemSourceIntegrityState.Current => "当前",
        QueueItemSourceIntegrityState.Unavailable => "源文件不可用，请移除后重新添加",
        QueueItemSourceIntegrityState.Changed => "源文件已更改，请移除后重新添加",
        _ => throw new ArgumentOutOfRangeException(nameof(SourceIntegrityState), SourceIntegrityState, "未知源文件状态")
    };

    public QueueItemPreflightState PreflightState
    {
        get => preflightState;
        private set => SetProperty(ref preflightState, value);
    }

    public QueueItemPreflightIssue? PreflightIssue
    {
        get => preflightIssue;
        private set => SetProperty(ref preflightIssue, value);
    }

    public long RowGeneration { get; private set; } = 1;

    public long ConfigGeneration { get; private set; }

    public long OutputGeneration { get; private set; }

    public long ValidationGeneration { get; private set; }

    public long DetectionGeneration { get; private set; }

    public long PlanGeneration { get; private set; }

    public long ExecutionGeneration { get; private set; }

    public int ProgressPercent
    {
        get => progressPercent;
        private set => SetProperty(ref progressPercent, value);
    }

    public string ResultText
    {
        get => resultText;
        private set => SetProperty(ref resultText, value);
    }

    public string DetailText
    {
        get => detailText;
        private set => SetProperty(ref detailText, value);
    }

    public bool IsSelected
    {
        get => isSelected;
        set => SetProperty(ref isSelected, value);
    }

    public int? HResult
    {
        get => hResult;
        private set => SetProperty(ref hResult, value);
    }

    public BatchItemReceipt? Receipt
    {
        get => receipt;
        private set => SetProperty(ref receipt, value);
    }

    public string AutomationName =>
        $"{FullPath}；源文件 {SourceStateText}；检测 {DetectionStateText}；格式 {FormatText}；" +
        $"引擎 {EngineText}；策略 {EffectivePolicyText}；" +
        $"{StateText}；进度 {ProgressPercent}%；{ResultText}";

    private SigningSubject? CurrentSubject =>
        detectedSource?.Subject.PolicySubject ?? currentIntakeFile?.Subject.PolicySubject;

    private SigningSubject RequiredSubject => CurrentSubject ??
        throw new InvalidOperationException("The queue item does not have a supported detection result.");

    private string DetectionPlaceholder => DetectionState switch
    {
        QueueItemDetectionState.Pending => "等待检测",
        QueueItemDetectionState.Running => "正在检测",
        QueueItemDetectionState.Blocked => "格式不受支持",
        QueueItemDetectionState.Faulted => "检测失败",
        QueueItemDetectionState.Cancelled => "检测已取消",
        QueueItemDetectionState.Supported => "等待输出规划",
        _ => throw new ArgumentOutOfRangeException(nameof(DetectionState), DetectionState, "未知检测状态")
    };

    public long BeginDetection()
    {
        EnsurePendingExecution("Only pending queue items can start detection.");
        if (DetectionState != QueueItemDetectionState.Pending)
        {
            throw new InvalidOperationException("Detection can start only once per queue item.");
        }

        DetectionGeneration++;
        DetectionState = QueueItemDetectionState.Running;
        OnPropertyChanged(nameof(DetectionGeneration));
        NotifySourcePresentationChanged();
        return DetectionGeneration;
    }

    public void CompleteDetection(DetectedQueuedSource result, long generation)
    {
        ArgumentNullException.ThrowIfNull(result);
        EnsureDetectionCompletion(generation);
        if (!string.Equals(result.Source.CanonicalPath, Source.CanonicalPath, StringComparison.OrdinalIgnoreCase) ||
            result.Source.Identity != Source.Identity)
        {
            throw new ArgumentException("The detection result must match the queue source.", nameof(result));
        }

        detectedSource = result;
        DetectionState = QueueItemDetectionState.Supported;
        OnPropertyChanged(nameof(DetectedSource));
        NotifySourcePresentationChanged();
    }

    public void BlockDetection(long generation) =>
        CompleteDetectionWithoutSource(QueueItemDetectionState.Blocked, generation);

    public void FaultDetection(long generation) =>
        CompleteDetectionWithoutSource(QueueItemDetectionState.Faulted, generation);

    public void CancelDetection(long generation) =>
        CompleteDetectionWithoutSource(QueueItemDetectionState.Cancelled, generation);

    public void MarkSourceUnavailable() => SetSourceIntegrity(QueueItemSourceIntegrityState.Unavailable);

    public void MarkSourceChanged() => SetSourceIntegrity(QueueItemSourceIntegrityState.Changed);

    public void MarkSourceCurrent()
    {
        EnsurePendingExecution("Historical queue items cannot rewrite source integrity.");
        if (SourceIntegrityState != QueueItemSourceIntegrityState.Current)
        {
            throw new InvalidOperationException("Changed or unavailable sources require remove and re-add.");
        }
    }

    public long BeginPlan(long configGeneration, long outputGeneration)
    {
        EnsurePendingExecution("Only pending queue items can start output planning.");
        if (DetectionState != QueueItemDetectionState.Supported ||
            SourceIntegrityState != QueueItemSourceIntegrityState.Current)
        {
            throw new InvalidOperationException("Only a supported, current source can be planned.");
        }

        ConfigGeneration = configGeneration;
        OutputGeneration = outputGeneration;
        PlanGeneration++;
        ValidationGeneration++;
        PreflightIssue = null;
        PreflightState = QueueItemPreflightState.Planning;
        OnPropertyChanged(nameof(ConfigGeneration));
        OnPropertyChanged(nameof(OutputGeneration));
        OnPropertyChanged(nameof(PlanGeneration));
        OnPropertyChanged(nameof(ValidationGeneration));
        return PlanGeneration;
    }

    public long BeginExecutionAttempt()
    {
        if (State is not (BatchItemState.Pending or BatchItemState.Failed or
            BatchItemState.PausedProvider or BatchItemState.PausedTimestamp))
        {
            throw new InvalidOperationException("The queue item cannot start a new execution attempt.");
        }

        ExecutionGeneration++;
        OnPropertyChanged(nameof(ExecutionGeneration));
        return ExecutionGeneration;
    }

    private void CompleteDetectionWithoutSource(QueueItemDetectionState terminal, long generation)
    {
        EnsureDetectionCompletion(generation);
        DetectionState = terminal;
        NotifySourcePresentationChanged();
    }

    private void EnsureDetectionCompletion(long generation)
    {
        EnsurePendingExecution("Historical queue items cannot rewrite source detection.");
        if (DetectionState != QueueItemDetectionState.Running || generation != DetectionGeneration)
        {
            throw new InvalidOperationException("The detection completion is stale or the detection is already terminal.");
        }
    }

    private void SetSourceIntegrity(QueueItemSourceIntegrityState value)
    {
        EnsurePendingExecution("Historical queue items cannot rewrite source integrity.");
        if (SourceIntegrityState != QueueItemSourceIntegrityState.Current)
        {
            throw new InvalidOperationException("Changed or unavailable sources require remove and re-add.");
        }

        SourceIntegrityState = value;
        if (PreflightState is QueueItemPreflightState.Planning or QueueItemPreflightState.Ready)
        {
            PreflightState = QueueItemPreflightState.Blocked;
        }

        OnPropertyChanged(nameof(SourceStateText));
        OnPropertyChanged(nameof(AutomationName));
    }

    private void EnsurePendingExecution(string message)
    {
        if (State != BatchItemState.Pending)
        {
            throw new InvalidOperationException(message);
        }
    }

    private void NotifySourcePresentationChanged()
    {
        OnPropertyChanged(nameof(DetectionStateText));
        OnPropertyChanged(nameof(FormatText));
        OnPropertyChanged(nameof(DetectedFormat));
        OnPropertyChanged(nameof(EngineText));
        OnPropertyChanged(nameof(SelectedEngine));
        OnPropertyChanged(nameof(EffectivePolicyText));
        OnPropertyChanged(nameof(EffectivePolicy));
        OnPropertyChanged(nameof(PolicyText));
        OnPropertyChanged(nameof(AutomationName));
    }

    public void UpdateSigningMode(SigningMode mode)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "未知签名模式");
        }

        if (requestedMode == mode)
        {
            return;
        }

        if (State != BatchItemState.Pending)
        {
            return;
        }

        requestedMode = mode;
        OnPropertyChanged(nameof(RequestedMode));
        OnPropertyChanged(nameof(EffectiveMode));
        OnPropertyChanged(nameof(EffectiveSigningMode));
        OnPropertyChanged(nameof(EffectivePolicyText));
        OnPropertyChanged(nameof(EffectivePolicy));
        OnPropertyChanged(nameof(PolicyText));
        OnPropertyChanged(nameof(EngineText));
        OnPropertyChanged(nameof(SelectedEngine));
        OnPropertyChanged(nameof(AutomationName));
    }

    public BatchItemRequest? RetainedRequest
    {
        get => retainedRequest;
        private set => SetProperty(ref retainedRequest, value);
    }

    public void ReplaceFile(IntakeFile updatedFile)
    {
        ArgumentNullException.ThrowIfNull(updatedFile);
        EnsurePendingExecution("Historical queue items cannot replace their planned file.");
        if (!string.Equals(updatedFile.OriginalPath, FullPath, StringComparison.OrdinalIgnoreCase) ||
            updatedFile.Identity != Source.Identity)
        {
            throw new ArgumentException("The planned file must match the queue source.", nameof(updatedFile));
        }

        currentIntakeFile = updatedFile;
        RowGeneration++;
        OnPropertyChanged(nameof(CurrentIntakeFile));
        OnPropertyChanged(nameof(File));
        OnPropertyChanged(nameof(FullPath));
        OnPropertyChanged(nameof(DestinationPath));
        OnPropertyChanged(nameof(FormatFamily));
        OnPropertyChanged(nameof(DetectedFormatFamily));
        OnPropertyChanged(nameof(Capability));
        OnPropertyChanged(nameof(Engine));
        OnPropertyChanged(nameof(SelectedEngineKind));
        OnPropertyChanged(nameof(Verification));
        OnPropertyChanged(nameof(FormatText));
        OnPropertyChanged(nameof(DetectedFormat));
        OnPropertyChanged(nameof(EngineText));
        OnPropertyChanged(nameof(SelectedEngine));
        OnPropertyChanged(nameof(EffectivePolicyText));
        OnPropertyChanged(nameof(EffectivePolicy));
        OnPropertyChanged(nameof(PolicyText));
        OnPropertyChanged(nameof(AutomationName));
    }

    public void CommitOutputPlan(IntakeFile updatedFile, long outputGeneration)
    {
        EnsurePendingExecution("Only pending queue items can accept a new output plan.");
        if (PreflightState != QueueItemPreflightState.Planning)
        {
            throw new InvalidOperationException("An output plan can be committed only while planning.");
        }

        if (!string.Equals(updatedFile.OriginalPath, FullPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The output plan source must match the queue item.", nameof(updatedFile));
        }

        ReplaceFile(updatedFile);
        OutputGeneration = outputGeneration;
        OnPropertyChanged(nameof(OutputGeneration));
    }

    public void InvalidateOutputPlan()
    {
        EnsurePendingExecution("Historical queue items cannot invalidate their output plan.");

        RowGeneration++;
        PlanGeneration++;
        PreflightIssue = null;
        PreflightState = QueueItemPreflightState.Stale;
        OnPropertyChanged(nameof(RowGeneration));
        OnPropertyChanged(nameof(PlanGeneration));
    }

    public bool HasOutputPlan(long outputGeneration) =>
        State == BatchItemState.Pending &&
        CurrentIntakeFile is not null &&
        OutputGeneration == outputGeneration;

    public void SetPreflightChecking(long configGeneration, long outputGeneration)
    {
        BeginPlan(configGeneration, outputGeneration);
    }

    public void SetPreflightReady()
    {
        EnsurePendingExecution("Historical queue items cannot rewrite their plan state.");
        if (PreflightState != QueueItemPreflightState.Planning)
        {
            throw new InvalidOperationException("Only a planning queue item can become ready.");
        }

        PreflightIssue = null;
        PreflightState = QueueItemPreflightState.Ready;
    }

    public void SetPreflightBlocked(QueueItemPreflightIssue issue)
    {
        EnsurePendingExecution("Historical queue items cannot rewrite their plan state.");
        PreflightIssue = issue ?? throw new ArgumentNullException(nameof(issue));
        PreflightState = QueueItemPreflightState.Blocked;
    }

    public void SetPreflightUnchecked()
    {
        EnsurePendingExecution("Historical queue items cannot rewrite their plan state.");
        PreflightIssue = null;
        PreflightState = QueueItemPreflightState.Unplanned;
    }

    public void RetainRequest(BatchItemRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!string.Equals(request.ItemId, ItemId, StringComparison.Ordinal))
        {
            throw new ArgumentException("The retained request item ID must match the queue item.", nameof(request));
        }

        if (RetainedRequest is not null)
        {
            if (ReferenceEquals(RetainedRequest, request))
            {
                return;
            }

            throw new InvalidOperationException("The retained request is immutable for the queue item lifetime.");
        }

        if (State != BatchItemState.Pending)
        {
            throw new InvalidOperationException("Historical queue items cannot accept a new retained request.");
        }

        RetainedRequest = request;
    }

    public void Apply(BatchItemState newState, BatchItemReceipt? receipt)
    {
        State = newState;
        ProgressPercent = ProgressFor(newState);
        Receipt = receipt;
        HResult = receipt?.HResult;
        ResultText = ResultFor(newState, receipt?.Code);
        DetailText = FormatFailureDetail(newState, receipt);
        OnPropertyChanged(nameof(StateText));
        OnPropertyChanged(nameof(AutomationName));
    }

    private static int ProgressFor(BatchItemState value) => value switch
    {
        BatchItemState.Pending or BatchItemState.Ready => 0,
        BatchItemState.SigningPrimary => 30,
        BatchItemState.SigningSecondary => 60,
        BatchItemState.Verifying => 85,
        _ => 100
    };

    internal const string OutputSaveRecoveryMessage =
        "签名结果保存失败。请更改文件输出位置，将失败文件移除并重新添加后再签名。当前目录可能受到权限或安全策略限制，建议选择其他可写文件夹。";

    private static string FormatFailureDetail(BatchItemState state, BatchItemReceipt? receipt)
    {
        if (receipt is null || state is not (
                BatchItemState.Failed or
                BatchItemState.PausedProvider or
                BatchItemState.PausedTimestamp))
        {
            return string.Empty;
        }

        string reason = $"原因代码：{receipt.Code}";
        if (receipt.Code == BatchResultCode.OutputSaveFailed)
        {
            return OutputSaveRecoveryMessage;
        }

        if (receipt.SigningDiagnostic is WorkerResponse signingDiagnostic)
        {
            return SigningRuntimeDiagnostic.FromWorkerResponse(signingDiagnostic).Redact().FailureSummary ?? reason;
        }

        return receipt.HResult is int value && value < 0
            ? $"{reason}；公共 HRESULT：0x{value:X8}"
            : reason;
    }

    private static string FormatState(BatchItemState value) => value switch
    {
        BatchItemState.Pending => "待处理",
        BatchItemState.Ready => "就绪",
        BatchItemState.SigningPrimary => "正在主签名",
        BatchItemState.SigningSecondary => "正在辅助签名",
        BatchItemState.Verifying => "正在验证",
        BatchItemState.Published => "已发布",
        BatchItemState.SkippedAlreadySigned => "已跳过：已签名",
        BatchItemState.Failed => "失败",
        BatchItemState.PausedProvider => "已暂停：提供程序",
        BatchItemState.PausedTimestamp => "已暂停：时间戳",
        BatchItemState.Cancelled => "已取消",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知的批次项目状态")
    };

    private static string DetectionTextFor(QueueItemDetectionState value) => value switch
    {
        QueueItemDetectionState.Pending => "等待检测",
        QueueItemDetectionState.Running => "正在检测",
        QueueItemDetectionState.Supported => "检测通过",
        QueueItemDetectionState.Blocked => "不支持",
        QueueItemDetectionState.Faulted => "检测失败",
        QueueItemDetectionState.Cancelled => "检测已取消",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知检测状态")
    };

    private string ResultFor(BatchItemState state, BatchResultCode? code) => state switch
    {
        BatchItemState.Published => EffectiveMode == SigningMode.Dual
            ? "双签完成，签名已验证并发布"
            : "单签完成，签名已验证并发布",
        BatchItemState.SkippedAlreadySigned => "有效签名已存在",
        BatchItemState.PausedProvider => "提供程序授权不可用，请从原始文件重试",
        BatchItemState.PausedTimestamp => "时间戳服务不可用，请从原始文件重试",
        BatchItemState.Cancelled => "签名已取消，原始文件未更改",
        BatchItemState.Failed => code switch
        {
            BatchResultCode.UnsupportedFileType => "不支持的签名文件类型",
            BatchResultCode.InvalidSigningPlan => "签名策略无效",
            BatchResultCode.MisleadingWorkerSuccess => "无法验证工作程序是否成功",
            BatchResultCode.OriginalChanged => "原始文件在签名期间发生变更",
            BatchResultCode.DestinationCollision => "目标文件已存在",
            BatchResultCode.CleanupFailed => "暂存清理失败",
            BatchResultCode.OutputSaveFailed => "结果保存失败，请更改输出位置",
            BatchResultCode.WorkerCrashed => "签名工作程序意外停止",
            _ => "签名失败，请从原始文件重试或导出诊断信息"
        },
        _ => string.Empty
    };

    private static string FormatFor(SigningFormatFamily value) => value switch
    {
        SigningFormatFamily.PeImage => "PE 映像",
        SigningFormatFamily.WindowsInstaller => "Windows Installer",
        SigningFormatFamily.Cabinet => "CAB 压缩包",
        SigningFormatFamily.Catalog => "目录文件",
        SigningFormatFamily.AppPackage => "AppX/MSIX 包",
        SigningFormatFamily.PowerShellScript => "PowerShell 脚本",
        SigningFormatFamily.WindowsScript => "Windows 脚本",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知签名格式")
    };

    private static string EngineFor(SigningEngine value, SigningMode effectiveMode) => value switch
    {
        SigningEngine.PeImage when effectiveMode == SigningMode.Dual => "PE 双重签名",
        SigningEngine.PeImage => "PE 单次签名",
        SigningEngine.WindowsSip => "Windows 单次签名",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知签名引擎")
    };
}
