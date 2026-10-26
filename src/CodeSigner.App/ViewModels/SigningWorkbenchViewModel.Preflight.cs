using System.ComponentModel;
using System.IO;
using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private readonly object preflightSync = new();
    private readonly IQueueAuditSink? queueAuditSink;
    private ActivePreflight? activePreflight;
    private long preflightConfigGeneration;
    private long preflightReadinessGeneration;
    private long observedPreflightConfigGeneration;
    private long observedPreflightReadinessGeneration;

    internal Task InvalidateCurrentPreflightAsync()
    {
        QueueItemViewModel? row = CurrentItem;
        CancelActivePreflight(PreflightCancellationKind.Superseded);
        InvalidatePlansForMutableGenerationChange();
        if (row is null ||
            row.State != Windows.Batch.BatchItemState.Pending ||
            row.DetectionState != QueueItemDetectionState.Supported ||
            row.SourceIntegrityState != QueueItemSourceIntegrityState.Current ||
            row.DetectedSource is null ||
            !HasValidOutputRoot())
        {
            return Task.CompletedTask;
        }

        PlanningAudit? planningAudit = BeginPlanningAudit(row.ItemId);
        if (planningAudit is null)
        {
            row.SetPreflightBlocked(Issue(
                QueueItemPreflightIssueCode.AuditLogUnavailable,
                QueueAuditReasons.AuditLogUnavailable,
                "无法写入签名诊断日志",
                "OpenLogDirectoryButton",
                PreflightRecoveryAction.DiagnosticsAccess));
            RefreshValidation(moveFocus: true);
            return Task.CompletedTask;
        }

        CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            startupProbeCancellation.Token);
        long configGeneration = Volatile.Read(ref preflightConfigGeneration);
        long readinessGeneration = Volatile.Read(ref preflightReadinessGeneration);
        long capturedOutputGeneration = Volatile.Read(ref outputGeneration);
        row.SetPreflightChecking(configGeneration, capturedOutputGeneration);
        var capture = new SelectedFilePreflightCapture(
            row.ItemId,
            row.RowGeneration,
            configGeneration,
            capturedOutputGeneration,
            readinessGeneration,
            row.ValidationGeneration,
            Guid.NewGuid().ToString("N"));
        var active = new ActivePreflight(capture, cancellation, planningAudit);
        lock (preflightSync)
        {
            activePreflight = active;
            active.Task = RunSelectedFilePreflightAsync(row, active);
        }

        RefreshValidation();
        return active.Task;
    }

    private void InvalidatePlansForMutableGenerationChange()
    {
        long configGeneration = Volatile.Read(ref preflightConfigGeneration);
        long readinessGeneration = Volatile.Read(ref preflightReadinessGeneration);
        if (configGeneration == observedPreflightConfigGeneration &&
            readinessGeneration == observedPreflightReadinessGeneration)
        {
            return;
        }

        observedPreflightConfigGeneration = configGeneration;
        observedPreflightReadinessGeneration = readinessGeneration;
        foreach (QueueItemViewModel candidate in Rows.Where(candidate =>
                     candidate.State == Windows.Batch.BatchItemState.Pending &&
                     candidate.PreflightState is QueueItemPreflightState.Planning or
                         QueueItemPreflightState.Ready or QueueItemPreflightState.Blocked))
        {
            candidate.InvalidateOutputPlan();
        }
    }

    private void CancelActivePreflight(PreflightCancellationKind kind)
    {
        ActivePreflight? active;
        lock (preflightSync)
        {
            active = activePreflight;
            if (active is null)
            {
                return;
            }

            active.CancellationKind = kind;
            active.Cancellation.Cancel();
        }
    }

    private async Task RunSelectedFilePreflightAsync(QueueItemViewModel row, ActivePreflight active)
    {
        SelectedFilePreflightCapture capture = active.Capture;
        CancellationToken token = active.Cancellation.Token;
        bool started = WritePreflightStart(capture);
        if (!started)
        {
            ApplyBlockedIfCurrent(row, capture, Issue(
                QueueItemPreflightIssueCode.AuditLogUnavailable,
                QueueAuditReasons.AuditLogUnavailable,
                "无法写入签名诊断日志",
                "OpenLogDirectoryButton",
                PreflightRecoveryAction.DiagnosticsAccess));
            CompleteActive(active);
            return;
        }

        string terminalOutcome = QueueAuditOutcomes.Faulted;
        string? terminalReason = QueueAuditReasons.UnexpectedFailure;
        try
        {
            RequireCheck(capture, QueueAuditChecks.AuditWritable, passed: true);
            token.ThrowIfCancellationRequested();

            DetectedQueuedSource detected = row.DetectedSource ??
                throw new InvalidOperationException("A supported row must retain its detected source.");
            QueuedSourceDetectionResult integrity = await intakeAdapter.VerifyIntegrityAsync(detected, token);
            if (!IsCaptureCurrent(row, capture))
            {
                terminalOutcome = QueueAuditOutcomes.Superseded;
                terminalReason = QueueAuditReasons.StaleValidation;
                return;
            }

            if (integrity.Status == QueuedSourceDetectionStatus.Unavailable)
            {
                QueueItemPreflightIssue issue = Issue(
                    QueueItemPreflightIssueCode.SourceUnavailable,
                    QueueAuditReasons.SourceUnavailable,
                    "签名文件不存在",
                    row.AutomationId,
                    PreflightRecoveryAction.RemoveAndReAdd);
                row.MarkSourceUnavailable();
                RequireCheck(capture, QueueAuditChecks.SourceAccess, passed: false, issue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, issue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = issue.DetailCode;
                return;
            }

            if (integrity.Status != QueuedSourceDetectionStatus.Supported ||
                integrity.DetectedSource is null ||
                integrity.DetectedSource.Source.Identity != row.Source.Identity)
            {
                QueueItemPreflightIssue issue = Issue(
                    QueueItemPreflightIssueCode.SourceChanged,
                    QueueAuditReasons.SourceChanged,
                    "原始文件在签名期间发生变更",
                    row.AutomationId,
                    PreflightRecoveryAction.RemoveAndReAdd);
                row.MarkSourceChanged();
                RequireCheck(capture, QueueAuditChecks.SourceIdentity, passed: false, issue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, issue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = issue.DetailCode;
                return;
            }

            RequireCheck(capture, QueueAuditChecks.SourceIdentity, passed: true);
            RequireCheck(capture, QueueAuditChecks.SourceAccess, passed: true);
            token.ThrowIfCancellationRequested();

            if (!HasValidOutputRoot())
            {
                QueueItemPreflightIssue issue = Issue(
                    QueueItemPreflightIssueCode.OutputUnavailable,
                    QueueAuditReasons.OutputRequired,
                    "选择有效的输出目录",
                    "OutputRootTextBox",
                    PreflightRecoveryAction.OutputRoot);
                RequireCheck(capture, QueueAuditChecks.Intake, passed: false, issue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, issue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = issue.DetailCode;
                return;
            }

            IntakeFile plannedFile;
            try
            {
                plannedFile = await intakeAdapter.PlanOutputAsync(detected, OutputRoot, token);
                RequireCheck(capture, QueueAuditChecks.Intake, passed: true);
            }
            catch (IntakeValidationException exception)
            {
                QueueItemPreflightIssue issue = MapIntakeIssue(row, exception);
                RequireCheck(capture, QueueAuditChecks.Intake, passed: false, issue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, issue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = issue.DetailCode;
                return;
            }

            token.ThrowIfCancellationRequested();
            ReadinessSnapshot snapshot = readinessAdapter.Probe(timestampUri);
            QueueItemPreflightIssue? blocker = CheckReadinessInOrder(row, plannedFile, snapshot, capture);
            if (blocker is not null)
            {
                ApplyBlockedIfCurrent(row, capture, blocker);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = blocker.DetailCode;
                return;
            }

            if (!Equals(plannedFile.Identity, row.Source.Identity))
            {
                QueueItemPreflightIssue issue = Issue(
                    QueueItemPreflightIssueCode.SourceChanged,
                    QueueAuditReasons.SourceChanged,
                    "原始文件在签名期间发生变更",
                    row.AutomationId,
                    PreflightRecoveryAction.RemoveAndReAdd);
                RequireCheck(capture, QueueAuditChecks.DestinationSafety, passed: false, issue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, issue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = issue.DetailCode;
                return;
            }

            QueueItemPreflightIssue? destinationIssue = ValidateDestination(row, plannedFile);
            if (destinationIssue is not null)
            {
                RequireCheck(capture, QueueAuditChecks.DestinationSafety, passed: false, destinationIssue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, destinationIssue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = destinationIssue.DetailCode;
                return;
            }

            if (!OwnsDestinationReservation(row, plannedFile.DestinationPath))
            {
                QueueItemPreflightIssue issue = Issue(
                    QueueItemPreflightIssueCode.OutputUnavailable,
                    QueueAuditReasons.DestinationUnsafe,
                    "多个签名文件输入解析到同一目标路径",
                    "OutputRootTextBox",
                    PreflightRecoveryAction.OutputRoot);
                RequireCheck(capture, QueueAuditChecks.DestinationSafety, passed: false, issue.DetailCode);
                ApplyBlockedIfCurrent(row, capture, issue);
                terminalOutcome = QueueAuditOutcomes.Blocked;
                terminalReason = issue.DetailCode;
                return;
            }

            RequireCheck(capture, QueueAuditChecks.DestinationSafety, passed: true);
            if (!IsCaptureCurrent(row, capture))
            {
                terminalOutcome = QueueAuditOutcomes.Superseded;
                terminalReason = QueueAuditReasons.StaleValidation;
                return;
            }

            row.CommitOutputPlan(plannedFile, capture.OutputGeneration);
            row.SetPreflightReady();
            terminalOutcome = QueueAuditOutcomes.Ready;
            terminalReason = null;
            RefreshValidation(moveFocus: true);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            terminalOutcome = active.CancellationKind == PreflightCancellationKind.Superseded
                ? QueueAuditOutcomes.Superseded
                : QueueAuditOutcomes.Cancelled;
            terminalReason = active.CancellationKind == PreflightCancellationKind.Superseded
                ? QueueAuditReasons.StaleValidation
                : QueueAuditReasons.Cancelled;
        }
        catch (AuditWriteException)
        {
            ApplyBlockedIfCurrent(row, capture, Issue(
                QueueItemPreflightIssueCode.AuditLogUnavailable,
                QueueAuditReasons.AuditLogUnavailable,
                "无法写入签名诊断日志",
                "OpenLogDirectoryButton",
                PreflightRecoveryAction.DiagnosticsAccess));
            terminalOutcome = QueueAuditOutcomes.Faulted;
            terminalReason = QueueAuditReasons.AuditLogUnavailable;
        }
        catch (Exception exception) when (exception is
            ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ApplyBlockedIfCurrent(row, capture, Issue(
                QueueItemPreflightIssueCode.WorkstationUnavailable,
                QueueAuditReasons.UnexpectedFailure,
                "就绪状态无法检查",
                "RefreshButton",
                PreflightRecoveryAction.RefreshReadiness));
            terminalOutcome = QueueAuditOutcomes.Faulted;
            terminalReason = QueueAuditReasons.UnexpectedFailure;
        }
        finally
        {
            if (!WriteTerminal(capture, terminalOutcome, terminalReason))
            {
                if (IsTerminalCaptureCurrent(row, capture))
                {
                    row.SetPreflightBlocked(Issue(
                        QueueItemPreflightIssueCode.AuditLogUnavailable,
                        QueueAuditReasons.AuditLogUnavailable,
                        "无法写入签名诊断日志",
                        "OpenLogDirectoryButton",
                        PreflightRecoveryAction.DiagnosticsAccess));
                    RefreshValidation(moveFocus: true);
                }
            }

            (string planningOutcome, string? planningReason) = PlanningTerminal(
                terminalOutcome,
                terminalReason);
            EndPlanningAudit(active.PlanningAudit, planningOutcome, planningReason);

            CompleteActive(active);
        }
    }

    private bool WritePreflightStart(SelectedFilePreflightCapture capture)
    {
        if (queueAuditSink is null)
        {
            return true;
        }

        return queueAuditSink.WriteQueueEvent(
                SigningRuntimeEventNames.PreflightStarted,
                capture.ItemId,
                capture.OperationId,
                QueueAuditPhases.Preflight);
    }

    private void RequireCheck(
        SelectedFilePreflightCapture capture,
        string check,
        bool passed,
        string? reason = null)
    {
        if (!TryWriteCheck(capture, check, passed, reason))
        {
            throw new AuditWriteException();
        }
    }

    private bool TryWriteCheck(
        SelectedFilePreflightCapture capture,
        string check,
        bool passed,
        string? reason) => queueAuditSink?.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCheckCompleted,
            capture.ItemId,
            capture.OperationId,
            QueueAuditPhases.Preflight,
            check: check,
            outcome: passed ? QueueAuditOutcomes.Passed : QueueAuditOutcomes.Failed,
            reason: reason) != false;

    private bool WriteTerminal(SelectedFilePreflightCapture capture, string outcome, string? reason)
    {
        return queueAuditSink?.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCompleted,
            capture.ItemId,
            capture.OperationId,
            QueueAuditPhases.Preflight,
            outcome: outcome,
            reason: reason) != false;
    }

    private static (string Outcome, string? Reason) PlanningTerminal(string outcome, string? reason)
    {
        if (outcome == QueueAuditOutcomes.Ready)
        {
            return (QueueAuditOutcomes.Ready, null);
        }

        if (outcome == QueueAuditOutcomes.Blocked && reason is
            QueueAuditReasons.OutputRequired or
            QueueAuditReasons.DestinationUnsafe or
            QueueAuditReasons.DestinationExists or
            QueueAuditReasons.HandlerUnavailable or
            QueueAuditReasons.WorkstationUnavailable or
            QueueAuditReasons.ProviderUnavailable or
            QueueAuditReasons.CertificateCatalogUnavailable or
            QueueAuditReasons.PrimaryCertificateUnavailable or
            QueueAuditReasons.SecondaryCertificateUnavailable or
            QueueAuditReasons.TimestampUnavailable or
            QueueAuditReasons.SourceUnavailable or
            QueueAuditReasons.SourceChanged)
        {
            return (outcome, reason);
        }

        if (outcome == QueueAuditOutcomes.Superseded)
        {
            return (outcome, QueueAuditReasons.StaleValidation);
        }

        if (outcome == QueueAuditOutcomes.Cancelled)
        {
            return (outcome, QueueAuditReasons.Cancelled);
        }

        return (QueueAuditOutcomes.Faulted, QueueAuditReasons.UnexpectedFailure);
    }

    private static IntakeFile RequireSinglePlan(string path, IntakePlan plan)
    {
        IntakeFile[] matches = plan.Files
            .Where(file => string.Equals(file.OriginalPath, path, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return matches.Length == 1
            ? matches[0]
            : throw new IntakeValidationException(IntakeError.InvalidInput, "单文件输出计划无效", path);
    }

    private QueueItemPreflightIssue? CheckReadinessInOrder(
        QueueItemViewModel row,
        IntakeFile file,
        ReadinessSnapshot snapshot,
        SelectedFilePreflightCapture capture)
    {
        if (snapshot.Workstation.Status != WorkstationSupportStatus.Supported)
        {
            return FailedCheck(capture, QueueAuditChecks.Workstation, Issue(
                QueueItemPreflightIssueCode.WorkstationUnavailable,
                QueueAuditReasons.WorkstationUnavailable,
                "此 Windows 计算机不受支持",
                "ReadinessWorkstation",
                PreflightRecoveryAction.RepairReadiness));
        }

        RequireCheck(capture, QueueAuditChecks.Workstation, passed: true);
        QueueItemPreflightIssue? handlerIssue = HandlerIssue(file, snapshot);
        if (handlerIssue is not null)
        {
            return FailedCheck(capture, QueueAuditChecks.FormatHandler, handlerIssue);
        }

        RequireCheck(capture, QueueAuditChecks.FormatHandler, passed: true);
        if (snapshot.CertificateCatalog.Status != CertificateAvailabilityStatus.CertificateAvailable)
        {
            return FailedCheck(capture, QueueAuditChecks.CertificateCatalog, Issue(
                QueueItemPreflightIssueCode.CertificateUnavailable,
                QueueAuditReasons.CertificateCatalogUnavailable,
                "没有可用的代码签名证书",
                "ReadinessCertificates",
                PreflightRecoveryAction.RefreshReadiness));
        }

        RequireCheck(capture, QueueAuditChecks.CertificateCatalog, passed: true);
        if (PrimaryCertificate is null)
        {
            return FailedCheck(capture, QueueAuditChecks.PrimaryCertificate, Issue(
                QueueItemPreflightIssueCode.CertificateUnavailable,
                QueueAuditReasons.PrimaryCertificateUnavailable,
                "选择主签名证书",
                "PrimaryCertificateCombo",
                PreflightRecoveryAction.PrimaryCertificate));
        }

        RequireCheck(capture, QueueAuditChecks.PrimaryCertificate, passed: true);
        if (SelectedMode == SigningMode.Dual &&
            file.Subject.PolicySubject.Capability == SigningCapability.PeImageDualCapable)
        {
            if (SecondaryCertificate is null)
            {
                return FailedCheck(capture, QueueAuditChecks.SecondaryCertificate, Issue(
                    QueueItemPreflightIssueCode.CertificateUnavailable,
                    QueueAuditReasons.SecondaryCertificateUnavailable,
                    "选择 SHA-256 辅助签名证书",
                    "SecondaryCertificateCombo",
                    PreflightRecoveryAction.SecondaryCertificate));
            }

            RequireCheck(capture, QueueAuditChecks.SecondaryCertificate, passed: true);
        }

        if (snapshot.Timestamp.Status != TimestampConfigurationStatus.Configured)
        {
            return FailedCheck(capture, QueueAuditChecks.Timestamp, Issue(
                QueueItemPreflightIssueCode.TimestampUnavailable,
                QueueAuditReasons.TimestampUnavailable,
                "时间戳 URI 无效",
                "TimestampStatus",
                PreflightRecoveryAction.TimestampSettings));
        }

        RequireCheck(capture, QueueAuditChecks.Timestamp, passed: true);
        return null;
    }

    private static QueueItemPreflightIssue? HandlerIssue(IntakeFile file, ReadinessSnapshot snapshot)
    {
        if (file.Subject.PolicySubject.Capability == SigningCapability.PeImageDualCapable)
        {
            return snapshot.NativeApi == NativeApiAvailability.Available
                ? null
                : Issue(
                    QueueItemPreflightIssueCode.SigningCapabilityUnavailable,
                    QueueAuditReasons.HandlerUnavailable,
                    "Windows 签名 API 不可用",
                    "ReadinessNativeApi",
                    PreflightRecoveryAction.RefreshReadiness);
        }

        return snapshot.PowerShellBridge?.Status == WindowsPowerShellBridgeStatus.Available
            ? null
            : Issue(
                QueueItemPreflightIssueCode.SigningCapabilityUnavailable,
                QueueAuditReasons.HandlerUnavailable,
                file.Subject.PolicySubject.FormatFamily == SigningFormatFamily.PowerShellScript
                    ? "Windows PowerShell 5.1 签名桥不可用"
                    : "Windows 签名处理程序不可用",
                "ReadinessNativeApi",
                PreflightRecoveryAction.RefreshReadiness);
    }

    private static QueueItemPreflightIssue? ValidateDestination(QueueItemViewModel row, IntakeFile file)
    {
        if (string.IsNullOrWhiteSpace(file.DestinationPath) || string.IsNullOrWhiteSpace(file.OutputRoot))
        {
            return Issue(
                QueueItemPreflightIssueCode.OutputUnavailable,
                QueueAuditReasons.OutputRequired,
                "选择有效的输出目录",
                "OutputRootTextBox",
                PreflightRecoveryAction.OutputRoot);
        }

        if (string.Equals(file.OriginalPath, file.DestinationPath, StringComparison.OrdinalIgnoreCase) ||
            File.Exists(file.DestinationPath))
        {
            return Issue(
                QueueItemPreflightIssueCode.OutputUnavailable,
                QueueAuditReasons.DestinationExists,
                "目标文件已存在，请选择其他输出目录",
                "OutputRootTextBox",
                PreflightRecoveryAction.OutputRoot);
        }

        return null;
    }

    private static QueueItemPreflightIssue MapIntakeIssue(
        QueueItemViewModel row,
        IntakeValidationException exception) => exception.Error switch
        {
            IntakeError.UnsupportedExtension or IntakeError.NotSignableSubject => Issue(
                QueueItemPreflightIssueCode.UnsupportedFormat,
                QueueAuditReasons.UnsupportedFormat,
                FormatIntakeError(exception),
                row.AutomationId,
                PreflightRecoveryAction.RemoveAndReAdd),
            IntakeError.SipUnavailable => Issue(
                QueueItemPreflightIssueCode.SigningCapabilityUnavailable,
                QueueAuditReasons.HandlerUnavailable,
                FormatIntakeError(exception),
                "ReadinessNativeApi",
                PreflightRecoveryAction.RefreshReadiness),
            IntakeError.DestinationExists => Issue(
                QueueItemPreflightIssueCode.OutputUnavailable,
                QueueAuditReasons.DestinationExists,
                FormatIntakeError(exception),
                "OutputRootTextBox",
                PreflightRecoveryAction.OutputRoot),
            IntakeError.DestinationCollision or IntakeError.InputInsideOutputRoot => Issue(
                QueueItemPreflightIssueCode.OutputUnavailable,
                QueueAuditReasons.DestinationUnsafe,
                FormatIntakeError(exception),
                "OutputRootTextBox",
                PreflightRecoveryAction.OutputRoot),
            IntakeError.InputNotFound => Issue(
                QueueItemPreflightIssueCode.SourceUnavailable,
                QueueAuditReasons.SourceUnavailable,
                FormatIntakeError(exception),
                row.AutomationId,
                PreflightRecoveryAction.RemoveAndReAdd),
            IntakeError.InaccessibleInput or IntakeError.ReparsePoint => Issue(
                QueueItemPreflightIssueCode.SourceUnavailable,
                QueueAuditReasons.SourceAccessDenied,
                FormatIntakeError(exception),
                row.AutomationId,
                PreflightRecoveryAction.RemoveAndReAdd),
            _ => Issue(
                QueueItemPreflightIssueCode.UnsupportedFormat,
                QueueAuditReasons.IntakeFailed,
                FormatIntakeError(exception),
                row.AutomationId,
                PreflightRecoveryAction.RemoveAndReAdd)
        };

    private QueueItemPreflightIssue FailedCheck(
        SelectedFilePreflightCapture capture,
        string check,
        QueueItemPreflightIssue issue)
    {
        RequireCheck(capture, check, passed: false, issue.DetailCode);
        return issue;
    }

    private static QueueItemPreflightIssue Issue(
        QueueItemPreflightIssueCode code,
        string detailCode,
        string message,
        string focusTargetAutomationId,
        PreflightRecoveryAction recoveryAction) =>
        new(code, detailCode, message, focusTargetAutomationId, recoveryAction);

    private void ApplyBlockedIfCurrent(
        QueueItemViewModel row,
        SelectedFilePreflightCapture capture,
        QueueItemPreflightIssue issue)
    {
        if (!IsCaptureCurrent(row, capture))
        {
            return;
        }

        row.SetPreflightBlocked(issue);
        RefreshValidation(moveFocus: true);
    }

    private bool IsCaptureCurrent(QueueItemViewModel row, SelectedFilePreflightCapture capture) =>
        ReferenceEquals(CurrentItem, row) &&
        Rows.Contains(row) &&
        row.ItemId == capture.ItemId &&
        row.RowGeneration == capture.RowGeneration &&
        row.ConfigGeneration == capture.ConfigGeneration &&
        row.OutputGeneration == capture.OutputGeneration &&
        row.ValidationGeneration == capture.ValidationGeneration &&
        Volatile.Read(ref preflightConfigGeneration) == capture.ConfigGeneration &&
        Volatile.Read(ref outputGeneration) == capture.OutputGeneration &&
        Volatile.Read(ref preflightReadinessGeneration) == capture.ReadinessGeneration;

    private bool IsTerminalCaptureCurrent(QueueItemViewModel row, SelectedFilePreflightCapture capture) =>
        ReferenceEquals(CurrentItem, row) &&
        Rows.Contains(row) &&
        row.ItemId == capture.ItemId &&
        row.ConfigGeneration == capture.ConfigGeneration &&
        row.OutputGeneration == capture.OutputGeneration &&
        row.ValidationGeneration == capture.ValidationGeneration &&
        Volatile.Read(ref preflightConfigGeneration) == capture.ConfigGeneration &&
        Volatile.Read(ref outputGeneration) == capture.OutputGeneration &&
        Volatile.Read(ref preflightReadinessGeneration) == capture.ReadinessGeneration;

    private void CompleteActive(ActivePreflight active)
    {
        lock (preflightSync)
        {
            if (ReferenceEquals(activePreflight, active))
            {
                activePreflight = null;
            }
        }

        active.Cancellation.Dispose();
    }

    private void OnPreflightDependencyPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is not (
            nameof(PrimaryCertificate) or
            nameof(SecondaryCertificate) or
            nameof(SelectedMode) or
            nameof(TimestampUri)))
        {
            return;
        }

        Interlocked.Increment(ref preflightConfigGeneration);
        _ = InvalidateCurrentPreflightAsync();
    }

    private sealed class ActivePreflight(
        SelectedFilePreflightCapture capture,
        CancellationTokenSource cancellation,
        PlanningAudit planningAudit)
    {
        public SelectedFilePreflightCapture Capture { get; } = capture;

        public CancellationTokenSource Cancellation { get; } = cancellation;

        public PlanningAudit PlanningAudit { get; } = planningAudit;

        public PreflightCancellationKind CancellationKind { get; set; } = PreflightCancellationKind.Cancelled;

        public Task Task { get; set; } = Task.CompletedTask;
    }

    private sealed class AuditWriteException : IOException;

}
