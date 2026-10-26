using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.App.Tests;

public sealed class SelectedFilePreflightTests
{
    [Theory]
    [InlineData(".exe", false)]
    [InlineData(".msi", false)]
    [InlineData(".exe", true)]
    [InlineData(".msi", true)]
    public async Task ClientInstallationDoesNotGateEligibleCertificatesOrStartSigning(string extension, bool installed)
    {
        using var fixture = new PreflightFixture("provider" + extension);
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: installed);
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        Assert.True(viewModel.CanSign);
        Assert.DoesNotContain(QueueAuditChecks.SimplySign, audit.ChecksForLastRun());
        Assert.Equal(0, batch.ProductionCalls);
        Assert.Contains("代码签名证书", viewModel.CertificateStatus, StringComparison.Ordinal);
        Assert.Contains("UKey", viewModel.CertificatePreparationHint, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmptyCatalogBlocksRegardlessOfClientInstallationAndRefreshRecovers(bool installed)
    {
        using var fixture = new PreflightFixture("no-certificate.exe");
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: installed, catalogAvailable: false);
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        AssertIssue(row, "没有可用的代码签名证书", "ReadinessCertificates", PreflightRecoveryAction.RefreshReadiness);
        Assert.False(viewModel.CanSign);
        Assert.Equal("未发现可用证书", viewModel.CertificateStatus);
        Assert.Contains("SafeNet", viewModel.CertificatePreparationHint, StringComparison.Ordinal);
        Assert.Contains("SimplySign", viewModel.CertificatePreparationHint, StringComparison.Ordinal);
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: installed);
        await viewModel.RefreshReadinessAsync();
        await viewModel.InvalidateCurrentPreflightAsync();
        Assert.True(viewModel.CanSign);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task NoSimplySignStillRequiresPrimarySecondaryTimestampAndSafeOutput()
    {
        using var fixture = new PreflightFixture("hardware.exe");
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: false);
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        viewModel.PrimaryCertificate = null;
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "选择主签名证书", "PrimaryCertificateCombo", PreflightRecoveryAction.PrimaryCertificate);
        PreflightFixture.ResetCertificate(viewModel);
        viewModel.SelectedMode = SigningMode.Dual;
        viewModel.SecondaryCertificate = null;
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "选择 SHA-256 辅助签名证书", "SecondaryCertificateCombo", PreflightRecoveryAction.SecondaryCertificate);
        viewModel.SecondaryCertificate = viewModel.PrimaryCertificate;
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: false, timestampConfigured: false);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "时间戳 URI 无效", "TimestampStatus", PreflightRecoveryAction.TimestampSettings);
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: false);
        await viewModel.InvalidateCurrentPreflightAsync();
        Assert.True(viewModel.CanSign);
        viewModel.OutputRoot = string.Empty;
        Assert.False(viewModel.CanSign);
        Assert.False(viewModel.CanSignQueue);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task CharacterizationNoCurrentItemUsesExistingQueueRecoveryPrompt()
    {
        await using SigningWorkbenchViewModel viewModel = CreateViewModel();

        Assert.Equal("请选择一个签名文件项目", viewModel.SignDisabledReason);
        Assert.False(viewModel.CanSign);
    }

    [Fact]
    public async Task ReadyPreflightUsesOrderedChecksAndPreservesSource()
    {
        using var fixture = new PreflightFixture("ready.exe");
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        string before = fixture.SourceHash();

        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);

        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        Assert.Null(row.PreflightIssue);
        Assert.Equal(before, fixture.SourceHash());
        Assert.Equal(0, batch.ProductionCalls);
        Assert.Equal(
            [
                QueueAuditChecks.AuditWritable,
                QueueAuditChecks.SourceIdentity,
                QueueAuditChecks.SourceAccess,
                QueueAuditChecks.Intake,
                QueueAuditChecks.Workstation,
                QueueAuditChecks.FormatHandler,
                QueueAuditChecks.CertificateCatalog,
                QueueAuditChecks.PrimaryCertificate,
                QueueAuditChecks.Timestamp,
                QueueAuditChecks.DestinationSafety
            ],
            audit.ChecksForLastRun());
        Assert.Equal(QueueAuditOutcomes.Ready, audit.TerminalForLastRun().Outcome);
    }

    [Fact]
    public async Task UnsupportedFormatMapsExactRemoveAndReAddRecovery()
    {
        using var fixture = new PreflightFixture("unsupported.bin");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel, configureAfterQueue: () =>
            fixture.Intake.Error = new IntakeValidationException(
                IntakeError.UnsupportedExtension,
                "untrusted C:/secret/token=1234",
                fixture.SourcePath));

        Assert.Equal(QueueItemPreflightState.Blocked, row.PreflightState);
        Assert.Equal(QueueItemPreflightIssueCode.UnsupportedFormat, row.PreflightIssue?.Code);
        Assert.Equal("不支持的签名文件类型：unsupported.bin", row.PreflightIssue?.Message);
        Assert.Equal(row.AutomationId, row.PreflightIssue?.FocusTargetAutomationId);
        Assert.Equal(PreflightRecoveryAction.RemoveAndReAdd, row.PreflightIssue?.RecoveryAction);
        Assert.DoesNotContain("secret", audit.SerializedVocabulary(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectedIntakeKeepsBlockedCurrentPreflightFocusAndRecovery()
    {
        using var fixture = new PreflightFixture("blocked-focus.exe");
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        string sourceHash = fixture.SourceHash();

        QueueItemViewModel current = await fixture.QueueAndPreflightAsync(viewModel, configureAfterQueue: () =>
            fixture.Intake.Error = new IntakeValidationException(
                IntakeError.NotSignableSubject,
                "untrusted provider response",
                fixture.SourcePath));
        QueueItemPreflightIssue issue = Assert.IsType<QueueItemPreflightIssue>(current.PreflightIssue);
        Assert.Equal(current.AutomationId, issue.FocusTargetAutomationId);
        Assert.Equal(PreflightRecoveryAction.RemoveAndReAdd, issue.RecoveryAction);
        var before = (viewModel.SignDisabledReason, viewModel.FocusTargetAutomationId, issue);

        await viewModel.QueueFilesAsync([]);

        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal("请至少选择一个支持的签名文件", viewModel.InputError);
        Assert.Equal(before, (viewModel.SignDisabledReason, viewModel.FocusTargetAutomationId, current.PreflightIssue));
        Assert.NotEqual("InputError", viewModel.FocusTargetAutomationId);
        Assert.Equal(sourceHash, fixture.SourceHash());
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task PeAndSipUseOnlyTheirOwnFormatHandler()
    {
        using var fixture = new PreflightFixture("native.exe", "sip.msi");
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(
            nativeApi: NativeApiAvailability.LibraryUnavailable,
            bridge: WindowsPowerShellBridgeStatus.Available);
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel pe = viewModel.Rows.Single(row => row.FullPath.EndsWith("native.exe", StringComparison.Ordinal));
        QueueItemViewModel sip = viewModel.Rows.Single(row => row.FullPath.EndsWith("sip.msi", StringComparison.Ordinal));

        await viewModel.SetCurrentItemAsync(pe.ItemId);
        Assert.Equal("Windows 签名 API 不可用", pe.PreflightIssue?.Message);
        Assert.Equal("ReadinessNativeApi", pe.PreflightIssue?.FocusTargetAutomationId);

        await viewModel.SetCurrentItemAsync(sip.ItemId);
        Assert.Equal(QueueItemPreflightState.Ready, sip.PreflightState);
        Assert.Null(sip.PreflightIssue);
    }

    [Fact]
    public async Task PowerShellHandlerHasItsOwnExactBlockerText()
    {
        using var fixture = new PreflightFixture("script.ps1");
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(
            nativeApi: NativeApiAvailability.Available,
            bridge: WindowsPowerShellBridgeStatus.ExecutionDenied);
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);

        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);

        AssertIssue(
            row,
            "Windows PowerShell 5.1 签名桥不可用",
            "ReadinessNativeApi",
            PreflightRecoveryAction.RefreshReadiness);
    }

    [Fact]
    public async Task ReadyFirstAndBlockedSecondSwitchKeepsIssuesRowLocal()
    {
        using var fixture = new PreflightFixture("ready-a.exe", "blocked-b.msi");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];
        fixture.Intake.Errors[second.FullPath] = new IntakeValidationException(
            IntakeError.NotSignableSubject,
            "untrusted provider response",
            second.FullPath);

        await viewModel.SetCurrentItemAsync(first.ItemId);
        Assert.Equal(QueueItemPreflightState.Ready, first.PreflightState);
        await viewModel.SetCurrentItemAsync(second.ItemId);

        Assert.Same(second, viewModel.CurrentItem);
        Assert.Equal(QueueItemPreflightState.Ready, first.PreflightState);
        AssertIssue(
            second,
            "文件内容不是可签名的受支持格式：blocked-b.msi",
            second.AutomationId,
            PreflightRecoveryAction.RemoveAndReAdd);
        Assert.Equal(second.PreflightIssue?.Message, viewModel.SignDisabledReason);
        Assert.Equal(second.PreflightIssue?.FocusTargetAutomationId, viewModel.FocusTargetAutomationId);
    }

    [Fact]
    public async Task SecondaryCertificateIsRequiredOnlyForDualPe()
    {
        using var fixture = new PreflightFixture("dual.exe", "single.msi");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        viewModel.SelectedMode = SigningMode.Dual;
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel pe = viewModel.Rows.Single(row => row.FullPath.EndsWith("dual.exe", StringComparison.Ordinal));
        QueueItemViewModel sip = viewModel.Rows.Single(row => row.FullPath.EndsWith("single.msi", StringComparison.Ordinal));

        await viewModel.SetCurrentItemAsync(pe.ItemId);
        Assert.Equal("选择 SHA-256 辅助签名证书", pe.PreflightIssue?.Message);
        Assert.Equal("SecondaryCertificateCombo", pe.PreflightIssue?.FocusTargetAutomationId);
        Assert.Equal(PreflightRecoveryAction.SecondaryCertificate, pe.PreflightIssue?.RecoveryAction);

        await viewModel.SetCurrentItemAsync(sip.ItemId);
        Assert.Equal(QueueItemPreflightState.Ready, sip.PreflightState);
    }

    [Fact]
    public async Task PrimaryTimestampAndWorkstationMapExactExistingRecoveryTargets()
    {
        using var fixture = new PreflightFixture("mapping.exe");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        viewModel.PrimaryCertificate = null;
        await viewModel.SetCurrentItemAsync(row.ItemId);
        AssertIssue(row, "选择主签名证书", "PrimaryCertificateCombo", PreflightRecoveryAction.PrimaryCertificate);

        PreflightFixture.ResetCertificate(viewModel);
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(timestampConfigured: false);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "时间戳 URI 无效", "TimestampStatus", PreflightRecoveryAction.TimestampSettings);

        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(workstationSupported: false);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "此 Windows 计算机不受支持", "ReadinessWorkstation", PreflightRecoveryAction.RepairReadiness);
    }

    [Fact]
    public async Task PlannerCannotReplaceCachedDetectionIdentityAtFinalBoundary()
    {
        using var fixture = new PreflightFixture("changed.exe");
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        await fixture.QueueAsync(viewModel);
        fixture.Intake.OverrideIdentity = new StableFileIdentity(ulong.MaxValue, "changed-at-final-boundary");

        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        await viewModel.InvalidateCurrentPreflightAsync();

        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        Assert.Equal(row.Source.Identity, row.File.Identity);
        Assert.Null(row.PreflightIssue);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task AuditStartFailureBlocksBeforeProductionChecks()
    {
        using var fixture = new PreflightFixture("audit.exe");
        var audit = new RecordingAuditSink
        {
            FailEvent = SigningRuntimeEventNames.PreflightStarted
        };
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);

        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);

        Assert.Equal(QueueItemPreflightIssueCode.AuditLogUnavailable, row.PreflightIssue?.Code);
        Assert.Equal("无法写入签名诊断日志", row.PreflightIssue?.Message);
        Assert.Empty(audit.ChecksForLastRun());
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task ProviderCatalogAndPowerShellBlockersUseReadinessRecovery()
    {
        using var fixture = new PreflightFixture("readiness.msi");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: false);
        await viewModel.InvalidateCurrentPreflightAsync();
        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        Assert.Null(row.PreflightIssue);

        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(catalogAvailable: false);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "没有可用的代码签名证书", "ReadinessCertificates", PreflightRecoveryAction.RefreshReadiness);

        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(
            bridge: WindowsPowerShellBridgeStatus.Unavailable);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "Windows 签名处理程序不可用", "ReadinessNativeApi", PreflightRecoveryAction.RefreshReadiness);
    }

    [Fact]
    public async Task ReadinessRefreshInvalidatesAndRechecksCurrentVersion()
    {
        using var fixture = new PreflightFixture("refresh.exe");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        long readyGeneration = row.ValidationGeneration;
        fixture.Readiness.Snapshot = PreflightFixture.ReadySnapshot(providerInstalled: false);

        await viewModel.RefreshReadinessAsync();

        Assert.True(row.ValidationGeneration > readyGeneration);
        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        Assert.True(viewModel.CanSign);
    }

    [Fact]
    public async Task OutputAndMissingSourceBlockersUseExactRecoveryMapping()
    {
        using var fixture = new PreflightFixture("recovery.exe");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        fixture.Intake.Error = new IntakeValidationException(
            IntakeError.DestinationExists,
            "untrusted destination text",
            fixture.SourcePath);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(
            row,
            "目标文件已存在，请选择其他输出目录：recovery.exe",
            "OutputRootTextBox",
            PreflightRecoveryAction.OutputRoot);

        fixture.Intake.Error = null;
        fixture.Intake.Error = new IntakeValidationException(
            IntakeError.InputNotFound,
            "untrusted missing source",
            fixture.SourcePath);
        await viewModel.InvalidateCurrentPreflightAsync();
        AssertIssue(row, "签名文件不存在：recovery.exe", row.AutomationId, PreflightRecoveryAction.RemoveAndReAdd);
    }

    [Fact]
    public async Task AuditCheckFailureAndAdapterExceptionsEndFaultedWithoutLeakingText()
    {
        using var fixture = new PreflightFixture("fault.exe");
        var audit = new RecordingAuditSink();
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit, batch);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);

        audit.FailEvent = SigningRuntimeEventNames.PreflightCheckCompleted;
        await viewModel.InvalidateCurrentPreflightAsync();
        Assert.Equal(QueueItemPreflightIssueCode.AuditLogUnavailable, row.PreflightIssue?.Code);
        Assert.Equal(QueueAuditOutcomes.Faulted, audit.TerminalForLastRun().Outcome);

        audit.FailEvent = null;
        fixture.Readiness.Error = new InvalidOperationException("provider token=untrusted-secret");
        await viewModel.InvalidateCurrentPreflightAsync();
        Assert.Equal("就绪状态无法检查", row.PreflightIssue?.Message);
        Assert.Equal(QueueAuditReasons.UnexpectedFailure, audit.TerminalForLastRun().Reason);
        Assert.DoesNotContain("untrusted-secret", audit.SerializedVocabulary(), StringComparison.Ordinal);

        fixture.Readiness.Error = null;
        fixture.Intake.Fault = new InvalidOperationException("intake path=C:/secret/token=second-secret");
        await viewModel.InvalidateCurrentPreflightAsync();
        Assert.Equal(QueueAuditOutcomes.Faulted, audit.TerminalForLastRun().Outcome);
        Assert.DoesNotContain("second-secret", audit.SerializedVocabulary(), StringComparison.Ordinal);
        Assert.Equal(0, batch.ProductionCalls);
    }

    [Fact]
    public async Task TerminalAuditFailureReplacesReadyWithAuditBlocker()
    {
        using var fixture = new PreflightFixture("terminal-audit.exe");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        audit.FailEvent = SigningRuntimeEventNames.PreflightCompleted;

        await viewModel.InvalidateCurrentPreflightAsync();

        Assert.Equal(QueueItemPreflightState.Blocked, row.PreflightState);
        Assert.Equal(QueueItemPreflightIssueCode.AuditLogUnavailable, row.PreflightIssue?.Code);
        Assert.Equal("OpenLogDirectoryButton", row.PreflightIssue?.FocusTargetAutomationId);
        Assert.Equal(PreflightRecoveryAction.DiagnosticsAccess, row.PreflightIssue?.RecoveryAction);
    }

    [Fact]
    public async Task DisposeCancelsActivePreflightWithCancelledTerminal()
    {
        using var fixture = new PreflightFixture("cancel.exe");
        var audit = new RecordingAuditSink();
        SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        fixture.Intake.BlockPath = row.FullPath;

        Task preflight = viewModel.InvalidateCurrentPreflightAsync();
        await fixture.Intake.BlockStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await viewModel.DisposeAsync();
        await preflight;

        Assert.Equal(QueueAuditOutcomes.Cancelled, audit.TerminalForLastRun().Outcome);
        Assert.Equal(QueueAuditReasons.Cancelled, audit.TerminalForLastRun().Reason);
    }

    [Fact]
    public async Task RapidSelectionSupersedesLateOldRunWithoutMutatingNewCurrent()
    {
        using var fixture = new PreflightFixture("late-a.exe", "current-b.msi");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel first = viewModel.Rows[0];
        QueueItemViewModel second = viewModel.Rows[1];
        fixture.Intake.BlockPath = first.FullPath;

        Task late = viewModel.InvalidateCurrentPreflightAsync();
        await fixture.Intake.BlockStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await viewModel.SetCurrentItemAsync(second.ItemId);
        fixture.Intake.ReleaseBlock();
        await late;

        Assert.Same(second, viewModel.CurrentItem);
        Assert.Equal(QueueItemPreflightState.Ready, second.PreflightState);
        Assert.Null(second.PreflightIssue);
        Assert.Contains(audit.Events, entry =>
            entry.ItemId == first.ItemId && entry.Outcome == QueueAuditOutcomes.Superseded);
    }

    [Fact]
    public async Task ConfigurationChangeCancelsOldGenerationAndOnlyNewGenerationUpdatesRow()
    {
        using var fixture = new PreflightFixture("config.exe");
        var audit = new RecordingAuditSink();
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(audit);
        await fixture.QueueAsync(viewModel);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        fixture.Intake.BlockPath = row.FullPath;

        Task oldRun = viewModel.InvalidateCurrentPreflightAsync();
        await fixture.Intake.BlockStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        long oldGeneration = row.ValidationGeneration;
        viewModel.SelectedMode = SigningMode.Dual;
        fixture.Intake.ReleaseBlock();
        await oldRun;
        await viewModel.InvalidateCurrentPreflightAsync();

        Assert.True(row.ValidationGeneration > oldGeneration);
        Assert.Equal(QueueItemPreflightState.Blocked, row.PreflightState);
        Assert.Equal(PreflightRecoveryAction.SecondaryCertificate, row.PreflightIssue?.RecoveryAction);
        Assert.Contains(audit.Events, entry => entry.Outcome == QueueAuditOutcomes.Superseded);
    }

    [Fact]
    public async Task RealJsonlHasOneTerminalPerPersistedStartAndNoSensitiveValues()
    {
        using var fixture = new PreflightFixture("jsonl.exe");
        string logRoot = Path.Combine(fixture.Root, "diagnostics");
        var log = new SigningRuntimeEventLog(logRoot);
        await using SigningWorkbenchViewModel viewModel = fixture.CreateViewModel(new SigningRuntimeQueueAuditSink(log));

        QueueItemViewModel row = await fixture.QueueAndPreflightAsync(viewModel);
        SigningRuntimeEvent[] events = SigningRuntimeEventLog.ReadAll(log.Path).ToArray();
        string[] starts = events
            .Where(entry => entry.Event == SigningRuntimeEventNames.PreflightStarted)
            .Select(entry => entry.OperationId!)
            .ToArray();
        SigningRuntimeEvent[] terminals = events
            .Where(entry => entry.Event == SigningRuntimeEventNames.PreflightCompleted)
            .ToArray();

        Assert.NotEmpty(starts);
        Assert.All(starts, operationId => Assert.Single(terminals, terminal => terminal.OperationId == operationId));
        Assert.Equal(QueueItemPreflightState.Ready, row.PreflightState);
        string json = File.ReadAllText(log.Path);
        Assert.DoesNotContain(fixture.SourcePath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", json, StringComparison.OrdinalIgnoreCase);
    }

    private static void AssertIssue(
        QueueItemViewModel row,
        string message,
        string focus,
        PreflightRecoveryAction recovery)
    {
        Assert.Equal(QueueItemPreflightState.Blocked, row.PreflightState);
        Assert.Equal(message, row.PreflightIssue?.Message);
        Assert.Equal(focus, row.PreflightIssue?.FocusTargetAutomationId);
        Assert.Equal(recovery, row.PreflightIssue?.RecoveryAction);
    }

    internal sealed class PreflightFixture : IDisposable
    {
        private readonly string[] sourcePaths;

        public PreflightFixture(params string[] names)
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSigner-Preflight-" + Guid.NewGuid().ToString("N"));
            OutputRoot = Path.Combine(Root, "out");
            Directory.CreateDirectory(OutputRoot);
            sourcePaths = names.Select(name => Path.Combine(Root, name)).ToArray();
            foreach (string path in sourcePaths)
            {
                File.WriteAllBytes(path, [0x4D, 0x5A, 0x01, 0x02, 0x03]);
            }

            Intake = new PlanningIntakeAdapter(OutputRoot);
            Readiness = new MutableReadinessAdapter(ReadySnapshot());
        }

        public string Root { get; }

        public string OutputRoot { get; }

        public string SourcePath => sourcePaths[0];

        public PlanningIntakeAdapter Intake { get; }

        public MutableReadinessAdapter Readiness { get; }

        public SigningWorkbenchViewModel CreateViewModel(
            IQueueAuditSink audit,
            RecordingBatchAdapter? batch = null)
        {
            var viewModel = new SigningWorkbenchViewModel(
                Readiness,
                Intake,
                batch ?? new RecordingBatchAdapter(),
                new NoopOperatorShell(),
                new HealthyWorkerHealthService(),
                new NoopWorkerRepairService(),
                static _ => ValueTask.FromResult(true),
                sdkSignToolReadinessState: null,
                audit);
            Assert.True(viewModel.ApplySettings(TimestampPolicy.DefaultUri, 30));
            return viewModel;
        }

        public async Task QueueAsync(SigningWorkbenchViewModel viewModel)
        {
            viewModel.OutputRoot = OutputRoot;
            await viewModel.ReplanOutputRootAsync(OutputRoot);
            await viewModel.QueueFilesAsync(sourcePaths);
            await WaitForPreflightAsync(viewModel);
        }

        public async Task<QueueItemViewModel> QueueAndPreflightAsync(
            SigningWorkbenchViewModel viewModel,
            Action? configureAfterQueue = null)
        {
            await QueueAsync(viewModel);
            QueueItemViewModel row = Assert.Single(viewModel.Rows);
            configureAfterQueue?.Invoke();
            await viewModel.InvalidateCurrentPreflightAsync();
            return row;
        }

        private static async Task WaitForPreflightAsync(SigningWorkbenchViewModel viewModel)
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (viewModel.Rows.Count == 0 || viewModel.Rows.Any(row => row.DetectionState is
                       QueueItemDetectionState.Pending or QueueItemDetectionState.Running) ||
                   viewModel.CurrentItem?.PreflightState is
                       QueueItemPreflightState.Unplanned or QueueItemPreflightState.Planning)
            {
                await Task.Delay(10, cancellation.Token);
            }
        }

        public string SourceHash() => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(SourcePath)));

        public static void ResetCertificate(SigningWorkbenchViewModel viewModel) =>
            viewModel.PrimaryCertificate = Assert.Single(viewModel.Certificates);

        public static ReadinessSnapshot ReadySnapshot(
            NativeApiAvailability nativeApi = NativeApiAvailability.Available,
            WindowsPowerShellBridgeStatus bridge = WindowsPowerShellBridgeStatus.Available,
            bool workstationSupported = true,
            bool timestampConfigured = true,
            bool providerInstalled = true,
            bool catalogAvailable = true) => new(
            new WorkstationReadiness(
                workstationSupported ? WorkstationSupportStatus.Supported : WorkstationSupportStatus.Unsupported,
                "test"),
            nativeApi,
            new SimplySignInstallation(
                providerInstalled
                    ? SimplySignInstallationStatus.Installed
                    : SimplySignInstallationStatus.NotInstalled,
                "{A}",
                "{B}",
                "SimplySign Desktop",
                "Certum",
                "1.0"),
            new CertificateCatalog(
                catalogAvailable
                    ? CertificateAvailabilityStatus.CertificateAvailable
                    : CertificateAvailabilityStatus.Unavailable,
                catalogAvailable ? [Certificate()] : [],
                [new CertificateStoreDiagnostic(StoreLocation.CurrentUser, "My", CertificateStoreReadStatus.Success)]),
            new TimestampConfiguration(
                timestampConfigured ? TimestampConfigurationStatus.Configured : TimestampConfigurationStatus.Invalid,
                timestampConfigured ? new Uri(TimestampPolicy.DefaultUri) : null),
            ProviderAuthorizationStatus.AuthorizationUnknown,
            new WindowsPowerShellBridgeReadiness(
                bridge,
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "5.1",
                "test"));

        private static EligibleCertificate Certificate() => new(
            StoreLocation.CurrentUser,
            "My",
            new string('A', 40),
            "CN=Preflight",
            "CN=Issuer",
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            true,
            [CertificateCatalogProbe.CodeSigningEkuOid]);

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    internal sealed class MutableReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public ReadinessSnapshot Snapshot { get; set; } = snapshot;

        public Exception? Error { get; set; }

        public ReadinessSnapshot Probe(Uri timestampUri) =>
            Error is null ? Snapshot : throw Error;
    }

    internal sealed class PlanningIntakeAdapter(string defaultOutputRoot) : StagedIntakeAdapterFake
    {
        private TaskCompletionSource? block;

        public IntakeValidationException? Error { get; set; }

        public Exception? Fault { get; set; }

        public Dictionary<string, IntakeValidationException> Errors { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public StableFileIdentity? OverrideIdentity { get; set; }

        public string? BlockPath { get; set; }

        public TaskCompletionSource BlockStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            if (Fault is not null)
            {
                throw Fault;
            }

            if (Error is not null)
            {
                throw Error;
            }

            if (inputs.Count == 1 && Errors.TryGetValue(inputs.Single(), out IntakeValidationException? error))
            {
                throw error;
            }

            if (BlockPath is not null && inputs.Count == 1 &&
                string.Equals(inputs.Single(), BlockPath, StringComparison.OrdinalIgnoreCase))
            {
                block ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                BlockStarted.TrySetResult();
                await block.Task.WaitAsync(cancellationToken);
            }

            string root = outputRoot ?? defaultOutputRoot;
            IntakeFile[] files = inputs.Select(path => FileFor(path, root)).ToArray();
            return new IntakePlan(root, files);
        }

        public void ReleaseBlock() => block?.TrySetResult();

        private IntakeFile FileFor(string path, string root)
        {
            QueuedSourceAdmissionResult admitted = QueuedSourceAdmission.Admit([path], false, CancellationToken.None);
            StableFileIdentity identity = OverrideIdentity ?? Assert.Single(admitted.Sources).Identity;
            PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(Path.GetExtension(path));
            SigningSubject policy = subject.Value ?? SigningSubject.TryCreateForExtension(".exe").Value!;
            return new IntakeFile(
                path,
                Path.GetFileName(path),
                Path.Combine(root, Path.GetFileName(path)),
                root,
                identity,
                new SignableSubject(policy, Guid.NewGuid(), null));
        }
    }

    internal sealed class RecordingAuditSink : IQueueAuditSink
    {
        private readonly object sync = new();

        public string? FailEvent { get; set; }

        public List<AuditEntry> Events { get; } = [];

        public bool WriteAdmissionEvent(
            string eventName,
            string operationId,
            string? outcome = null,
            string? reason = null) => true;

        public bool WriteQueueEvent(
            string eventName,
            string itemId,
            string operationId,
            string phase,
            string? check = null,
            string? action = null,
            string? outcome = null,
            string? reason = null)
        {
            if (eventName == FailEvent)
            {
                return false;
            }

            lock (sync)
            {
                Events.Add(new AuditEntry(eventName, itemId, operationId, check, outcome, reason));
            }

            return true;
        }

        public string[] ChecksForLastRun()
        {
            string? operationId = Events.LastOrDefault(entry =>
                entry.EventName == SigningRuntimeEventNames.PreflightStarted)?.OperationId;
            return operationId is null
                ? []
                : Events
                    .Where(entry => entry.OperationId == operationId && entry.Check is not null)
                    .Select(entry => entry.Check!)
                    .ToArray();
        }

        public AuditEntry TerminalForLastRun()
        {
            string operationId = Events.Last(entry =>
                entry.EventName == SigningRuntimeEventNames.PreflightStarted).OperationId;
            return Assert.Single(Events, entry =>
                entry.OperationId == operationId &&
                entry.EventName == SigningRuntimeEventNames.PreflightCompleted);
        }

        public string SerializedVocabulary() => string.Join('|', Events.Select(entry => entry.ToString()));
    }

    internal sealed record AuditEntry(
        string EventName,
        string ItemId,
        string OperationId,
        string? Check,
        string? Outcome,
        string? Reason);

    private static SigningWorkbenchViewModel CreateViewModel() => new(
        new ThrowingReadinessAdapter(),
        new ThrowingIntakeAdapter(),
        new RecordingBatchAdapter(),
        new NoopOperatorShell(),
        new HealthyWorkerHealthService(),
        new NoopWorkerRepairService(),
        static _ => ValueTask.FromResult(true));

    private sealed class ThrowingReadinessAdapter : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) =>
            throw new InvalidOperationException("Characterization must not probe readiness.");
    }

    private sealed class ThrowingIntakeAdapter : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Characterization must not plan intake.");
    }

    internal sealed class RecordingBatchAdapter : IBatchAdapter
    {
        public int ProductionCalls { get; private set; }

        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }

        public Task<BatchProgressUpdate> RunAsync(BatchItemRequest request, CancellationToken cancellationToken) =>
            throw CountUnexpectedProductionCall("run");

        public Task<BatchProgressUpdate> ResumeAsync(
            string itemId,
            bool retryFailed,
            CancellationToken cancellationToken) =>
            throw CountUnexpectedProductionCall("resume");

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) =>
            throw CountUnexpectedProductionCall("cancel");

        private InvalidOperationException CountUnexpectedProductionCall(string operation)
        {
            ProductionCalls++;
            return new InvalidOperationException($"Preflight must not {operation} a batch.");
        }

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

    private sealed class HealthyWorkerHealthService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
    }

    private sealed class NoopWorkerRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Characterization must not repair a worker.");

        public void Dispose()
        {
        }
    }
}
