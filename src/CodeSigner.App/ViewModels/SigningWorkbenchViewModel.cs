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

internal enum CurrentItemExecutionCapability
{
    ItemTargetedExecution
}

public sealed partial class SigningWorkbenchViewModel : ObservableObject, IAsyncDisposable
{
    private static readonly int[] AllowedRetentionDays = [7, 30, 90];

    private readonly IReadinessAdapter readinessAdapter;
    private readonly IIntakeAdapter intakeAdapter;
    private readonly IBatchAdapter batchAdapter;
    private readonly IOperatorShell operatorShell;
    private readonly IWorkerHealthService workerHealthService;
    private readonly IWorkerRepairService workerRepairService;
    private readonly Func<CancellationToken, ValueTask<bool>> workerRepairConfirmation;
    private readonly ISdkSignToolReadinessState? sdkSignToolReadinessState;
    private readonly CurrentItemExecutionCapability currentItemExecutionCapability =
        CurrentItemExecutionCapability.ItemTargetedExecution;
    private readonly SynchronizationContext? synchronizationContext;
    private readonly SemaphoreSlim workerOperationGate = new(1, 1);
    private readonly CancellationTokenSource startupProbeCancellation = new();
    private readonly object startupTaskSync = new();
    private readonly object workerObservationSync = new();
    private readonly HashSet<string> removedPaths = new(StringComparer.OrdinalIgnoreCase);
    private QueueItemViewModel? currentItem;

    private ReadinessSnapshot? readiness;
    private CertificateOptionViewModel? primaryCertificate;
    private CertificateOptionViewModel? secondaryCertificate;
    private SigningMode selectedMode = SigningMode.Single;
    private string outputRoot = string.Empty;
    private string inputError = string.Empty;
    private IntakeSource? inputErrorSource;
    private IntakeError? inputErrorKind;
    private string outputError = string.Empty;
    private string settingsValidationError = string.Empty;
    private string signDisabledReason = string.Empty;
    private string focusTargetAutomationId = string.Empty;
    private string statusMessage = "请添加支持的签名文件或文件夹开始";
    private string readinessAnnouncement = string.Empty;
    private string lastDiagnosticsPath = string.Empty;
    private int aggregateProgressPercent;
    private bool isBusy;
    private Uri timestampUri = new(TimestampPolicy.DefaultUri);
    private int diagnosticRetentionDays = 30;
    private CancellationTokenSource? activeOperation;
    private Task? startupTask;
    private int nextItemId = 1;
    private int disposeRequested;
    private long nextWorkerObservationId;
    private long latestWorkerObservationId;
    private long activeBatchObservationId;
    private WorkerHealthState workerHealthState = WorkerHealthState.Unknown;
    private WorkerLaunchDiagnostic? workerDiagnostic;
    private WorkerRepairResult? lastWorkerRepairResult;
    private WorkerRepairOutcome? lastWorkerRepairOutcome;
    private SigningRuntimeEvent? lastSigningDiagnosticEvent;
    private SdkSignToolDiscoveryResult sdkSignToolDiscovery = SdkSignToolDiscoveryResult.Unavailable();

    public SigningWorkbenchViewModel(
        IReadinessAdapter readinessAdapter,
        IIntakeAdapter intakeAdapter,
        IBatchAdapter batchAdapter,
        IOperatorShell operatorShell,
        IWorkerHealthService workerHealthService,
        IWorkerRepairService workerRepairService,
        Func<CancellationToken, ValueTask<bool>> workerRepairConfirmation,
        ISdkSignToolReadinessState? sdkSignToolReadinessState = null,
        IQueueAuditSink? queueAuditSink = null)
    {
        this.readinessAdapter = readinessAdapter ?? throw new ArgumentNullException(nameof(readinessAdapter));
        this.intakeAdapter = intakeAdapter ?? throw new ArgumentNullException(nameof(intakeAdapter));
        this.batchAdapter = batchAdapter ?? throw new ArgumentNullException(nameof(batchAdapter));
        this.operatorShell = operatorShell ?? throw new ArgumentNullException(nameof(operatorShell));
        this.workerHealthService = workerHealthService ?? throw new ArgumentNullException(nameof(workerHealthService));
        this.workerRepairService = workerRepairService ?? throw new ArgumentNullException(nameof(workerRepairService));
        this.workerRepairConfirmation = workerRepairConfirmation ??
            throw new ArgumentNullException(nameof(workerRepairConfirmation));
        this.sdkSignToolReadinessState = sdkSignToolReadinessState;
        this.queueAuditSink = queueAuditSink;
        synchronizationContext = SynchronizationContext.Current;

        AddFilesCommand = new AsyncCommand(
            parameter => QueueFilesAsync(ToPaths(parameter)),
            _ => !IsBusy);
        AddFolderCommand = new AsyncCommand(
            parameter => QueueFolderAsync(ToSinglePath(parameter)),
            _ => !IsBusy);
        RemoveCommand = new RelayCommand(_ => RemoveSelected(), _ => CanRemoveSelected());
        RemoveQueueItemCommand = new RelayCommand(RemoveQueueItem, CanRemoveQueueItem);
        RefreshCommand = new AsyncCommand(_ => RefreshReadinessAsync(), _ => CanRefreshWorker);
        RefreshWorkerCommand = new AsyncCommand(_ => RefreshWorkerHealthAsync(), _ => CanRefreshWorker);
        RefreshSdkSignToolCommand = new AsyncCommand(
            _ => RefreshSdkSignToolReadinessActionAsync(CancellationToken.None),
            _ => disposeRequested == 0 && !auditIncomplete && !IsBusy);
        RepairWorkerCommand = new AsyncCommand(_ => RepairWorkerAsync(), _ => CanRepairWorker);
        RetryCommand = new AsyncCommand(_ => RetryAsync(), _ => CanRetry());
        OpenOutputCommand = new RelayCommand(_ => OpenOutput(), _ => !IsBusy && HasValidOutputRoot());
        OpenLogDirectoryCommand = new RelayCommand(_ => OpenLogDirectory());
        OpenInstallationDirectoryCommand = new RelayCommand(
            _ => OpenInstallationDirectory(),
            _ => IsWorkerRecoveryVisible);
        ExportDiagnosticsCommand = new AsyncCommand(_ => ExportDiagnosticsAsync());
        SignCommand = new AsyncCommand(_ => SignQueueAsync(), _ => CanSignQueue);
        CancelCommand = new AsyncCommand(_ => CancelAsync(), _ => IsBusy);
        SettingsCommand = new RelayCommand(_ => SettingsRequested?.Invoke(this, EventArgs.Empty), _ => !IsBusy);

        batchAdapter.ProgressChanged += OnBatchProgressChanged;
        RefreshValidation();
        PropertyChanged += OnPreflightDependencyPropertyChanged;
    }

    public event EventHandler? SettingsRequested;

    public ObservableCollection<CertificateOptionViewModel> Certificates { get; } = [];

    public ObservableCollection<QueueItemViewModel> Rows { get; } = [];

    internal CurrentItemExecutionCapability CurrentItemExecutionCapability =>
        currentItemExecutionCapability;

    public QueueItemViewModel? CurrentItem
    {
        get => currentItem;
        private set => SetProperty(ref currentItem, value);
    }

    public Task SetCurrentItemAsync(string? itemId)
    {
        QueueItemViewModel? candidate = itemId is null
            ? null
            : Rows.FirstOrDefault(row => string.Equals(row.ItemId, itemId, StringComparison.Ordinal));
        if (itemId is not null && candidate is null)
        {
            return Task.CompletedTask;
        }

        if (ReferenceEquals(CurrentItem, candidate))
        {
            PrioritizeDetection(candidate);
            return Task.CompletedTask;
        }

        if (IsBusy)
        {
            QueueItemViewModel? auditItem = candidate ?? CurrentItem;
            string action = candidate is null
                ? QueueAuditActions.CurrentDeselection
                : QueueAuditActions.CurrentSelection;
            ActionAudit? audit = BeginActionAudit(action, auditItem);
            if (audit is not null)
            {
                EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
            }

            return Task.CompletedTask;
        }

        QueueItemViewModel? previous = CurrentItem;
        ActionAudit? deselectionAudit = previous is null
            ? ActionAudit.Disabled
            : BeginActionAudit(QueueAuditActions.CurrentDeselection, previous);
        if (deselectionAudit is null)
        {
            return Task.CompletedTask;
        }

        ActionAudit? selectionAudit = candidate is null
            ? ActionAudit.Disabled
            : BeginActionAudit(QueueAuditActions.CurrentSelection, candidate);
        if (selectionAudit is null)
        {
            EndActionAudit(deselectionAudit, QueueAuditOutcomes.Rejected, QueueAuditReasons.AuditLogUnavailable);
            return Task.CompletedTask;
        }

        SetCurrentItem(candidate);
        EndActionAudit(deselectionAudit, QueueAuditOutcomes.Completed);
        EndActionAudit(selectionAudit, QueueAuditOutcomes.Completed);
        return Task.CompletedTask;
    }

    private void SetCurrentItem(QueueItemViewModel? item)
    {
        if (ReferenceEquals(CurrentItem, item))
        {
            return;
        }

        QueueItemViewModel? previous = CurrentItem;
        CurrentItem = item;
        if (previous is not null)
        {
            WriteSelectionEvent(SigningRuntimeEventNames.ItemDeselected, previous);
        }
        if (item is not null)
        {
            WriteSelectionEvent(SigningRuntimeEventNames.ItemSelected, item);
        }
        PrioritizeDetection(item);
        RefreshValidation();
    }

    public IAsyncCommand AddFilesCommand { get; }

    public IAsyncCommand AddFolderCommand { get; }

    public RelayCommand RemoveCommand { get; }

    public RelayCommand RemoveQueueItemCommand { get; }

    public IAsyncCommand RefreshCommand { get; }

    public IAsyncCommand RefreshWorkerCommand { get; }

    public IAsyncCommand RefreshSdkSignToolCommand { get; }

    public IAsyncCommand RepairWorkerCommand { get; }

    public IAsyncCommand RetryCommand { get; }

    public RelayCommand OpenOutputCommand { get; }

    public RelayCommand OpenLogDirectoryCommand { get; }

    public RelayCommand OpenInstallationDirectoryCommand { get; }

    public IAsyncCommand ExportDiagnosticsCommand { get; }

    public IAsyncCommand SignCommand { get; }

    public IAsyncCommand CancelCommand { get; }

    public RelayCommand SettingsCommand { get; }

}
