using System.Diagnostics;
using System.IO;
using CodeSigner.Core.Evidence;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using Microsoft.Win32;
using System.Windows;

namespace CodeSigner.App.Services;

internal sealed class ProductionReadinessAdapter : IReadinessAdapter
{
    private readonly ReadinessProbe probe = new();

    public ReadinessSnapshot Probe(Uri timestampUri) => probe.Probe(timestampUri);
}

internal sealed class ProductionWorkerHealthService : IWorkerHealthService
{
    private readonly WorkerHealthProbe probe;
    private readonly SigningRuntimeEventLog? runtimeEventLog;

    public ProductionWorkerHealthService(
        string applicationPath,
        string workerPath,
        SigningRuntimeEventLog? runtimeEventLog = null)
    {
        probe = new WorkerHealthProbe(applicationPath, workerPath);
        this.runtimeEventLog = runtimeEventLog;
    }

    public async Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken)
    {
        runtimeEventLog?.Write(SigningRuntimeEventNames.WorkerProbeStart);
        WorkerLaunchDiagnostic diagnostic = await probe.ProbeAsync(cancellationToken).ConfigureAwait(false);
        runtimeEventLog?.Write(
            diagnostic.Reason == WorkerLaunchReason.Healthy
                ? SigningRuntimeEventNames.WorkerProbeSucceeded
                : SigningRuntimeEventNames.WorkerProbeFailed,
            diagnostic: diagnostic);
        return diagnostic;
    }
}

internal sealed class ProductionWorkerRepairService : IWorkerRepairService
{
    private readonly NsisMaintenance runner = new();

    public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
        runner.RepairAsync(cancellationToken);

    public void Dispose() => runner.Dispose();
}

internal sealed class ProductionIntakeAdapter : IIntakeAdapter
{
    private readonly IntakePlanner planner = new(new CryptSipSignableSubjectProbe());

    public Task<QueuedSourceAdmissionResult> AdmitAsync(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        CancellationToken cancellationToken) => Task.Run(
            () => QueuedSourceAdmission.Admit(inputs, recurseDirectories, cancellationToken),
            cancellationToken);

    public Task<QueuedSourceDetectionResult> DetectAsync(
        QueuedSource source,
        CancellationToken cancellationToken) => Task.Run(
            () => planner.Detect(source, cancellationToken),
            cancellationToken);

    public Task<IntakeFile> PlanOutputAsync(
        DetectedQueuedSource detectedSource,
        string outputRoot,
        CancellationToken cancellationToken) => Task.Run(
            () => IntakePlanner.PlanOutput(detectedSource, outputRoot, cancellationToken),
            cancellationToken);

    public Task<QueuedSourceDetectionResult> VerifyIntegrityAsync(
        DetectedQueuedSource detectedSource,
        CancellationToken cancellationToken) => Task.Run(
            () => IntakePlanner.VerifyIntegrity(detectedSource, cancellationToken),
            cancellationToken);
}

internal sealed class SequentialBatchAdapter : IBatchAdapter
{
    private static readonly TimeSpan DefaultStallThreshold = TimeSpan.FromSeconds(30);
    private readonly SequentialBatchOrchestrator orchestrator;
    private readonly SigningRuntimeEventLog? runtimeEventLog;
    private readonly TimeSpan stallThreshold;
    private readonly Action? operationPublished;
    private readonly object batchStateSync = new();
    private readonly Dictionary<string, SigningBatch> retainedBatches = new(StringComparer.Ordinal);
    private bool batchOperationActive;
    private string? activeItemId;
    private ExecutionAttemptContext? activeAttempt;
    private SigningRuntimeEvent? lastDiagnosticRuntimeEvent;
    private string? lastDiagnosticRuntimeEventItemId;

    public SequentialBatchAdapter(
        string workerPath,
        SigningRuntimeEventLog? runtimeEventLog = null,
        TimeSpan? stallThreshold = null)
    {
        this.runtimeEventLog = runtimeEventLog;
        this.stallThreshold = stallThreshold ?? DefaultStallThreshold;
        if (this.stallThreshold <= TimeSpan.Zero || this.stallThreshold == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(stallThreshold));
        }

        orchestrator = new(
            new ProcessBatchWorkerSessionFactory(workerPath),
            TimeSpan.FromMinutes(5),
            runtimeEventSink: null,
            diagnosticRuntimeEventSink: runtimeEventLog is null ? null : WriteRuntimeDiagnosticEvent);
        orchestrator.StateChanged += OnStateChanged;
    }

    internal SequentialBatchAdapter(
        SequentialBatchOrchestrator orchestrator,
        SigningRuntimeEventLog? runtimeEventLog = null,
        TimeSpan? stallThreshold = null,
        Action? operationPublished = null)
    {
        this.orchestrator = orchestrator ?? throw new ArgumentNullException(nameof(orchestrator));
        this.runtimeEventLog = runtimeEventLog;
        this.operationPublished = operationPublished;
        this.stallThreshold = stallThreshold ?? DefaultStallThreshold;
        if (this.stallThreshold <= TimeSpan.Zero || this.stallThreshold == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(stallThreshold));
        }
        orchestrator.StateChanged += OnStateChanged;
    }

    public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

    public string? RuntimeEventLogPath => runtimeEventLog?.Path;

    public SigningRuntimeEvent? LastRuntimeEvent => runtimeEventLog?.LastEvent;

    public SigningRuntimeEvent? LastDiagnosticRuntimeEvent => Volatile.Read(ref lastDiagnosticRuntimeEvent);

    public async Task<BatchProgressUpdate> RunAsync(
        BatchItemRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateItemId(request.ItemId, nameof(request));
        var attempt = new ExecutionAttemptContext(
            request.ItemId,
            Guid.NewGuid().ToString("N"),
            1);
        return await RunAsync(request, attempt, cancellationToken).ConfigureAwait(false);
    }

    public async Task<BatchProgressUpdate> RunAsync(
        BatchItemRequest request,
        ExecutionAttemptContext attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(attempt);
        ValidateItemId(request.ItemId, nameof(request));
        EnsureAttemptMatchesItem(attempt, request.ItemId);
        SigningBatch batch = BeginRunOperation(request, attempt);
        try
        {
            operationPublished?.Invoke();
            await RunObservedAsync(
                () => orchestrator.RunAsync(batch, cancellationToken),
                batch,
                cancellationToken).ConfigureAwait(false);
            EnsureRetainedBatch(request.ItemId, batch);
            return LastUpdate(batch, attempt);
        }
        finally
        {
            ExitBatchOperation();
        }
    }

    public async Task<BatchProgressUpdate> ResumeAsync(
        string itemId,
        bool retryFailed,
        CancellationToken cancellationToken)
    {
        ValidateItemId(itemId, nameof(itemId));
        var attempt = new ExecutionAttemptContext(itemId, Guid.NewGuid().ToString("N"), 1);
        return await ResumeAsync(attempt, retryFailed, cancellationToken).ConfigureAwait(false);
    }

    public async Task<BatchProgressUpdate> ResumeAsync(
        ExecutionAttemptContext attempt,
        bool retryFailed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        string itemId = attempt.ItemId;
        ValidateItemId(itemId, nameof(itemId));
        SigningBatch batch = BeginResumeOperation(attempt);
        try
        {
            await RunObservedAsync(
                () => orchestrator.ResumeAsync(batch, retryFailed, cancellationToken),
                batch,
                cancellationToken).ConfigureAwait(false);
            EnsureRetainedBatch(itemId, batch);
            return LastUpdate(batch, attempt);
        }
        finally
        {
            ExitBatchOperation();
        }
    }

    public void PruneItems(IReadOnlyCollection<string> itemIds)
    {
        ArgumentNullException.ThrowIfNull(itemIds);
        if (itemIds.Count == 0)
        {
            return;
        }

        var prunedIds = new HashSet<string>(itemIds, StringComparer.Ordinal);
        if (prunedIds.Count != itemIds.Count || prunedIds.Any(string.IsNullOrWhiteSpace))
        {
            throw ItemContextError(
                BatchAdapterItemContextError.InvalidItemId,
                "Pruned batch item identifiers must be present and unique.");
        }

        lock (batchStateSync)
        {
            ThrowIfBatchOperationActive();
            if (prunedIds.Any(itemId => !retainedBatches.ContainsKey(itemId)))
            {
                throw ItemContextError(
                    BatchAdapterItemContextError.UnknownItem,
                    "No retained signing context exists for every item requested for pruning.");
            }

            foreach (string itemId in prunedIds)
            {
                retainedBatches.Remove(itemId);
            }
        }
    }

    public async Task CancelAsync(string itemId, CancellationToken cancellationToken)
    {
        ValidateItemId(itemId, nameof(itemId));
        cancellationToken.ThrowIfCancellationRequested();
        SigningBatch batch;
        lock (batchStateSync)
        {
            if (!string.Equals(activeItemId, itemId, StringComparison.Ordinal))
            {
                throw ItemContextError(
                    BatchAdapterItemContextError.InactiveItem,
                    $"Item '{itemId}' is not the active signing operation.");
            }

            batch = GetRetainedBatchLocked(itemId);
        }

        await orchestrator.CancelAsync(batch).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        orchestrator.StateChanged -= OnStateChanged;
        await orchestrator.DisposeAsync().ConfigureAwait(false);
    }

    private void OnStateChanged(object? sender, BatchItemStateChangedEventArgs e)
    {
        ExecutionAttemptContext attempt = GetActiveAttempt(e.Item.Request.ItemId);
        SigningBatch batch = GetRetainedBatch(e.Item.Request.ItemId);
        if (!batch.Items.Contains(e.Item))
        {
            throw new InvalidOperationException(
                $"Batch progress referenced item '{e.Item.Request.ItemId}' outside the retained batch.");
        }

        BatchItemReceipt? receipt = e.Item.Receipt;
        SigningRuntimeDiagnostic? diagnostic = receipt?.SigningDiagnostic is WorkerResponse signingFailure
            ? SigningRuntimeDiagnostic.FromWorkerResponse(
                signingFailure,
                receipt.WorkerStderrTail,
                receipt.WorkerStderrTruncated,
                e.Item.Request.SigningPlanJson)
            : receipt?.LaunchDiagnostic is WorkerLaunchDiagnostic launchFailure
                ? SigningRuntimeDiagnostic.FromWorkerLaunchDiagnostic(
                    launchFailure,
                    e.Item.Request.OperationId)
                : receipt?.Code == BatchResultCode.OutputSaveFailed
                    ? SigningRuntimeDiagnostic.FromOutputSaveFailure(receipt.HResult, e.Item.Request.OperationId)
                    : null;
        if (diagnostic is not null && runtimeEventLog is not null)
        {
            SigningRuntimeEvent? previousRuntimeEvent = Volatile.Read(ref lastDiagnosticRuntimeEvent);
            bool launchDiagnosticAlreadyWritten = receipt?.LaunchDiagnostic is WorkerLaunchDiagnostic recordedLaunchFailure &&
                previousRuntimeEvent is
                {
                    Event: SigningRuntimeEventNames.WorkerStartFailed
                } prior &&
                string.Equals(
                    Volatile.Read(ref lastDiagnosticRuntimeEventItemId),
                    e.Item.Request.ItemId,
                    StringComparison.Ordinal) &&
                string.Equals(prior.Reason, recordedLaunchFailure.ReasonCode, StringComparison.Ordinal) &&
                prior.HResult == recordedLaunchFailure.HResult &&
                prior.NativeErrorCode == recordedLaunchFailure.NativeErrorCode &&
                prior.ExitCode == recordedLaunchFailure.ExitCode;
            if (launchDiagnosticAlreadyWritten)
            {
                Volatile.Write(ref lastDiagnosticRuntimeEvent, previousRuntimeEvent);
            }
            else if (runtimeEventLog.Write(
                SigningRuntimeEventNames.BatchFailed,
                e.Item.Request.ItemId,
                receipt?.WorkerProcessId,
                signingDiagnostic: diagnostic))
            {
                Volatile.Write(ref lastDiagnosticRuntimeEventItemId, e.Item.Request.ItemId);
                Volatile.Write(ref lastDiagnosticRuntimeEvent, runtimeEventLog.LastEvent);
            }
        }

        ProgressChanged?.Invoke(
            this,
            new BatchProgressChangedEventArgs(
                new BatchProgressUpdate(attempt, e.Item.State, e.Item.Receipt)));
    }

    private void EnsureRetainedBatch(string itemId, SigningBatch expected)
    {
        lock (batchStateSync)
        {
            if (!retainedBatches.TryGetValue(itemId, out SigningBatch? actual) ||
                !ReferenceEquals(actual, expected))
            {
                throw new InvalidOperationException("The retained signing context changed during the adapter operation.");
            }
        }
    }

    private SigningBatch GetRetainedBatch(string itemId)
    {
        lock (batchStateSync)
        {
            return GetRetainedBatchLocked(itemId);
        }
    }

    private SigningBatch GetRetainedBatchLocked(string itemId) =>
        retainedBatches.TryGetValue(itemId, out SigningBatch? batch)
            ? batch
            : throw ItemContextError(
                BatchAdapterItemContextError.UnknownItem,
                $"There is no retained signing context for item '{itemId}'.");

    private SigningBatch BeginRunOperation(
        BatchItemRequest request,
        ExecutionAttemptContext attempt)
    {
        lock (batchStateSync)
        {
            ThrowIfBatchOperationActive();
            if (retainedBatches.ContainsKey(request.ItemId))
            {
                throw ItemContextError(
                    BatchAdapterItemContextError.DuplicateItem,
                    $"A retained signing context already exists for item '{request.ItemId}'.");
            }

            var batch = new SigningBatch([request]);
            retainedBatches.Add(request.ItemId, batch);
            batchOperationActive = true;
            activeItemId = request.ItemId;
            activeAttempt = attempt;
            return batch;
        }
    }

    private SigningBatch BeginResumeOperation(ExecutionAttemptContext attempt)
    {
        lock (batchStateSync)
        {
            ThrowIfBatchOperationActive();
            string itemId = attempt.ItemId;
            SigningBatch batch = GetRetainedBatchLocked(itemId);
            batchOperationActive = true;
            activeItemId = itemId;
            activeAttempt = attempt;
            return batch;
        }
    }

    private void ExitBatchOperation()
    {
        lock (batchStateSync)
        {
            activeItemId = null;
            activeAttempt = null;
            batchOperationActive = false;
        }
    }

    private void ThrowIfBatchOperationActive()
    {
        if (batchOperationActive)
        {
            throw ItemContextError(
                BatchAdapterItemContextError.OperationActive,
                "The retained signing contexts cannot change while an adapter operation is active.");
        }
    }

    private static void ValidateItemId(string itemId, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(itemId))
        {
            throw ItemContextError(
                BatchAdapterItemContextError.InvalidItemId,
                $"Parameter '{parameterName}' must contain an item identifier.");
        }
    }

    private static void EnsureAttemptMatchesItem(ExecutionAttemptContext attempt, string itemId)
    {
        if (!string.Equals(attempt.ItemId, itemId, StringComparison.Ordinal))
        {
            throw new ArgumentException("The execution attempt must match the request item.", nameof(attempt));
        }
    }

    private ExecutionAttemptContext GetActiveAttempt(string itemId)
    {
        lock (batchStateSync)
        {
            if (activeAttempt is null ||
                !string.Equals(activeAttempt.ItemId, itemId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Batch progress did not match the active execution attempt.");
            }

            return activeAttempt;
        }
    }

    private static BatchAdapterItemContextException ItemContextError(
        BatchAdapterItemContextError error,
        string message) => new(error, message);

    private async Task RunObservedAsync(
        Func<Task<SigningBatch>> operation,
        SigningBatch batch,
        CancellationToken cancellationToken)
    {
        Volatile.Write(ref lastDiagnosticRuntimeEvent, null);
        Volatile.Write(ref lastDiagnosticRuntimeEventItemId, null);
        runtimeEventLog?.Write(SigningRuntimeEventNames.BatchStart);
        using var stallCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task? stallMonitor = runtimeEventLog?.MonitorForStallAsync(stallThreshold, stallCancellation.Token);
        try
        {
            await operation().ConfigureAwait(false);
            RecordBatchOutcome(batch);
        }
        catch (OperationCanceledException)
        {
            runtimeEventLog?.Write(SigningRuntimeEventNames.BatchCancelled);
            throw;
        }
        catch
        {
            runtimeEventLog?.Write(SigningRuntimeEventNames.BatchFailed);
            throw;
        }
        finally
        {
            stallCancellation.Cancel();
            if (stallMonitor is not null)
            {
                try
                {
                    await stallMonitor.ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stallCancellation.IsCancellationRequested)
                {
                }
            }
        }
    }

    private void RecordBatchOutcome(SigningBatch batch)
    {
        string runtimeEvent = batch.Items.Any(static item => item.State == BatchItemState.Cancelled)
            ? SigningRuntimeEventNames.BatchCancelled
            : batch.Items.Any(static item => item.State is
                BatchItemState.Failed or BatchItemState.PausedProvider or BatchItemState.PausedTimestamp)
                ? SigningRuntimeEventNames.BatchFailed
                : SigningRuntimeEventNames.BatchCompleted;
        runtimeEventLog?.Write(runtimeEvent);
    }

    private void WriteRuntimeDiagnosticEvent(
        string runtimeEvent,
        string? itemId,
        int? processId,
        WorkerLaunchDiagnostic? diagnostic)
    {
        if (runtimeEventLog?.Write(runtimeEvent, itemId, processId, diagnostic: diagnostic) == true)
        {
            Volatile.Write(ref lastDiagnosticRuntimeEventItemId, itemId);
            Volatile.Write(ref lastDiagnosticRuntimeEvent, runtimeEventLog.LastEvent);
        }
    }

    private static BatchProgressUpdate LastUpdate(
        SigningBatch batch,
        ExecutionAttemptContext attempt)
    {
        BatchItem item = batch.Items[^1];
        return new BatchProgressUpdate(attempt, item.State, item.Receipt);
    }
}

internal sealed class WindowsOperatorShell : IOperatorShell
{
    private const string DiagnosticPrefix = "CodeSigner-diagnostics-";
    private readonly Func<ProcessStartInfo, Process?> startProcess;

    public WindowsOperatorShell()
        : this(Process.Start)
    {
    }

    internal WindowsOperatorShell(Func<ProcessStartInfo, Process?> startProcess) =>
        this.startProcess = startProcess ?? throw new ArgumentNullException(nameof(startProcess));

    public void OpenFolder(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(fullPath);
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
            UseShellExecute = true
        };
        startInfo.ArgumentList.Add(fullPath);
        using Process? process = startProcess(startInfo);
        if (process is null)
        {
            throw new InvalidOperationException("Windows Explorer did not start.");
        }
    }

    public async Task<string> ExportDiagnosticsAsync(
        IReadOnlyDictionary<string, object?> diagnostics,
        int retentionDays,
        CancellationToken cancellationToken)
    {
        string root = SigningRuntimeEventLog.DefaultDiagnosticsRoot;
        Directory.CreateDirectory(root);
        DeleteExpiredDiagnostics(root, retentionDays);

        string path = Path.Combine(
            root,
            $"{DiagnosticPrefix}{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}.json");
        await using FileStream stream = new(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous);
        await AllowListEvidenceWriter.WriteAsync(stream, diagnostics, cancellationToken).ConfigureAwait(false);
        return path;
    }

    private static void DeleteExpiredDiagnostics(string root, int retentionDays)
    {
        DateTime cutoff = DateTime.UtcNow.AddDays(-retentionDays);
        foreach (string path in Directory.EnumerateFiles(root, $"{DiagnosticPrefix}*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(path) < cutoff)
                {
                    File.Delete(path);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}

internal static class ProductionComposition
{
    public static ViewModels.SigningWorkbenchViewModel CreateViewModel()
    {
        string workerPath = Path.Combine(AppContext.BaseDirectory, "CodeSigner.Worker.exe");
        string applicationPath = Environment.ProcessPath ??
            Path.Combine(AppContext.BaseDirectory, "CodeSigner.App.exe");
        SigningRuntimeEventLog? runtimeEventLog = CreateRuntimeEventLog();
        return new ViewModels.SigningWorkbenchViewModel(
            new ProductionReadinessAdapter(),
            new ProductionIntakeAdapter(),
            new SequentialBatchAdapter(workerPath, runtimeEventLog),
            new WindowsOperatorShell(),
            new ProductionWorkerHealthService(applicationPath, workerPath, runtimeEventLog),
            new ProductionWorkerRepairService(),
            ConfirmWorkerRepairAsync,
            new SdkSignToolReadinessState(new TrustedSdkSignToolLocator()),
            runtimeEventLog is null
                ? new ViewModels.UnavailableQueueAuditSink()
                : new ViewModels.SigningRuntimeQueueAuditSink(runtimeEventLog));
    }

    private static ValueTask<bool> ConfirmWorkerRepairAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MessageBoxResult result = MessageBox.Show(
            "继续后将出现 Windows 用户帐户控制（UAC）提示；只会重新安装 Worker 组件，不会重新安装应用或自动签名。是否继续？",
            "修复 Worker",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        return ValueTask.FromResult(result == MessageBoxResult.Yes);
    }

    private static SigningRuntimeEventLog? CreateRuntimeEventLog()
    {
        try
        {
            return new SigningRuntimeEventLog(SigningRuntimeEventLog.DefaultDiagnosticsRoot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

internal sealed class WindowsWorkbenchDialogs : IWorkbenchDialogs
{
    public IReadOnlyList<string> PickExeFiles(Window owner)
    {
        var dialog = new OpenFileDialog
        {
            Title = "添加支持的签名文件",
            Filter =
                "支持的签名文件 (*.exe;*.dll;*.ocx;*.cpl;*.scr;*.sys;*.drv;*.ax;*.acm;*.efi;*.msi;*.msp;*.msm;*.cab;*.cat;*.appx;*.appxbundle;*.msix;*.msixbundle;*.ps1;*.psm1;*.psd1;*.ps1xml;*.cdxml;*.xaml;*.vbs;*.js;*.jse;*.vbe;*.wsf)|" +
                "*.exe;*.dll;*.ocx;*.cpl;*.scr;*.sys;*.drv;*.ax;*.acm;*.efi;*.msi;*.msp;*.msm;*.cab;*.cat;*.appx;*.appxbundle;*.msix;*.msixbundle;*.ps1;*.psm1;*.psd1;*.ps1xml;*.cdxml;*.xaml;*.vbs;*.js;*.jse;*.vbe;*.wsf|" +
                "所有文件 (*.*)|*.*",
            AddExtension = false,
            CheckFileExists = true,
            Multiselect = true
        };
        return dialog.ShowDialog(owner) == true ? dialog.FileNames : [];
    }

    public string? PickInputFolder(Window owner)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "添加包含支持签名文件的文件夹",
            Multiselect = false
        };
        return dialog.ShowDialog(owner) == true ? dialog.FolderName : null;
    }

    public string? PickOutputRoot(Window owner, string? currentOutputRoot)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择输出目录",
            Multiselect = false
        };
        if (!string.IsNullOrWhiteSpace(currentOutputRoot) && Directory.Exists(currentOutputRoot))
        {
            dialog.InitialDirectory = currentOutputRoot;
        }

        return dialog.ShowDialog(owner) == true ? dialog.FolderName : null;
    }
}
