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
    private string? activeBatchItemId;
    private readonly object executionAttemptSync = new();
    private readonly ExecutionAttemptContextFactory executionAttemptFactory = new();
    private readonly ExecutionAttemptRegistry executionAttemptRegistry = new();
    private ExecutionAttemptContext? activeExecutionAttempt;

    public SigningPlan BuildSigningPlan()
    {
        IntakeFile file = Rows.FirstOrDefault()?.File
            ?? throw new InvalidOperationException("签名队列为空");
        return BuildSigningPlan(file);
    }

    public SigningPlan BuildSigningPlan(IntakeFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        SigningSubject subject = file.Subject.PolicySubject;
        bool needsSecondary = subject.Capability == SigningCapability.PeImageDualCapable;
        PolicyResult<SigningPlan> result = SelectedMode == SigningMode.Single
            ? SigningPlan.TryCreateSingle(
                PrimaryCertificate?.ToCertificateRef(),
                subject,
                timestampUri.OriginalString)
            : SigningPlan.TryCreateDual(
                PrimaryCertificate?.ToCertificateRef(),
                needsSecondary ? SecondaryCertificate?.ToCertificateRef() : null,
                subject,
                timestampUri.OriginalString);
        return result.IsSuccess
            ? result.Value!
            : throw new InvalidOperationException(result.Errors[0].Message);
    }

    public Task SignAsync() => SignCurrentAsync(allowQueueExecution: false, CancellationToken.None);

    private async Task SignCurrentAsync(bool allowQueueExecution, CancellationToken cancellationToken)
    {
        if (disposeRequested != 0 || isBusy || (queueCancellation is not null && !allowQueueExecution))
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        QueueItemViewModel? item = CurrentItem;
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.Sign, item);
        if (audit is null)
        {
            return;
        }

        if (item is null || item.State != BatchItemState.Pending)
        {
            RefreshValidation(moveFocus: true);
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.InvalidState);
            return;
        }

        await InvalidateCurrentPreflightAsync();
        cancellationToken.ThrowIfCancellationRequested();
        RefreshValidation(moveFocus: true);
        if (!ReferenceEquals(CurrentItem, item) ||
            !Rows.Contains(item) ||
            item.State != BatchItemState.Pending ||
            disposeRequested != 0 ||
            FirstBlocking(allowQueueExecution).Reason is not null)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.ActionUnavailable);
            return;
        }

        string operationId = Guid.NewGuid().ToString("N");
        WorkerSdkFallback sdkFallback = CaptureSdkSignToolFallback();
        SigningPlan plan = BuildSigningPlan(item.File);
        var request = new BatchItemRequest(
            item.ItemId,
            item.File,
            SigningPlanJson.Serialize(plan),
            OperationId: operationId,
            SdkFallback: sdkFallback);
        item.RetainRequest(request);
        ExecutionAttemptContext attempt = BeginExecutionAttempt(item);
        long observationId = StartWorkerObservation();
        Volatile.Write(ref activeBatchObservationId, observationId);
        activeOperation = new CancellationTokenSource();
        activeBatchItemId = item.ItemId;
        IsBusy = true;
        StatusMessage = "正在签名：0 / 1 个签名文件项目";
        try
        {
            BatchProgressUpdate final = await batchAdapter.RunAsync(request, attempt, activeOperation.Token);
            ApplyBatchProgress(final, observationId);
            CompleteExecutionAttempt(attempt);
            if (IsLatestWorkerObservation(observationId) &&
                final.Receipt?.Code != BatchResultCode.WorkerLaunchFailed)
            {
                UpdateSummaryAndFocus();
            }
            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
        catch (OperationCanceledException)
        {
            if (IsLatestWorkerObservation(observationId))
            {
                StatusMessage = "签名已取消，原始文件保持不变";
                FocusTargetAutomationId = "SummaryRegion";
            }
            EndActionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            if (IsLatestWorkerObservation(observationId))
            {
                StatusMessage = "签名批次无法启动，导出诊断信息以查看失败详情";
                FocusTargetAutomationId = "SummaryRegion";
            }
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.UnexpectedFailure);
        }
        catch
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.UnexpectedFailure);
            throw;
        }
        finally
        {
            CompleteExecutionAttempt(attempt);
            Interlocked.CompareExchange(ref activeBatchObservationId, 0, observationId);
            activeOperation.Dispose();
            activeOperation = null;
            activeBatchItemId = null;
            IsBusy = false;
            RefreshCommands();
        }
    }

    public async Task RetryAsync()
    {
        QueueItemViewModel? item = CurrentItem;
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.Retry, item);
        if (audit is null)
        {
            return;
        }

        if (!CanRetry() || item is null)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.InvalidState);
            return;
        }

        BatchItemRequest? retainedRequest = await ValidateRetainedRequestAsync(item);
        if (retainedRequest is null)
        {
            StatusMessage = "无法重试当前签名文件项目，保留的原始请求已失效";
            FocusTargetAutomationId = item.AutomationId;
            RefreshValidation();
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.StaleValidation);
            return;
        }

        ExecutionAttemptContext attempt = BeginExecutionAttempt(item);
        long observationId = StartWorkerObservation();
        Volatile.Write(ref activeBatchObservationId, observationId);
        activeOperation = new CancellationTokenSource();
        activeBatchItemId = retainedRequest.ItemId;
        IsBusy = true;
        StatusMessage = "正在从原始文件重试失败或暂停的签名文件项目";
        try
        {
            BatchProgressUpdate final = await batchAdapter.ResumeAsync(
                attempt,
                retryFailed: true,
                cancellationToken: activeOperation.Token);
            ApplyBatchProgress(final, observationId);
            CompleteExecutionAttempt(attempt);
            if (IsLatestWorkerObservation(observationId) &&
                final.Receipt?.Code != BatchResultCode.WorkerLaunchFailed)
            {
                UpdateSummaryAndFocus();
            }
            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
        catch (OperationCanceledException)
        {
            if (IsLatestWorkerObservation(observationId))
            {
                StatusMessage = "重试已取消，原始文件保持不变";
                FocusTargetAutomationId = "SummaryRegion";
            }
            EndActionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
        }
        catch
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.UnexpectedFailure);
            throw;
        }
        finally
        {
            CompleteExecutionAttempt(attempt);
            Interlocked.CompareExchange(ref activeBatchObservationId, 0, observationId);
            activeOperation.Dispose();
            activeOperation = null;
            activeBatchItemId = null;
            IsBusy = false;
            RefreshCommands();
        }
    }

    public async Task CancelAsync()
    {
        if (!IsBusy)
        {
            return;
        }

        string? itemId;
        lock (executionAttemptSync)
        {
            itemId = activeExecutionAttempt?.ItemId;
        }
        queueCancellation?.Cancel();
        if (itemId is null)
        {
            CancelActivePreflight(PreflightCancellationKind.Cancelled);
            WriteCancelAuditAfterExecution(CurrentItem, QueueAuditOutcomes.Completed);
            return;
        }
        QueueItemViewModel? item = Rows.FirstOrDefault(row => row.ItemId == itemId);
        try
        {
            await batchAdapter.CancelAsync(itemId, CancellationToken.None);
            activeOperation?.Cancel();
            WriteCancelAuditAfterExecution(item, QueueAuditOutcomes.Completed);
        }
        catch
        {
            WriteCancelAuditAfterExecution(
                item,
                QueueAuditOutcomes.Rejected,
                QueueAuditReasons.UnexpectedFailure);
            throw;
        }
    }

    private async Task<BatchItemRequest?> ValidateRetainedRequestAsync(QueueItemViewModel item)
    {
        BatchItemRequest? retainedRequest = item.RetainedRequest;
        DetectedQueuedSource? detectedSource = item.DetectedSource;
        if (retainedRequest is null ||
            detectedSource is null ||
            !string.Equals(retainedRequest.ItemId, item.ItemId, StringComparison.Ordinal) ||
            !string.Equals(retainedRequest.File.OriginalPath, item.Source.CanonicalPath, StringComparison.OrdinalIgnoreCase) ||
            !Equals(retainedRequest.File.Identity, item.Source.Identity) ||
            !string.Equals(retainedRequest.File.DestinationPath, item.File.DestinationPath, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(retainedRequest.File.OriginalPath, retainedRequest.File.DestinationPath, StringComparison.OrdinalIgnoreCase) ||
            File.Exists(retainedRequest.File.DestinationPath) ||
            !SigningPlanJson.Parse(retainedRequest.SigningPlanJson).IsSuccess)
        {
            return null;
        }

        QueuedSourceDetectionResult integrity = await intakeAdapter.VerifyIntegrityAsync(
            detectedSource,
            CancellationToken.None);
        return integrity.Status == QueuedSourceDetectionStatus.Supported &&
            integrity.DetectedSource is not null &&
            integrity.DetectedSource.Source.Identity == item.Source.Identity &&
            integrity.DetectedSource.Fingerprint == detectedSource.Fingerprint
                ? retainedRequest
                : null;
    }

    private ExecutionAttemptContext BeginExecutionAttempt(QueueItemViewModel item)
    {
        lock (executionAttemptSync)
        {
            ExecutionAttemptContext attempt = executionAttemptFactory.Next(item.ItemId);
            long rowGeneration = item.BeginExecutionAttempt();
            if (attempt.ExecutionGeneration != rowGeneration)
            {
                throw new InvalidOperationException("The queue row and execution attempt generations diverged.");
            }

            executionAttemptRegistry.Begin(attempt);
            activeExecutionAttempt = attempt;
            return attempt;
        }
    }

    private void CompleteExecutionAttempt(ExecutionAttemptContext attempt)
    {
        lock (executionAttemptSync)
        {
            if (!Equals(activeExecutionAttempt, attempt))
            {
                return;
            }

            executionAttemptRegistry.Complete(attempt);
            activeExecutionAttempt = null;
        }
    }

    private ExecutionProgressDisposition ClassifyExecutionProgress(BatchProgressUpdate update)
    {
        lock (executionAttemptSync)
        {
            return executionAttemptRegistry.Classify(update);
        }
    }

    private ExecutionAttemptContext? FailActiveExecutionContractViolation()
    {
        lock (executionAttemptSync)
        {
            ExecutionAttemptContext? attempt = activeExecutionAttempt;
            if (attempt is not null)
            {
                executionAttemptRegistry.Complete(attempt);
                activeExecutionAttempt = null;
            }

            return attempt;
        }
    }

    private void RegisterExecutionItem(string itemId)
    {
        lock (executionAttemptSync)
        {
            executionAttemptRegistry.RegisterLiveItem(itemId);
        }
    }

    private void TombstoneExecutionItem(string itemId)
    {
        lock (executionAttemptSync)
        {
            executionAttemptRegistry.Tombstone(itemId);
        }
    }

    public Task ExportDiagnosticsAsync() => ExportDiagnosticsCoreAsync();

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposeRequested, 1) != 0)
        {
            return;
        }

        queueCancellation?.Cancel();
        activeOperation?.Cancel();
        CancelActivePreflight(PreflightCancellationKind.Cancelled);
        Task? pendingQueue = queueCompletion?.Task;
        if (pendingQueue is not null)
        {
            await pendingQueue;
        }
        batchAdapter.ProgressChanged -= OnBatchProgressChanged;
        activeOperation?.Dispose();
        startupProbeCancellation.Cancel();
        await StopDetectionConsumerAsync();
        Task? pendingStartup;
        lock (startupTaskSync)
        {
            pendingStartup = startupTask;
        }

        if (pendingStartup is not null)
        {
            try
            {
                await pendingStartup;
            }
            catch (OperationCanceledException) when (startupProbeCancellation.IsCancellationRequested)
            {
            }
        }

        await batchAdapter.DisposeAsync();
        await workerOperationGate.WaitAsync();
        try
        {
            workerRepairService.Dispose();
        }
        finally
        {
            workerOperationGate.Release();
            workerOperationGate.Dispose();
            startupProbeCancellation.Dispose();
            detectionLifetimeCancellation.Dispose();
            admissionGate.Dispose();
        }
    }
}
