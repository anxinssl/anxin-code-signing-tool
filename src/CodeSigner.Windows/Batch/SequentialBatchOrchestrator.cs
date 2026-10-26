using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Batch;

public enum BatchWorkerPhase
{
    SigningPrimary,
    SigningSecondary,
    Verifying
}

public sealed class BatchItemStateChangedEventArgs(BatchItem item) : EventArgs
{
    public BatchItem Item { get; } = item;
}

public sealed record BatchWorkerSigningResult(
    WorkerResponse Response,
    string? WorkerStderrTail,
    bool WorkerStderrTruncated);

public interface IBatchWorkerSession : IAsyncDisposable
{
    int ProcessId { get; }

    bool IsRunning { get; }

    Task<WorkerResponse> SignAsync(
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        Action<BatchWorkerPhase> reportProgress,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    async Task<BatchWorkerSigningResult> SignWithDiagnosticsAsync(
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        string? operationId,
        Action<BatchWorkerPhase> reportProgress,
        TimeSpan timeout,
        CancellationToken cancellationToken) => new(
            await SignAsync(
                originalPath,
                stagedPath,
                signingPlanJson,
                reportProgress,
                timeout,
                cancellationToken).ConfigureAwait(false),
            null,
            false);

    async Task<BatchWorkerSigningResult> SignWithDiagnosticsAsync(
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        string? operationId,
        WorkerSdkFallback sdkFallback,
        Action<BatchWorkerPhase> reportProgress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sdkFallback);
        if (sdkFallback.Enabled || sdkFallback.Candidate is not null)
        {
            throw new InvalidOperationException(
                "This Worker session implementation cannot carry an enabled SDK fallback snapshot.");
        }

        return await SignWithDiagnosticsAsync(
            originalPath,
            stagedPath,
            signingPlanJson,
            operationId,
            reportProgress,
            timeout,
            cancellationToken).ConfigureAwait(false);
    }

    Task<int> CompleteAsync(CancellationToken cancellationToken);

    Task TerminateAsync();
}

public interface IBatchWorkerSessionFactory
{
    ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken);
}

public sealed class ProcessBatchWorkerSessionFactory(string workerPath) : IBatchWorkerSessionFactory
{
    private readonly string workerPath = Path.GetFullPath(
        workerPath ?? throw new ArgumentNullException(nameof(workerPath)));

    public ValueTask<IBatchWorkerSession> StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IBatchWorkerSession>(
            new ProcessBatchWorkerSession(WorkerProcessSession.Start(workerPath)));
    }

    private sealed class ProcessBatchWorkerSession(WorkerProcessSession session) : IBatchWorkerSession
    {
        public int ProcessId => session.ProcessId;

        public bool IsRunning => session.IsRunning;

        public async Task<WorkerResponse> SignAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken) =>
            (await SignWithDiagnosticsAsync(
                originalPath,
                stagedPath,
                signingPlanJson,
                operationId: null,
                reportProgress,
                timeout,
                cancellationToken).ConfigureAwait(false)).Response;

        public async Task<BatchWorkerSigningResult> SignWithDiagnosticsAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            string? operationId,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken) => await SignWithDiagnosticsAsync(
                originalPath,
                stagedPath,
                signingPlanJson,
                operationId,
                WorkerSdkFallback.Disabled,
                reportProgress,
                timeout,
                cancellationToken).ConfigureAwait(false);

        public async Task<BatchWorkerSigningResult> SignWithDiagnosticsAsync(
            string originalPath,
            string stagedPath,
            string signingPlanJson,
            string? operationId,
            WorkerSdkFallback sdkFallback,
            Action<BatchWorkerPhase> reportProgress,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(reportProgress);
            ArgumentNullException.ThrowIfNull(sdkFallback);
            using Process owner = Process.GetCurrentProcess();
            WorkerSigningContract contract = WorkerSigningContract.FromSigningPlanJson(signingPlanJson);
            WorkerRequest request = new(
                WorkerProtocol.Version,
                WorkerCommands.SignBatch,
                Path.GetFullPath(originalPath),
                Path.GetFullPath(stagedPath),
                signingPlanJson,
                owner.Id,
                new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
                operationId,
                contract.Subject,
                contract.Capability,
                contract.Engine,
                contract.Verification,
                sdkFallback);
            WorkerSessionResult result = await session.SendAsync(
                request,
                timeout,
                progress =>
                {
                    if (!contract.Matches(progress))
                    {
                        throw new WorkerProtocolException(
                            WorkerResponseCodes.SubjectCapabilityMismatch,
                            "The worker progress contract does not match the signing plan.");
                    }

                    reportProgress(Map(progress));
                },
                cancellationToken).ConfigureAwait(false);
            return new BatchWorkerSigningResult(
                result.Response,
                result.WorkerStderrTail,
                result.WorkerStderrTruncated);
        }

        public Task<int> CompleteAsync(CancellationToken cancellationToken) =>
            session.CompleteAsync(cancellationToken);

        public Task TerminateAsync() => session.TerminateAsync();

        public ValueTask DisposeAsync() => session.DisposeAsync();

        private static BatchWorkerPhase Map(WorkerProgress progress) => progress.Phase switch
        {
            WorkerProgressPhases.SigningPrimary => BatchWorkerPhase.SigningPrimary,
            WorkerProgressPhases.SigningSecondary => BatchWorkerPhase.SigningSecondary,
            WorkerProgressPhases.Verifying => BatchWorkerPhase.Verifying,
            _ => throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidFrame,
                "The worker emitted an unknown progress phase.")
        };
    }
}

public sealed class SequentialBatchOrchestrator : IAsyncDisposable
{
    private readonly IBatchWorkerSessionFactory workerFactory;
    private readonly TimeSpan perFileTimeout;
    private readonly Action<string, string?, int?>? runtimeEventSink;
    private readonly Action<string, string?, int?, WorkerLaunchDiagnostic?>? diagnosticRuntimeEventSink;
    private readonly SemaphoreSlim runGate = new(1, 1);
    private readonly object activeRunSync = new();
    private IBatchWorkerSession? worker;
    private SigningBatch? activeBatch;
    private CancellationTokenSource? activeRunCancellation;
    private TaskCompletionSource<bool>? activeRunCompletion;
    private int disposed;

    public SequentialBatchOrchestrator(
        IBatchWorkerSessionFactory workerFactory,
        TimeSpan perFileTimeout,
        Action<string, string?, int?>? runtimeEventSink = null,
        Action<string, string?, int?, WorkerLaunchDiagnostic?>? diagnosticRuntimeEventSink = null)
    {
        this.workerFactory = workerFactory ?? throw new ArgumentNullException(nameof(workerFactory));
        if (perFileTimeout <= TimeSpan.Zero || perFileTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(perFileTimeout));
        }

        this.perFileTimeout = perFileTimeout;
        this.runtimeEventSink = runtimeEventSink;
        this.diagnosticRuntimeEventSink = diagnosticRuntimeEventSink;
    }

    public event EventHandler<BatchItemStateChangedEventArgs>? StateChanged;

    public StagingRecoveryReceipt LastRecoveryReceipt { get; private set; } = new(0, 0);

    public Task<SigningBatch> RunAsync(SigningBatch batch, CancellationToken cancellationToken) =>
        ProcessAsync(batch, retryFailed: false, cancellationToken);

    public Task<SigningBatch> ResumeAsync(
        SigningBatch batch,
        bool retryFailed,
        CancellationToken cancellationToken) => ProcessAsync(batch, retryFailed, cancellationToken);

    public async Task CancelAsync(SigningBatch batch)
    {
        ArgumentNullException.ThrowIfNull(batch);
        CancellationTokenSource? cancellation;
        Task? completion;
        IBatchWorkerSession? activeWorker;
        lock (activeRunSync)
        {
            cancellation = ReferenceEquals(activeBatch, batch) ? activeRunCancellation : null;
            completion = ReferenceEquals(activeBatch, batch) ? activeRunCompletion?.Task : null;
            activeWorker = ReferenceEquals(activeBatch, batch) ? worker : null;
        }

        if (cancellation is not null && completion is not null)
        {
            cancellation.Cancel();
            if (activeWorker is not null)
            {
                await activeWorker.TerminateAsync().ConfigureAwait(false);
            }

            await completion.ConfigureAwait(false);
            return;
        }

        await runGate.WaitAsync().ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await TerminateWorkerAsync().ConfigureAwait(false);
            CancelNonTerminalItems(batch);
        }
        finally
        {
            runGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await runGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await TerminateWorkerAsync().ConfigureAwait(false);
        }
        finally
        {
            runGate.Release();
            runGate.Dispose();
        }
    }

    private async Task<SigningBatch> ProcessAsync(
        SigningBatch batch,
        bool retryFailed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(batch);
        await runGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        using CancellationTokenSource runCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var runCompletion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (activeRunSync)
        {
            activeBatch = batch;
            activeRunCancellation = runCancellation;
            activeRunCompletion = runCompletion;
        }

        try
        {
            ThrowIfDisposed();
            CancellationToken runToken = runCancellation.Token;
            if (runToken.IsCancellationRequested)
            {
                CancelNonTerminalItems(batch);
                return batch;
            }

            RecoverAbandonedStaging(batch);
            PrepareResume(batch, retryFailed);

            foreach (BatchItem item in batch.Items)
            {
                if (runToken.IsCancellationRequested)
                {
                    await TerminateWorkerAsync().ConfigureAwait(false);
                    CancelNonTerminalItems(batch);
                    return batch;
                }

                if (item.State is BatchItemState.Published or BatchItemState.SkippedAlreadySigned or
                    BatchItemState.Failed or BatchItemState.Cancelled)
                {
                    continue;
                }

                if (item.State is BatchItemState.PausedProvider or BatchItemState.PausedTimestamp)
                {
                    return batch;
                }

                if (!TryValidateExecutableRequest(
                    item.Request,
                    out SigningPlan? parsedPlan,
                    out BatchResultCode validationCode))
                {
                    Finish(item, BatchItemState.Failed, validationCode);
                    continue;
                }

                if (item.State == BatchItemState.Pending)
                {
                    Transition(item, BatchItemState.Ready);
                }

                string? preAttemptOriginalHash = null;
                try
                {
                    preAttemptOriginalHash = await HashFileAsync(
                        item.Request.File.OriginalPath,
                        runToken).ConfigureAwait(false);
                    if (worker is null)
                    {
                        ReportRuntimeEvent("worker-starting", item);
                        try
                        {
                            worker = await workerFactory.StartAsync(runToken).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception error)
                        {
                            WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);
                            ReportRuntimeEvent("worker-start-failed", item, diagnostic: diagnostic);
                            Finish(
                                item,
                                BatchItemState.Failed,
                                BatchResultCode.WorkerLaunchFailed,
                                workerProcessId: null,
                                hResult: diagnostic.HResult,
                                launchDiagnostic: diagnostic);
                            return batch;
                        }

                        ReportRuntimeEvent("worker-started", item, worker.ProcessId);
                    }

                    await PublishItemAsync(item, parsedPlan!, worker, runToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    await TerminateWorkerAsync().ConfigureAwait(false);
                    CancelNonTerminalItems(batch, item, preAttemptOriginalHash);
                    return batch;
                }
                catch (BatchWorkerSkipException skipped)
                {
                    Finish(
                        item,
                        BatchItemState.SkippedAlreadySigned,
                        BatchResultCode.AlreadySigned,
                        preAttemptOriginalHash,
                        publishedSha256: null,
                        attemptId: null,
                        workerProcessId: worker?.ProcessId,
                        hResult: skipped.Response.HResult,
                        signingDiagnostic: skipped.Response,
                        workerStderrTail: skipped.Result.WorkerStderrTail,
                        workerStderrTruncated: skipped.Result.WorkerStderrTruncated);
                }
                catch (BatchWorkerFailureException error)
                {
                    BatchItemState failureState = error.IsMisleadingSuccess
                        ? BatchItemState.Failed
                        : ClassifyFailureState(error.Response);
                    BatchResultCode code = error.IsMisleadingSuccess
                        ? BatchResultCode.MisleadingWorkerSuccess
                        : failureState switch
                        {
                            BatchItemState.PausedProvider => BatchResultCode.ProviderUnavailable,
                            BatchItemState.PausedTimestamp => BatchResultCode.TimestampUnavailable,
                            BatchItemState.Cancelled => BatchResultCode.Cancelled,
                            _ when string.Equals(
                                error.Response.Code,
                                WorkerResponseCodes.OriginalChanged,
                                StringComparison.Ordinal) => BatchResultCode.OriginalChanged,
                            _ => BatchResultCode.WorkerFailure
                        };
                    Finish(
                        item,
                        failureState,
                        code,
                        preAttemptOriginalHash,
                        null,
                        null,
                        worker?.ProcessId,
                        error.Response.HResult,
                        signingDiagnostic: error.Response,
                        workerStderrTail: error.Result.WorkerStderrTail,
                        workerStderrTruncated: error.Result.WorkerStderrTruncated);
                    if (failureState is BatchItemState.PausedProvider or BatchItemState.PausedTimestamp)
                    {
                        return batch;
                    }
                }
                catch (WorkerProcessTimeoutException error)
                {
                    WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);
                    Finish(
                        item,
                        BatchItemState.Failed,
                        BatchResultCode.WorkerTimedOut,
                        originalSha256: preAttemptOriginalHash,
                        workerProcessId: worker?.ProcessId,
                        hResult: diagnostic.HResult,
                        launchDiagnostic: diagnostic);
                    await TerminateWorkerAsync().ConfigureAwait(false);
                }
                catch (WorkerProcessCrashedException error)
                {
                    WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);
                    Finish(
                        item,
                        BatchItemState.Failed,
                        BatchResultCode.WorkerCrashed,
                        originalSha256: preAttemptOriginalHash,
                        workerProcessId: worker?.ProcessId,
                        hResult: diagnostic.HResult,
                        launchDiagnostic: diagnostic);
                    await TerminateWorkerAsync().ConfigureAwait(false);
                }
                catch (WorkerProtocolException error)
                {
                    WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);
                    Finish(
                        item,
                        BatchItemState.Failed,
                        BatchResultCode.WorkerProtocolFailure,
                        originalSha256: preAttemptOriginalHash,
                        workerProcessId: worker?.ProcessId,
                        hResult: diagnostic.HResult,
                        launchDiagnostic: diagnostic);
                    await TerminateWorkerAsync().ConfigureAwait(false);
                }
                catch (FilePipelineException error)
                {
                    Finish(
                        item,
                        BatchItemState.Failed,
                        MapPipelineFailure(error.Error),
                        preAttemptOriginalHash,
                        workerProcessId: error.Error == FilePipelineError.OutputSaveFailed ? worker?.ProcessId : null,
                        hResult: error.Error == FilePipelineError.OutputSaveFailed
                            ? error.InnerException?.HResult
                            : null);
                    if (error.Error == FilePipelineError.OutputSaveFailed)
                    {
                        await TerminateWorkerAsync().ConfigureAwait(false);
                    }
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);
                    Finish(
                        item,
                        BatchItemState.Failed,
                        BatchResultCode.WorkerCrashed,
                        originalSha256: preAttemptOriginalHash,
                        workerProcessId: worker?.ProcessId,
                        hResult: diagnostic.HResult,
                        launchDiagnostic: diagnostic);
                    await TerminateWorkerAsync().ConfigureAwait(false);
                }
            }

            await CompleteWorkerAsync().ConfigureAwait(false);
            return batch;
        }
        finally
        {
            lock (activeRunSync)
            {
                if (ReferenceEquals(activeRunCompletion, runCompletion))
                {
                    activeBatch = null;
                    activeRunCancellation = null;
                    activeRunCompletion = null;
                }
            }

            runCompletion.TrySetResult(true);
            runGate.Release();
        }
    }

    private async Task PublishItemAsync(
        BatchItem item,
        SigningPlan plan,
        IBatchWorkerSession activeWorker,
        CancellationToken cancellationToken)
    {
        var signer = new SessionSigner(this, item, plan, activeWorker, perFileTimeout);
        var verifier = new SessionReceiptVerifier(item.Request.File.OriginalPath, signer);
        PublishReceipt receipt = await new TransactionalFilePublisher(
            signer,
            verifier,
            hooks: null,
            runtimeEventSink: runtimeEvent => ReportRuntimeEvent(runtimeEvent, item, activeWorker.ProcessId))
            .PublishAsync(item.Request.File, cancellationToken).ConfigureAwait(false);
        Finish(
            item,
            BatchItemState.Published,
            BatchResultCode.Published,
            receipt.OriginalSha256,
            receipt.PublishedSha256,
            receipt.AttemptId,
            activeWorker.ProcessId,
            signer.Response?.HResult ?? 0,
            signingDiagnostic: signer.Response,
            workerStderrTail: signer.Result?.WorkerStderrTail,
            workerStderrTruncated: signer.Result?.WorkerStderrTruncated ?? false);
    }

    private void OnProgress(BatchItem item, bool isDual, BatchWorkerPhase phase)
    {
        switch (phase)
        {
            case BatchWorkerPhase.SigningPrimary when item.State == BatchItemState.SigningPrimary:
                return;
            case BatchWorkerPhase.SigningSecondary when isDual && item.State == BatchItemState.SigningPrimary:
                ReportRuntimeEvent("signing-secondary-enter", item, worker?.ProcessId);
                Transition(item, BatchItemState.SigningSecondary);
                return;
            case BatchWorkerPhase.Verifying when
                (!isDual && item.State == BatchItemState.SigningPrimary) ||
                (isDual && item.State == BatchItemState.SigningSecondary):
                ReportRuntimeEvent("verifying-enter", item, worker?.ProcessId);
                Transition(item, BatchItemState.Verifying);
                return;
            default:
                throw new WorkerProtocolException(
                    WorkerResponseCodes.InvalidFrame,
                    "The worker emitted an invalid signing phase transition.");
        }
    }

    private static bool TryValidateExecutableRequest(
        BatchItemRequest request,
        out SigningPlan? plan,
        out BatchResultCode error)
    {
        plan = null;
        PolicyResult<SigningPlan> parsed = SigningPlanJson.Parse(request.SigningPlanJson);
        if (!parsed.IsSuccess)
        {
            error = BatchResultCode.InvalidSigningPlan;
            return false;
        }

        SigningPlan parsedPlan = parsed.Value!;
        SigningSubject intakeSubject = request.File.Subject.PolicySubject;
        if (!MatchesSubject(intakeSubject, parsedPlan.Subject))
        {
            error = BatchResultCode.InvalidSigningPlan;
            return false;
        }

        if (!MatchesPathExtension(request.File.OriginalPath, parsedPlan.Subject.Extension) ||
            !MatchesPathExtension(request.File.DestinationPath, parsedPlan.Subject.Extension))
        {
            error = BatchResultCode.UnsupportedFileType;
            return false;
        }

        plan = parsedPlan;
        error = default;
        return true;
    }

    private static bool MatchesSubject(SigningSubject intake, SigningSubject planned) =>
        intake.FormatFamily == planned.FormatFamily &&
        intake.Capability == planned.Capability &&
        string.Equals(intake.Extension, planned.Extension, StringComparison.Ordinal);

    private static bool MatchesPathExtension(string path, string expectedExtension) =>
        string.Equals(Path.GetExtension(path), expectedExtension, StringComparison.OrdinalIgnoreCase);

    private void PrepareResume(SigningBatch batch, bool retryFailed)
    {
        foreach (BatchItem item in batch.Items)
        {
            if (item.State is BatchItemState.PausedProvider or BatchItemState.PausedTimestamp ||
                (retryFailed && item.State == BatchItemState.Failed))
            {
                Transition(item, BatchItemState.Ready);
            }
        }
    }

    private void RecoverAbandonedStaging(SigningBatch batch)
    {
        int removed = 0;
        int skipped = 0;
        foreach (string outputRoot in batch.Items
            .Select(static item => item.Request.File.OutputRoot)
            .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            StagingRecoveryReceipt receipt = TransactionalStaging.Recover(outputRoot);
            removed += receipt.RemovedAttemptCount;
            skipped += receipt.SkippedAttemptCount;
        }

        LastRecoveryReceipt = new StagingRecoveryReceipt(removed, skipped);
    }

    private async Task CompleteWorkerAsync()
    {
        if (worker is null)
        {
            return;
        }

        IBatchWorkerSession completed = worker;
        worker = null;
        try
        {
            await completed.CompleteAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            await completed.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task TerminateWorkerAsync()
    {
        if (worker is null)
        {
            return;
        }

        IBatchWorkerSession terminated = worker;
        worker = null;
        try
        {
            await terminated.TerminateAsync().ConfigureAwait(false);
        }
        finally
        {
            await terminated.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void CancelNonTerminalItems(
        SigningBatch batch,
        BatchItem? activeItem = null,
        string? activeOriginalSha256 = null)
    {
        foreach (BatchItem item in batch.Items)
        {
            if (item.State is BatchItemState.Published or BatchItemState.SkippedAlreadySigned or
                BatchItemState.Failed or BatchItemState.Cancelled)
            {
                continue;
            }

            if (BatchItemStateMachine.CanTransition(item.State, BatchItemState.Cancelled))
            {
                Finish(
                    item,
                    BatchItemState.Cancelled,
                    BatchResultCode.Cancelled,
                    ReferenceEquals(item, activeItem) ? activeOriginalSha256 : null);
            }
        }
    }

    private void Finish(
        BatchItem item,
        BatchItemState state,
        BatchResultCode code,
        string? originalSha256 = null,
        string? publishedSha256 = null,
        string? attemptId = null,
        int? workerProcessId = null,
        int? hResult = null,
        WorkerLaunchDiagnostic? launchDiagnostic = null,
        WorkerResponse? signingDiagnostic = null,
        string? workerStderrTail = null,
        bool workerStderrTruncated = false)
    {
        item.Transition(state);
        item.Record(new BatchItemReceipt(
            item.Request.ItemId,
            state,
            code,
            item.Request.File.OriginalPath,
            item.Request.File.DestinationPath,
            originalSha256,
            publishedSha256,
            attemptId,
            workerProcessId,
            hResult,
            launchDiagnostic,
            signingDiagnostic,
            workerStderrTail,
            workerStderrTruncated));
        StateChanged?.Invoke(this, new BatchItemStateChangedEventArgs(item));
    }

    private void Transition(BatchItem item, BatchItemState state)
    {
        item.Transition(state);
        StateChanged?.Invoke(this, new BatchItemStateChangedEventArgs(item));
    }

    private void ReportRuntimeEvent(
        string runtimeEvent,
        BatchItem item,
        int? processId = null,
        WorkerLaunchDiagnostic? diagnostic = null)
    {
        runtimeEventSink?.Invoke(runtimeEvent, item.Request.ItemId, processId);
        diagnosticRuntimeEventSink?.Invoke(runtimeEvent, item.Request.ItemId, processId, diagnostic);
    }

    private static BatchItemState ClassifyFailureState(WorkerResponse response) => response.Code switch
    {
        WorkerResponseCodes.ProviderCancelled or
        WorkerResponseCodes.CertificateNotFound or
        WorkerResponseCodes.CertificateHasNoPrivateKey => BatchItemState.PausedProvider,
        WorkerResponseCodes.TimestampUnavailable => BatchItemState.PausedTimestamp,
        WorkerResponseCodes.Cancelled => BatchItemState.Cancelled,
        _ => BatchItemState.Failed
    };

    private static BatchResultCode MapPipelineFailure(FilePipelineError error) => error switch
    {
        FilePipelineError.OriginalChanged => BatchResultCode.OriginalChanged,
        FilePipelineError.DestinationCollision => BatchResultCode.DestinationCollision,
        FilePipelineError.CleanupFailed => BatchResultCode.CleanupFailed,
        FilePipelineError.OutputSaveFailed => BatchResultCode.OutputSaveFailed,
        _ => BatchResultCode.WorkerFailure
    };

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private static async Task<string> HashFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }

    private sealed class SessionSigner(
        SequentialBatchOrchestrator owner,
        BatchItem item,
        SigningPlan plan,
        IBatchWorkerSession worker,
        TimeSpan timeout) : IStagedFileSigner
    {
        private readonly WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);

        public WorkerResponse? Response { get; private set; }

        public BatchWorkerSigningResult? Result { get; private set; }

        public async Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            owner.ReportRuntimeEvent("signing-primary-enter", item, worker.ProcessId);
            owner.Transition(item, BatchItemState.SigningPrimary);
            BatchWorkerSigningResult result = await worker.SignWithDiagnosticsAsync(
                item.Request.File.OriginalPath,
                stagedPath,
                item.Request.SigningPlanJson,
                item.Request.OperationId,
                item.Request.SdkFallback ?? WorkerSdkFallback.Disabled,
                phase => owner.OnProgress(item, plan.EffectiveMode == SigningMode.Dual, phase),
                timeout,
                cancellationToken).ConfigureAwait(false);
            WorkerResponse response = result.Response;
            Result = result;
            Response = response;
            if (response.Success &&
                response.Outcome == WorkerSigningOutcome.Signed &&
                response.Route == WorkerExecutionRoute.ProductPe)
            {
                try
                {
                    WorkerProtocol.ValidateResponse(response);
                }
                catch (WorkerProtocolException)
                {
                    throw new BatchWorkerFailureException(result, isMisleadingSuccess: true);
                }
            }
            bool claimsSkip = response.Outcome == WorkerSigningOutcome.SkippedExistingSignature ||
                response.Route == WorkerExecutionRoute.Skip ||
                string.Equals(
                    response.Code,
                    WorkerResponseCodes.SkippedExistingSignature,
                    StringComparison.Ordinal);
            if (claimsSkip)
            {
                string originalHash = await HashFileAsync(
                    item.Request.File.OriginalPath,
                    cancellationToken).ConfigureAwait(false);
                string stagedHash = await HashFileAsync(stagedPath, cancellationToken).ConfigureAwait(false);
                bool consistentSkip = response.Success &&
                    string.Equals(
                        response.Code,
                        WorkerResponseCodes.SkippedExistingSignature,
                        StringComparison.Ordinal) &&
                    response.HResult is >= 0 &&
                    response.ProtocolVersion == WorkerProtocol.Version &&
                    contract.Matches(response) &&
                    response.Outcome == WorkerSigningOutcome.SkippedExistingSignature &&
                    response.Route == WorkerExecutionRoute.Skip &&
                    response.Failure is null &&
                    response.LegacyFallbackAttempted == false &&
                    item.State == BatchItemState.SigningPrimary &&
                    string.Equals(response.OriginalSha256, originalHash, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(response.StagedSha256, stagedHash, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(originalHash, stagedHash, StringComparison.Ordinal);
                if (consistentSkip)
                {
                    throw new BatchWorkerSkipException(result);
                }

                throw new BatchWorkerFailureException(result, isMisleadingSuccess: true);
            }

            bool consistentSuccess = response.Success &&
                string.Equals(response.Code, WorkerResponseCodes.SigningCompleted, StringComparison.Ordinal) &&
                response.HResult is >= 0 &&
                IsSha256(response.OriginalSha256) &&
                IsSha256(response.StagedSha256) &&
                response.ProtocolVersion == WorkerProtocol.Version &&
                contract.Matches(response) &&
                item.State == BatchItemState.Verifying;
            if (!consistentSuccess)
            {
                throw new BatchWorkerFailureException(
                    result,
                    response.Success || !contract.Matches(response));
            }
        }

        private static bool IsSha256(string? value) =>
            value is { Length: 64 } && value.All(static character =>
                (character >= '0' && character <= '9') ||
                (character >= 'A' && character <= 'F') ||
                (character >= 'a' && character <= 'f'));
    }

    private sealed class SessionReceiptVerifier(
        string originalPath,
        SessionSigner signer) : IStagedFileVerifier
    {
        public async Task VerifyAsync(string stagedPath, CancellationToken cancellationToken)
        {
            WorkerResponse response = signer.Response
                ?? throw new WorkerProtocolException(
                    WorkerResponseCodes.InvalidFrame,
                    "The worker returned no signing receipt.");
            string originalHash = await HashAsync(originalPath, cancellationToken).ConfigureAwait(false);
            string stagedHash = await HashAsync(stagedPath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(response.OriginalSha256, originalHash, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(response.StagedSha256, stagedHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new BatchWorkerFailureException(
                    signer.Result ?? new BatchWorkerSigningResult(response, null, false),
                    isMisleadingSuccess: true);
            }
        }

        private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
        {
            await using FileStream stream = new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        }
    }

    private sealed class BatchWorkerFailureException(
        BatchWorkerSigningResult result,
        bool isMisleadingSuccess) : Exception("The worker returned a typed signing failure.")
    {
        public BatchWorkerSigningResult Result { get; } = result;

        public WorkerResponse Response => Result.Response;

        public bool IsMisleadingSuccess { get; } = isMisleadingSuccess;
    }

    private sealed class BatchWorkerSkipException(BatchWorkerSigningResult result)
        : Exception("The Worker reported an authoritative existing-signature skip.")
    {
        public BatchWorkerSigningResult Result { get; } = result;

        public WorkerResponse Response => Result.Response;
    }
}
