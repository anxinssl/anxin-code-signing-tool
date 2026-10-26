using System.Diagnostics;

namespace CodeSigner.Core.Worker;

public sealed record WorkerSessionResult
{
    public WorkerSessionResult(WorkerResponse response, int processId)
        : this(response, processId, WorkerStderrDiagnostic.Empty)
    {
    }

    internal WorkerSessionResult(
        WorkerResponse response,
        int processId,
        WorkerStderrDiagnostic stderr)
    {
        Response = response ?? throw new ArgumentNullException(nameof(response));
        ProcessId = processId;
        WorkerStderrTail = stderr.Tail;
        WorkerStderrTruncated = stderr.Truncated;
    }

    public WorkerResponse Response { get; }
    public int ProcessId { get; }
    public string? WorkerStderrTail { get; }
    public bool WorkerStderrTruncated { get; }
}

public sealed class WorkerProcessCrashedException : IOException
{
    public WorkerProcessCrashedException(int? exitCode = null)
        : this(exitCode, WorkerStderrDiagnostic.Empty)
    {
    }

    internal WorkerProcessCrashedException(int? exitCode, WorkerStderrDiagnostic stderr)
        : base("The signing worker exited before returning a complete typed response.")
    {
        ExitCode = exitCode;
        WorkerStderrTail = stderr.Tail;
        WorkerStderrTruncated = stderr.Truncated;
    }

    public int? ExitCode { get; }
    public string? WorkerStderrTail { get; }
    public bool WorkerStderrTruncated { get; }
}

public sealed class WorkerProcessSession : IAsyncDisposable
{
    private readonly Process process;
    private readonly WorkerJob job;
    private readonly CancellationTokenSource stderrCancellation = new();
    private readonly WorkerStderrTailCapture stderrCapture;
    private readonly SemaphoreSlim sendGate = new(1, 1);
    private int stopped;
    private int disposed;

    private WorkerProcessSession(Process process, WorkerJob job)
    {
        this.process = process;
        this.job = job;
        stderrCapture = WorkerStderrTailCapture.Start(
            process.StandardError.BaseStream,
            stderrCancellation.Token);
    }

    public int ProcessId => process.Id;

    public bool IsRunning => Volatile.Read(ref stopped) == 0 && !process.HasExited;

    public static WorkerProcessSession Start(string workerPath) =>
        Start(workerPath, WorkerProcessLaunchPolicy.Validate);

    internal static WorkerProcessSession Start(
        string workerPath,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerPath);
        ArgumentNullException.ThrowIfNull(validateLaunchPolicy);
        if (!Path.IsPathFullyQualified(workerPath))
        {
            throw new ArgumentException("The worker path must be absolute.", nameof(workerPath));
        }

        string canonicalPath = Path.GetFullPath(workerPath);
        if (!File.Exists(canonicalPath))
        {
            throw new FileNotFoundException("The worker executable does not exist.", canonicalPath);
        }

        using Process launcher = Process.GetCurrentProcess();
        WorkerProcessIdentity launcherIdentity = WorkerProcessIdentity.Capture(launcher);
        Process process = Process.Start(WorkerProcessClient.CreateStartInfo(canonicalPath))
            ?? throw new InvalidOperationException("The worker process did not start.");
        WorkerJob job = WorkerJob.CreateKillOnClose();
        try
        {
            job.Assign(process);
            validateLaunchPolicy(launcherIdentity, WorkerProcessIdentity.Capture(process));
            return new WorkerProcessSession(process, job);
        }
        catch
        {
            try
            {
                job.Terminate(WorkerJob.TimeoutExitCode);
            }
            catch (Exception)
            {
            }

            process.Dispose();
            job.Dispose();
            throw;
        }
    }

    public async Task<WorkerSessionResult> SendAsync(
        WorkerRequest request,
        TimeSpan timeout,
        Action<WorkerProgress>? onProgress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        await sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfUnavailable();
            using CancellationTokenSource deadline = new(timeout);
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                deadline.Token);
            try
            {
                bool isSigningRequest =
                    string.Equals(request.Command, WorkerCommands.Sign, StringComparison.Ordinal) ||
                    string.Equals(request.Command, WorkerCommands.SignBatch, StringComparison.Ordinal);
                WorkerRequest transportRequest = request;
                if (isSigningRequest)
                {
                    await WorkerProtocol.WriteRequestAsync(
                        Stream.Null,
                        request,
                        linked.Token).ConfigureAwait(false);
                    transportRequest = request with { OperationId = Guid.NewGuid().ToString("N") };
                }

                await WorkerProtocol.WriteRequestAsync(
                    process.StandardInput.BaseStream,
                    transportRequest,
                    linked.Token).ConfigureAwait(false);
                while (true)
                {
                    WorkerSessionMessage message = await WorkerProtocol.ReadSessionMessageAsync(
                        process.StandardOutput.BaseStream,
                        linked.Token).ConfigureAwait(false);
                    if (message.Progress is not null)
                    {
                        onProgress?.Invoke(message.Progress);
                        continue;
                    }

                    WorkerResponse response = message.Response
                        ?? throw new WorkerProtocolException(
                            WorkerResponseCodes.InvalidFrame,
                            "The worker message has no typed payload.");
                    if (!string.Equals(response.OperationId, transportRequest.OperationId, StringComparison.Ordinal))
                    {
                        throw new WorkerProtocolException(
                            WorkerResponseCodes.InvalidFrame,
                            "The worker response operation identifier does not match the request.");
                    }

                    if (isSigningRequest)
                    {
                        response = response with { OperationId = request.OperationId };
                    }

                    return new WorkerSessionResult(response, process.Id, stderrCapture.Snapshot());
                }
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                await TerminateAsync().ConfigureAwait(false);
                throw new WorkerProcessTimeoutException(stderrCapture.Snapshot());
            }
            catch (OperationCanceledException error)
            {
                await TerminateAsync().ConfigureAwait(false);
                WorkerProcessDiagnosticAttachments.Attach(error, stderrCapture.Snapshot());
                throw;
            }
            catch (WorkerEndOfStreamException error)
            {
                await TerminateAsync().ConfigureAwait(false);
                throw new WorkerProcessCrashedException(
                    GetExitCode(),
                    stderrCapture.Snapshot())
                {
                    Source = error.Source
                };
            }
            catch (IOException error) when (error is not WorkerProcessCrashedException)
            {
                await TerminateAsync().ConfigureAwait(false);
                throw new WorkerProcessCrashedException(
                    GetExitCode(),
                    stderrCapture.Snapshot())
                {
                    Source = error.Source
                };
            }
            catch (Exception error)
            {
                await TerminateAsync().ConfigureAwait(false);
                WorkerProcessDiagnosticAttachments.Attach(error, stderrCapture.Snapshot());
                throw;
            }
        }
        finally
        {
            sendGate.Release();
        }
    }

    public async Task<int> CompleteAsync(CancellationToken cancellationToken = default)
    {
        await sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Interlocked.Exchange(ref stopped, 1) != 0)
            {
                return process.HasExited ? process.ExitCode : unchecked((int)WorkerJob.TimeoutExitCode);
            }

            process.StandardInput.Close();
            using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
                await stderrCapture.Completion.WaitAsync(deadline.Token).ConfigureAwait(false);
                return process.ExitCode;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    job.Terminate(WorkerJob.TimeoutExitCode);
                }
                catch (Exception)
                {
                }

                await TerminateAsync().ConfigureAwait(false);
                throw new WorkerProcessTimeoutException(stderrCapture.Snapshot());
            }
        }
        finally
        {
            sendGate.Release();
        }
    }

    public async Task TerminateAsync()
    {
        if (Interlocked.Exchange(ref stopped, 1) == 0)
        {
            try
            {
                job.Terminate(WorkerJob.TimeoutExitCode);
            }
            catch (Exception) when (process.HasExited)
            {
            }
        }

        if (!process.HasExited)
        {
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(5));
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
        }

        try
        {
            await stderrCapture.Completion.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            stderrCancellation.Cancel();
            await stderrCapture.Completion.ConfigureAwait(false);
            throw new WorkerProcessTimeoutException(stderrCapture.Snapshot());
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        try
        {
            if (!process.HasExited)
            {
                await TerminateAsync().ConfigureAwait(false);
            }
            else
            {
                await stderrCapture.Completion.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
        }
        finally
        {
            stderrCancellation.Cancel();
            stderrCancellation.Dispose();
            sendGate.Dispose();
            process.Dispose();
            job.Dispose();
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Volatile.Read(ref stopped) != 0 || process.HasExited)
        {
            throw new WorkerProcessCrashedException(
                GetExitCode(),
                stderrCapture.Snapshot());
        }
    }

    private int? GetExitCode() => process.HasExited ? process.ExitCode : null;
}
