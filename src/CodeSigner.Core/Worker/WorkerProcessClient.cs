using System.Diagnostics;

namespace CodeSigner.Core.Worker;

public sealed record WorkerProcessResult
{
    public WorkerProcessResult(WorkerResponse response, int processId, int exitCode)
        : this(response, processId, exitCode, WorkerStderrDiagnostic.Empty)
    {
    }

    internal WorkerProcessResult(
        WorkerResponse response,
        int processId,
        int exitCode,
        WorkerStderrDiagnostic stderr)
    {
        Response = response ?? throw new ArgumentNullException(nameof(response));
        ProcessId = processId;
        ExitCode = exitCode;
        WorkerStderrTail = stderr.Tail;
        WorkerStderrTruncated = stderr.Truncated;
    }

    public WorkerResponse Response { get; }
    public int ProcessId { get; }
    public int ExitCode { get; }
    public string? WorkerStderrTail { get; }
    public bool WorkerStderrTruncated { get; }
}

public sealed class WorkerProcessTimeoutException : TimeoutException
{
    public WorkerProcessTimeoutException()
        : this(WorkerStderrDiagnostic.Empty)
    {
    }

    internal WorkerProcessTimeoutException(WorkerStderrDiagnostic stderr)
        : base("The worker exceeded its execution deadline.")
    {
        WorkerStderrTail = stderr.Tail;
        WorkerStderrTruncated = stderr.Truncated;
    }

    public string? WorkerStderrTail { get; }
    public bool WorkerStderrTruncated { get; }
}

public sealed class WorkerProcessClient
{
    private readonly string workerPath;
    private readonly Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy;
    private readonly Func<string, ProcessStartInfo> createStartInfo;

    public static TimeSpan ProbeTimeout { get; } = TimeSpan.FromSeconds(5);

    public WorkerProcessClient(string workerPath)
        : this(workerPath, WorkerProcessLaunchPolicy.Validate)
    {
    }

    internal WorkerProcessClient(
        string workerPath,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
        : this(workerPath, validateLaunchPolicy, CreateStartInfo)
    {
    }

    internal WorkerProcessClient(
        string workerPath,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy,
        Func<string, ProcessStartInfo> createStartInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerPath);
        if (!Path.IsPathFullyQualified(workerPath))
        {
            throw new ArgumentException("The worker path must be absolute.", nameof(workerPath));
        }

        this.workerPath = Path.GetFullPath(workerPath);
        this.validateLaunchPolicy = validateLaunchPolicy
            ?? throw new ArgumentNullException(nameof(validateLaunchPolicy));
        this.createStartInfo = createStartInfo
            ?? throw new ArgumentNullException(nameof(createStartInfo));
    }

    public static ProcessStartInfo CreateStartInfo(string workerPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerPath);
        return new ProcessStartInfo(workerPath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            ErrorDialog = false
        };
    }

    public async Task<WorkerProcessResult> SendAsync(
        WorkerRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        if (!File.Exists(workerPath))
        {
            throw new FileNotFoundException("The worker executable does not exist.", workerPath);
        }

        using Process launcher = Process.GetCurrentProcess();
        WorkerProcessIdentity launcherIdentity = WorkerProcessIdentity.Capture(launcher);
        using Process process = Process.Start(createStartInfo(workerPath))
            ?? throw new InvalidOperationException("The worker process did not start.");
        using WorkerJob job = WorkerJob.CreateKillOnClose();
        try
        {
            job.Assign(process);
            validateLaunchPolicy(launcherIdentity, WorkerProcessIdentity.Capture(process));
        }
        catch
        {
            TerminateQuietly(job);
            throw;
        }

        using CancellationTokenSource deadline = new(timeout);
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            deadline.Token);
        WorkerStderrTailCapture stderrCapture = WorkerStderrTailCapture.Start(
            process.StandardError.BaseStream,
            linked.Token);
        try
        {
            await WorkerProtocol.WriteRequestAsync(
                process.StandardInput.BaseStream,
                request,
                linked.Token).ConfigureAwait(false);
            process.StandardInput.Close();

            WorkerResponse response = await WorkerProtocol.ReadResponseAsync(
                process.StandardOutput.BaseStream,
                linked.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            await stderrCapture.Completion.ConfigureAwait(false);
            WorkerStderrDiagnostic stderr = stderrCapture.Snapshot();
            int trailingByte = process.StandardOutput.BaseStream.ReadByte();
            if (trailingByte != -1)
            {
                throw new WorkerProtocolException(
                    WorkerResponseCodes.InvalidFrame,
                    "The worker emitted more than one response frame.");
            }

            ValidateOutcome(response, process.ExitCode);
            return new WorkerProcessResult(response, process.Id, process.ExitCode, stderr);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            TerminateQuietly(job);
            await WaitForTerminationAsync(process).ConfigureAwait(false);
            WorkerStderrDiagnostic stderr = await CompleteFailedStderrCaptureAsync(stderrCapture)
                .ConfigureAwait(false);
            throw new WorkerProcessTimeoutException(stderr);
        }
        catch (Exception error)
        {
            TerminateQuietly(job);
            await WaitForTerminationAsync(process).ConfigureAwait(false);
            WorkerStderrDiagnostic stderr = await CompleteFailedStderrCaptureAsync(stderrCapture)
                .ConfigureAwait(false);
            WorkerProcessDiagnosticAttachments.Attach(error, stderr);
            throw;
        }
    }

    public Task<WorkerProcessResult> SignAsync(
        string originalPath,
        string stagedPath,
        string signingPlanJson,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using Process owner = Process.GetCurrentProcess();
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            Path.GetFullPath(originalPath),
            Path.GetFullPath(stagedPath),
            signingPlanJson,
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
            Guid.NewGuid().ToString("N"));
        return SendAsync(request, timeout, cancellationToken);
    }

    public Task<WorkerProcessResult> ProbeAsync(CancellationToken cancellationToken) =>
        ProbeAsync(ProbeTimeout, cancellationToken);

    internal async Task<WorkerProcessResult> ProbeAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Probe,
            workerPath);
        WorkerProcessResult result = await SendAsync(
            request,
            timeout,
            cancellationToken).ConfigureAwait(false);
        WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromProbeResult(result);
        if (diagnostic.Reason != WorkerLaunchReason.Healthy)
        {
            throw new WorkerProbeException(diagnostic);
        }

        return result;
    }

    public static void ValidateOutcome(WorkerResponse response, int exitCode)
    {
        ArgumentNullException.ThrowIfNull(response);
        if ((exitCode == 0) != response.Success)
        {
            throw new WorkerProtocolException(
                WorkerResponseCodes.InvalidFrame,
                "The worker exit code and typed response disagree.");
        }
    }

    private static void TerminateQuietly(WorkerJob job)
    {
        try
        {
            job.Terminate(WorkerJob.TimeoutExitCode);
        }
        catch (Exception)
        {
        }
    }

    private static async Task WaitForTerminationAsync(Process process)
    {
        if (process.HasExited)
        {
            return;
        }

        using CancellationTokenSource boundedWait = new(TimeSpan.FromSeconds(5));
        await process.WaitForExitAsync(boundedWait.Token).ConfigureAwait(false);
    }

    private static async Task<WorkerStderrDiagnostic> CompleteFailedStderrCaptureAsync(
        WorkerStderrTailCapture capture)
    {
        try
        {
            await capture.Completion.ConfigureAwait(false);
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }

        return capture.Snapshot();
    }
}
