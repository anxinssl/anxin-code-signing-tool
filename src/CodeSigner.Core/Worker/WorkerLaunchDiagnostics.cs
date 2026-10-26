using System.ComponentModel;
using System.Diagnostics;

namespace CodeSigner.Core.Worker;

public enum WorkerLaunchReason
{
    Healthy,
    Missing,
    InvalidImage,
    VersionMismatch,
    AccessDenied,
    StartFailed,
    UserMismatch,
    SessionMismatch,
    MissingUserSid,
    Timeout,
    Crashed,
    ProtocolMismatch,
    InvalidFrame
}

public enum WorkerRepairEligibility
{
    NotEligible,
    Eligible
}

public sealed record WorkerLaunchDiagnostic
{
    internal WorkerLaunchDiagnostic(
        WorkerLaunchReason reason,
        int? hResult,
        int? nativeErrorCode,
        int? exitCode,
        WorkerStderrDiagnostic stderr)
    {
        Reason = reason;
        RepairEligibility = reason is WorkerLaunchReason.Missing or
            WorkerLaunchReason.InvalidImage or
            WorkerLaunchReason.VersionMismatch
                ? WorkerRepairEligibility.Eligible
                : WorkerRepairEligibility.NotEligible;
        HResult = hResult;
        NativeErrorCode = nativeErrorCode;
        ExitCode = exitCode;
        WorkerStderrTail = stderr.Tail;
        WorkerStderrTruncated = stderr.Truncated;
    }

    public WorkerLaunchReason Reason { get; }
    public string ReasonCode => WorkerLaunchDiagnosticMapper.GetReasonCode(Reason);
    public WorkerRepairEligibility RepairEligibility { get; }
    public bool RepairEligible => RepairEligibility == WorkerRepairEligibility.Eligible;
    public int? HResult { get; }
    public int? NativeErrorCode { get; }
    public int? ExitCode { get; }
    public string? WorkerStderrTail { get; }
    public bool WorkerStderrTruncated { get; }
}

public static class WorkerLaunchDiagnosticMapper
{
    public static WorkerLaunchDiagnostic ForReason(WorkerLaunchReason reason) =>
        Create(reason);

    public static WorkerLaunchDiagnostic FromException(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        WorkerStderrDiagnostic stderr = WorkerProcessDiagnosticAttachments.Get(error);
        return error switch
        {
            WorkerProbeException probeError => probeError.Diagnostic,
            FileNotFoundException fileError => Create(
                WorkerLaunchReason.Missing,
                fileError.HResult,
                GetNativeErrorCode(fileError.HResult),
                stderr: stderr),
            Win32Exception nativeError => FromNativeError(nativeError, stderr),
            BadImageFormatException imageError => Create(
                WorkerLaunchReason.InvalidImage,
                imageError.HResult,
                stderr: stderr),
            UnauthorizedAccessException accessError => Create(
                WorkerLaunchReason.AccessDenied,
                accessError.HResult,
                GetNativeErrorCode(accessError.HResult),
                stderr: stderr),
            WorkerProcessSecurityException securityError => FromSecurityCode(securityError.Code, stderr),
            WorkerProcessTimeoutException => Create(WorkerLaunchReason.Timeout, stderr: stderr),
            WorkerProcessCrashedException crashError => Create(
                WorkerLaunchReason.Crashed,
                exitCode: crashError.ExitCode,
                stderr: stderr),
            WorkerEndOfStreamException endOfStreamError => Create(
                endOfStreamError.IsCleanEof
                    ? WorkerLaunchReason.Crashed
                    : WorkerLaunchReason.InvalidFrame,
                stderr: stderr),
            WorkerProtocolException protocolError => Create(
                protocolError.Code == WorkerResponseCodes.ProtocolVersionMismatch
                    ? WorkerLaunchReason.ProtocolMismatch
                    : WorkerLaunchReason.InvalidFrame,
                stderr: stderr),
            EndOfStreamException => Create(WorkerLaunchReason.Crashed, stderr: stderr),
            IOException ioError => Create(WorkerLaunchReason.Crashed, ioError.HResult, stderr: stderr),
            _ => Create(WorkerLaunchReason.StartFailed, stderr: stderr)
        };
    }

    public static WorkerLaunchDiagnostic FromProbeResult(WorkerProcessResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        WorkerResponse response = result.Response;
        WorkerLaunchReason reason;
        if (response.ProtocolVersion != WorkerProtocol.Version ||
            string.Equals(response.Code, WorkerResponseCodes.ProtocolVersionMismatch, StringComparison.Ordinal))
        {
            reason = WorkerLaunchReason.ProtocolMismatch;
        }
        else if (response.Success &&
                 result.ExitCode == 0 &&
                 string.Equals(response.Code, WorkerResponseCodes.Ready, StringComparison.Ordinal))
        {
            reason = WorkerLaunchReason.Healthy;
        }
        else
        {
            reason = WorkerLaunchReason.InvalidFrame;
        }

        return Create(
            reason,
            response.HResult,
            exitCode: result.ExitCode,
            stderr: new WorkerStderrDiagnostic(
                result.WorkerStderrTail,
                result.WorkerStderrTruncated));
    }

    public static string GetReasonCode(WorkerLaunchReason reason) => reason switch
    {
        WorkerLaunchReason.Healthy => "healthy",
        WorkerLaunchReason.Missing => "missing",
        WorkerLaunchReason.InvalidImage => "invalid_image",
        WorkerLaunchReason.VersionMismatch => "version_mismatch",
        WorkerLaunchReason.AccessDenied => "access_denied",
        WorkerLaunchReason.StartFailed => "start_failed",
        WorkerLaunchReason.UserMismatch => "user_mismatch",
        WorkerLaunchReason.SessionMismatch => "session_mismatch",
        WorkerLaunchReason.MissingUserSid => "missing_user_sid",
        WorkerLaunchReason.Timeout => "timeout",
        WorkerLaunchReason.Crashed => "crashed",
        WorkerLaunchReason.ProtocolMismatch => "protocol_mismatch",
        WorkerLaunchReason.InvalidFrame => "invalid_frame",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Unknown Worker launch reason.")
    };

    private static WorkerLaunchDiagnostic FromNativeError(
        Win32Exception error,
        WorkerStderrDiagnostic stderr)
    {
        WorkerLaunchReason reason = error.NativeErrorCode switch
        {
            2 or 3 => WorkerLaunchReason.Missing,
            5 => WorkerLaunchReason.AccessDenied,
            193 or 216 => WorkerLaunchReason.InvalidImage,
            _ => WorkerLaunchReason.StartFailed
        };
        return Create(reason, error.HResult, error.NativeErrorCode, stderr: stderr);
    }

    private static WorkerLaunchDiagnostic FromSecurityCode(
        string code,
        WorkerStderrDiagnostic stderr) => Create(
        code switch
        {
            "user_mismatch" => WorkerLaunchReason.UserMismatch,
            "session_mismatch" => WorkerLaunchReason.SessionMismatch,
            "missing_user_sid" => WorkerLaunchReason.MissingUserSid,
            _ => WorkerLaunchReason.StartFailed
        },
        stderr: stderr);

    private static WorkerLaunchDiagnostic Create(
        WorkerLaunchReason reason,
        int? hResult = null,
        int? nativeErrorCode = null,
        int? exitCode = null,
        WorkerStderrDiagnostic stderr = default) =>
        new(reason, hResult, nativeErrorCode, exitCode, stderr);

    private static int? GetNativeErrorCode(int hResult) =>
        (hResult & unchecked((int)0xFFFF0000)) == unchecked((int)0x80070000)
            ? hResult & 0xFFFF
            : null;
}

public sealed class WorkerHealthProbe
{
    private readonly string applicationPath;
    private readonly string workerPath;
    private readonly Func<string, string?> readFileVersion;
    private readonly Func<TimeSpan, CancellationToken, Task<WorkerProcessResult>> runProbe;

    public WorkerHealthProbe(string applicationPath, string workerPath)
        : this(
            applicationPath,
            workerPath,
            static path => FileVersionInfo.GetVersionInfo(path).FileVersion,
            new WorkerProcessClient(workerPath).ProbeAsync)
    {
    }

    internal WorkerHealthProbe(
        string applicationPath,
        string workerPath,
        Func<string, string?> readFileVersion,
        Func<TimeSpan, CancellationToken, Task<WorkerProcessResult>> runProbe)
    {
        this.applicationPath = GetCanonicalPath(applicationPath, nameof(applicationPath));
        this.workerPath = GetCanonicalPath(workerPath, nameof(workerPath));
        this.readFileVersion = readFileVersion ?? throw new ArgumentNullException(nameof(readFileVersion));
        this.runProbe = runProbe ?? throw new ArgumentNullException(nameof(runProbe));
    }

    public async Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(workerPath))
        {
            return WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Missing);
        }

        try
        {
            string? applicationVersion = readFileVersion(applicationPath);
            string? workerVersion = readFileVersion(workerPath);
            if (!string.IsNullOrWhiteSpace(applicationVersion) &&
                !string.IsNullOrWhiteSpace(workerVersion) &&
                !string.Equals(applicationVersion, workerVersion, StringComparison.Ordinal))
            {
                return WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.VersionMismatch);
            }

            WorkerProcessResult result = await runProbe(
                WorkerProcessClient.ProbeTimeout,
                cancellationToken).ConfigureAwait(false);
            return WorkerLaunchDiagnosticMapper.FromProbeResult(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            return WorkerLaunchDiagnosticMapper.FromException(error);
        }
    }

    private static string GetCanonicalPath(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path, parameterName);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("The executable path must be absolute.", parameterName);
        }

        return Path.GetFullPath(path);
    }
}

internal sealed class WorkerProbeException(WorkerLaunchDiagnostic diagnostic)
    : IOException("The Worker Probe response was not Ready with exit code zero.")
{
    internal WorkerLaunchDiagnostic Diagnostic { get; } = diagnostic;
}
