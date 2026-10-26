using System.Diagnostics;

namespace CodeSigner.CompatibilityProbe.Signing;

public sealed record BoundedProcessResult(int ProcessId, int? ExitCode, bool TimedOut);

public static class BoundedProcessRunner
{
    public static async Task<BoundedProcessResult> RunAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("The bounded process could not be started.");
        int processId = process.Id;
        Task<string>? standardOutput = startInfo.RedirectStandardOutput
            ? process.StandardOutput.ReadToEndAsync(CancellationToken.None)
            : null;
        Task<string>? standardError = startInfo.RedirectStandardError
            ? process.StandardError.ReadToEndAsync(CancellationToken.None)
            : null;
        Task exit = process.WaitForExitAsync(CancellationToken.None);
        Task boundary = Task.Delay(timeout, cancellationToken);
        Task completed = await Task.WhenAny(exit, boundary).ConfigureAwait(false);
        if (completed == exit)
        {
            await exit.ConfigureAwait(false);
            await DrainAsync(standardOutput, standardError).ConfigureAwait(false);
            return new BoundedProcessResult(processId, process.ExitCode, TimedOut: false);
        }

        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }

        await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        await DrainAsync(standardOutput, standardError).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return new BoundedProcessResult(processId, null, TimedOut: true);
    }

    private static Task DrainAsync(Task<string>? standardOutput, Task<string>? standardError)
    {
        IEnumerable<Task> streams = new[] { standardOutput, standardError }.OfType<Task>();
        return Task.WhenAll(streams);
    }
}
