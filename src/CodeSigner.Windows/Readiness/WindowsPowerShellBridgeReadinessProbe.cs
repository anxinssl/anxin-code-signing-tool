using System.Diagnostics;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Readiness;

public sealed class WindowsPowerShellBridgeReadinessProbe
{
    private readonly IWindowsPowerShellEnvironment environment;
    private readonly IWindowsPowerShellProcessRunner processRunner;

    public WindowsPowerShellBridgeReadinessProbe()
        : this(new SystemWindowsPowerShellEnvironment(), new SystemWindowsPowerShellProcessRunner())
    {
    }

    internal WindowsPowerShellBridgeReadinessProbe(
        IWindowsPowerShellEnvironment environment,
        IWindowsPowerShellProcessRunner processRunner)
    {
        this.environment = environment ?? throw new ArgumentNullException(nameof(environment));
        this.processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
    }

    public async Task<WindowsPowerShellBridgeReadiness> ProbeAsync(CancellationToken cancellationToken)
    {
        if (!TryResolveExecutable(out string? executablePath))
        {
            return new(
                WindowsPowerShellBridgeStatus.Unavailable,
                null,
                null,
                "SystemWindowsPowerShellMissing");
        }

        ProcessStartInfo startInfo = new(executablePath!)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            ErrorDialog = false
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(WindowsPowerShellSipCommand.Probe);

        WindowsPowerShellProcessResult result;
        try
        {
            result = await processRunner.RunAsync(startInfo, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }

        if (result.StartFailure == WindowsPowerShellProcessStartFailure.ExecutionDenied)
        {
            return new(
                WindowsPowerShellBridgeStatus.ExecutionDenied,
                executablePath,
                null,
                "SystemWindowsPowerShellExecutionDenied");
        }

        if (result.StartFailure != WindowsPowerShellProcessStartFailure.None)
        {
            return new(
                WindowsPowerShellBridgeStatus.Unavailable,
                executablePath,
                null,
                "SystemWindowsPowerShellLaunchFailed");
        }

        return result.ExitCode switch
        {
            0 => new(
                WindowsPowerShellBridgeStatus.Available,
                executablePath,
                "5.1",
                "SystemWindowsPowerShell51Available"),
            51 => new(
                WindowsPowerShellBridgeStatus.UnsupportedVersion,
                executablePath,
                null,
                "SystemWindowsPowerShellVersionUnsupported"),
            _ => new(
                WindowsPowerShellBridgeStatus.Unavailable,
                executablePath,
                null,
                "SystemWindowsPowerShellProbeFailed")
        };
    }

    private bool TryResolveExecutable(out string? executablePath)
    {
        executablePath = null;
        try
        {
            if (!environment.IsWindows || string.IsNullOrWhiteSpace(environment.WindowsDirectory))
            {
                return false;
            }

            string windowsDirectory = Path.GetFullPath(environment.WindowsDirectory);
            string expected = Path.GetFullPath(Path.Combine(
                windowsDirectory,
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe"));
            if (!expected.StartsWith(windowsDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                !environment.FileExists(expected) ||
                (environment.GetAttributes(expected) & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            executablePath = expected;
            return true;
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            UnauthorizedAccessException or
            System.Security.SecurityException)
        {
            return false;
        }
    }
}
