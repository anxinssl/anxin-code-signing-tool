using System.Diagnostics;
using CodeSigner.CompatibilityProbe.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class BoundedProcessRunnerTests
{
    [Fact]
    [Trait("Category", "NativeSigning")]
    public async Task TimeoutKillsTheExactProcessTree()
    {
        ProcessStartInfo startInfo = new("ping.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("127.0.0.1");
        startInfo.ArgumentList.Add("-n");
        startInfo.ArgumentList.Add("30");

        BoundedProcessResult result = await BoundedProcessRunner.RunAsync(
            startInfo,
            TimeSpan.FromMilliseconds(300),
            CancellationToken.None);

        Assert.True(result.TimedOut);
        Assert.Null(result.ExitCode);
        Assert.False(IsProcessRunning(result.ProcessId));
    }

    private static bool IsProcessRunning(int processId)
    {
        try
        {
            using Process process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
