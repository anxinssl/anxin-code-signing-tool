using System.Diagnostics;
using CodeSigner.Core.Worker;

namespace CodeSigner.IntegrationTests;

public sealed class WorkerProcessBoundaryTests
{
    [Fact]
    public void WorkerLaunchNeverUsesShellCredentialsOrElevation()
    {
        ProcessStartInfo startInfo = WorkerProcessClient.CreateStartInfo("C:\\app\\CodeSigner.Worker.exe");

        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.RedirectStandardInput);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Empty(startInfo.ArgumentList);
        Assert.True(string.IsNullOrEmpty(startInfo.UserName));
        Assert.False(string.Equals("runas", startInfo.Verb, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void WorkerIdentitySourceContainsNoElevationInspection()
    {
        string[] matches = FindForbiddenIdentityInspection(FindRepositoryRoot());

        Assert.True(
            matches.Length == 0,
            "Live source still contains elevation inspection or typed elevation states:" +
                Environment.NewLine + string.Join(Environment.NewLine, matches));
    }

    [Fact]
    public void WorkerIdentitySourceScanChecksEveryProductionSourceFile()
    {
        string repositoryRoot = Path.Combine(
            Path.GetTempPath(),
            "codesigner-worker-identity-source-scan",
            Guid.NewGuid().ToString("N"));
        string workerSource = Path.Combine(
            repositoryRoot,
            "src",
            "CodeSigner.Worker",
            "InjectedIdentityInspection.cs");
        string adjacentSource = Path.Combine(
            repositoryRoot,
            "src",
            "CodeSigner.Windows",
            "InjectedIdentityInspection.cs");

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(workerSource)!);
            Directory.CreateDirectory(Path.GetDirectoryName(adjacentSource)!);
            File.WriteAllText(workerSource, "TokenElevation");
            File.WriteAllText(adjacentSource, "GetTokenInformation");

            string[] matches = FindForbiddenIdentityInspection(repositoryRoot);

            Assert.Equal(2, matches.Length);
            Assert.Contains(
                Path.Combine("src", "CodeSigner.Worker", "InjectedIdentityInspection.cs") + ": TokenElevation",
                matches);
            Assert.Contains(
                Path.Combine("src", "CodeSigner.Windows", "InjectedIdentityInspection.cs") + ": GetTokenInformation",
                matches);
        }
        finally
        {
            if (Directory.Exists(repositoryRoot))
            {
                Directory.Delete(repositoryRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void LaunchPolicyAllowsExactUserAndSessionAndRejectsExactMismatches()
    {
        WorkerProcessIdentity expected = new("S-1-5-21-1", 7);
        WorkerProcessLaunchPolicy.Validate(expected, expected);

        WorkerProcessSecurityException userMismatch = Assert.Throws<WorkerProcessSecurityException>(() =>
            WorkerProcessLaunchPolicy.Validate(
                expected,
                expected with { UserSid = "S-1-5-21-2" }));
        WorkerProcessSecurityException sessionMismatch = Assert.Throws<WorkerProcessSecurityException>(() =>
            WorkerProcessLaunchPolicy.Validate(
                expected,
                expected with { SessionId = 8 }));

        Assert.Equal("user_mismatch", userMismatch.Code);
        Assert.Equal("session_mismatch", sessionMismatch.Code);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void MisleadingSuccessOutputOrExitCodeIsRejected()
    {
        WorkerResponse success = new(WorkerProtocol.Version, true, WorkerResponseCodes.Ready);
        WorkerResponse failure = new(
            WorkerProtocol.Version,
            false,
            WorkerResponseCodes.UnsupportedCommand);

        WorkerProcessClient.ValidateOutcome(success, 0);
        WorkerProcessClient.ValidateOutcome(failure, 2);
        Assert.Throws<WorkerProtocolException>(() => WorkerProcessClient.ValidateOutcome(success, 2));
        Assert.Throws<WorkerProtocolException>(() => WorkerProcessClient.ValidateOutcome(failure, 0));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RealWorkerLaunchReturnsTypedResponseAndCleanExit()
    {
        WorkerProcessClient client = new(WorkerPath());
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Probe,
            Path.Combine(Path.GetTempPath(), "worker-probe", "fixture.exe"));

        WorkerProcessResult result = await client.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.True(result.Response.Success);
        Assert.Equal(WorkerResponseCodes.Ready, result.Response.Code);
        Assert.Equal(0, result.ExitCode);
        Assert.False(IsProcessRunning(result.ProcessId));
    }

    [Fact]
    public async Task HungWorkerTestHostJobTerminationKillsExactParentAndChildTree()
    {
        ProcessStartInfo startInfo = new("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add("$null=[Console]::ReadLine(); $child=Start-Process ping.exe -ArgumentList @('127.0.0.1','-n','30') -PassThru -WindowStyle Hidden; [Console]::Out.WriteLine($child.Id); [Console]::Out.Flush(); Wait-Process -Id $child.Id");

        using Process parent = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start hung process host.");
        using WorkerJob job = WorkerJob.CreateKillOnClose();
        job.Assign(parent);
        await parent.StandardInput.WriteLineAsync(string.Empty);
        await parent.StandardInput.FlushAsync();
        string? childLine = await parent.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
        int childId = int.Parse(childLine!, System.Globalization.CultureInfo.InvariantCulture);

        job.Terminate(WorkerJob.TimeoutExitCode);
        await parent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(IsProcessRunning(parent.Id));
        Assert.False(IsProcessRunning(childId));
    }

    private static string WorkerPath() => Path.Combine(
        FindRepositoryRoot(),
        "src",
        "CodeSigner.Worker",
        "bin",
#if DEBUG
        "Debug",
#else
        "Release",
#endif
        "net10.0-windows",
        "win-x64",
        "CodeSigner.Worker.exe");

    private static string[] FindForbiddenIdentityInspection(string repositoryRoot)
    {
        string sourceRoot = Path.Combine(repositoryRoot, "src");
        string[] forbiddenIdentifiers =
        [
            "IsElevated",
            "TokenElevation",
            "GetTokenInformation",
            "LauncherElevated",
            "WorkerElevated",
            "launcher_elevated",
            "worker_elevated"
        ];

        return Directory
            .EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories)
            .SelectMany(path => forbiddenIdentifiers
                .Where(identifier => File.ReadAllText(path).Contains(identifier, StringComparison.Ordinal))
                .Select(identifier => $"{Path.GetRelativePath(repositoryRoot, path)}: {identifier}"))
            .ToArray();
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
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
