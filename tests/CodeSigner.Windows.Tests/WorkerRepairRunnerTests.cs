using System.ComponentModel;
using System.Diagnostics;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.Windows.Tests;

public sealed class WorkerRepairRunnerTests
{
    [Fact]
    public async Task StartsOnlySystemMsiexecWithRunasAndFixedWorkerFeatureArguments()
    {
        RecordingStarter starter = new(new FakeInstallerProcess(0));
        WorkerRepairRunner runner = CreateRunner(starter);

        WorkerRepairResult result = await runner.RepairAsync(CancellationToken.None);

        Assert.Equal(WorkerRepairOutcome.Succeeded, result.Outcome);
        Assert.Equal(0, result.ExitCode);
        Assert.True(result.Started);
        Assert.NotNull(result.LogPath);
        ProcessStartInfo startInfo = Assert.IsType<ProcessStartInfo>(starter.StartInfo);
        Assert.Equal("C:\\Windows\\System32\\msiexec.exe", startInfo.FileName);
        Assert.True(startInfo.UseShellExecute);
        Assert.Equal("runas", startInfo.Verb);
        Assert.Equal(
            "/i {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA} REINSTALL=WorkerFeature REINSTALLMODE=amus /qn /norestart /L*V \"C:\\repair logs\\worker repair.log\"",
            startInfo.Arguments);
    }

    [Fact]
    public async Task ConfirmationDeclineDoesNotStartInstaller()
    {
        RecordingStarter starter = new(new FakeInstallerProcess(0));
        WorkerRepairRunner runner = CreateRunner(starter, static _ => new ValueTask<bool>(false));

        WorkerRepairResult result = await runner.RepairAsync(CancellationToken.None);

        Assert.Equal(WorkerRepairOutcome.ConfirmationDeclined, result.Outcome);
        Assert.False(result.Started);
        Assert.Null(starter.StartInfo);
    }

    [Theory]
    [InlineData(1641, WorkerRepairOutcome.SucceededRestartRequired)]
    [InlineData(3010, WorkerRepairOutcome.SucceededRestartRequired)]
    [InlineData(1612, WorkerRepairOutcome.SourceUnavailable)]
    [InlineData(1618, WorkerRepairOutcome.InstallerBusy)]
    [InlineData(1603, WorkerRepairOutcome.Fatal)]
    [InlineData(777, WorkerRepairOutcome.UnknownExitCode)]
    public async Task MapsInstallerExitCodes(int exitCode, WorkerRepairOutcome expected)
    {
        WorkerRepairRunner runner = CreateRunner(new RecordingStarter(new FakeInstallerProcess(exitCode)));

        WorkerRepairResult result = await runner.RepairAsync(CancellationToken.None);

        Assert.Equal(expected, result.Outcome);
        Assert.Equal(exitCode, result.ExitCode);
        Assert.True(result.Started);
    }

    [Fact]
    public async Task MapsUacCancellationWithoutStartingASecondProcess()
    {
        RecordingStarter starter = new(new FakeInstallerProcess(0)) { StartException = new Win32Exception(1223) };
        WorkerRepairRunner runner = CreateRunner(starter);

        WorkerRepairResult result = await runner.RepairAsync(CancellationToken.None);

        Assert.Equal(WorkerRepairOutcome.UacCancelled, result.Outcome);
        Assert.Equal(1223, result.NativeErrorCode);
        Assert.False(result.Started);
    }

    [Fact]
    public async Task ConcurrentRepairsAreSerializedAndSecondCallIsBusy()
    {
        TaskCompletionSource<bool> release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        RecordingStarter starter = new(new BlockingInstallerProcess(release.Task));
        WorkerRepairRunner runner = CreateRunner(starter);

        Task<WorkerRepairResult> first = runner.RepairAsync(CancellationToken.None);
        await starter.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        WorkerRepairResult secondResult = await runner.RepairAsync(CancellationToken.None);
        release.SetResult(true);
        WorkerRepairResult firstResult = await first;

        Assert.Equal(WorkerRepairOutcome.Busy, secondResult.Outcome);
        Assert.Equal(WorkerRepairOutcome.Succeeded, firstResult.Outcome);
        Assert.Equal(1, starter.StartCalls);
    }

    [Fact]
    public async Task PreservesChineseAndSpaceLogPathInFixedVerboseArgument()
    {
        RecordingStarter starter = new(new FakeInstallerProcess(0));
        const string logPath = "C:\\修复 日志\\Worker Repair.log";
        WorkerRepairRunner runner = CreateRunner(starter, logPath: logPath);

        WorkerRepairResult result = await runner.RepairAsync();

        Assert.Equal(WorkerRepairOutcome.Succeeded, result.Outcome);
        Assert.Equal(logPath, result.LogPath);
        Assert.Equal(
            "/i {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA} REINSTALL=WorkerFeature REINSTALLMODE=amus /qn /norestart /L*V \"" + logPath + "\"",
            starter.StartInfo!.Arguments);
    }

    [Theory]
    [InlineData(CodeSignerInstallationStatus.NotInstalled, WorkerRepairOutcome.ProductNotInstalled)]
    [InlineData(CodeSignerInstallationStatus.Ambiguous, WorkerRepairOutcome.AmbiguousProduct)]
    [InlineData(CodeSignerInstallationStatus.Advertised, WorkerRepairOutcome.ProductAdvertised)]
    [InlineData(CodeSignerInstallationStatus.Malformed, WorkerRepairOutcome.MalformedProduct)]
    [InlineData(CodeSignerInstallationStatus.WindowsInstallerUnavailable, WorkerRepairOutcome.WindowsInstallerUnavailable)]
    public async Task MapsEveryDiscoveryFailureOutcome(
        CodeSignerInstallationStatus status,
        WorkerRepairOutcome expected)
    {
        RecordingStarter starter = new(new FakeInstallerProcess(0));
        WorkerRepairRunner runner = CreateRunner(
            starter,
            source: DiscoverySourceFor(status));

        WorkerRepairResult result = await runner.RepairAsync();

        Assert.Equal(expected, result.Outcome);
        Assert.False(result.Started);
        Assert.Equal(status, result.Installation.Status);
        Assert.Null(starter.StartInfo);
    }

    private static IWindowsInstallerProductSource DiscoverySourceFor(CodeSignerInstallationStatus status) =>
        status switch
        {
            CodeSignerInstallationStatus.NotInstalled => new FakeProductSource(),
            CodeSignerInstallationStatus.Ambiguous => new FakeProductSource(
                Registration("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"),
                Registration("{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}")),
            CodeSignerInstallationStatus.Advertised => new FakeProductSource(
                Registration("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", WindowsInstallerInstallState.Advertised)),
            CodeSignerInstallationStatus.Malformed => new FakeProductSource(Registration("not-a-guid")),
            CodeSignerInstallationStatus.WindowsInstallerUnavailable => new ThrowingProductSource(),
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, null)
        };

    private static WindowsInstallerProductRegistration Registration(
        string productCode,
        WindowsInstallerInstallState state = WindowsInstallerInstallState.Default) =>
        new(
            productCode,
            CodeSignerInstallationProbe.ObservedProductName,
            CodeSignerInstallationProbe.ObservedPublisher,
            "1.0.0",
            state);

    private static WorkerRepairRunner CreateRunner(
        RecordingStarter starter,
        Func<CancellationToken, ValueTask<bool>>? confirmation = null,
        string logPath = "C:\\repair logs\\worker repair.log",
        IWindowsInstallerProductSource? source = null)
    {
        CodeSignerInstallationProbe probe = new(source ?? new FakeProductSource(
            new WindowsInstallerProductRegistration(
                "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                CodeSignerInstallationProbe.ObservedProductName,
                CodeSignerInstallationProbe.ObservedPublisher,
                "1.0.0",
                WindowsInstallerInstallState.Default)));
        return new WorkerRepairRunner(
            probe,
            starter,
            new FakeMsiExecPathResolver(),
            () => logPath,
            confirmation ?? (static _ => new ValueTask<bool>(true)));
    }

    private sealed class FakeProductSource(params WindowsInstallerProductRegistration[] registrations)
        : IWindowsInstallerProductSource
    {
        public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode) => registrations;
    }

    private sealed class ThrowingProductSource : IWindowsInstallerProductSource
    {
        public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode) =>
            throw new Win32Exception(1717);
    }

    private sealed class FakeMsiExecPathResolver : ISystemMsiExecPathResolver
    {
        public string Resolve() => "C:\\Windows\\System32\\msiexec.exe";
    }

    private sealed class RecordingStarter(IInstallerProcess process) : IInstallerProcessStarter
    {
        public ProcessStartInfo? StartInfo { get; private set; }
        public int StartCalls { get; private set; }
        public Exception? StartException { get; init; }
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IInstallerProcess Start(ProcessStartInfo startInfo)
        {
            StartCalls++;
            StartInfo = startInfo;
            Started.TrySetResult(true);
            if (StartException is not null)
            {
                throw StartException;
            }

            return process;
        }
    }

    private sealed class FakeInstallerProcess(int exitCode) : IInstallerProcess
    {
        public Task<int> WaitForExitAsync() => Task.FromResult(exitCode);
    }

    private sealed class BlockingInstallerProcess(Task release) : IInstallerProcess
    {
        public async Task<int> WaitForExitAsync()
        {
            await release.ConfigureAwait(false);
            return 0;
        }
    }
}
