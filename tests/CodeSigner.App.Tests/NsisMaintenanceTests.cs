using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using CodeSigner.App.Services;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.App.Tests;

public sealed class NsisMaintenanceTests
{
    private static readonly string[] RepairArguments = ["/S", "/REPAIR"];
    [Fact]
    public void MaintenanceUsesFixedAbsoluteExecutablesAndSeparateArguments()
    {
        const string root = @"C:\Program Files\AnxinCodeSigner";
        ProcessStartInfo repair = NsisMaintenance.CreateStartInfo(root, true);
        Assert.Equal(Path.Combine(root, "Maintenance\\Setup.exe"), repair.FileName);
        Assert.Equal(RepairArguments, repair.ArgumentList);
        Assert.Equal("runas", repair.Verb);
        Assert.True(repair.UseShellExecute);
        ProcessStartInfo uninstall = NsisMaintenance.CreateStartInfo(root, false);
        Assert.Equal(Path.Combine(root, "Uninstall.exe"), uninstall.FileName);
        Assert.Empty(uninstall.ArgumentList);
        Assert.Throws<ArgumentException>(() => NsisMaintenance.CreateStartInfo("relative", true));
    }

    [Theory]
    [InlineData(0, WorkerRepairOutcome.Succeeded)]
    [InlineData(10, WorkerRepairOutcome.InstallerBusy)]
    [InlineData(20, WorkerRepairOutcome.SourceUnavailable)]
    [InlineData(30, WorkerRepairOutcome.MalformedProduct)]
    [InlineData(999, WorkerRepairOutcome.Fatal)]
    public async Task RepairMapsInstallerResultsWithoutCallingSigning(int code, WorkerRepairOutcome expected)
    {
        using var runner = new NsisMaintenance(() => @"C:\Program Files\AnxinCodeSigner", start =>
        {
            Assert.Equal(RepairArguments, start.ArgumentList);
            return Task.FromResult(code);
        });
        WorkerRepairResult result = await runner.RepairAsync(CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        Assert.True(result.Started);
        Assert.Equal(code, result.ExitCode);
    }

    [Fact]
    public async Task RepairRejectsCancellationMissingSourceAndDeclinedElevation()
    {
        using var cancelled = new NsisMaintenance(() => throw new InvalidOperationException(), _ => throw new InvalidOperationException());
        WorkerRepairResult cancel = await cancelled.RepairAsync(new CancellationToken(true));
        Assert.Equal(WorkerRepairOutcome.ConfirmationDeclined, cancel.Outcome);
        using var missing = new NsisMaintenance(() => @"C:\Program Files\AnxinCodeSigner", _ => throw new FileNotFoundException());
        Assert.Equal(WorkerRepairOutcome.SourceUnavailable, (await missing.RepairAsync(CancellationToken.None)).Outcome);
        using var denied = new NsisMaintenance(() => @"C:\Program Files\AnxinCodeSigner", _ => throw new Win32Exception(1223));
        Assert.Equal(WorkerRepairOutcome.UacCancelled, (await denied.RepairAsync(CancellationToken.None)).Outcome);
    }

    [Fact]
    public async Task ParallelRepairsAreRejectedAndGateIsReleased()
    {
        var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var runner = new NsisMaintenance(() => @"C:\Program Files\AnxinCodeSigner", _ => completion.Task);
        Task<WorkerRepairResult> first = runner.RepairAsync(CancellationToken.None);
        Assert.Equal(WorkerRepairOutcome.Busy, (await runner.RepairAsync(CancellationToken.None)).Outcome);
        completion.SetResult(0);
        Assert.True((await first).Succeeded);
        Assert.True((await runner.RepairAsync(CancellationToken.None)).Succeeded);
    }

    [Fact]
    public void RegistrationCannotRedirectMaintenanceToAnotherDirectoryOrVersion()
    {
        const string root = @"C:\Program Files\AnxinCodeSigner";
        Assert.True(NsisMaintenance.RegistrationMatches(NsisMaintenance.ProductName, NsisMaintenance.Publisher,
            NsisMaintenance.CurrentVersion, root, root + "\\", root));
        Assert.False(NsisMaintenance.RegistrationMatches(NsisMaintenance.ProductName, NsisMaintenance.Publisher,
            "1.0.40", root, root, root));
        Assert.False(NsisMaintenance.RegistrationMatches(NsisMaintenance.ProductName, NsisMaintenance.Publisher,
            NsisMaintenance.CurrentVersion, @"C:\Temp", root, root));
        Assert.False(NsisMaintenance.RegistrationMatches("Other product", NsisMaintenance.Publisher,
            NsisMaintenance.CurrentVersion, root, root, root));
        Assert.False(NsisMaintenance.RegistrationMatches(NsisMaintenance.ProductName, NsisMaintenance.Publisher,
            NsisMaintenance.CurrentVersion, root, @"C:\Temp", root));
    }
}
