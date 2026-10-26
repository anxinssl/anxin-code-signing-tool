using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using CodeSigner.Windows.Readiness;
using Microsoft.Win32;

namespace CodeSigner.App.Services;

// Installation maintenance only; no certificate discovery or signing operations.
internal sealed class NsisMaintenance : IDisposable
{
    internal const string RegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AnxinCodeSigner";
    internal const string ProductName = "安信代码签名证书工具";
    internal const string Publisher = "安徽斯百德信息技术有限公司";
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Func<string> resolveDirectory;
    private readonly Func<ProcessStartInfo, Task<int>> run;

    public NsisMaintenance() : this(ResolveInstalledDirectory, RunAsync) { }

    internal NsisMaintenance(Func<string> resolveDirectory, Func<ProcessStartInfo, Task<int>> run)
    {
        this.resolveDirectory = resolveDirectory;
        this.run = run;
    }

    internal static string CurrentVersion =>
        typeof(NsisMaintenance).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;

    internal static string ExpectedDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AnxinCodeSigner");

    internal static bool RegistrationMatches(
        string? name, string? publisher, string? version, string? location,
        string applicationDirectory, string expectedDirectory) =>
        name == ProductName && publisher == Publisher && version == CurrentVersion &&
        string.Equals(location, expectedDirectory, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(Path.TrimEndingDirectorySeparator(applicationDirectory),
            expectedDirectory, StringComparison.OrdinalIgnoreCase);

    private static string ResolveInstalledDirectory()
    {
        using RegistryKey root = Microsoft.Win32.RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using RegistryKey? registration = root.OpenSubKey(RegistryPath);
        string expected = ExpectedDirectory;
        if (registration is null || !RegistrationMatches(
                registration.GetValue("DisplayName") as string,
                registration.GetValue("Publisher") as string,
                registration.GetValue("DisplayVersion") as string,
                registration.GetValue("InstallLocation") as string,
                AppContext.BaseDirectory, expected))
        {
            throw new InvalidOperationException("未找到与当前程序匹配的安装记录，请使用本版本 EXE 安装包重新安装。");
        }
        for (DirectoryInfo? directory = new(expected); directory is not null; directory = directory.Parent)
        {
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("安装目录不能是链接或重定向目录，请重新安装。");
        }
        return expected;
    }

    internal static ProcessStartInfo CreateStartInfo(string directory, bool repair)
    {
        if (!Path.IsPathFullyQualified(directory))
            throw new ArgumentException("An absolute installation path is required.", nameof(directory));
        string executable = Path.Combine(directory, repair ? "Maintenance\\Setup.exe" : "Uninstall.exe");
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
        if (repair)
        {
            start.ArgumentList.Add("/S");
            start.ArgumentList.Add("/REPAIR");
        }
        return start;
    }

    internal static ProcessStartInfo CreateUninstallStartInfo()
    {
        ProcessStartInfo start = CreateStartInfo(ResolveInstalledDirectory(), repair: false);
        EnsureExecutable(start.FileName);
        return start;
    }

    private static void EnsureExecutable(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (file.Directory!.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new FileNotFoundException("安装维护文件缺失或无效，请使用本版本 EXE 安装包重新安装。", path);
    }

    public async Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken)
    {
        CodeSignerInstallation installation = new(CodeSignerInstallationStatus.Installed,
            CodeSignerInstallationProbe.ObservedUpgradeCode, null, ProductName, Publisher, CurrentVersion);
        if (!gate.Wait(0, CancellationToken.None))
            return new(WorkerRepairOutcome.Busy, installation, null, null, null, false);
        bool started = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProcessStartInfo start = CreateStartInfo(resolveDirectory(), repair: true);
            started = true;
            int code = await run(start).ConfigureAwait(false);
            return new(MapExitCode(code), installation, null, code, null, true);
        }
        catch (OperationCanceledException)
        {
            return new(WorkerRepairOutcome.ConfirmationDeclined, installation, null, null, null, false);
        }
        catch (Win32Exception exception)
        {
            return new(exception.NativeErrorCode == 1223 ? WorkerRepairOutcome.UacCancelled : WorkerRepairOutcome.UnknownExitCode,
                installation, null, null, exception.NativeErrorCode, false);
        }
        catch (FileNotFoundException)
        {
            return new(WorkerRepairOutcome.SourceUnavailable, installation, null, null, null, false);
        }
        catch (InvalidOperationException)
        {
            return new(WorkerRepairOutcome.ProductNotInstalled, installation, null, null, null, false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or TimeoutException)
        {
            return new(WorkerRepairOutcome.Fatal, installation, null, null, null, started);
        }
        finally
        {
            gate.Release();
        }
    }

    internal static WorkerRepairOutcome MapExitCode(int code) => code switch
    {
        0 => WorkerRepairOutcome.Succeeded,
        10 => WorkerRepairOutcome.InstallerBusy,
        20 => WorkerRepairOutcome.SourceUnavailable,
        30 => WorkerRepairOutcome.MalformedProduct,
        _ => WorkerRepairOutcome.Fatal
    };

    private static async Task<int> RunAsync(ProcessStartInfo start)
    {
        EnsureExecutable(start.FileName);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("安装维护程序未启动。");
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(3)).ConfigureAwait(false);
        return process.ExitCode;
    }

    public void Dispose() => gate.Dispose();
}
