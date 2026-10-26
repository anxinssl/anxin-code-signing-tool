using System.ComponentModel;
using System.Diagnostics;

namespace CodeSigner.Windows.Readiness;

public sealed class CodeSignerInstallationProbe
{
    public const string ObservedUpgradeCode = "{C81BF087-67D0-41F3-8581-9E773813118B}";
    public const string ObservedProductName = "安信证书签名工具";
    private const string LegacyProductName = "代码签名工具";
    public const string ObservedPublisher = "CodeSigner";

    private readonly IWindowsInstallerProductSource productSource;

    public CodeSignerInstallationProbe()
        : this(new WindowsInstallerProductSource())
    {
    }

    internal CodeSignerInstallationProbe(IWindowsInstallerProductSource productSource)
    {
        this.productSource = productSource ?? throw new ArgumentNullException(nameof(productSource));
    }

    public CodeSignerInstallation Probe()
    {
        IReadOnlyList<WindowsInstallerProductRegistration> registrations;
        try
        {
            registrations = productSource.FindRelatedProducts(ObservedUpgradeCode);
        }
        catch (Exception exception) when (
            exception is Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            return Failure(CodeSignerInstallationStatus.WindowsInstallerUnavailable, "WindowsInstallerUnavailable");
        }

        List<WindowsInstallerProductRegistration> exactMetadata = [];
        foreach (WindowsInstallerProductRegistration registration in registrations)
        {
            if ((string.Equals(registration.ProductName, ObservedProductName, StringComparison.Ordinal) ||
                 string.Equals(registration.ProductName, LegacyProductName, StringComparison.Ordinal)) &&
                string.Equals(registration.Publisher, ObservedPublisher, StringComparison.Ordinal))
            {
                exactMetadata.Add(registration);
            }
        }

        if (exactMetadata.Count == 0)
        {
            return Failure(CodeSignerInstallationStatus.NotInstalled, "VerifiedRegistrationNotFound");
        }

        if (exactMetadata.Any(static registration => !IsBraceGuid(registration.ProductCode)))
        {
            return Failure(CodeSignerInstallationStatus.Malformed, "MalformedProductCode");
        }

        if (exactMetadata.Any(static registration =>
                registration.InstallState == WindowsInstallerInstallState.Advertised))
        {
            return Failure(CodeSignerInstallationStatus.Advertised, "RegistrationAdvertised");
        }

        List<WindowsInstallerProductRegistration> verified = exactMetadata
            .Where(static registration => registration.InstallState == WindowsInstallerInstallState.Default)
            .ToList();
        if (verified.Count == 0)
        {
            return Failure(CodeSignerInstallationStatus.NotInstalled, "RegistrationNotInstalled");
        }

        if (verified.Count != 1)
        {
            return Failure(CodeSignerInstallationStatus.Ambiguous, "MultipleVerifiedRegistrations");
        }

        WindowsInstallerProductRegistration selected = verified[0];
        return new(
            CodeSignerInstallationStatus.Installed,
            ObservedUpgradeCode,
            selected.ProductCode,
            selected.ProductName,
            selected.Publisher,
            selected.Version);
    }

    private static bool IsBraceGuid(string value) =>
        value.Length == 38 && Guid.TryParseExact(value, "B", out _);

    private static CodeSignerInstallation Failure(
        CodeSignerInstallationStatus status,
        string diagnosticCode) =>
        new(status, ObservedUpgradeCode, null, null, null, null, diagnosticCode);
}

public enum WorkerRepairOutcome
{
    Succeeded,
    SucceededRestartRequired,
    Busy,
    ConfirmationDeclined,
    UacCancelled,
    SourceUnavailable,
    InstallerBusy,
    Fatal,
    UnknownExitCode,
    ProductNotInstalled,
    AmbiguousProduct,
    ProductAdvertised,
    MalformedProduct,
    WindowsInstallerUnavailable
}

public sealed record WorkerRepairResult(
    WorkerRepairOutcome Outcome,
    CodeSignerInstallation Installation,
    string? LogPath,
    int? ExitCode,
    int? NativeErrorCode,
    bool Started)
{
    public bool Succeeded =>
        Outcome is WorkerRepairOutcome.Succeeded or WorkerRepairOutcome.SucceededRestartRequired;

    public bool RestartRequired => Outcome == WorkerRepairOutcome.SucceededRestartRequired;
}

internal interface ISystemMsiExecPathResolver
{
    string Resolve();
}

internal interface IInstallerProcessStarter
{
    IInstallerProcess Start(ProcessStartInfo startInfo);
}

internal interface IInstallerProcess
{
    Task<int> WaitForExitAsync();
}

public sealed class WorkerRepairRunner : IDisposable
{
    private const int ErrorCancelled = 1223;
    private const int ErrorSourceAbsent = 1612;
    private const int ErrorInstallerBusy = 1618;
    private const int ErrorFatal = 1603;
    private const int ErrorSuccessRestartRequired = 1641;
    private const int ErrorSuccessRebootRequired = 3010;

    private readonly CodeSignerInstallationProbe installationProbe;
    private readonly IInstallerProcessStarter processStarter;
    private readonly ISystemMsiExecPathResolver msiExecPathResolver;
    private readonly Func<string> logPathFactory;
    private readonly Func<CancellationToken, ValueTask<bool>> confirmation;
    private readonly SemaphoreSlim repairGate = new(1, 1);

    public WorkerRepairRunner()
        : this(
            new CodeSignerInstallationProbe(),
            new SystemInstallerProcessStarter(),
            new SystemMsiExecPathResolver(),
            CreateLogPath,
            static _ => new ValueTask<bool>(true))
    {
    }

    internal WorkerRepairRunner(
        CodeSignerInstallationProbe installationProbe,
        IInstallerProcessStarter processStarter,
        ISystemMsiExecPathResolver msiExecPathResolver,
        Func<string> logPathFactory,
        Func<CancellationToken, ValueTask<bool>> confirmation)
    {
        this.installationProbe = installationProbe ?? throw new ArgumentNullException(nameof(installationProbe));
        this.processStarter = processStarter ?? throw new ArgumentNullException(nameof(processStarter));
        this.msiExecPathResolver = msiExecPathResolver ?? throw new ArgumentNullException(nameof(msiExecPathResolver));
        this.logPathFactory = logPathFactory ?? throw new ArgumentNullException(nameof(logPathFactory));
        this.confirmation = confirmation ?? throw new ArgumentNullException(nameof(confirmation));
    }

    public Task<WorkerRepairResult> RepairAsync() =>
        RepairAsync(CancellationToken.None);

    public async Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken)
    {
        if (!repairGate.Wait(0, CancellationToken.None))
        {
            return BusyResult();
        }

        try
        {
            CodeSignerInstallation installation = installationProbe.Probe();
            if (!installation.IsInstalled)
            {
                return DiscoveryFailure(installation);
            }

            bool confirmed;
            try
            {
                confirmed = await confirmation(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return new(
                    WorkerRepairOutcome.ConfirmationDeclined,
                    installation,
                    null,
                    null,
                    null,
                    false);
            }

            if (!confirmed)
            {
                return new(
                    WorkerRepairOutcome.ConfirmationDeclined,
                    installation,
                    null,
                    null,
                    null,
                    false);
            }

            string logPath = Path.GetFullPath(logPathFactory());
            ProcessStartInfo startInfo = new()
            {
                FileName = msiExecPathResolver.Resolve(),
                UseShellExecute = true,
                Verb = "runas",
                Arguments = BuildArguments(installation.ProductCode!, logPath)
            };

            IInstallerProcess process;
            try
            {
                process = processStarter.Start(startInfo);
            }
            catch (Win32Exception exception) when (exception.NativeErrorCode == ErrorCancelled)
            {
                return new(
                    WorkerRepairOutcome.UacCancelled,
                    installation,
                    logPath,
                    null,
                    exception.NativeErrorCode,
                    false);
            }
            catch (Win32Exception exception) when (exception.NativeErrorCode == ErrorInstallerBusy)
            {
                return new(
                    WorkerRepairOutcome.InstallerBusy,
                    installation,
                    logPath,
                    null,
                    exception.NativeErrorCode,
                    false);
            }
            catch (Win32Exception exception)
            {
                return new(
                    WorkerRepairOutcome.UnknownExitCode,
                    installation,
                    logPath,
                    null,
                    exception.NativeErrorCode,
                    false);
            }
            catch (Exception)
            {
                return new(
                    WorkerRepairOutcome.UnknownExitCode,
                    installation,
                    logPath,
                    null,
                    null,
                    false);
            }

            try
            {
                int exitCode = await process.WaitForExitAsync().ConfigureAwait(false);
                return MapExitCode(installation, logPath, exitCode);
            }
            catch (Win32Exception exception)
            {
                return new(
                    WorkerRepairOutcome.UnknownExitCode,
                    installation,
                    logPath,
                    null,
                    exception.NativeErrorCode,
                    true);
            }
            catch (Exception)
            {
                return new(
                    WorkerRepairOutcome.UnknownExitCode,
                    installation,
                    logPath,
                    null,
                    null,
                    true);
            }
        }
        finally
        {
            repairGate.Release();
        }
    }

    private static string BuildArguments(string productCode, string logPath)
    {
        if (logPath.Contains('"') ||
            logPath.Contains('\r') ||
            logPath.Contains('\n'))
        {
            throw new ArgumentException("The repair log path contains unsupported characters.", nameof(logPath));
        }

        return $"/i {productCode} REINSTALL=WorkerFeature REINSTALLMODE=amus /qn /norestart /L*V \"{logPath}\"";
    }

    private static WorkerRepairResult MapExitCode(
        CodeSignerInstallation installation,
        string logPath,
        int exitCode) =>
        exitCode switch
        {
            0 => new(WorkerRepairOutcome.Succeeded, installation, logPath, exitCode, null, true),
            ErrorSuccessRestartRequired or ErrorSuccessRebootRequired =>
                new(WorkerRepairOutcome.SucceededRestartRequired, installation, logPath, exitCode, null, true),
            ErrorSourceAbsent => new(WorkerRepairOutcome.SourceUnavailable, installation, logPath, exitCode, null, true),
            ErrorInstallerBusy => new(WorkerRepairOutcome.InstallerBusy, installation, logPath, exitCode, null, true),
            ErrorFatal => new(WorkerRepairOutcome.Fatal, installation, logPath, exitCode, null, true),
            _ => new(WorkerRepairOutcome.UnknownExitCode, installation, logPath, exitCode, null, true)
        };

    private static WorkerRepairResult DiscoveryFailure(CodeSignerInstallation installation) =>
        new(
            installation.Status switch
            {
                CodeSignerInstallationStatus.Ambiguous => WorkerRepairOutcome.AmbiguousProduct,
                CodeSignerInstallationStatus.Advertised => WorkerRepairOutcome.ProductAdvertised,
                CodeSignerInstallationStatus.Malformed => WorkerRepairOutcome.MalformedProduct,
                CodeSignerInstallationStatus.WindowsInstallerUnavailable => WorkerRepairOutcome.WindowsInstallerUnavailable,
                _ => WorkerRepairOutcome.ProductNotInstalled
            },
            installation,
            null,
            null,
            null,
            false);

    private static WorkerRepairResult BusyResult() =>
        new(
            WorkerRepairOutcome.Busy,
            new(
                CodeSignerInstallationStatus.NotInstalled,
                CodeSignerInstallationProbe.ObservedUpgradeCode,
                null,
                null,
                null,
                null,
                "RepairBusy"),
            null,
            null,
            null,
            false);

    private static string CreateLogPath()
    {
        string directory = Path.Combine(Path.GetTempPath(), "CodeSigner");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $"WorkerRepair-{Guid.NewGuid():N}.log");
    }

    public void Dispose() =>
        repairGate.Dispose();

    private sealed class SystemMsiExecPathResolver : ISystemMsiExecPathResolver
    {
        public string Resolve()
        {
            string systemDirectory = Environment.SystemDirectory;
            return Path.Combine(systemDirectory, "msiexec.exe");
        }
    }

    private sealed class SystemInstallerProcessStarter : IInstallerProcessStarter
    {
        public IInstallerProcess Start(ProcessStartInfo startInfo) =>
            new SystemInstallerProcess(Process.Start(startInfo)
                ?? throw new InvalidOperationException("Windows Installer process could not be started."));
    }

    private sealed class SystemInstallerProcess(Process process) : IInstallerProcess
    {
        public async Task<int> WaitForExitAsync()
        {
            using (process)
            {
                await process.WaitForExitAsync().ConfigureAwait(false);
                return process.ExitCode;
            }
        }
    }
}
