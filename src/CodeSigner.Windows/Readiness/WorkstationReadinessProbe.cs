using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;

namespace CodeSigner.Windows.Readiness;

internal interface IWorkstationEnvironment
{
    bool IsWindows { get; }
    Version OperatingSystemVersion { get; }
    Architecture Architecture { get; }
    string? ProductType { get; }
}

public sealed class WorkstationReadinessProbe
{
    private readonly IWorkstationEnvironment environment;

    public WorkstationReadinessProbe()
        : this(new SystemWorkstationEnvironment())
    {
    }

    internal WorkstationReadinessProbe(IWorkstationEnvironment environment)
    {
        this.environment = environment ?? throw new ArgumentNullException(nameof(environment));
    }

    public WorkstationReadiness Probe()
    {
        if (!environment.IsWindows || environment.OperatingSystemVersion.Major != 10)
        {
            return new(WorkstationSupportStatus.Unsupported, "RequiresWindows10Or11Nt10");
        }

        if (environment.Architecture != Architecture.X64)
        {
            return new(WorkstationSupportStatus.Unsupported, "RequiresX64");
        }

        return string.Equals(environment.ProductType, "WinNT", StringComparison.Ordinal)
            ? new(WorkstationSupportStatus.Supported, "SupportedWindowsWorkstationX64")
            : new(WorkstationSupportStatus.Unsupported, "RequiresWorkstation");
    }
}

internal sealed class SystemWorkstationEnvironment : IWorkstationEnvironment
{
    private const string ProductOptionsKey = @"SYSTEM\CurrentControlSet\Control\ProductOptions";

    public bool IsWindows => OperatingSystem.IsWindows();

    public Version OperatingSystemVersion => Environment.OSVersion.Version;

    public Architecture Architecture => RuntimeInformation.OSArchitecture;

    public string? ProductType
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return null;
            }

            try
            {
                using RegistryKey localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using RegistryKey? productOptions = localMachine.OpenSubKey(ProductOptionsKey, writable: false);
                return productOptions?.GetValue("ProductType", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException)
            {
                return null;
            }
        }
    }
}
