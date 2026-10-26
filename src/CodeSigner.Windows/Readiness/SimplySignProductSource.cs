using System.ComponentModel;
using System.Security;
using System.Security.Cryptography;
using CodeSigner.Windows.Files;
using Microsoft.Win32;

namespace CodeSigner.Windows.Readiness;

internal sealed record SimplySignExeRegistration(
    string ProductCode,
    string? ProductName,
    string? Publisher,
    string? Version,
    string? InstallLocation);

internal sealed class SimplySignProductSource : IWindowsInstallerProductSource
{
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private readonly IWindowsInstallerProductSource msiSource;
    private readonly Func<RegistryHive, RegistryView, IReadOnlyList<SimplySignExeRegistration>> registrySource;
    private readonly ISdkSignToolExecutableInspector executableInspector;

    public SimplySignProductSource()
        : this(new WindowsInstallerProductSource(), ReadRegistrations, new WindowsSdkSignToolExecutableInspector())
    {
    }

    internal SimplySignProductSource(
        IWindowsInstallerProductSource msiSource,
        Func<RegistryHive, RegistryView, IReadOnlyList<SimplySignExeRegistration>> registrySource,
        ISdkSignToolExecutableInspector executableInspector)
    {
        this.msiSource = msiSource;
        this.registrySource = registrySource;
        this.executableInspector = executableInspector;
    }

    public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode)
    {
        List<WindowsInstallerProductRegistration> products = [];
        Exception? msiFailure = null;
        try
        {
            products.AddRange(msiSource.FindRelatedProducts(upgradeCode));
        }
        catch (Exception exception) when (
            exception is Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            msiFailure = exception;
        }

        // EXE installers need not register a Windows Installer UpgradeCode.
        // Restrict this fallback to SimplySign; Worker repair keeps its MSI-only source.
        if (string.Equals(upgradeCode, SimplySignInstallationProbe.ObservedUpgradeCode, StringComparison.Ordinal))
        {
            foreach (RegistryHive hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                {
                    IReadOnlyList<SimplySignExeRegistration> registrations;
                    try
                    {
                        registrations = registrySource(hive, view);
                    }
                    catch (Exception exception) when (IsUnavailable(exception))
                    {
                        continue;
                    }

                    foreach (SimplySignExeRegistration registration in registrations)
                    {
                        if (IsVerifiedExeRegistration(registration))
                        {
                            products.Add(new(
                                registration.ProductCode,
                                registration.ProductName!,
                                registration.Publisher!,
                                registration.Version!));
                        }
                    }
                }
            }
        }

        if (products.Count == 0 && msiFailure is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(msiFailure).Throw();
        }

        return products;
    }

    private bool IsVerifiedExeRegistration(SimplySignExeRegistration registration)
    {
        if (!Guid.TryParseExact(registration.ProductCode, "B", out _) ||
            !string.Equals(registration.ProductName, SimplySignInstallationProbe.ObservedProductName, StringComparison.Ordinal) ||
            !string.Equals(registration.Publisher, SimplySignInstallationProbe.ObservedPublisher, StringComparison.Ordinal) ||
            !Version.TryParse(registration.Version, out Version? version) ||
            version < Version.Parse(SimplySignInstallationProbe.ObservedVersion) ||
            string.IsNullOrWhiteSpace(registration.InstallLocation))
        {
            return false;
        }

        try
        {
            string location = registration.InstallLocation;
            // Do not contact network shares or resolve relative paths during readiness checks.
            if (!Path.IsPathFullyQualified(location) ||
                location.Length < 3 || !char.IsAsciiLetter(location[0]) ||
                location[1] != ':' || location[2] != Path.DirectorySeparatorChar)
            {
                return false;
            }

            string executable = Path.Combine(Path.GetFullPath(location), "SimplySignDesktop.exe");
            PathSafety.EnsureNoReparsePoints(executable);
            if (!File.Exists(executable))
            {
                return false;
            }

            SdkSignToolExecutableInspection inspection = executableInspector.Inspect(executable);
            return inspection.WindowsTrustValid &&
                string.Equals(inspection.Publisher, SimplySignInstallationProbe.ObservedAuthenticodePublisher, StringComparison.Ordinal) &&
                string.Equals(inspection.CompanyName, SimplySignInstallationProbe.ObservedAuthenticodePublisher, StringComparison.Ordinal) &&
                string.Equals(inspection.ProductName, "SimplySign", StringComparison.Ordinal) &&
                string.Equals(inspection.OriginalFileName, "SimplySignDesktop.exe", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(inspection.FileDescription, "SimplySign Desktop", StringComparison.Ordinal);
        }
        catch (Exception exception) when (
            IsUnavailable(exception) || exception is ArgumentException or NotSupportedException or
                CryptographicException or Win32Exception or IntakeValidationException)
        {
            return false;
        }
    }

    private static IReadOnlyList<SimplySignExeRegistration> ReadRegistrations(RegistryHive hive, RegistryView view)
    {
        List<SimplySignExeRegistration> registrations = [];
        using RegistryKey root = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey? uninstall = root.OpenSubKey(UninstallKey, writable: false);
        if (uninstall is null)
        {
            return registrations;
        }

        foreach (string keyName in uninstall.GetSubKeyNames())
        {
            try
            {
                using RegistryKey? product = uninstall.OpenSubKey(keyName, writable: false);
                if (product?.GetValue("DisplayName") is not string name ||
                    !string.Equals(name, SimplySignInstallationProbe.ObservedProductName, StringComparison.Ordinal))
                {
                    continue;
                }

                registrations.Add(new(
                    keyName,
                    name,
                    product.GetValue("Publisher") as string,
                    product.GetValue("DisplayVersion") as string,
                    product.GetValue("InstallLocation") as string));
            }
            catch (Exception exception) when (IsUnavailable(exception))
            {
                // A removed or inaccessible entry must not hide another valid installation.
            }
        }

        return registrations;
    }

    private static bool IsUnavailable(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or SecurityException;
}
