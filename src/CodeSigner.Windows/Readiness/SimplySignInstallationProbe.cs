using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CodeSigner.Windows.Readiness;

internal interface IWindowsInstallerProductSource
{
    IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode);
}

public sealed class SimplySignInstallationProbe
{
    public const string ObservedUpgradeCode = "{541ED859-5757-467F-8331-8A69C410A6AF}";
    public const string ObservedProductName = "proCertum SmartSign SimplySign Desktop";
    public const string ObservedPublisher = "Certum";
    public const string ObservedAuthenticodePublisher = "Asseco Data Systems S.A.";
    public const string ObservedVersion = "9.2.14.61";

    private static readonly Version MinimumObservedVersion = Version.Parse(ObservedVersion);

    private readonly IWindowsInstallerProductSource productSource;

    public SimplySignInstallationProbe()
        : this(new SimplySignProductSource())
    {
    }

    internal SimplySignInstallationProbe(IWindowsInstallerProductSource productSource)
    {
        this.productSource = productSource ?? throw new ArgumentNullException(nameof(productSource));
    }

    public SimplySignInstallation Probe()
    {
        IReadOnlyList<WindowsInstallerProductRegistration> registrations;
        try
        {
            registrations = productSource.FindRelatedProducts(ObservedUpgradeCode);
        }
        catch (Exception exception) when (
            exception is Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            return NotInstalled("WindowsInstallerUnavailable");
        }

        WindowsInstallerProductRegistration? selected = null;
        Version? selectedVersion = null;
        foreach (WindowsInstallerProductRegistration registration in registrations)
        {
            if (!IsVerifiedFamilyRegistration(registration, out Version? version))
            {
                continue;
            }

            bool isBetterVersion = selectedVersion is null || version > selectedVersion;
            bool isDeterministicTieBreak = selected is not null
                && version == selectedVersion
                && string.CompareOrdinal(registration.ProductCode, selected.ProductCode) < 0;
            if (!isBetterVersion && !isDeterministicTieBreak)
            {
                continue;
            }

            selected = registration;
            selectedVersion = version;
        }

        return selected is null
            ? NotInstalled("VerifiedRegistrationNotFound")
            : new(
                SimplySignInstallationStatus.Installed,
                ObservedUpgradeCode,
                selected.ProductCode,
                selected.ProductName,
                selected.Publisher,
                selected.Version);
    }

    private static bool IsVerifiedFamilyRegistration(
        WindowsInstallerProductRegistration registration,
        out Version? version)
    {
        version = null;
        return Guid.TryParseExact(registration.ProductCode, "B", out _)
            && string.Equals(registration.ProductName, ObservedProductName, StringComparison.Ordinal)
            && string.Equals(registration.Publisher, ObservedPublisher, StringComparison.Ordinal)
            && Version.TryParse(registration.Version, out version)
            && version >= MinimumObservedVersion;
    }

    private static SimplySignInstallation NotInstalled(string diagnosticCode) =>
        new(
            SimplySignInstallationStatus.NotInstalled,
            ObservedUpgradeCode,
            null,
            null,
            null,
            null,
            diagnosticCode);
}

internal sealed class WindowsInstallerProductSource : IWindowsInstallerProductSource
{
    private const uint ErrorSuccess = 0;
    private const uint ErrorMoreData = 234;
    private const uint ErrorNoMoreItems = 259;

    private readonly IWindowsInstallerApi windowsInstallerApi;

    public WindowsInstallerProductSource()
        : this(new NativeWindowsInstallerApi())
    {
    }

    internal WindowsInstallerProductSource(IWindowsInstallerApi windowsInstallerApi)
    {
        this.windowsInstallerApi = windowsInstallerApi ?? throw new ArgumentNullException(nameof(windowsInstallerApi));
    }

    public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        List<WindowsInstallerProductRegistration> registrations = [];
        for (uint index = 0; ; index++)
        {
            char[] productCode = new char[39];
            uint result = windowsInstallerApi.EnumRelatedProducts(upgradeCode, 0, index, productCode);
            if (result == ErrorNoMoreItems)
            {
                break;
            }

            if (result != ErrorSuccess)
            {
                throw new Win32Exception((int)result);
            }

            int terminator = Array.IndexOf(productCode, '\0');
            int productCodeLength = terminator >= 0 ? terminator : productCode.Length;
            string productCodeValue = new(productCode, 0, productCodeLength);
            string? productName = ReadProductProperty(productCodeValue, "ProductName");
            string? publisher = ReadProductProperty(productCodeValue, "Publisher");
            string? version = ReadProductProperty(productCodeValue, "VersionString");
            if (productName is not null && publisher is not null && version is not null)
            {
                WindowsInstallerInstallState installState =
                    (WindowsInstallerInstallState)windowsInstallerApi.QueryProductState(productCodeValue);
                registrations.Add(new(productCodeValue, productName, publisher, version, installState));
            }
        }

        return registrations;
    }

    private string? ReadProductProperty(string productCode, string propertyName)
    {
        uint length = 0;
        uint result = windowsInstallerApi.GetProductInfo(productCode, propertyName, null, ref length);
        if (result is not ErrorSuccess and not ErrorMoreData)
        {
            return null;
        }

        char[] value = new char[checked((int)length + 1)];
        length++;
        result = windowsInstallerApi.GetProductInfo(productCode, propertyName, value, ref length);
        return result == ErrorSuccess ? new string(value, 0, checked((int)length)) : null;
    }
}

internal interface IWindowsInstallerApi
{
    uint EnumRelatedProducts(
        string upgradeCode,
        uint reserved,
        uint productIndex,
        char[] productCode);

    uint GetProductInfo(
        string productCode,
        string propertyName,
        char[]? value,
        ref uint valueLength);

    int QueryProductState(string productCode) => (int)WindowsInstallerInstallState.Default;
}

internal sealed class NativeWindowsInstallerApi : IWindowsInstallerApi
{
    public uint EnumRelatedProducts(
        string upgradeCode,
        uint reserved,
        uint productIndex,
        char[] productCode) =>
        MsiEnumRelatedProducts(upgradeCode, reserved, productIndex, productCode);

    public uint GetProductInfo(
        string productCode,
        string propertyName,
        char[]? value,
        ref uint valueLength) =>
        MsiGetProductInfo(productCode, propertyName, value, ref valueLength);

    public int QueryProductState(string productCode) =>
        MsiQueryProductState(productCode);

    [DllImport("msi.dll", EntryPoint = "MsiEnumRelatedProductsW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiEnumRelatedProducts(
        string upgradeCode,
        uint reserved,
        uint productIndex,
        [Out] char[] productCode);

    [DllImport("msi.dll", EntryPoint = "MsiGetProductInfoW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiGetProductInfo(
        string productCode,
        string propertyName,
        [Out] char[]? value,
        ref uint valueLength);

    [DllImport("msi.dll", EntryPoint = "MsiQueryProductStateW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int MsiQueryProductState(string productCode);
}
