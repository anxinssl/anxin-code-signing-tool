using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class ReadinessProbeTests
{
    [Fact]
    [Trait("Category", "ReadinessRealSurface")]
    public void RealProbeReportsOnlyPublicReadinessMetadata()
    {
        ReadinessSnapshot result = new ReadinessProbe().Probe(new Uri("http://time.certum.pl", UriKind.Absolute));

        Assert.Equal(WorkstationSupportStatus.Supported, result.Workstation.Status);
        Assert.Equal(NativeApiAvailability.Available, result.NativeApi);
        Assert.Equal(ProviderAuthorizationStatus.AuthorizationUnknown, result.Authorization);
        Assert.Equal(TimestampConfigurationStatus.Configured, result.Timestamp.Status);
        Assert.All(result.CertificateCatalog.Certificates, certificate =>
        {
            Assert.True(certificate.StoreLocation is StoreLocation.CurrentUser or StoreLocation.LocalMachine);
            Assert.Equal(StoreName.My.ToString(), certificate.StoreName);
            Assert.Equal(40, certificate.Thumbprint.Length);
            Assert.True(certificate.HasPrivateKey);
            Assert.Contains(CertificateCatalogProbe.CodeSigningEkuOid, certificate.EnhancedKeyUsageOids);
        });
        Assert.Equal(SimplySignInstallationStatus.Installed, result.SimplySign.Status);
        Assert.Equal(SimplySignInstallationProbe.ObservedUpgradeCode, result.SimplySign.UpgradeCode);
        Assert.Equal(SimplySignInstallationProbe.ObservedProductName, result.SimplySign.ProductName);
        Assert.Equal("Certum", result.SimplySign.Publisher);
    }

    [Theory]
    [InlineData(true, 10, Architecture.X64, "WinNT", WorkstationSupportStatus.Supported)]
    [InlineData(false, 10, Architecture.X64, "WinNT", WorkstationSupportStatus.Unsupported)]
    [InlineData(true, 10, Architecture.Arm64, "WinNT", WorkstationSupportStatus.Unsupported)]
    [InlineData(true, 10, Architecture.X64, "ServerNT", WorkstationSupportStatus.Unsupported)]
    [InlineData(true, 11, Architecture.X64, "WinNT", WorkstationSupportStatus.Unsupported)]
    public void WorkstationProbeRequiresNtTenX64Workstation(
        bool isWindows,
        int ntMajorVersion,
        Architecture architecture,
        string productType,
        WorkstationSupportStatus expected)
    {
        FakeWorkstationEnvironment environment = new(isWindows, new Version(ntMajorVersion, 0), architecture, productType);

        WorkstationReadiness result = new WorkstationReadinessProbe(environment).Probe();

        Assert.Equal(expected, result.Status);
    }

    [Fact]
    public void SnapshotUsesUnknownAuthorizationAndConfiguredTimestampWithoutProviderOperations()
    {
        int workstationCalls = 0;
        int nativeCalls = 0;
        int installationCalls = 0;
        int certificateCalls = 0;
        ReadinessProbe probe = new(
            () => { workstationCalls++; return new(WorkstationSupportStatus.Supported, "SupportedWindowsWorkstationX64"); },
            () => { nativeCalls++; return NativeApiAvailability.Available; },
            () =>
            {
                installationCalls++;
                return new(
                    SimplySignInstallationStatus.Installed,
                    SimplySignInstallationProbe.ObservedUpgradeCode,
                    "{5394C22A-6EC6-4910-8A32-7C411EE290DF}",
                    SimplySignInstallationProbe.ObservedProductName,
                    "Certum",
                    "9.2.14.61");
            },
            () =>
            {
                certificateCalls++;
                return new(CertificateAvailabilityStatus.Unavailable, [], []);
            });

        ReadinessSnapshot result = probe.Probe(new Uri("http://time.certum.pl", UriKind.Absolute));

        Assert.Equal(ProviderAuthorizationStatus.AuthorizationUnknown, result.Authorization);
        Assert.Equal(TimestampConfigurationStatus.Configured, result.Timestamp.Status);
        Assert.Equal("http://time.certum.pl/", result.Timestamp.Uri?.AbsoluteUri);
        Assert.Equal(SimplySignInstallationStatus.Installed, result.SimplySign.Status);
        Assert.Equal(CertificateAvailabilityStatus.Unavailable, result.CertificateCatalog.Status);
        Assert.Equal((1, 1, 1, 1), (workstationCalls, nativeCalls, installationCalls, certificateCalls));
        Assert.DoesNotContain(typeof(ReadinessSnapshot).GetProperties(), property =>
            property.Name.Contains("Login", StringComparison.OrdinalIgnoreCase)
            || property.Name.Contains("Session", StringComparison.OrdinalIgnoreCase)
            || property.Name.Contains("Credential", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SnapshotProjectsPowerShellBridgeReadiness()
    {
        int bridgeCalls = 0;
        WindowsPowerShellBridgeReadiness bridge = new(
            WindowsPowerShellBridgeStatus.Available,
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "5.1",
            "SystemWindowsPowerShell51Available");
        ReadinessProbe probe = new(
            () => new(WorkstationSupportStatus.Supported, "SupportedWindowsWorkstationX64"),
            () => NativeApiAvailability.Available,
            () => new(SimplySignInstallationStatus.NotInstalled, SimplySignInstallationProbe.ObservedUpgradeCode, null, null, null, null),
            () => new(CertificateAvailabilityStatus.Unavailable, [], []),
            () =>
            {
                bridgeCalls++;
                return bridge;
            });

        ReadinessSnapshot result = probe.Probe(new Uri("http://time.certum.pl", UriKind.Absolute));

        Assert.Equal(1, bridgeCalls);
        Assert.Same(bridge, result.PowerShellBridge);
    }

    [Theory]
    [InlineData("file:///C:/timestamp")]
    [InlineData("ftp://timestamp.example.test")]
    public void RejectsNonHttpTimestampConfiguration(string value)
    {
        ReadinessProbe probe = new(
            () => new(WorkstationSupportStatus.Supported, "SupportedWindowsWorkstationX64"),
            () => NativeApiAvailability.Available,
            () => new(SimplySignInstallationStatus.NotInstalled, SimplySignInstallationProbe.ObservedUpgradeCode, null, null, null, null),
            () => new(CertificateAvailabilityStatus.Unavailable, [], []));

        ReadinessSnapshot result = probe.Probe(new Uri(value, UriKind.Absolute));

        Assert.Equal(TimestampConfigurationStatus.Invalid, result.Timestamp.Status);
        Assert.Null(result.Timestamp.Uri);
    }

    [Fact]
    public void RelativeTimestampUriIsInvalidWithoutThrowing()
    {
        ReadinessProbe probe = new(
            () => new(WorkstationSupportStatus.Supported, "SupportedWindowsWorkstationX64"),
            () => NativeApiAvailability.Available,
            () => new(SimplySignInstallationStatus.NotInstalled, SimplySignInstallationProbe.ObservedUpgradeCode, null, null, null, null),
            () => new(CertificateAvailabilityStatus.Unavailable, [], []));

        ReadinessSnapshot result = probe.Probe(new Uri("relative-timestamp", UriKind.Relative));

        Assert.Equal(TimestampConfigurationStatus.Invalid, result.Timestamp.Status);
        Assert.Null(result.Timestamp.Uri);
    }

    private sealed class FakeWorkstationEnvironment(
        bool isWindows,
        Version operatingSystemVersion,
        Architecture architecture,
        string? productType) : IWorkstationEnvironment
    {
        public bool IsWindows => isWindows;
        public Version OperatingSystemVersion => operatingSystemVersion;
        public Architecture Architecture => architecture;
        public string? ProductType => productType;
    }
}
