using CodeSigner.Windows.Readiness;

namespace CodeSigner.Windows.Tests;

public sealed class SimplySignInstallationProbeTests
{
    [Fact]
    public void AcceptsObservedAndFutureVersionsOnlyWithExactFamilyMetadata()
    {
        FakeProductSource source = new(
            new("{5394C22A-6EC6-4910-8A32-7C411EE290DF}", "proCertum SmartSign SimplySign Desktop", "Certum", "9.2.14.61"),
            new("{11111111-1111-1111-1111-111111111111}", "proCertum SmartSign SimplySign Desktop", "Certum", "10.0.0.0"));

        SimplySignInstallation result = new SimplySignInstallationProbe(source).Probe();

        Assert.Equal(SimplySignInstallationStatus.Installed, result.Status);
        Assert.Equal("{541ED859-5757-467F-8331-8A69C410A6AF}", source.RequestedUpgradeCode);
        Assert.Equal("10.0.0.0", result.Version);
        Assert.Equal("{11111111-1111-1111-1111-111111111111}", result.ProductCode);
        Assert.DoesNotContain(typeof(SimplySignInstallation).GetProperties(), property =>
            property.Name.Contains("Path", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("Other Product", "Certum", "10.0.0.0")]
    [InlineData("proCertum SmartSign SimplySign Desktop", "Other Publisher", "10.0.0.0")]
    [InlineData("proCertum SmartSign SimplySign Desktop", "Asseco Data Systems S.A.", "10.0.0.0")]
    [InlineData("proCertum SmartSign SimplySign Desktop", "Certum", "not-a-version")]
    public void RejectsUnverifiedOrMalformedRegistrations(string productName, string publisher, string version)
    {
        FakeProductSource source = new(
            new WindowsInstallerProductRegistration(
                "{5394C22A-6EC6-4910-8A32-7C411EE290DF}",
                productName,
                publisher,
                version));

        SimplySignInstallation result = new SimplySignInstallationProbe(source).Probe();

        Assert.Equal(SimplySignInstallationStatus.NotInstalled, result.Status);
        Assert.Null(result.ProductCode);
        Assert.Null(result.Version);
    }

    [Fact]
    public void DoesNotCacheStaleInstallationState()
    {
        MutableProductSource source = new();
        SimplySignInstallationProbe probe = new(source);

        Assert.Equal(SimplySignInstallationStatus.NotInstalled, probe.Probe().Status);
        source.Registrations =
        [
            new("{5394C22A-6EC6-4910-8A32-7C411EE290DF}", "proCertum SmartSign SimplySign Desktop", "Certum", "9.2.14.61")
        ];
        Assert.Equal(SimplySignInstallationStatus.Installed, probe.Probe().Status);
        Assert.Equal(2, source.Calls);
    }

    [Fact]
    public void EqualVersionsUseProductCodeAsDeterministicTieBreak()
    {
        WindowsInstallerProductRegistration higher = new(
            "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
            SimplySignInstallationProbe.ObservedProductName,
            SimplySignInstallationProbe.ObservedPublisher,
            SimplySignInstallationProbe.ObservedVersion);
        WindowsInstallerProductRegistration lower = new(
            "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            SimplySignInstallationProbe.ObservedProductName,
            SimplySignInstallationProbe.ObservedPublisher,
            SimplySignInstallationProbe.ObservedVersion);

        SimplySignInstallation forward = new SimplySignInstallationProbe(new FakeProductSource(higher, lower)).Probe();
        SimplySignInstallation reverse = new SimplySignInstallationProbe(new FakeProductSource(lower, higher)).Probe();

        Assert.Equal(lower.ProductCode, forward.ProductCode);
        Assert.Equal(lower.ProductCode, reverse.ProductCode);
    }

    private sealed class FakeProductSource(params WindowsInstallerProductRegistration[] registrations)
        : IWindowsInstallerProductSource
    {
        public string? RequestedUpgradeCode { get; private set; }

        public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode)
        {
            RequestedUpgradeCode = upgradeCode;
            return registrations;
        }
    }

    private sealed class MutableProductSource : IWindowsInstallerProductSource
    {
        public IReadOnlyList<WindowsInstallerProductRegistration> Registrations { get; set; } = [];
        public int Calls { get; private set; }

        public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode)
        {
            Calls++;
            return Registrations;
        }
    }
}
