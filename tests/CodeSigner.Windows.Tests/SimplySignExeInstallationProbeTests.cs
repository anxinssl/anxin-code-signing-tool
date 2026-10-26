using System.ComponentModel;
using CodeSigner.Windows.Readiness;
using Microsoft.Win32;

namespace CodeSigner.Windows.Tests;

public sealed class SimplySignExeInstallationProbeTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "codesigner-simplysign-" + Guid.NewGuid().ToString("N"));
    private readonly FakeInspector inspector = new();

    public SimplySignExeInstallationProbeTests()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "SimplySignDesktop.exe"), "test fixture only");
    }

    [Theory]
    [InlineData(RegistryHive.LocalMachine, RegistryView.Registry32)]
    [InlineData(RegistryHive.LocalMachine, RegistryView.Registry64)]
    [InlineData(RegistryHive.CurrentUser, RegistryView.Registry32)]
    [InlineData(RegistryHive.CurrentUser, RegistryView.Registry64)]
    public void FindsVerifiedExeInEveryRegistryScope(RegistryHive expectedHive, RegistryView expectedView)
    {
        List<(RegistryHive, RegistryView)> scopes = [];
        SimplySignProductSource source = new(new FakeMsi(),
            (hive, view) =>
            {
                scopes.Add((hive, view));
                return hive == expectedHive && view == expectedView ? [Registration()] : [];
            }, inspector);

        SimplySignInstallation result = new SimplySignInstallationProbe(source).Probe();

        Assert.Equal(SimplySignInstallationStatus.Installed, result.Status);
        Assert.Equal("9.4.5.95", result.Version);
        Assert.Equal(4, scopes.Distinct().Count());
        Assert.Equal(Path.Combine(directory, "SimplySignDesktop.exe"), Assert.Single(inspector.Paths));
    }

    [Theory]
    [InlineData("name")]
    [InlineData("publisher")]
    [InlineData("version")]
    [InlineData("old-version")]
    [InlineData("product-code")]
    [InlineData("empty-location")]
    [InlineData("relative-location")]
    [InlineData("network-location")]
    [InlineData("missing-file")]
    public void RejectsInvalidOrStaleRegistrationWithoutInspectingFile(string invalidField)
    {
        SimplySignExeRegistration registration = invalidField switch
        {
            "name" => Registration() with { ProductName = "Other Product" },
            "publisher" => Registration() with { Publisher = "Other Publisher" },
            "version" => Registration() with { Version = "invalid" },
            "old-version" => Registration() with { Version = "9.1.0.0" },
            "product-code" => Registration() with { ProductCode = "invalid" },
            "empty-location" => Registration() with { InstallLocation = null },
            "relative-location" => Registration() with { InstallLocation = "relative" },
            "network-location" => Registration() with { InstallLocation = @"\\server\share" },
            "missing-file" => Registration() with { InstallLocation = Path.Combine(directory, "missing") },
            _ => throw new ArgumentOutOfRangeException(nameof(invalidField))
        };

        Assert.Equal(SimplySignInstallationStatus.NotInstalled, Probe(registration).Status);
        Assert.Empty(inspector.Paths);
    }

    [Theory]
    [InlineData("trust")]
    [InlineData("signer")]
    [InlineData("company")]
    [InlineData("product")]
    [InlineData("filename")]
    [InlineData("description")]
    public void RejectsUntrustedOrUnrelatedExecutable(string invalidField)
    {
        inspector.Result = invalidField switch
        {
            "trust" => inspector.Result with { WindowsTrustValid = false },
            "signer" => inspector.Result with { Publisher = "Other Signer" },
            "company" => inspector.Result with { CompanyName = "Other Company" },
            "product" => inspector.Result with { ProductName = "Other Product" },
            "filename" => inspector.Result with { OriginalFileName = "Other.exe" },
            "description" => inspector.Result with { FileDescription = "Other" },
            _ => throw new ArgumentOutOfRangeException(nameof(invalidField))
        };

        Assert.Equal(SimplySignInstallationStatus.NotInstalled, Probe(Registration()).Status);
    }

    [Fact]
    public void InaccessibleRegistryScopeDoesNotHideValidScope()
    {
        SimplySignProductSource source = new(new FakeMsi(), (hive, view) =>
            hive == RegistryHive.LocalMachine
                ? throw new UnauthorizedAccessException()
                : view == RegistryView.Registry32 ? [Registration()] : [], inspector);

        Assert.Equal(SimplySignInstallationStatus.Installed, new SimplySignInstallationProbe(source).Probe().Status);
    }

    [Fact]
    public void MsiEnumerationFailureStillAllowsVerifiedExe()
    {
        SimplySignProductSource source = new(new FakeMsi { Failure = new Win32Exception(5) },
            (_, _) => [Registration()], inspector);

        Assert.Equal(SimplySignInstallationStatus.Installed, new SimplySignInstallationProbe(source).Probe().Status);
    }

    [Fact]
    public void MsiFailureWithoutVerifiedExeKeepsOriginalDiagnostic()
    {
        SimplySignProductSource source = new(new FakeMsi { Failure = new Win32Exception(5) },
            (_, _) => [], inspector);

        Assert.Equal("WindowsInstallerUnavailable", new SimplySignInstallationProbe(source).Probe().DiagnosticCode);
    }

    [Fact]
    public void ExistingMsiPathAndHighestVersionSelectionArePreserved()
    {
        WindowsInstallerProductRegistration msi = new(
            "{11111111-1111-1111-1111-111111111111}",
            SimplySignInstallationProbe.ObservedProductName, SimplySignInstallationProbe.ObservedPublisher, "10.0.0.0");
        SimplySignProductSource source = new(new FakeMsi { Registrations = [msi] },
            (_, _) => [Registration()], inspector);
        SimplySignInstallation result = new SimplySignInstallationProbe(source).Probe();

        Assert.Equal(msi.ProductCode, result.ProductCode);
        Assert.Equal(msi.Version, result.Version);
    }

    [Fact]
    public void NewerVerifiedExeIsSelectedAlongsideOlderMsi()
    {
        WindowsInstallerProductRegistration msi = new(
            "{11111111-1111-1111-1111-111111111111}",
            SimplySignInstallationProbe.ObservedProductName, SimplySignInstallationProbe.ObservedPublisher,
            SimplySignInstallationProbe.ObservedVersion);
        SimplySignProductSource source = new(new FakeMsi { Registrations = [msi] },
            (_, _) => [Registration()], inspector);

        SimplySignInstallation result = new SimplySignInstallationProbe(source).Probe();

        Assert.Equal(Registration().ProductCode, result.ProductCode);
        Assert.Equal("9.4.5.95", result.Version);
    }

    [Fact]
    public void InvalidExeDoesNotHideValidMsi()
    {
        WindowsInstallerProductRegistration msi = new(
            "{11111111-1111-1111-1111-111111111111}",
            SimplySignInstallationProbe.ObservedProductName, SimplySignInstallationProbe.ObservedPublisher,
            SimplySignInstallationProbe.ObservedVersion);
        inspector.Failure = new IOException("Executable unavailable");
        SimplySignProductSource source = new(new FakeMsi { Registrations = [msi] },
            (_, _) => [Registration()], inspector);

        SimplySignInstallation result = new SimplySignInstallationProbe(source).Probe();

        Assert.Equal(SimplySignInstallationStatus.Installed, result.Status);
        Assert.Equal(msi.ProductCode, result.ProductCode);
    }

    [Fact]
    public void RefreshObservesNewRegistrationWithoutRestart()
    {
        IReadOnlyList<SimplySignExeRegistration> registrations = [];
        SimplySignInstallationProbe probe = new(new SimplySignProductSource(
            new FakeMsi(), (_, _) => registrations, inspector));
        Assert.Equal(SimplySignInstallationStatus.NotInstalled, probe.Probe().Status);

        registrations = [Registration()];

        Assert.Equal(SimplySignInstallationStatus.Installed, probe.Probe().Status);
    }

    [Fact]
    public void ExeFallbackDoesNotApplyToWorkerOrOtherProductFamilies()
    {
        SimplySignProductSource source = new(new FakeMsi(),
            (_, _) => throw new InvalidOperationException("Must not read registry"), inspector);

        Assert.Empty(source.FindRelatedProducts("{C81BF087-67D0-41F3-8581-9E773813118B}"));
    }

    [Fact]
    public void RefreshDoesNotReuseRemovedExecutable()
    {
        SimplySignProductSource source = new(new FakeMsi(), (_, _) => [Registration()], inspector);
        SimplySignInstallationProbe probe = new(source);
        Assert.Equal(SimplySignInstallationStatus.Installed, probe.Probe().Status);
        File.Delete(Path.Combine(directory, "SimplySignDesktop.exe"));

        Assert.Equal(SimplySignInstallationStatus.NotInstalled, probe.Probe().Status);
    }

    [Fact]
    public void InspectionFailureDoesNotEscapeReadinessProbe()
    {
        inspector.Failure = new IOException("File disappeared");
        Assert.Equal(SimplySignInstallationStatus.NotInstalled, Probe(Registration()).Status);
    }

    private SimplySignInstallation Probe(SimplySignExeRegistration registration) =>
        new SimplySignInstallationProbe(new SimplySignProductSource(
            new FakeMsi(), (_, _) => [registration], inspector)).Probe();

    private SimplySignExeRegistration Registration() => new(
        "{9766A015-4A97-44A5-9B87-318FA95203AE}",
        SimplySignInstallationProbe.ObservedProductName,
        SimplySignInstallationProbe.ObservedPublisher,
        "9.4.5.95",
        directory);

    public void Dispose()
    {
        Directory.Delete(directory, recursive: true);
    }

    private sealed class FakeMsi : IWindowsInstallerProductSource
    {
        public Exception? Failure { get; init; }
        public IReadOnlyList<WindowsInstallerProductRegistration> Registrations { get; init; } = [];
        public IReadOnlyList<WindowsInstallerProductRegistration> FindRelatedProducts(string upgradeCode) =>
            Failure is null ? Registrations : throw Failure;
    }

    private sealed class FakeInspector : ISdkSignToolExecutableInspector
    {
        public List<string> Paths { get; } = [];
        public Exception? Failure { get; set; }
        public SdkSignToolExecutableInspection Result { get; set; } = new(
            0x8664, true,
            SimplySignInstallationProbe.ObservedAuthenticodePublisher,
            SimplySignInstallationProbe.ObservedAuthenticodePublisher,
            "SimplySign", "SimplySignDesktop.exe", "SimplySign Desktop",
            new Version(7, 6, 95, 0), new string('A', 64));

        public SdkSignToolExecutableInspection Inspect(string path)
        {
            Paths.Add(path);
            return Failure is null ? Result : throw Failure;
        }
    }
}
