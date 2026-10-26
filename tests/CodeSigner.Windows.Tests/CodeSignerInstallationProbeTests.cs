using CodeSigner.Windows.Readiness;

namespace CodeSigner.Windows.Tests;

public sealed class CodeSignerInstallationProbeTests
{
    [Theory]
    [InlineData("安信证书签名工具", "CodeSigner", CodeSignerInstallationStatus.Installed)]
    [InlineData("代码签名工具", "CodeSigner", CodeSignerInstallationStatus.Installed)]
    [InlineData("安信证书签名工具", "Other Publisher", CodeSignerInstallationStatus.NotInstalled)]
    [InlineData("安信证书签名工具 ", "CodeSigner", CodeSignerInstallationStatus.NotInstalled)]
    public void ProductRenamePreservesExactCurrentAndLegacyRegistrationRecognition(
        string productName,
        string publisher,
        CodeSignerInstallationStatus expected)
    {
        var source = new FakeProductSource(new WindowsInstallerProductRegistration(
            "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            productName,
            publisher,
            "1.0.32",
            WindowsInstallerInstallState.Default));

        CodeSignerInstallation result = new CodeSignerInstallationProbe(source).Probe();

        Assert.Equal(expected, result.Status);
        Assert.Equal(CodeSignerInstallationProbe.ObservedUpgradeCode, source.RequestedUpgradeCode);
        if (expected == CodeSignerInstallationStatus.Installed)
        {
            Assert.Equal(productName, result.ProductName);
        }
        else
        {
            Assert.Null(result.ProductCode);
        }
    }

    [Fact]
    public void AcceptsOnlyExactInstalledDefaultCodeSignerRegistration()
    {
        FakeProductSource source = new(
            new(
                "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                CodeSignerInstallationProbe.ObservedProductName,
                CodeSignerInstallationProbe.ObservedPublisher,
                "1.0.0",
                WindowsInstallerInstallState.Default),
            new(
                "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
                "代码签名工具",
                "Other Publisher",
                "1.0.0",
                WindowsInstallerInstallState.Default));

        CodeSignerInstallation result = new CodeSignerInstallationProbe(source).Probe();

        Assert.Equal(CodeSignerInstallationStatus.Installed, result.Status);
        Assert.Equal(CodeSignerInstallationProbe.ObservedUpgradeCode, source.RequestedUpgradeCode);
        Assert.Equal("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", result.ProductCode);
        Assert.Equal("1.0.0", result.Version);
    }

    [Fact]
    public void ZeroVerifiedRegistrationsFailClosedAsNotInstalled()
    {
        CodeSignerInstallation result = new CodeSignerInstallationProbe(new FakeProductSource()).Probe();

        Assert.Equal(CodeSignerInstallationStatus.NotInstalled, result.Status);
        Assert.Null(result.ProductCode);
        Assert.Equal("VerifiedRegistrationNotFound", result.DiagnosticCode);
    }

    [Fact]
    public void MultipleVerifiedRegistrationsFailClosedAsAmbiguous()
    {
        CodeSignerInstallation result = new CodeSignerInstallationProbe(
            new FakeProductSource(
                Registration("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"),
                Registration("{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"))).Probe();

        Assert.Equal(CodeSignerInstallationStatus.Ambiguous, result.Status);
        Assert.Null(result.ProductCode);
        Assert.Equal("MultipleVerifiedRegistrations", result.DiagnosticCode);
    }

    [Fact]
    public void AdvertisedExactRegistrationDoesNotQualifyForRepair()
    {
        CodeSignerInstallation result = new CodeSignerInstallationProbe(
            new FakeProductSource(Registration(
                "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                WindowsInstallerInstallState.Advertised))).Probe();

        Assert.Equal(CodeSignerInstallationStatus.Advertised, result.Status);
        Assert.Null(result.ProductCode);
        Assert.Equal("RegistrationAdvertised", result.DiagnosticCode);
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")]
    public void MalformedExactRegistrationDoesNotQualifyForRepair(string productCode)
    {
        CodeSignerInstallation result = new CodeSignerInstallationProbe(
            new FakeProductSource(Registration(productCode))).Probe();

        Assert.Equal(CodeSignerInstallationStatus.Malformed, result.Status);
        Assert.Null(result.ProductCode);
        Assert.Equal("MalformedProductCode", result.DiagnosticCode);
    }

    private static WindowsInstallerProductRegistration Registration(
        string productCode,
        WindowsInstallerInstallState state = WindowsInstallerInstallState.Default) =>
        new(
            productCode,
            CodeSignerInstallationProbe.ObservedProductName,
            CodeSignerInstallationProbe.ObservedPublisher,
            "1.0.0",
            state);

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
}
