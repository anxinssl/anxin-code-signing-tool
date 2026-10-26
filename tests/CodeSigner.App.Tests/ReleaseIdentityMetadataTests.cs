using System.Reflection;
using System.Diagnostics;
using System.IO;
using CodeSigner.App;

namespace CodeSigner.App.Tests;

public sealed class ReleaseIdentityMetadataTests
{
    [Fact]
    public void UninstallUsesAbsoluteSystemExecutableAndInteractiveArguments()
    {
        ProcessStartInfo startInfo = Services.NsisMaintenance.CreateStartInfo(Services.NsisMaintenance.ExpectedDirectory, false);
        Assert.Equal(Path.Combine(Services.NsisMaintenance.ExpectedDirectory, "Uninstall.exe"), startInfo.FileName);
        Assert.True(Path.IsPathFullyQualified(startInfo.FileName));
        Assert.True(startInfo.UseShellExecute);
        Assert.Empty(startInfo.ArgumentList);
        Assert.Empty(startInfo.Arguments);
    }

    [Fact]
    public void ProductVersionDisplayTextUsesCentralInformationalVersionWhenRead()
    {
        string displayText = SettingsWindow.ProductVersionDisplayText;

        Assert.Equal("安信代码签名证书工具 v1.0.44", displayText);
    }

    [Fact]
    public void InstalledProductCodeUsesGeneratedAssemblyMetadataWhenRead()
    {
        AssemblyMetadataAttribute metadata = Assert.Single(
            typeof(SettingsWindow).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>(),
            static attribute => string.Equals(
                attribute.Key,
                "CodeSignerProductCode",
                StringComparison.Ordinal));

        string productCode = SettingsWindow.InstalledProductCode;

        Assert.Equal(metadata.Value, productCode);
        Assert.True(Guid.TryParseExact(productCode, "B", out _));
    }
}
