using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class ProductIconContractTests
{
    [Fact]
    public void ProductIconsAreBoundToWindowsShellAndWpfRuntimeSurfaces()
    {
        string repositoryRoot = ResolveRepositoryRoot();
        string appProjectPath = Path.Combine(
            repositoryRoot,
            "src",
            "CodeSigner.App",
            "CodeSigner.App.csproj");
        string iconPath = Path.Combine(
            repositoryRoot,
            "src",
            "CodeSigner.App",
            "Assets",
            "CodeSigner.ico");
        string headerImagePath = Path.Combine(
            repositoryRoot,
            "src",
            "CodeSigner.App",
            "Assets",
            "CodeSigner.png");
        string[] windowPaths =
        [
            Path.Combine(repositoryRoot, "src", "CodeSigner.App", "MainWindow.xaml"),
            Path.Combine(repositoryRoot, "src", "CodeSigner.App", "SettingsWindow.xaml"),
            Path.Combine(repositoryRoot, "src", "CodeSigner.App", "PrimitiveShowcaseWindow.xaml")
        ];

        Assert.True(File.Exists(iconPath));
        Assert.True(File.Exists(headerImagePath));
        Assert.Contains("<ApplicationIcon>Assets\\CodeSigner.ico</ApplicationIcon>", File.ReadAllText(appProjectPath), StringComparison.Ordinal);
        XDocument appProject = XDocument.Load(appProjectPath);
        string[] runtimeResources = appProject
            .Descendants()
            .Where(static element => element.Name.LocalName == "Resource")
            .Select(static element => element.Attribute("Include")?.Value)
            .OfType<string>()
            .ToArray();
        Assert.Contains("Assets\\CodeSigner.ico", runtimeResources);
        Assert.Contains("Assets\\CodeSigner.png", runtimeResources);

        foreach (string windowPath in windowPaths)
        {
            XDocument window = XDocument.Load(windowPath);
            Assert.Equal("Assets/CodeSigner.ico", window.Root?.Attribute("Icon")?.Value);
        }
    }

    [Fact]
    public void HeaderAndInstallerShortcutsUseTheProductIcon()
    {
        string repositoryRoot = ResolveRepositoryRoot();
        XDocument mainWindow = XDocument.Load(
            Path.Combine(repositoryRoot, "src", "CodeSigner.App", "MainWindow.xaml"));
        XElement[] headerImages = mainWindow
            .Descendants()
            .Where(static element => element.Name.LocalName == "Image")
            .Where(static element => string.Equals(
                element.Attribute("Source")?.Value,
                "Assets/CodeSigner.png",
                StringComparison.Ordinal))
            .ToArray();
        string installer = File.ReadAllText(
            Path.Combine(repositoryRoot, "packaging", "nsis", "installer.nsi"));

        XElement headerIcon = Assert.Single(headerImages);
        Assert.Equal("安信 SSL 证书", headerIcon
            .Attributes()
            .Single(static attribute => attribute.Name.LocalName == "AutomationProperties.Name")
            .Value);
        Assert.DoesNotContain(
            mainWindow.Descendants()
                .Where(static element => element.Name.LocalName == "TextBlock")
                .Select(static element => element.Attribute("Text")?.Value),
            static text => string.Equals(text, "Windows 支持格式签名", StringComparison.Ordinal));
        Assert.Contains("MUI_ICON", installer, StringComparison.Ordinal);
        Assert.Contains(@"src\CodeSigner.App\Assets\CodeSigner.ico", installer, StringComparison.Ordinal);
        Assert.Contains("CreateShortcut", installer, StringComparison.Ordinal);
        Assert.Contains(@"$INSTDIR\CodeSigner.App.exe", installer, StringComparison.Ordinal);
    }

    private static string ResolveRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "CodeSigner.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the repository root.");
    }
}
