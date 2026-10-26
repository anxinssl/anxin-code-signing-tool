using System.IO;
using System.Threading;
using System.Windows;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class DesignTokenRuntimeContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [Fact]
    public void ScalarSpacingAndIconSizingTokensPreserveTheirSemanticBaseline()
    {
        XDocument tokens = XDocument.Load(DesignTokensPath);

        AssertResource(tokens, "Space.2", "Double", "8");
        AssertResource(tokens, "Space.3", "Double", "12");
        AssertResource(tokens, "Metric.Icon.Command.Size", "Double", "16");
        XElement mergedDictionaries = Assert.Single(tokens.Root!.Elements(), element =>
            element.Name.LocalName == "ResourceDictionary.MergedDictionaries");
        XElement iconDictionary = Assert.Single(mergedDictionaries.Elements(), element =>
            element.Name.LocalName == "ResourceDictionary");
        Assert.Equal("../Assets/CommandIcons/LucideCommandIcons.xaml", Attribute(iconDictionary, "Source"));
    }

    [Fact]
    public void RuntimeSharedPaddingStylesResolveToThicknessAndLoadTheirTemplates()
    {
        RunOnSta(() =>
        {
            var dictionary = (ResourceDictionary)System.Windows.Application.LoadComponent(
                new Uri("/CodeSigner.App;component/Themes/DesignTokens.xaml", UriKind.Relative));
            var command = new System.Windows.Controls.Button { Style = (Style)dictionary["CommandButtonStyle"] };
            var band = new System.Windows.Controls.Border { Style = (Style)dictionary["BandBorderStyle"] };
            var segmented = new System.Windows.Controls.RadioButton { Style = (Style)dictionary["SegmentedRadioButtonStyle"] };
            var certificate = new System.Windows.Controls.ComboBox { Style = (Style)dictionary["CertificateComboBoxStyle"] };

            Assert.IsType<Thickness>(command.Padding);
            Assert.IsType<Thickness>(band.Padding);
            Assert.IsType<Thickness>(segmented.Padding);
            Assert.IsType<Thickness>(certificate.Padding);
            command.ApplyTemplate();
            segmented.ApplyTemplate();
            certificate.ApplyTemplate();
        });
    }

    private static string DesignTokensPath => Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "Themes",
        "DesignTokens.xaml");

    private static void AssertResource(XDocument tokens, string key, string localName, string value)
    {
        XElement resource = Assert.Single(tokens.Root!.Elements(), element => Key(element) == key);
        Assert.Equal(localName, resource.Name.LocalName);
        Assert.Equal(value, resource.Value);
    }

    private static string? Attribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
        ?.Value;

    private static string? Key(XElement element) => element.Attribute(
        XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml"))?.Value;

    private static void RunOnSta(Action action)
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception caught)
            {
                exception = caught;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (exception is not null)
        {
            throw new InvalidOperationException("STA WPF resource assertion failed.", exception);
        }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("CodeSigner repository root was not found.");
    }
}
