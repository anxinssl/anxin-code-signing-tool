using System.Globalization;
using System.IO;
using System.Threading;
using System.Windows;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class DesignTokenContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly (string Element, string Property, string Literal, string Token)[] SemanticConsumerTokens =
    [
        ("Image", "Width", "16", "Metric.Icon.Command.Size"),
        ("Image", "Height", "16", "Metric.Icon.Command.Size"),
        ("*", "FontSize", "12", "Typography.Caption.Size"),
        ("*", "FontSize", "16", "Typography.SectionHeading.Size"),
        ("*", "FontSize", "20", "Typography.WindowHeading.Size"),
        ("Border", "CornerRadius", "8", "Metric.CornerRadius.Container"),
        ("Border", "Padding", "12,8", "Inset.Control.Standard"),
        ("Button", "Padding", "12,8", "Inset.Control.Standard"),
        ("Grid", "Margin", "16", "Inset.Window.Content")
    ];

    [Fact]
    public void DeclaredForegroundBackgroundPairsMeetTheirContrastThresholds()
    {
        IReadOnlyDictionary<string, string> colors = LoadColors(LoadTokens());

        AssertContrast(colors, "Color.Text.Primary", "Color.Surface.Secondary", 4.5d);
        AssertContrast(colors, "Color.Text.Secondary", "Color.Surface.Secondary", 4.5d);
        AssertContrast(colors, "Color.Text.Tertiary", "Color.Surface.Secondary", 4.5d);
        AssertContrast(colors, "Color.Text.OnAccent", "Color.Accent.Primary", 4.5d);
        AssertContrast(colors, "Color.Text.OnAccent", "Color.Accent.Hover", 4.5d);
        AssertContrast(colors, "Color.Text.OnAccent", "Color.Accent.Pressed", 4.5d);

        foreach (string status in new[] { "Success", "Warning", "Error", "Info" })
        {
            AssertContrast(colors, $"Color.Status.{status}", "Color.Surface.Secondary", 4.5d);
            AssertContrast(colors, $"Color.Status.{status}", $"Color.Status.{status}Background", 4.5d);
            AssertContrast(colors, $"Color.Status.{status}Border", $"Color.Status.{status}Background", 3d);
        }

        AssertContrast(colors, "Color.Accent.Primary", "Color.Surface.Secondary", 3d);
        AssertContrast(colors, "Color.Focus.Ring", "Color.Surface.Secondary", 3d);
        AssertContrast(colors, "Color.Border.Default", "Color.Surface.Secondary", 3d);
        AssertContrast(colors, "Color.Border.Subtle", "Color.Surface.Secondary", 3d);
    }

    [Fact]
    public void PrimaryActionFocusIndicatorMeetsContrastAgainstEveryLiveBackgroundState()
    {
        XDocument tokens = LoadTokens();
        IReadOnlyDictionary<string, string> colors = LoadColors(tokens);
        XElement primaryActionStyle = Assert.Single(tokens.Descendants(), element =>
            element.Name.LocalName == "Style" &&
            Key(element) == "PrimaryActionButtonStyle");
        XElement normalBackground = Assert.Single(primaryActionStyle.Elements(), element =>
            element.Name.LocalName == "Setter" &&
            Attribute(element, "Property") == "Background");
        XElement focusTrigger = Assert.Single(primaryActionStyle.Descendants(), element =>
            element.Name.LocalName == "Trigger" &&
            Attribute(element, "Property") == "IsKeyboardFocused" &&
            Attribute(element, "Value") == "True");
        XElement focusBorder = Assert.Single(focusTrigger.Descendants(), element =>
            element.Name.LocalName == "Setter" &&
            Attribute(element, "Property") == "BorderBrush");

        string focusKey = DynamicResourceKey(Attribute(focusBorder, "Value")!);
        string[] backgroundKeys =
        [
            DynamicResourceKey(Attribute(normalBackground, "Value")!),
            TriggerBackgroundKey(primaryActionStyle, "IsMouseOver"),
            TriggerBackgroundKey(primaryActionStyle, "IsPressed")
        ];

        foreach (string backgroundKey in backgroundKeys)
        {
            AssertContrast(colors, focusKey, backgroundKey, 3d);
        }
    }

    [Fact]
    public void LowContrastFixtureReportsTheExactViolation()
    {
        XDocument fixture = XDocument.Parse("""
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <SolidColorBrush x:Key="Foreground" Color="#73869A" />
                <SolidColorBrush x:Key="Background" Color="#FFFFFF" />
            </ResourceDictionary>
            """);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            AssertContrast(LoadColors(fixture), "Foreground", "Background", 4.5d));

        Assert.Equal("Foreground on Background has contrast 3.746, below 4.500.", exception.Message);
    }

    [Fact]
    public void MalformedColorFixtureFailsWithTheLiteralThatCouldNotBeParsed()
    {
        XDocument fixture = XDocument.Parse("""
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <SolidColorBrush x:Key="Foreground" Color="#not-a-color" />
                <SolidColorBrush x:Key="Background" Color="#FFFFFF" />
            </ResourceDictionary>
            """);

        FormatException exception = Assert.Throws<FormatException>(() =>
            AssertContrast(LoadColors(fixture), "Foreground", "Background", 4.5d));

        Assert.Equal("Unsupported color literal '#not-a-color'.", exception.Message);
    }

    [Fact]
    public void SemanticKeysAndMetricsAreUniqueAndTokenized()
    {
        XDocument tokens = LoadTokens();
        XElement[] keyedResources = tokens.Root!.Elements()
            .Where(static element => element.Attribute(XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml")) is not null)
            .ToArray();
        string[] duplicateKeys = keyedResources
            .Select(static element => Key(element)!)
            .GroupBy(static key => key, StringComparer.Ordinal)
            .Where(static group => group.Count() > 1)
            .Select(static group => group.Key)
            .ToArray();

        Assert.Empty(duplicateKeys);
        Assert.Contains(keyedResources, element => Key(element) == "Metric.CornerRadius.Control");
        Assert.Contains(keyedResources, element => Key(element) == "Metric.CornerRadius.Container");
        Assert.Contains(keyedResources, element => Key(element) == "Metric.Control.Height");
        Assert.Contains(keyedResources, element => Key(element) == "Metric.Border.Thickness");
        Assert.Contains(keyedResources, element => Key(element) == "Typography.Body.Size");
        Assert.Contains(keyedResources, element => Key(element) == "Typography.Caption.Size");
        Assert.Contains(keyedResources, element =>
            Key(element) == "Inset.Window.Content" &&
            element.Name.LocalName == "Thickness" &&
            element.Value == "16");
        Assert.All(
            keyedResources.Where(static element => element.Name.LocalName == "CornerRadius"),
            cornerRadius => Assert.InRange(
                double.Parse(cornerRadius.Value, CultureInfo.InvariantCulture),
                0d,
                8d));

        foreach (XElement cornerRadius in tokens.Descendants().Where(static element => element.Name.LocalName == "Border"))
        {
            Assert.DoesNotMatch("^[0-9]+$", Attribute(cornerRadius, "CornerRadius") ?? string.Empty);
        }

        XElement[] styles = tokens.Descendants().Where(static element => element.Name.LocalName == "Style").ToArray();
        Assert.All(styles.Where(static style =>
                Attribute(style, "TargetType") is "Button" or "RadioButton" or "ComboBox"),
            style => Assert.Contains(style.Descendants(), setter =>
                setter.Name.LocalName == "Setter" &&
                Attribute(setter, "Property") == "MinHeight" &&
                Attribute(setter, "Value") is "{StaticResource Metric.Control.Height}" or "{StaticResource Metric.Control.Height.PrimaryAction}"));

        Assert.All(tokens.Descendants().Where(static element => element.Name.LocalName == "Border"), border =>
            Assert.Equal("{StaticResource Metric.CornerRadius.Control}", Attribute(border, "CornerRadius")));
    }

    [Fact]
    public void TargetWindowConsumersUseSemanticTokensForRepeatedDesignValues()
    {
        string[] targetWindows =
        [
            "MainWindow.xaml",
            "SettingsWindow.xaml",
            "PrimitiveShowcaseWindow.xaml"
        ];

        string[] violations = targetWindows
            .SelectMany(window => SemanticConsumerLiteralViolations(
                XDocument.Load(Path.Combine(RepositoryRoot, "src", "CodeSigner.App", window)),
                window))
            .ToArray();

        Assert.Empty(violations);
    }

    [Fact]
    public void ConsumerTokenResourcesLoadWithTheirRequiredWpfRuntimeTypes()
    {
        RunOnSta(() =>
        {
            var dictionary = (ResourceDictionary)System.Windows.Application.LoadComponent(
                new Uri("/CodeSigner.App;component/Themes/DesignTokens.xaml", UriKind.Relative));

            Assert.IsType<double>(dictionary["Metric.Icon.Command.Size"]);
            Assert.IsType<double>(dictionary["Typography.Caption.Size"]);
            Assert.IsType<double>(dictionary["Typography.SectionHeading.Size"]);
            Assert.IsType<double>(dictionary["Typography.WindowHeading.Size"]);
            Assert.IsType<CornerRadius>(dictionary["Metric.CornerRadius.Container"]);
            Assert.IsType<Thickness>(dictionary["Inset.Control.Standard"]);
            Assert.IsType<Thickness>(dictionary["Inset.Window.Content"]);
        });
    }

    [Fact]
    public void LiteralCommandIconConsumerFixtureIsRejected()
    {
        XDocument fixture = XDocument.Parse("""
            <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <Grid>
                    <Image Width="16" Height="16" Source="{StaticResource Icon.Command.AddFile}" />
                </Grid>
            </Window>
            """);

        string[] violations = SemanticConsumerLiteralViolations(fixture, "literal-icon-fixture.xaml").ToArray();

        Assert.Equal(
        [
            "literal-icon-fixture.xaml: Image.Width=\"16\" must use {StaticResource Metric.Icon.Command.Size}.",
            "literal-icon-fixture.xaml: Image.Height=\"16\" must use {StaticResource Metric.Icon.Command.Size}."
        ],
        violations);
    }

    [Fact]
    public void LiteralCertificateSectionIconConsumerFixtureIsRejected()
    {
        XDocument fixture = XDocument.Parse("""
            <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <Grid>
                    <Image Width="16" Height="16" Source="{StaticResource Icon.Section.Certificate}" />
                </Grid>
            </Window>
            """);

        string[] violations = SemanticConsumerLiteralViolations(fixture, "literal-certificate-section-icon-fixture.xaml").ToArray();

        Assert.Equal(
        [
            "literal-certificate-section-icon-fixture.xaml: Image.Width=\"16\" must use {StaticResource Metric.Icon.Command.Size}.",
            "literal-certificate-section-icon-fixture.xaml: Image.Height=\"16\" must use {StaticResource Metric.Icon.Command.Size}."
        ],
        violations);
    }

    [Fact]
    public void FrozenGeometryFixtureRemainsAllowed()
    {
        XDocument fixture = XDocument.Parse("""
            <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                    Width="900"
                    Height="700">
                <Grid Margin="0,12,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="144" />
                    </Grid.ColumnDefinitions>
                    <ProgressBar Height="8" />
                </Grid>
            </Window>
            """);

        string[] violations = SemanticConsumerLiteralViolations(fixture, "frozen-geometry-fixture.xaml").ToArray();

        Assert.Empty(violations);
    }

    [Fact]
    public void ThemeManagerCoversAllChangedSemanticColorsForHighContrastAndNormalReset()
    {
        string themeManager = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "CodeSigner.App",
            "ThemeManager.cs"));

        string[] semanticColorKeys = LoadColors(LoadTokens()).Keys
            .Where(static key => key.StartsWith("Color.", StringComparison.Ordinal))
            .ToArray();
        int highContrastEnd = themeManager.IndexOf("        if (SystemParameters.HighContrast)", StringComparison.Ordinal);
        int normalResetStart = themeManager.IndexOf("        string[] keys =", StringComparison.Ordinal);
        Assert.True(highContrastEnd >= 0 && normalResetStart > highContrastEnd, "ThemeManager must contain separate high-contrast and normal-reset mappings.");
        string highContrastMappings = themeManager[highContrastEnd..normalResetStart];
        string normalResetMappings = themeManager[normalResetStart..];

        foreach (string key in semanticColorKeys)
        {
            Assert.Contains($"resources[\"{key}\"]", highContrastMappings, StringComparison.Ordinal);
            Assert.Contains($"\"{key}\"", normalResetMappings, StringComparison.Ordinal);
        }

        Assert.Contains("SystemColors.", themeManager, StringComparison.Ordinal);
        Assert.Contains("resources.Remove(key);", themeManager, StringComparison.Ordinal);
    }

    private static XDocument LoadTokens() => XDocument.Load(Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "Themes",
        "DesignTokens.xaml"));

    private static Dictionary<string, string> LoadColors(XDocument document) => document
        .Descendants()
        .Where(static element => element.Name.LocalName == "SolidColorBrush")
        .ToDictionary(static element => Key(element)!, static element => Attribute(element, "Color")!, StringComparer.Ordinal);

    private static void AssertContrast(IReadOnlyDictionary<string, string> colors, string foregroundKey, string backgroundKey, double minimum)
    {
        double contrast = ContrastRatio(ParseColor(colors[foregroundKey]), ParseColor(colors[backgroundKey]));
        if (contrast < minimum)
        {
            throw new InvalidOperationException(string.Format(
                CultureInfo.InvariantCulture,
                "{0} on {1} has contrast {2:F3}, below {3:F3}.",
                foregroundKey,
                backgroundKey,
                contrast,
                minimum));
        }
    }

    private static string TriggerBackgroundKey(XElement style, string triggerProperty)
    {
        XElement trigger = Assert.Single(style.Descendants(), element =>
            element.Name.LocalName == "Trigger" &&
            Attribute(element, "Property") == triggerProperty &&
            Attribute(element, "Value") == "True");
        XElement background = Assert.Single(trigger.Descendants(), element =>
            element.Name.LocalName == "Setter" &&
            Attribute(element, "Property") == "Background");
        return DynamicResourceKey(Attribute(background, "Value")!);
    }

    private static string DynamicResourceKey(string value)
    {
        const string Prefix = "{DynamicResource ";
        const string Suffix = "}";
        Assert.StartsWith(Prefix, value, StringComparison.Ordinal);
        Assert.EndsWith(Suffix, value, StringComparison.Ordinal);
        return value[Prefix.Length..^Suffix.Length];
    }

    private static IEnumerable<string> SemanticConsumerLiteralViolations(XDocument document, string documentName)
    {
        foreach (XElement element in document.Descendants())
        {
            foreach ((string expectedElement, string property, string literal, string token) in SemanticConsumerTokens)
            {
                if (!MatchesSemanticConsumer(element, expectedElement, property, literal))
                {
                    continue;
                }

                yield return $"{documentName}: {element.Name.LocalName}.{property}=\"{literal}\" must use {{StaticResource {token}}}.";
            }
        }
    }

    private static bool MatchesSemanticConsumer(XElement element, string expectedElement, string property, string literal)
    {
        if (expectedElement != "*" && element.Name.LocalName != expectedElement)
        {
            return false;
        }

        if (Attribute(element, property) != literal)
        {
            return false;
        }

        if (expectedElement == "Image")
        {
            string? source = Attribute(element, "Source");
            return source?.StartsWith("{StaticResource Icon.Command.", StringComparison.Ordinal) == true ||
                source?.StartsWith("{StaticResource Icon.Status.", StringComparison.Ordinal) == true ||
                source == "{StaticResource Icon.Section.Certificate}";
        }

        return expectedElement != "Grid" || element.Parent == element.Document?.Root;
    }

    private static (double Red, double Green, double Blue) ParseColor(string value)
    {
        string hexadecimal = value.TrimStart('#');
        if (hexadecimal.Length is not 6 and not 8 || !uint.TryParse(hexadecimal, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint parsed))
        {
            throw new FormatException($"Unsupported color literal '{value}'.");
        }

        if (hexadecimal.Length == 8)
        {
            parsed &= 0x00FFFFFF;
        }

        return ((parsed >> 16) & 0xFF, (parsed >> 8) & 0xFF, parsed & 0xFF);
    }

    private static double ContrastRatio((double Red, double Green, double Blue) first, (double Red, double Green, double Blue) second)
    {
        double firstLuminance = RelativeLuminance(first);
        double secondLuminance = RelativeLuminance(second);
        return (Math.Max(firstLuminance, secondLuminance) + 0.05d) /
            (Math.Min(firstLuminance, secondLuminance) + 0.05d);
    }

    private static double RelativeLuminance((double Red, double Green, double Blue) color) =>
        (0.2126d * Linearize(color.Red)) +
        (0.7152d * Linearize(color.Green)) +
        (0.0722d * Linearize(color.Blue));

    private static double Linearize(double channel)
    {
        double normalized = channel / 255d;
        return normalized <= 0.04045d
            ? normalized / 12.92d
            : Math.Pow((normalized + 0.055d) / 1.055d, 2.4d);
    }

    private static string? Key(XElement element) => element.Attribute(XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml"))?.Value;

    private static string? Attribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
        ?.Value;

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
            throw new InvalidOperationException("STA WPF consumer-token assertion failed.", exception);
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
