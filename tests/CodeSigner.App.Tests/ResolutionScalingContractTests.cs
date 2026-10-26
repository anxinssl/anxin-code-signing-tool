using System.IO;
using System.Text.Json;
using System.Windows;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class ResolutionScalingContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string TaskOneBaselinePath = Path.Combine(
        RepositoryRoot,
        "tests",
        "fixtures",
        "ui-baseline",
        "baseline.json");
    private static readonly string MainWindowPath = ProductPath("MainWindow.xaml");
    private static readonly string MainWindowCodeBehindPath = ProductPath("MainWindow.xaml.cs");
    private static readonly string SettingsWindowPath = ProductPath("SettingsWindow.xaml");
    private static readonly string PrimitiveShowcasePath = ProductPath("PrimitiveShowcaseWindow.xaml");
    private static readonly string TaskOneShowcasePath = Path.Combine(
        RepositoryRoot,
        "tests",
        "fixtures",
        "ui-baseline",
        "PrimitiveShowcaseWindow.xaml");
    private static readonly string DesignTokensPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "Themes",
        "DesignTokens.xaml");

    [Fact]
    public void ResponsiveContractPreservesControlsWithQueueSpaceCorrection()
    {
        using JsonDocument baseline = LoadTaskOneBaseline();
        JsonElement resolutionScaling = baseline.RootElement
            .GetProperty("inventories")
            .GetProperty("resolutionScaling");
        string codeBehind = File.ReadAllText(MainWindowCodeBehindPath);

        foreach (JsonElement responsiveLine in resolutionScaling.GetProperty("responsiveLines").EnumerateArray())
        {
            string expected = responsiveLine.GetProperty("text").GetString()
                ?? throw new InvalidOperationException("Task 1 responsive source text is missing.");
            if (expected.Trim() == "SimplySignStatusText.Visibility = statusVisibility;")
            {
                Assert.DoesNotContain("SimplySignStatusText", codeBehind, StringComparison.Ordinal);
                continue;
            }
            if (expected.Trim() == "private void UpdateWatermarkVisibility() => WatermarkText.Visibility =")
            {
                Assert.DoesNotContain("UpdateWatermarkVisibility", codeBehind, StringComparison.Ordinal);
                continue;
            }
            // Replace only the obsolete fixed queue height and condensed threshold.
            expected = expected.Trim() switch
            {
                "CommandActionsPanel.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;" =>
                    "CommandActionsPanel.Visibility = Visibility.Visible;",
                "UltraCommandButtons.Visibility = ultraCompact ? Visibility.Visible : Visibility.Collapsed;" =>
                    "UltraCommandButtons.Visibility = Visibility.Collapsed;",
                "UpdateSummaryBindings(compact);" => "UpdateSummaryBindings(useCondensedActionRail);",
                "QueueBody.Height = ultraCompact" or
                ": compact && ActualHeight <= 500" or
                ": !compact && heightCondensed && ActualHeight >= 720" => "QueueBody.Height = double.NaN;",
                "bool compact = ActualWidth < CompactWidth || ActualHeight < CompactHeight;" =>
                    "bool compact = width < CompactWidth || height < CompactHeight;",
                "bool ultraCompact = compact && (ActualWidth < 560 || ActualHeight < 420);" =>
                    "bool ultraCompact = compact && (width < 560 || height < 420);",
                "bool heightCondensed = ActualHeight < 760;" => "bool heightCondensed = height < CondensedHeight;",
                "bool sideBySideCertificateSelection = IsCompactLayout || ActualHeight < 760;" =>
                    "bool sideBySideCertificateSelection = IsCompactLayout || height < CondensedHeight;",
                "SecondaryCertificateLabel.Visibility = !IsCompactLayout && ActualHeight >= 760 && viewModel.IsDualMode" =>
                    "SecondaryCertificateLabel.Visibility = !IsCompactLayout && height >= CondensedHeight && viewModel.IsDualMode",
                _ => expected
            };
            Assert.Contains(expected, codeBehind, StringComparison.Ordinal);
        }
        Assert.Contains("private const double CondensedHeight = 1000;", codeBehind, StringComparison.Ordinal);

        AssertWindowSizingMatchesTaskOne(resolutionScaling.GetProperty("windowSizing"));
        AssertShowcaseRootGridSizingMatchesTaskOne();
        Assert.Equal(
            ["private const double CompactWidth = 900;", "private const double CompactHeight = 620;"],
            codeBehind.Split('\n')
                .Select(static line => line.Trim())
                .Where(static line => line.StartsWith("private const double Compact", StringComparison.Ordinal))
                .ToArray());
    }

    [Fact]
    public void ExistingViewportMatrixAndResponsiveAutomationRouteRemainFrozen()
    {
        using JsonDocument baseline = LoadTaskOneBaseline();
        JsonElement resolutionScaling = baseline.RootElement
            .GetProperty("inventories")
            .GetProperty("resolutionScaling");

        (string Label, double WidthDip, double HeightDip, int? ScalePercent)[] actualViewports = resolutionScaling
            .GetProperty("planDeclaredViewportMatrix")
            .EnumerateArray()
            .Select(viewport => (
                viewport.GetProperty("label").GetString()
                    ?? throw new InvalidOperationException("Task 1 viewport label is missing."),
                viewport.GetProperty("widthDip").GetDouble(),
                viewport.GetProperty("heightDip").GetDouble(),
                viewport.TryGetProperty("scalePercent", out JsonElement scale) && scale.ValueKind != JsonValueKind.Null
                    ? scale.GetInt32()
                    : (int?)null))
            .ToArray();
        Assert.Equal(
            [
                ("normal", 992d, 736d, (int?)null),
                ("compact", 650.67d, 480d, (int?)150),
                ("ultra-compact", 480d, 352d, (int?)200),
            ],
            actualViewports);

        XDocument mainWindow = XDocument.Load(MainWindowPath);
        XElement fullRail = Named(mainWindow, "FullActionRail");
        XElement compactRail = Named(mainWindow, "CompactActionRail");
        Assert.Null(Attribute(fullRail, "Visibility"));
        Assert.Equal("Collapsed", Attribute(compactRail, "Visibility"));
        AssertActionRailOwnership(fullRail, "OutputRootTextBox");
        AssertActionRailOwnership(compactRail, "CompactOutputRootTextBox");

        string codeBehind = File.ReadAllText(MainWindowCodeBehindPath);
        Assert.Contains(
            "FullActionRail.Visibility = useCondensedActionRail ? Visibility.Collapsed : Visibility.Visible;",
            codeBehind,
            StringComparison.Ordinal);
        Assert.Contains(
            "CompactActionRail.Visibility = useCondensedActionRail ? Visibility.Visible : Visibility.Collapsed;",
            codeBehind,
            StringComparison.Ordinal);
        Assert.Contains(
            "if (FindAutomationElement(this, automationId) is FrameworkElement element)",
            codeBehind,
            StringComparison.Ordinal);
        Assert.Contains("element.Focus();", codeBehind, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolutionScalingMutationsAreRejectedWithLiteralDrift()
    {
        string breakpointFixture = File.ReadAllText(MainWindowCodeBehindPath).Replace(
            "private const double CompactWidth = 900;",
            "private const double CompactWidth = 901;",
            StringComparison.Ordinal);
        Assert.Contains("resolution-scaling-drift", Validate(breakpointFixture, Load(SettingsWindowPath), Load(PrimitiveShowcasePath), Load(MainWindowPath)));

        XDocument settingsResizeModeFixture = Load(SettingsWindowPath);
        settingsResizeModeFixture.Root!.SetAttributeValue("ResizeMode", "CanResize");
        Assert.Contains("resolution-scaling-drift", Validate(File.ReadAllText(MainWindowCodeBehindPath), settingsResizeModeFixture, Load(PrimitiveShowcasePath), Load(MainWindowPath)));

        XDocument showcaseDimensionFixture = Load(PrimitiveShowcasePath);
        showcaseDimensionFixture.Root!.SetAttributeValue("Height", "701");
        Assert.Contains("resolution-scaling-drift", Validate(File.ReadAllText(MainWindowCodeBehindPath), Load(SettingsWindowPath), showcaseDimensionFixture, Load(MainWindowPath)));

        XDocument actionVisibilityFixture = Load(MainWindowPath);
        Named(actionVisibilityFixture, "CompactActionRail").SetAttributeValue("Visibility", "Visible");
        Assert.Contains("resolution-scaling-drift", Validate(File.ReadAllText(MainWindowCodeBehindPath), Load(SettingsWindowPath), Load(PrimitiveShowcasePath), actionVisibilityFixture));
    }

    private static void AssertWindowSizingMatchesTaskOne(JsonElement windows)
    {
        foreach (JsonElement expectedWindow in windows.EnumerateArray())
        {
            string relativePath = expectedWindow.GetProperty("path").GetString()
                ?? throw new InvalidOperationException("Task 1 window path is missing.");
            string absolutePath = Path.Combine(RepositoryRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
            XElement actualWindow = Load(absolutePath).Root
                ?? throw new InvalidOperationException($"Window root is missing: {relativePath}");

            foreach (JsonProperty expectedAttribute in expectedWindow.GetProperty("attributes").EnumerateObject())
            {
                string? actual = Attribute(actualWindow, expectedAttribute.Name);
                string? expected = expectedAttribute.Value.ValueKind == JsonValueKind.Null
                    ? null
                    : expectedAttribute.Value.GetString();
                if (relativePath == "src/CodeSigner.App/SettingsWindow.xaml" &&
                    expectedAttribute.Name == "WindowStartupLocation")
                {
                    expected = "CenterScreen";
                }

                Assert.Equal(expected, actual);
            }
        }
    }

    private static void AssertShowcaseRootGridSizingMatchesTaskOne()
    {
        XElement baselineGrid = RootGrid(Load(TaskOneShowcasePath));
        XElement currentGrid = RootGrid(Load(PrimitiveShowcasePath));
        AssertWindowContentInset(currentGrid);
        Assert.Equal(
            SizingAttributesWithResolvedRootInset(baselineGrid),
            SizingAttributesWithResolvedRootInset(currentGrid));
        Assert.Equal(
            RootGridDefinitions(baselineGrid)
                .Select(element => $"{element.Name.LocalName}:{Attribute(element, "Height")}:{Attribute(element, "Width")}")
                .ToArray(),
            RootGridDefinitions(currentGrid)
                .Select(element => $"{element.Name.LocalName}:{Attribute(element, "Height")}:{Attribute(element, "Width")}")
                .ToArray());
    }

    private static string Validate(
        string codeBehind,
        XDocument settingsWindow,
        XDocument primitiveShowcase,
        XDocument mainWindow)
    {
        bool valid = codeBehind.Contains("private const double CompactWidth = 900;", StringComparison.Ordinal) &&
            codeBehind.Contains("private const double CompactHeight = 620;", StringComparison.Ordinal) &&
            codeBehind.Contains("bool ultraCompact = compact && (width < 560 || height < 420);", StringComparison.Ordinal) &&
            codeBehind.Contains("FullActionRail.Visibility = useCondensedActionRail ? Visibility.Collapsed : Visibility.Visible;", StringComparison.Ordinal) &&
            codeBehind.Contains("CompactActionRail.Visibility = useCondensedActionRail ? Visibility.Visible : Visibility.Collapsed;", StringComparison.Ordinal) &&
            codeBehind.Contains("QueueGrid.RowHeight = compact && !ultraCompact ? 46 : 50;", StringComparison.Ordinal) &&
            codeBehind.Contains("QueueGrid.ColumnHeaderHeight = compact && !ultraCompact ? 34 : 36;", StringComparison.Ordinal) &&
            Attribute(settingsWindow.Root!, "Width") == "520" &&
            Attribute(settingsWindow.Root!, "SizeToContent") == "Height" &&
            Attribute(settingsWindow.Root!, "ResizeMode") == "NoResize" &&
            Attribute(settingsWindow.Root!, "WindowStartupLocation") == "CenterScreen" &&
            Attribute(primitiveShowcase.Root!, "Width") == "900" &&
            Attribute(primitiveShowcase.Root!, "Height") == "700" &&
            Attribute(primitiveShowcase.Root!, "WindowStartupLocation") == "CenterScreen" &&
            Attribute(Named(mainWindow, "CompactActionRail"), "Visibility") == "Collapsed" &&
            Attribute(Named(mainWindow, "FullActionRail"), "Visibility") is null;
        return valid ? "resolution-scaling-parity" : "resolution-scaling-drift";
    }

    private static void AssertActionRailOwnership(XElement rail, string outputOwnerName)
    {
        Assert.Single(rail.Descendants(), element => Attribute(element, "Name") == outputOwnerName);
        foreach (string automationId in new[] { "OutputRootTextBox", "AggregateProgress", "SignButton", "CancelButton" })
        {
            Assert.Single(rail.Descendants(), element => Attribute(element, "AutomationProperties.AutomationId") == automationId);
        }
    }

    private static XElement Named(XDocument document, string name) => Assert.Single(document.Descendants(), element =>
        Attribute(element, "Name") == name);

    private static XElement RootGrid(XDocument document) => Assert.Single(document.Root!.Elements(), element =>
        element.Name.LocalName == "Grid");

    private static IEnumerable<XElement> RootGridDefinitions(XElement grid) => grid.Elements()
        .Where(element => element.Name.LocalName is "Grid.RowDefinitions" or "Grid.ColumnDefinitions")
        .SelectMany(static definitions => definitions.Elements());

    private static void AssertWindowContentInset(XElement grid)
    {
        Assert.Equal("{StaticResource Inset.Window.Content}", Attribute(grid, "Margin"));

        XDocument tokens = Load(DesignTokensPath);
        XElement inset = Assert.Single(tokens.Root!.Elements(), element =>
            element.Name.LocalName == "Thickness" &&
            Key(element) == "Inset.Window.Content");
        Thickness thickness = Assert.IsType<Thickness>(
            new ThicknessConverter().ConvertFromInvariantString(inset.Value));
        Assert.Equal(16d, thickness.Left);
        Assert.Equal(16d, thickness.Top);
        Assert.Equal(16d, thickness.Right);
        Assert.Equal(16d, thickness.Bottom);
    }

    private static string[] SizingAttributesWithResolvedRootInset(XElement element) => element.Attributes()
        .Where(attribute => attribute.Name.LocalName is "Margin" or "Padding" or "Width" or "Height" or "MinWidth" or "MinHeight" or "MaxWidth" or "MaxHeight")
        .Select(attribute => attribute.Name.LocalName == "Margin" &&
            attribute.Value == "{StaticResource Inset.Window.Content}"
                ? "Margin=16"
                : $"{attribute.Name.LocalName}={attribute.Value}")
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static string? Attribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
        ?.Value;

    private static string? Key(XElement element) => element.Attribute(
        XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml"))?.Value;

    private static XDocument Load(string path) => XDocument.Load(path, LoadOptions.SetLineInfo);

    private static JsonDocument LoadTaskOneBaseline() => JsonDocument.Parse(File.ReadAllText(TaskOneBaselinePath));

    private static string ProductPath(string fileName) => Path.Combine(RepositoryRoot, "src", "CodeSigner.App", fileName);

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
