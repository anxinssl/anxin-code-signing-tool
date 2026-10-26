using System.IO;
using System.Reflection;
using System.Windows;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class PrimitiveShowcaseContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string ShowcasePath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "PrimitiveShowcaseWindow.xaml");
    private static readonly string DesignTokensPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "Themes",
        "DesignTokens.xaml");
    private static readonly string AppStartupPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "App.xaml.cs");
    private static readonly string ShowcaseCodeBehindPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "PrimitiveShowcaseWindow.xaml.cs");

    [Fact]
    public void ShowcasePreservesFixedStartupAndGridSizingContract()
    {
        string source = File.ReadAllText(ShowcasePath);
        XDocument showcase = LoadShowcase();
        XElement window = showcase.Root ?? throw new InvalidOperationException("Showcase root is missing.");
        XElement grid = Assert.Single(window.Elements(), element => element.Name.LocalName == "Grid");

        Assert.Equal("900", Attribute(window, "Width"));
        Assert.Equal("700", Attribute(window, "Height"));
        Assert.Equal("CenterScreen", Attribute(window, "WindowStartupLocation"));
        AssertWindowContentInset(grid);
        Assert.Equal(
            ["Auto", "Auto", "Auto", "Auto", "*", "Auto"],
            grid.Element(grid.Name.Namespace + "Grid.RowDefinitions")!.Elements()
                .Where(element => element.Name.LocalName == "RowDefinition")
                .Select(element => Attribute(element, "Height") ?? string.Empty)
                .ToArray());
        Assert.DoesNotContain("SizeToContent", source, StringComparison.Ordinal);
        Assert.DoesNotContain("MinWidth", source, StringComparison.Ordinal);
        Assert.DoesNotContain("MaxWidth", source, StringComparison.Ordinal);
        Assert.DoesNotContain("MinHeight", source, StringComparison.Ordinal);
        Assert.DoesNotContain("MaxHeight", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Dpi", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Responsive", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ShowcaseContainsEveryDeterministicAccessibilityStateFamily()
    {
        XDocument showcase = LoadShowcase();

        AssertSingleNamedHeading(showcase, "PrimitiveReadinessHeading");
        AssertSingleNamedHeading(showcase, "PrimitiveCommandStatesHeading");
        AssertSingleNamedHeading(showcase, "PrimitiveSigningModeHeading");
        AssertSingleNamedHeading(showcase, "PrimitiveCertificateHeading");
        AssertSingleNamedHeading(showcase, "PrimitiveQueueHeading");
        AssertSingleNamedHeading(showcase, "PrimitiveProgressHeading");

        AssertSingleAutomationElement(showcase, "PrimitiveReadiness");
        AssertSingleAutomationElement(showcase, "PrimitiveCommandButton");
        AssertSingleAutomationElement(showcase, "PrimitiveDisabledCommand");
        AssertSingleAutomationElement(showcase, "PrimitiveModeSingle");
        AssertSingleAutomationElement(showcase, "PrimitiveModeDual");
        AssertSingleAutomationElement(showcase, "PrimitiveCertificateCombo");
        AssertSingleAutomationElement(showcase, "PrimitiveValidationText");
        AssertSingleAutomationElement(showcase, "PrimitiveDataGrid");
        AssertSingleAutomationElement(showcase, "PrimitiveProgress");
        AssertSingleAutomationElement(showcase, "PrimitivePrimaryAction");
        AssertSingleAutomationElement(showcase, "PrimitiveDisabledPrimaryAction");
    }

    [Fact]
    public void ShowcaseUsesSharedTokensWithOwnedCertificateLabelAndSingleLiveOwners()
    {
        XDocument showcase = LoadShowcase();

        Assert.Contains(showcase.Descendants(), element =>
            element.Name.LocalName == "Border" &&
            Attribute(element, "Style") == "{StaticResource BandBorderStyle}");
        Assert.Contains(showcase.Descendants(), element =>
            element.Name.LocalName == "Button" &&
            Attribute(element, "Style") == "{StaticResource CommandButtonStyle}");
        Assert.Contains(showcase.Descendants(), element =>
            element.Name.LocalName == "RadioButton" &&
            Attribute(element, "Style") == "{StaticResource SegmentedRadioButtonStyle}");
        Assert.Contains(showcase.Descendants(), element =>
            element.Name.LocalName == "ComboBox" &&
            Attribute(element, "Style") == "{StaticResource CertificateComboBoxStyle}");
        Assert.Contains(showcase.Descendants(), element =>
            element.Name.LocalName == "DataGrid" &&
            Attribute(element, "Style") == "{StaticResource WorkbenchDataGridStyle}");
        Assert.Contains(showcase.Descendants(), element =>
            element.Name.LocalName == "Button" &&
            Attribute(element, "Style") == "{StaticResource PrimaryActionButtonStyle}");

        XElement certificateLabel = Assert.Single(showcase.Descendants(), element =>
            element.Name.LocalName == "Label" &&
            Attribute(element, "Target") == "{Binding ElementName=PrimitiveCertificateCombo}");
        Assert.Equal("证书", Attribute(certificateLabel, "Content"));
        Assert.Single(showcase.Descendants(), element => Attribute(element, "Name") == "PrimitiveCertificateCombo");

        AssertSingleLiveOwner(showcase, "PrimitiveValidationMessage", "Assertive");
        AssertSingleLiveOwner(showcase, "PrimitiveProgressMessage", "Polite");
    }

    [Fact]
    public void ShowcaseVisibleAutomationIdsAreUniqueAndQueueRowsUseBoundDeterministicIds()
    {
        XDocument showcase = LoadShowcase();

        Assert.Empty(VisibleAutomationIdDuplicates(showcase));

        XElement rowStyle = Assert.Single(showcase.Descendants(), element =>
            element.Name.LocalName == "Style" &&
            Attribute(element, "TargetType") == "DataGridRow");
        XElement rowIdSetter = Assert.Single(rowStyle.Elements(), element =>
            element.Name.LocalName == "Setter" &&
            Attribute(element, "Property") == "AutomationProperties.AutomationId");
        Assert.Null(Attribute(rowIdSetter, "Value"));
        XElement rowIdBinding = Assert.Single(rowIdSetter.Descendants(), element => element.Name.LocalName == "Binding");
        Assert.Equal("Id", Attribute(rowIdBinding, "Path"));
        Assert.Equal("PrimitiveQueueRow_{0}", Attribute(rowIdBinding, "StringFormat"));
    }

    [Fact]
    public void ShowcaseSampleDataAndAccessibleQueueCopyAreGenericAndMultiFormat()
    {
        string codeBehindSource = File.ReadAllText(ShowcaseCodeBehindPath);
        string showcaseSource = File.ReadAllText(ShowcasePath);
        object[] sampleRows = GetProductionSampleRows();

        Assert.DoesNotContain(".exe", codeBehindSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(".exe", showcaseSource, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, sampleRows.Length);
        Assert.Contains(sampleRows, row => ReadProperty(row, "Path").EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(sampleRows, row => ReadProperty(row, "Path").EndsWith(".cat", StringComparison.OrdinalIgnoreCase));

        XDocument showcase = LoadShowcase();
        XElement queue = AssertSingleAutomationElement(showcase, "PrimitiveDataGrid");
        Assert.Equal("签名文件队列", AttachedAttribute(queue, "Name"));
        Assert.Equal("每行对应一个支持的签名文件", AttachedAttribute(queue, "HelpText"));
        Assert.Equal("显示每个签名项目的状态、进度和结果", Attribute(queue, "ToolTip"));
    }

    [Fact]
    public void ProductionRowBindingProducesUniqueAutomationIdsForEqualPathRows()
    {
        XDocument showcase = LoadShowcase();
        XElement rowStyle = Assert.Single(showcase.Descendants(), element =>
            element.Name.LocalName == "Style" &&
            Attribute(element, "TargetType") == "DataGridRow");
        XElement rowIdSetter = Assert.Single(rowStyle.Elements(), element =>
            element.Name.LocalName == "Setter" &&
            Attribute(element, "Property") == "AutomationProperties.AutomationId");
        XElement rowIdBinding = Assert.Single(rowIdSetter.Descendants(), element => element.Name.LocalName == "Binding");
        object[] samples = GetProductionSampleRows();
        Type rowType = samples[0].GetType();
        Assert.All(["Id", "Path", "State", "Progress", "Result"], propertyName =>
            Assert.NotNull(rowType.GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)));
        ConstructorInfo constructor = Assert.Single(rowType.GetConstructors(), constructor =>
            constructor.GetParameters().Length == 5 &&
            constructor.GetParameters().All(parameter => parameter.ParameterType == typeof(string)));
        object first = constructor.Invoke(["same-path-first", @"C:\release\same-library.dll", "待处理", "0%", "等待签名"]);
        object second = constructor.Invoke(["same-path-second", @"C:\release\same-library.dll", "待处理", "0%", "等待签名"]);

        Assert.Equal(ReadProperty(first, "Path"), ReadProperty(second, "Path"));
        string[] automationIds = [
            FormatProductionRowAutomationId(rowIdBinding, first),
            FormatProductionRowAutomationId(rowIdBinding, second)
        ];

        Assert.Equal(2, automationIds.Distinct(StringComparer.Ordinal).Count());
        Assert.All(automationIds, automationId => Assert.StartsWith("PrimitiveQueueRow_", automationId, StringComparison.Ordinal));
    }

    [Fact]
    public void TwoRowFixtureWithConstantAutomationIdIsRejectedAsDuplicate()
    {
        XDocument fixture = XDocument.Parse(
            """
            <StackPanel xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                        xmlns:automation="clr-namespace:System.Windows.Automation;assembly=PresentationCore">
                <DataGridRow automation:AutomationProperties.AutomationId="PrimitiveQueueRow" />
                <DataGridRow automation:AutomationProperties.AutomationId="PrimitiveQueueRow" />
            </StackPanel>
            """);

        Assert.Equal(
            ["Visible AutomationId 'PrimitiveQueueRow' must be unique."],
            VisibleAutomationIdDuplicates(fixture));
    }

    [Fact]
    public void ShowcaseUsesCurrentGenericAccessibleCopyAndNoProductionSigningDependency()
    {
        string source = File.ReadAllText(ShowcasePath);
        XDocument showcase = XDocument.Parse(source, LoadOptions.SetLineInfo);

        Assert.DoesNotContain(".exe", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Worker", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Provider", source, StringComparison.Ordinal);
        Assert.DoesNotContain("SigningAdapter", source, StringComparison.Ordinal);
        Assert.Contains(showcase.Descendants(), element =>
            Attribute(element, "AutomationProperties.Name") == "签名文件队列");
        Assert.Contains(showcase.Descendants(), element =>
            Attribute(element, "AutomationProperties.HelpText") == "每行对应一个支持的签名文件");
    }

    [Fact]
    public void PrimitiveShowcaseLaunchSwitchRemainsExactAndSeparateFromProductionComposition()
    {
        string startupSource = File.ReadAllText(AppStartupPath);

        Assert.Contains(
            "e.Args.Contains(\"--primitive-showcase\", StringComparer.Ordinal)",
            startupSource,
            StringComparison.Ordinal);
        Assert.Contains("MainWindow = new PrimitiveShowcaseWindow();", startupSource, StringComparison.Ordinal);
        Assert.Contains("MainWindow = new MainWindow();", startupSource, StringComparison.Ordinal);
    }

    private static void AssertSingleNamedHeading(XDocument document, string name)
    {
        XElement heading = Assert.Single(document.Descendants(), element => Attribute(element, "Name") == name);
        Assert.Equal("Level2", AttachedAttribute(heading, "HeadingLevel"));
    }

    private static XElement AssertSingleAutomationElement(XDocument document, string automationId) =>
        Assert.Single(document.Descendants(), element => AttachedAttribute(element, "AutomationId") == automationId);

    private static void AssertSingleLiveOwner(XDocument document, string messageName, string setting)
    {
        XElement message = Assert.Single(document.Descendants(), element => Attribute(element, "Name") == messageName);
        XElement owner = Assert.Single(message.AncestorsAndSelf(), HasNonOffLiveSetting);
        Assert.Equal(setting, AttachedAttribute(owner, "LiveSetting"));
    }

    private static string[] VisibleAutomationIdDuplicates(XDocument document) => document
        .Descendants()
        .Select(element => AttachedAttribute(element, "AutomationId"))
        .Where(static automationId => !string.IsNullOrWhiteSpace(automationId))
        .GroupBy(automationId => automationId!, StringComparer.Ordinal)
        .Where(group => group.Count() > 1)
        .Select(group => $"Visible AutomationId '{group.Key}' must be unique.")
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static bool HasNonOffLiveSetting(XElement element) =>
        !string.Equals(AttachedAttribute(element, "LiveSetting"), "Off", StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(AttachedAttribute(element, "LiveSetting"));

    private static XDocument LoadShowcase() => XDocument.Load(ShowcasePath, LoadOptions.SetLineInfo);

    private static void AssertWindowContentInset(XElement grid)
    {
        Assert.Equal("{StaticResource Inset.Window.Content}", Attribute(grid, "Margin"));

        XDocument tokens = XDocument.Load(DesignTokensPath);
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

    private static object[] GetProductionSampleRows()
    {
        FieldInfo sampleRows = typeof(CodeSigner.App.PrimitiveShowcaseWindow).GetField(
            "SampleRows",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("Primitive showcase sample rows must be declared as production data.");
        return ((System.Collections.IEnumerable)sampleRows.GetValue(null)!).Cast<object>().ToArray();
    }

    private static string FormatProductionRowAutomationId(XElement binding, object row)
    {
        string path = Attribute(binding, "Path")
            ?? throw new InvalidOperationException("Row AutomationId binding path is missing.");
        string format = Attribute(binding, "StringFormat")
            ?? throw new InvalidOperationException("Row AutomationId binding format is missing.");
        return string.Format(System.Globalization.CultureInfo.InvariantCulture, format, ReadProperty(row, path));
    }

    private static string ReadProperty(object row, string propertyName) => row.GetType()
        .GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)
        ?.GetValue(row)?.ToString()
        ?? throw new InvalidOperationException($"Primitive showcase row property '{propertyName}' is missing.");

    private static string? Attribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
        ?.Value;

    private static string? Key(XElement element) => element.Attribute(
        XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml"))?.Value;

    private static string? AttachedAttribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName.EndsWith($".{localName}", StringComparison.Ordinal))
        ?.Value;

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
