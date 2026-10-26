using System.IO;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class SettingsWindowXamlContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string SettingsWindowPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "SettingsWindow.xaml");
    private static readonly string SettingsWindowCodeBehindPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "SettingsWindow.xaml.cs");
    private static readonly string BaselineDirectory = Path.Combine(
        RepositoryRoot,
        "tests",
        "fixtures",
        "ui-baseline");
    private static readonly XDocument SettingsWindow = XDocument.Load(SettingsWindowPath);
    private static readonly XDocument BaselineSettingsWindow = XDocument.Load(
        Path.Combine(BaselineDirectory, "SettingsWindow.xaml"));

    [Fact]
    public void FixedWindowSizingStartupAndScalingBoundaryArePreserved()
    {
        Assert.Empty(ValidateSizingPolicy(SettingsWindow, File.ReadAllText(SettingsWindowPath)));

        XDocument sizingMutation = Clone(SettingsWindow);
        sizingMutation.Root!.SetAttributeValue("Width", "521");
        Assert.Equal(
            ["settings-sizing-drift: Width must remain 520."],
            ValidateSizingPolicy(sizingMutation, sizingMutation.ToString(SaveOptions.DisableFormatting)));

        XDocument startupMutation = Clone(SettingsWindow);
        startupMutation.Root!.SetAttributeValue("WindowStartupLocation", "CenterOwner");
        Assert.Equal(
            ["settings-sizing-drift: WindowStartupLocation must remain CenterScreen."],
            ValidateSizingPolicy(startupMutation, startupMutation.ToString(SaveOptions.DisableFormatting)));

        string branchMutation = File.ReadAllText(SettingsWindowPath) + "\n<!-- Dpi responsive branch -->";
        Assert.Equal(
            ["settings-sizing-drift: DPI or responsive branch is not allowed."],
            ValidateSizingPolicy(SettingsWindow, branchMutation));
    }

    [Fact]
    public void InputLabelsOwnTimestampAndRetentionControls()
    {
        AssertLabelOwnsControl("TimestampUriLabel", "TimestampUriTextBox", "SettingsTimestampUri");
        AssertLabelOwnsControl("RetentionLabel", "RetentionComboBox", "SettingsRetention");
    }

    [Fact]
    public void TaskOneSettingsFixtureIsRejectedBeforeLabelAndTokenRefactor()
    {
        Assert.Equal(
            [
                "settings-accessibility-drift: retention input must be owned by a Label.",
                "settings-accessibility-drift: timestamp input must be owned by a Label.",
                "settings-token-drift: retention input must use SettingsComboBoxStyle.",
                "settings-token-drift: timestamp input must use SettingsTextInputStyle."
            ],
            ValidateLabelAndTokenContract(BaselineSettingsWindow));
    }

    [Fact]
    public void SharedTokenStylesProvideSpacingColorTypeAndFocusTreatment()
    {
        Assert.Empty(ValidateLabelAndTokenContract(SettingsWindow));
        Assert.Equal("{StaticResource Inset.Settings.Content}", Attribute(Named("SettingsRootGrid"), "Margin"));
        Assert.Equal("{StaticResource SettingsTextInputStyle}", Attribute(Named("TimestampUriTextBox"), "Style"));
        Assert.Equal("{StaticResource SettingsComboBoxStyle}", Attribute(Named("RetentionComboBox"), "Style"));
        Assert.Equal("{StaticResource CommandButtonStyle}", Attribute(Automation("SettingsDetectSdkSignToolButton"), "Style"));
        Assert.Equal("{StaticResource CommandButtonStyle}", Attribute(Automation("SettingsCancelButton"), "Style"));
        Assert.Equal("{StaticResource PrimaryActionButtonStyle}", Attribute(Automation("SettingsOkButton"), "Style"));
        Assert.Equal("{StaticResource CommandButtonStyle}", Attribute(Automation("SettingsUninstallButton"), "Style"));

        foreach (string styleKey in new[] { "SettingsTextInputStyle", "SettingsComboBoxStyle", "SettingsSectionLabelStyle" })
        {
            XElement style = Style(styleKey);
            Assert.Contains(style.DescendantsAndSelf().Attributes(), attribute =>
                attribute.Value.Contains("Metric.Control.Height", StringComparison.Ordinal) ||
                attribute.Value.Contains("Typography.Body.Size", StringComparison.Ordinal) ||
                attribute.Value.Contains("Color.Text.Primary", StringComparison.Ordinal));
        }

        foreach (string styleKey in new[] { "SettingsTextInputStyle", "SettingsComboBoxStyle" })
        {
            XElement focusTrigger = Assert.Single(Style(styleKey).Descendants(), element =>
                element.Name.LocalName == "Trigger" &&
                Attribute(element, "Property") == "IsKeyboardFocused" &&
                Attribute(element, "Value") == "True");
            Assert.Contains(focusTrigger.Elements(), element =>
                element.Name.LocalName == "Setter" &&
                Attribute(element, "Property") == "BorderBrush" &&
                Attribute(element, "Value") == "{DynamicResource Color.Focus.Ring}");
        }
    }

    [Fact]
    public void AutomationAndBehavioralContractsRemainUnchanged()
    {
        foreach (string attributeName in new[]
                 {
                     "AutomationProperties.AutomationId",
                     "AutomationProperties.Name",
                     "Click",
                     "Command"
                 })
        {
            Assert.Equal(AttributeInventory(BaselineSettingsWindow, attributeName), AttributeInventory(SettingsWindow, attributeName));
        }
        foreach (string attributeName in new[] { "AutomationProperties.HelpText", "ToolTip" })
        {
            Assert.Equal(
                AttributeInventory(BaselineSettingsWindow, attributeName)
                    .Select(value => value.Replace("代码签名工具", "安信代码签名证书工具", StringComparison.Ordinal))
                    .Order(StringComparer.Ordinal)
                    .ToArray(),
                AttributeInventory(SettingsWindow, attributeName));
        }

        string[] automationIds = SettingsWindow.Descendants()
            .Select(element => Attribute(element, "AutomationProperties.AutomationId"))
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray();
        Assert.Equal(automationIds.Length, automationIds.Distinct(StringComparer.Ordinal).Count());

        XElement validation = Named("ValidationText");
        XElement validationOwner = Assert.Single(validation.AncestorsAndSelf(), HasNonOffLiveSetting);
        Assert.Same(validation, validationOwner);
        Assert.Equal("Assertive", Attribute(validationOwner, "AutomationProperties.LiveSetting"));

        Assert.Equal("True", Attribute(Automation("SettingsOkButton"), "IsDefault"));
        Assert.Equal("True", Attribute(Automation("SettingsCancelButton"), "IsCancel"));
        Assert.Equal("Ok_Click", Attribute(Automation("SettingsOkButton"), "Click"));
        Assert.Equal("Uninstall_Click", Attribute(Automation("SettingsUninstallButton"), "Click"));
        Assert.Equal("{Binding RefreshSdkSignToolCommand}", Attribute(Automation("SettingsDetectSdkSignToolButton"), "Command"));
        Assert.Equal("时间戳", Attribute(Named("TimestampUriLabel"), "Content"));
        Assert.Equal("诊断保留期", Attribute(Named("RetentionLabel"), "Content"));

        string codeBehind = File.ReadAllText(SettingsWindowCodeBehindPath);
        Assert.Contains("ContentRendered += OnContentRendered;", codeBehind, StringComparison.Ordinal);
        Assert.Contains("private void OnContentRendered", codeBehind, StringComparison.Ordinal);
        Assert.Contains("Activate();", codeBehind, StringComparison.Ordinal);
        Assert.Contains("Topmost = true;", codeBehind, StringComparison.Ordinal);
        Assert.Contains("Topmost = false;", codeBehind, StringComparison.Ordinal);
        Assert.Equal("CenterScreen", Attribute(SettingsWindow.Root!, "WindowStartupLocation"));
        Assert.Equal("True", Attribute(SettingsWindow.Root!, "ShowInTaskbar"));
        Assert.Equal(
            "从计算机中卸载安信代码签名证书工具",
            Attribute(Automation("SettingsUninstallButton"), "AutomationProperties.HelpText"));
    }

    private static void AssertLabelOwnsControl(string labelName, string controlName, string automationId)
    {
        XElement label = Named(labelName);
        XElement control = Named(controlName);
        Assert.Equal("Label", label.Name.LocalName);
        Assert.Equal($"{{Binding ElementName={controlName}}}", Attribute(label, "Target"));
        Assert.Equal(automationId, Attribute(control, "AutomationProperties.AutomationId"));
        Assert.Equal($"{{x:Reference {labelName}}}", Attribute(control, "AutomationProperties.LabeledBy"));
    }

    private static string[] ValidateSizingPolicy(XDocument document, string xaml) =>
    [
        .. ValidateRootAttribute(document, "Width", "520", "Width must remain 520."),
        .. ValidateRootAttribute(document, "SizeToContent", "Height", "SizeToContent must remain Height."),
        .. ValidateRootAttribute(document, "ResizeMode", "NoResize", "ResizeMode must remain NoResize."),
        .. ValidateRootAttribute(
            document,
            "WindowStartupLocation",
            "CenterScreen",
            "WindowStartupLocation must remain CenterScreen."),
        .. document.Root!.Attributes()
            .Where(attribute => attribute.Name.LocalName is "MinWidth" or "MinHeight" or "MaxWidth" or "MaxHeight")
            .Select(attribute => $"settings-sizing-drift: window sizing policy must not add {attribute.Name.LocalName}."),
        .. ValidateDpiOrResponsiveBranch(xaml)
    ];

    private static IEnumerable<string> ValidateRootAttribute(
        XDocument document,
        string name,
        string expected,
        string message) => Attribute(document.Root!, name) == expected
            ? []
            : [$"settings-sizing-drift: {message}"];

    private static string[] ValidateLabelAndTokenContract(XDocument document)
    {
        var violations = new List<string>();
        if (Attribute(Named(document, "TimestampUriTextBox"), "Style") != "{StaticResource SettingsTextInputStyle}")
        {
            violations.Add("settings-token-drift: timestamp input must use SettingsTextInputStyle.");
        }

        if (Attribute(Named(document, "RetentionComboBox"), "Style") != "{StaticResource SettingsComboBoxStyle}")
        {
            violations.Add("settings-token-drift: retention input must use SettingsComboBoxStyle.");
        }

        if (!HasOwningLabel(document, "TimestampUriLabel", "TimestampUriTextBox"))
        {
            violations.Add("settings-accessibility-drift: timestamp input must be owned by a Label.");
        }

        if (!HasOwningLabel(document, "RetentionLabel", "RetentionComboBox"))
        {
            violations.Add("settings-accessibility-drift: retention input must be owned by a Label.");
        }

        return violations.Order(StringComparer.Ordinal).ToArray();
    }

    private static string[] ValidateDpiOrResponsiveBranch(string xaml) =>
        xaml.Contains("dpi", StringComparison.OrdinalIgnoreCase) ||
        xaml.Contains("responsive", StringComparison.OrdinalIgnoreCase)
            ? new[] { "settings-sizing-drift: DPI or responsive branch is not allowed." }
            : Array.Empty<string>();

    private static XElement Named(string name) => Assert.Single(SettingsWindow.Descendants(), element => Attribute(element, "Name") == name);

    private static XElement Named(XDocument document, string name) => Assert.Single(document.Descendants(), element => Attribute(element, "Name") == name);

    private static XElement Automation(string automationId) => Assert.Single(SettingsWindow.Descendants(), element =>
        Attribute(element, "AutomationProperties.AutomationId") == automationId);

    private static XElement Style(string key) => Assert.Single(SettingsWindow.Descendants(), element =>
        element.Name.LocalName == "Style" && Attribute(element, "Key") == key);

    private static bool HasNonOffLiveSetting(XElement element)
    {
        string? value = Attribute(element, "AutomationProperties.LiveSetting");
        return !string.IsNullOrWhiteSpace(value) && !string.Equals(value, "Off", StringComparison.Ordinal);
    }

    private static bool HasOwningLabel(XDocument document, string labelName, string controlName)
    {
        XElement? label = document.Descendants().SingleOrDefault(element => Attribute(element, "Name") == labelName);
        XElement? control = document.Descendants().SingleOrDefault(element => Attribute(element, "Name") == controlName);
        return label is not null && control is not null &&
            label.Name.LocalName == "Label" &&
            Attribute(label, "Target") == $"{{Binding ElementName={controlName}}}" &&
            Attribute(control, "AutomationProperties.LabeledBy") == $"{{x:Reference {labelName}}}";
    }

    private static string[] AttributeInventory(XDocument document, string attributeName) => document.Descendants()
        .SelectMany(element => element.Attributes())
        .Where(attribute => attribute.Name.LocalName == attributeName)
        .Select(attribute => attribute.Value)
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static string? Attribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
        ?.Value;

    private static XDocument Clone(XDocument document) => XDocument.Parse(document.ToString(SaveOptions.DisableFormatting));

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
