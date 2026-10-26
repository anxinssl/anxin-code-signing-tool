using System.Globalization;
using System.IO;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class UiAccessibilityContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly XDocument MainWindow = LoadXaml("src", "CodeSigner.App", "MainWindow.xaml");
    private static readonly XDocument DesignTokens = LoadXaml(
        "src",
        "CodeSigner.App",
        "Themes",
        "DesignTokens.xaml");
    private static readonly string MainWindowCodeBehind = File.ReadAllText(
        Path.Combine(RepositoryRoot, "src", "CodeSigner.App", "MainWindow.xaml.cs"));

    private static readonly string[] ExpectedShortcutClauses =
    [
        "key == Key.Delete && QueueGrid.IsKeyboardFocusWithin",
        "key == Key.F5",
        "key == Key.O && modifiers == ModifierKeys.Control",
        "key == Key.O && modifiers == (ModifierKeys.Control | ModifierKeys.Shift)",
        "key == Key.R && modifiers == (ModifierKeys.Control | ModifierKeys.Shift)",
        "key == Key.W && modifiers == (ModifierKeys.Control | ModifierKeys.Shift)",
        "key == Key.R && modifiers == ModifierKeys.Control",
        "key == Key.E && modifiers == (ModifierKeys.Control | ModifierKeys.Shift)",
        "key == Key.A && modifiers == ModifierKeys.Alt",
        "key == Key.L && modifiers == ModifierKeys.Alt",
        "key == Key.O && modifiers == ModifierKeys.Alt",
        "key == Key.G && modifiers == ModifierKeys.Alt",
        "key == Key.S && modifiers == ModifierKeys.Alt",
        "key == Key.Escape && viewModel.IsBusy"
    ];

    [Fact]
    public void ReadinessStatusImagesAreDecorativeAndExcludedFromControlPeers()
    {
        string[] readinessAutomationIds =
        [
            "ReadinessWorkstation",
            "ReadinessNativeApi",
            "ReadinessCertificates",
            "TimestampStatus"
        ];

        XElement[] readinessImages = readinessAutomationIds
            .Select(AutomationElement)
            .ToArray();

        Assert.All(readinessImages, image =>
        {
            Assert.Equal("Image", image.Name.LocalName);
            AssertExcludedFromControlPeer(image);
        });
        Assert.Empty(ValidateDecorativeImages(readinessImages));
    }

    [Fact]
    public void WorkerRecoveryMessageHasExactlyOneLiveRegionOwner()
    {
        XElement message = Named("WorkerRecoveryMessageText");
        string[] owners = message
            .AncestorsAndSelf()
            .Where(HasNonOffLiveSetting)
            .Select(Describe)
            .ToArray();

        Assert.Single(owners);
        Assert.Equal("WorkerRecoveryRegion", owners[0]);
    }

    [Fact]
    public void MainWindowUsesSupportedHeadingAndLabelRelationships()
    {
        Assert.Equal("Level1", AttachedAttribute(Named("WorkbenchTitle"), "HeadingLevel"));
        Assert.Equal("Level2", AttachedAttribute(Named("SigningPolicyHeadingText"), "HeadingLevel"));
        Assert.Equal("Level2", AttachedAttribute(Named("QueueHeading"), "HeadingLevel"));

        Assert.Equal("{x:Reference PrimaryCertificateLabel}",
            AttachedAttribute(Named("PrimaryCertificateCombo"), "LabeledBy"));
        Assert.Equal("{x:Reference SecondaryCertificateLabel}",
            AttachedAttribute(Named("SecondaryCertificateCombo"), "LabeledBy"));
        Assert.Equal("{x:Reference QueueHeading}",
            AttachedAttribute(Named("QueueGrid"), "LabeledBy"));
        XElement[] outputOwners = MainWindow.Descendants()
            .Where(element => AttachedAttribute(element, "AutomationId") == "OutputRootTextBox")
            .ToArray();
        Assert.Equal(2, outputOwners.Length);
        Assert.All(outputOwners, owner => Assert.Equal(
            "{x:Reference OutputRootLabel}",
            AttachedAttribute(owner, "LabeledBy")));
    }

    [Fact]
    public void MainWindowDeclaresDeterministicLogicalTabStages()
    {
        Assert.Equal("Continue", AttachedAttribute(Named("RootGrid"), "TabNavigation"));

        AssertTabIndex("AddFilesButton", 0);
        AssertTabIndex("SettingsButton", 8);
        AssertTabIndex("CompactOverflowButton", 0);
        AssertTabIndex("WorkerRecoveryRegion", 9);
        AssertTabIndex("SigningModeSingle", 20);
        AssertTabIndex("SigningModeDual", 21);
        AssertTabIndex("PrimaryCertificateCombo", 22);
        AssertTabIndex("SecondaryCertificateCombo", 23);
        AssertTabIndex("SigningQueueGrid", 30);
        AssertTabIndex("QueueDirectAddButton", 31);
        AssertTabIndex("OutputRootTextBox", 40);
        AssertTabIndex("BrowseOutputButton", 41);
        AssertTabIndex("ActionOpenOutputButton", 42);
        AssertTabIndex("SignButton", 50);
        AssertTabIndex("CancelButton", 51);
    }

    [Fact]
    public void MainWindowDynamicMessagesHaveOneOwnerPerVisibleRoute()
    {
        AssertSingleLiveOwner("WorkerRecoveryMessageText", "WorkerRecoveryRegion", "Assertive");
        AssertResponsiveLiveOwners("AggregateProgress", "FullActionRail", "CompactActionRail", "Polite");
        AssertSingleLiveOwner("SelectedFileDisabledReason", "SelectedFileDisabledReason", "Polite");
        AssertSingleLiveOwner("SummaryRegion", "SummaryRegion", "Polite");
        AssertSingleLiveOwner("RuntimeError", "RuntimeError", "Assertive");
        AssertSingleLiveOwner("InputError", "InputError", "Assertive");
        AssertSingleLiveOwner("OutputError", "OutputError", "Assertive");

        Assert.Contains("string propertyName = compact", MainWindowCodeBehind, StringComparison.Ordinal);
        Assert.Contains("? nameof(SigningWorkbenchViewModel.QueueStatusText)", MainWindowCodeBehind, StringComparison.Ordinal);
        Assert.Contains(": nameof(SigningWorkbenchViewModel.StatusMessage);", MainWindowCodeBehind, StringComparison.Ordinal);
    }

    [Fact]
    public void ResponsiveDuplicatesPreserveVisibleTargetRoutesAndMutatedFixtureIsRejected()
    {
        Assert.Empty(ValidateResponsiveRoutes(MainWindow));

        XDocument mutated = XDocument.Parse(MainWindow.ToString(SaveOptions.DisableFormatting));
        XElement compactRail = Named(mutated, "CompactActionRail");
        AttributeNode(compactRail, "Visibility")!.Value = "Visible";

        Assert.Equal(
            ["routing-drift: full layout exposes 2 visible targets for AutomationId 'OutputRootTextBox'."],
            ValidateResponsiveRoutes(mutated));
    }

    [Fact]
    public void ShortcutAndProgrammaticFocusRoutingInventoryIsUnchanged()
    {
        foreach (string clause in ExpectedShortcutClauses)
        {
            Assert.Equal(1, CountOccurrences(MainWindowCodeBehind, clause));
        }

        Assert.Equal(1, CountOccurrences(MainWindowCodeBehind, "dialog.ShowDialog();"));
        Assert.Equal(1, CountOccurrences(MainWindowCodeBehind, "SettingsButton.Focus();"));
        Assert.Equal(1, CountOccurrences(MainWindowCodeBehind, "element.IsVisible && string.Equals("));
        Assert.Equal(1, CountOccurrences(MainWindowCodeBehind, "container.Focus();"));
        Assert.Equal(1, CountOccurrences(MainWindowCodeBehind, "element.Focus();"));
    }

    [Fact]
    public void WpfRuntimeAcceptsHeadingLabelAndKeyboardNavigationAttachedProperties()
    {
        RunOnSta(() =>
        {
            var heading = new System.Windows.Controls.TextBlock();
            System.Windows.Automation.AutomationProperties.SetHeadingLevel(
                heading,
                System.Windows.Automation.AutomationHeadingLevel.Level2);
            Assert.Equal(
                System.Windows.Automation.AutomationHeadingLevel.Level2,
                System.Windows.Automation.AutomationProperties.GetHeadingLevel(heading));

            var label = new System.Windows.Controls.TextBlock();
            var input = new System.Windows.Controls.TextBox();
            System.Windows.Automation.AutomationProperties.SetLabeledBy(input, label);
            Assert.Same(label, System.Windows.Automation.AutomationProperties.GetLabeledBy(input));

            var root = new System.Windows.Controls.Grid();
            System.Windows.Input.KeyboardNavigation.SetTabNavigation(
                root,
                System.Windows.Input.KeyboardNavigationMode.Continue);
            Assert.Equal(
                System.Windows.Input.KeyboardNavigationMode.Continue,
                System.Windows.Input.KeyboardNavigation.GetTabNavigation(root));
        });
    }

    [Fact]
    public void QueueRowRemoveActionRemainsKeyboardReachableAndNamed()
    {
        XElement remove = Assert.Single(MainWindow.Descendants(), element =>
            element.Name.LocalName == "Button" &&
            AttachedAttribute(element, "AutomationId") == "{Binding RemoveAutomationId}");

        Assert.NotEqual("False", Attribute(remove, "Focusable"));
        Assert.NotEqual("False", Attribute(remove, "IsTabStop"));
        Assert.Equal("从队列移除此签名文件", AttachedAttribute(remove, "Name"));
        Assert.Equal("仅从内存队列移除，不删除、覆盖或改变源文件", AttachedAttribute(remove, "HelpText"));
        Assert.Equal("{Binding DataContext.RemoveQueueItemCommand, RelativeSource={RelativeSource AncestorType={x:Type DataGrid}}}",
            Attribute(remove, "Command"));
        Assert.Equal("{Binding}", Attribute(remove, "CommandParameter"));
    }

    [Fact]
    public void ProgrammaticStatusAndErrorTargetsDoNotCreateExtraTabStops()
    {
        foreach (string target in new[] { "SummaryRegion", "RuntimeError", "InputError" })
        {
            XElement element = Named(target);
            Assert.Equal("True", Attribute(element, "Focusable"));
            Assert.Equal("False", AttachedAttribute(element, "IsTabStop"));
        }

        Assert.Equal("True", Attribute(Named("WorkerRecoveryRegion"), "Focusable"));
        Assert.Equal("9", Attribute(Named("WorkerRecoveryRegion"), "TabIndex"));
    }

    [Fact]
    public void CustomFocusableSharedStylesExposeTwoDipContrastingFocusRings()
    {
        Dictionary<string, string> colors = DesignTokens
            .Descendants()
            .Where(element => element.Name.LocalName == "SolidColorBrush")
            .ToDictionary(
                element => Attribute(element, "Key")
                    ?? throw new InvalidOperationException("A SolidColorBrush is missing x:Key."),
                element => Attribute(element, "Color")
                    ?? throw new InvalidOperationException("A SolidColorBrush is missing Color."),
                StringComparer.Ordinal);

        foreach ((string styleKey, string focusColorKey, string adjacentColorKey) in new[]
                 {
                     ("CommandButtonStyle", "Color.Focus.Ring", "Color.Surface.Secondary"),
                     ("SegmentedRadioButtonStyle", "Color.Focus.Ring", "Color.Surface.Secondary"),
                     ("PrimaryActionButtonStyle", "Color.Focus.Ring.OnAccent", "Color.Accent.Primary")
                 })
        {
            XElement style = Style(styleKey);
            XElement focusTrigger = Assert.Single(style.Descendants(), element =>
                element.Name.LocalName == "Trigger" &&
                Attribute(element, "Property") == "IsKeyboardFocused" &&
                Attribute(element, "Value") == "True");
            XElement ringSetter = Assert.Single(focusTrigger.Elements(), element =>
                element.Name.LocalName == "Setter" &&
                Attribute(element, "Property") == "BorderBrush");
            XElement thicknessSetter = Assert.Single(focusTrigger.Elements(), element =>
                element.Name.LocalName == "Setter" &&
                Attribute(element, "Property") == "BorderThickness");

            Assert.Equal($"{{DynamicResource {focusColorKey}}}", Attribute(ringSetter, "Value"));
            Assert.Equal("2", Attribute(thicknessSetter, "Value"));
            Assert.True(
                ContrastRatio(colors[focusColorKey], colors[adjacentColorKey]) >= 3.0,
                $"{styleKey} focus ring {focusColorKey} must contrast at least 3:1 with {adjacentColorKey}.");
        }
    }

    [Fact]
    public void StructuralAccessibilityValidatorsAcceptKnownGoodFixture()
    {
        XDocument fixture = XDocument.Parse(
            """
            <StackPanel xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                        xmlns:automation="clr-namespace:System.Windows.Automation;assembly=PresentationCore">
                <TextBlock x:Name="FixtureHeading" automation:AutomationProperties.HeadingLevel="Level1" />
                <Label Target="{Binding ElementName=FixtureInput}" />
                <TextBox x:Name="FixtureInput" TabIndex="0" />
                <Button x:Name="FixtureAction" TabIndex="1" automation:AutomationProperties.AutomationId="FixtureAction" />
                <Image x:Name="FixtureDecorativeImage" Focusable="False"
                       />
                <Border x:Name="FixtureMessage" automation:AutomationProperties.LiveSetting="Polite">
                    <TextBlock Text="fixture" />
                </Border>
            </StackPanel>
            """);

        Assert.Empty(ValidateHeadingSemantics(fixture));
        Assert.Empty(ValidateLabelOwnership(fixture));
        Assert.Empty(ValidateLogicalTabOrder(fixture));
        Assert.Empty(ValidateDecorativeImages(fixture.Descendants().Where(element => element.Name.LocalName == "Image")));
        Assert.Empty(ValidateUniqueVisibleAutomationIds(fixture.Descendants()));
        Assert.Empty(ValidateSingleLiveOwner(fixture, "FixtureMessage"));
    }

    [Fact]
    public void StructuralAccessibilityValidatorsReportExactlyTwoViolationsForDuplicateLiveOwnerAndFocusableDecoration()
    {
        XDocument fixture = XDocument.Parse(
            """
            <StackPanel xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                        xmlns:automation="clr-namespace:System.Windows.Automation;assembly=PresentationCore">
                <Border automation:AutomationProperties.LiveSetting="Assertive">
                    <TextBlock x:Name="FixtureMessage" automation:AutomationProperties.LiveSetting="Assertive" Text="fixture" />
                </Border>
                <Image x:Name="FixtureDecorativeImage" Focusable="True" />
            </StackPanel>
            """);

        string[] violations = ValidateSingleLiveOwner(fixture, "FixtureMessage")
            .Concat(ValidateDecorativeImages(fixture.Descendants().Where(element => element.Name.LocalName == "Image")))
            .OrderBy(static violation => violation, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
        [
            "Decorative image 'FixtureDecorativeImage' must set Focusable=False so its WPF automation peer is excluded from control/content trees.",
            "Dynamic message 'FixtureMessage' must have exactly one non-Off LiveSetting owner; found 2."
        ],
        violations);
    }

    private static IEnumerable<string> ValidateHeadingSemantics(XDocument document) => document
        .Descendants()
        .Where(element => Attribute(element, "Name")?.Contains("Heading", StringComparison.Ordinal) == true)
        .Where(element => string.IsNullOrWhiteSpace(AttachedAttribute(element, "HeadingLevel")))
        .Select(element => $"Heading '{Describe(element)}' must declare AutomationProperties.HeadingLevel.");

    private static IEnumerable<string> ValidateLabelOwnership(XDocument document)
    {
        XElement[] namedElements = document.Descendants()
            .Where(element => !string.IsNullOrWhiteSpace(Attribute(element, "Name")))
            .ToArray();

        return document.Descendants()
            .Where(element => element.Name.LocalName == "Label")
            .Where(label => !namedElements.Any(element =>
                Attribute(label, "Target")?.Contains(Attribute(element, "Name")!, StringComparison.Ordinal) == true))
            .Select(label => $"Label '{Describe(label)}' must target a named control.");
    }

    private static IEnumerable<string> ValidateLogicalTabOrder(XDocument document)
    {
        int?[] tabIndexes = document.Descendants()
            .Where(IsFocusableControl)
            .Select(element => ParseTabIndex(Attribute(element, "TabIndex")))
            .ToArray();

        if (tabIndexes.Any(index => index is null))
        {
            return ["Focusable controls must declare an explicit logical TabIndex."];
        }

        int[] ordered = tabIndexes.Select(index => index!.Value).ToArray();
        return ordered.SequenceEqual(ordered.OrderBy(index => index))
            ? []
            : ["Focusable controls must declare nondecreasing TabIndex values in XAML order."];
    }

    private static IEnumerable<string> ValidateDecorativeImages(IEnumerable<XElement> images) => images
        .Where(image =>
            Attribute(image, "Focusable") != "False")
        .Select(image =>
            $"Decorative image '{Describe(image)}' must set Focusable=False so its WPF automation peer is excluded from control/content trees.");

    private static IEnumerable<string> ValidateUniqueVisibleAutomationIds(IEnumerable<XElement> visibleElements) => visibleElements
        .Select(element => AttachedAttribute(element, "AutomationId"))
        .Where(static automationId => !string.IsNullOrWhiteSpace(automationId))
        .GroupBy(automationId => automationId!, StringComparer.Ordinal)
        .Where(group => group.Count() > 1)
        .Select(group => $"Visible AutomationId '{group.Key}' must be unique.");

    private static IEnumerable<string> ValidateSingleLiveOwner(XDocument document, string messageName)
    {
        XElement message = document.Descendants().Single(element => Attribute(element, "Name") == messageName);
        int ownerCount = message.AncestorsAndSelf().Count(HasNonOffLiveSetting);
        return ownerCount == 1
            ? []
            : [$"Dynamic message '{messageName}' must have exactly one non-Off LiveSetting owner; found {ownerCount}."];
    }

    private static void AssertTabIndex(string automationId, int expected)
    {
        XElement[] owners = MainWindow.Descendants()
            .Where(element => AttachedAttribute(element, "AutomationId") == automationId)
            .ToArray();
        Assert.NotEmpty(owners);
        Assert.All(owners, owner => Assert.Equal(expected.ToString(CultureInfo.InvariantCulture), Attribute(owner, "TabIndex")));
    }

    private static void AssertSingleLiveOwner(string messageName, string expectedOwner, string expectedSetting)
    {
        XElement message = MainWindow.Descendants().Single(element =>
            Attribute(element, "Name") == messageName || AttachedAttribute(element, "AutomationId") == messageName);
        XElement[] owners = message.AncestorsAndSelf().Where(HasNonOffLiveSetting).ToArray();
        XElement owner = Assert.Single(owners);
        Assert.Equal(expectedOwner, Describe(owner));
        Assert.Equal(expectedSetting, AttachedAttribute(owner, "LiveSetting"));
    }

    private static void AssertResponsiveLiveOwners(
        string automationId,
        string fullRoute,
        string compactRoute,
        string expectedSetting)
    {
        XElement[] owners = MainWindow.Descendants()
            .Where(element => AttachedAttribute(element, "AutomationId") == automationId)
            .ToArray();
        Assert.Equal(2, owners.Length);
        Assert.All(owners, owner => Assert.Equal(expectedSetting, AttachedAttribute(owner, "LiveSetting")));
        Assert.Contains(owners, owner => owner.Ancestors().Any(ancestor => Attribute(ancestor, "Name") == fullRoute));
        Assert.Contains(owners, owner => owner.Ancestors().Any(ancestor => Attribute(ancestor, "Name") == compactRoute));
    }

    private static string[] ValidateResponsiveRoutes(XDocument document)
    {
        XElement fullRail = Named(document, "FullActionRail");
        XElement compactRail = Named(document, "CompactActionRail");
        bool fullVisible = Attribute(fullRail, "Visibility") != "Collapsed";
        bool compactVisible = Attribute(compactRail, "Visibility") != "Collapsed";
        int visibleOutputOwners = (fullVisible ? 1 : 0) + (compactVisible ? 1 : 0);
        return visibleOutputOwners == 1
            ? []
            : [$"routing-drift: full layout exposes {visibleOutputOwners} visible targets for AutomationId 'OutputRootTextBox'."];
    }

    private static int CountOccurrences(string text, string value)
    {
        int count = 0;
        int offset = 0;
        while ((offset = text.IndexOf(value, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += value.Length;
        }

        return count;
    }

    private static bool IsFocusableControl(XElement element) => element.Name.LocalName is "Button" or "ComboBox" or "RadioButton" or "TextBox";

    private static void AssertExcludedFromControlPeer(XElement xamlImage)
    {
        RunOnSta(() =>
        {
            var image = new System.Windows.Controls.Image
            {
                Focusable = bool.Parse(Attribute(xamlImage, "Focusable")!)
            };
            System.Windows.Automation.AutomationProperties.SetAutomationId(
                image,
                AttachedAttribute(xamlImage, "AutomationId")!);
            System.Windows.Automation.AutomationProperties.SetName(
                image,
                AttachedAttribute(xamlImage, "Name")!);

            System.Windows.Automation.Peers.AutomationPeer peer =
                System.Windows.Automation.Peers.UIElementAutomationPeer.CreatePeerForElement(image)
                ?? throw new InvalidOperationException("Image did not create an automation peer.");
            Assert.False(peer.IsControlElement());
            Assert.False(peer.IsContentElement());
        });
    }

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
            throw new InvalidOperationException("STA accessibility peer assertion failed.", exception);
        }
    }

    private static int? ParseTabIndex(string? value) => int.TryParse(value, CultureInfo.InvariantCulture, out int tabIndex)
        ? tabIndex
        : null;

    private static bool HasNonOffLiveSetting(XElement element) =>
        !string.Equals(AttachedAttribute(element, "LiveSetting"), "Off", StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(AttachedAttribute(element, "LiveSetting"));

    private static XElement AutomationElement(string automationId) => Assert.Single(MainWindow.Descendants(), element =>
        AttachedAttribute(element, "AutomationId") == automationId);

    private static XElement Named(string name) => Assert.Single(MainWindow.Descendants(), element =>
        Attribute(element, "Name") == name);

    private static XElement Named(XDocument document, string name) => Assert.Single(document.Descendants(), element =>
        Attribute(element, "Name") == name);

    private static XElement Style(string key) => Assert.Single(DesignTokens.Descendants(), element =>
        element.Name.LocalName == "Style" && Attribute(element, "Key") == key);

    private static string Describe(XElement element) => Attribute(element, "Name")
        ?? AttachedAttribute(element, "AutomationId")
        ?? element.Name.LocalName;

    private static string? Attribute(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
        ?.Value;

    private static XAttribute? AttributeNode(XElement element, string localName) => element.Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName);

    private static string? AttachedAttribute(XElement element, string propertyName) => element.Attributes()
        .SingleOrDefault(attribute =>
            attribute.Name.LocalName.EndsWith($".{propertyName}", StringComparison.Ordinal))
        ?.Value;

    private static XDocument LoadXaml(params string[] pathSegments) => XDocument.Load(
        Path.Combine([RepositoryRoot, .. pathSegments]),
        LoadOptions.SetLineInfo);

    private static double ContrastRatio(string first, string second)
    {
        double firstLuminance = RelativeLuminance(first);
        double secondLuminance = RelativeLuminance(second);
        return (Math.Max(firstLuminance, secondLuminance) + 0.05) /
            (Math.Min(firstLuminance, secondLuminance) + 0.05);
    }

    private static double RelativeLuminance(string color)
    {
        if (color.Length != 7 || color[0] != '#')
        {
            throw new InvalidOperationException($"Unsupported color literal '{color}'.");
        }

        double[] channels =
        [
            Convert.ToInt32(color.Substring(1, 2), 16) / 255.0,
            Convert.ToInt32(color.Substring(3, 2), 16) / 255.0,
            Convert.ToInt32(color.Substring(5, 2), 16) / 255.0
        ];
        double[] linear = channels.Select(channel => channel <= 0.04045
            ? channel / 12.92
            : Math.Pow((channel + 0.055) / 1.055, 2.4)).ToArray();
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
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
