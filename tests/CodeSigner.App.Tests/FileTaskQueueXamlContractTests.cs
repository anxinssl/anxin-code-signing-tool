using System.IO;
using System.Xml.Linq;

namespace CodeSigner.App.Tests;

public sealed class FileTaskQueueXamlContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string MainWindowPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "MainWindow.xaml");
    private static readonly string MainWindowCodeBehindPath = Path.Combine(
        RepositoryRoot,
        "src",
        "CodeSigner.App",
        "MainWindow.xaml.cs");
    private static readonly XDocument MainWindow = XDocument.Load(MainWindowPath, LoadOptions.SetLineInfo);

    private static readonly string[] QueueHeaders =
    [
        "文件输入",
        "检测格式",
        "签名引擎",
        "有效策略",
        "状态",
        "进度",
        "结果",
        "操作",
    ];

    [Fact]
    public void QueueSelectionUsesExtendedMembershipAndAsyncCurrentTransition()
    {
        XElement queue = Named("QueueGrid");
        Assert.Equal("QueueGrid_SelectionChanged", Attribute(queue, "SelectionChanged"));
        Assert.Equal("QueueGrid_CurrentCellChanged", Attribute(queue, "CurrentCellChanged"));
        Assert.Equal("{Binding Rows}", Attribute(queue, "ItemsSource"));

        XDocument tokens = XDocument.Load(Path.Combine(
            RepositoryRoot,
            "src",
            "CodeSigner.App",
            "Themes",
            "DesignTokens.xaml"));
        XElement gridStyle = Assert.Single(tokens.Descendants(), element =>
            element.Name.LocalName == "Style" &&
            Attribute(element, "Key") == "WorkbenchDataGridStyle");
        Assert.Contains(gridStyle.Elements(), element =>
            element.Name.LocalName == "Setter" &&
            Attribute(element, "Property") == "SelectionMode" &&
            Attribute(element, "Value") == "Extended");
    }

    [Fact]
    public void CurrentOnlyPresentationNeverReadsDataGridSelectedItem()
    {
        XElement runtimeError = Named("RuntimeError");
        Assert.Equal("{Binding CurrentItem.DetailText}", Attribute(runtimeError, "Text"));
        Assert.Equal(
            "{Binding CurrentItem.DetailText}",
            Attribute(runtimeError, "AutomationProperties.Name"));

        XElement runtimeBand = Named("RuntimeErrorBand");
        XElement summaryBand = Named("SummaryBand");
        Assert.All(
            runtimeBand.Descendants().Concat(summaryBand.Descendants())
                .SelectMany(element => element.Attributes())
                .Where(attribute => attribute.Value.Contains("DetailText", StringComparison.Ordinal)),
            attribute => Assert.Contains("CurrentItem.DetailText", attribute.Value, StringComparison.Ordinal));
    }

    [Fact]
    public void QueueStatusIsWrappedAndHasStableAutomationContract()
    {
        XElement status = AutomationElement("SelectedFileDisabledReason");
        Assert.Equal("TextBlock", status.Name.LocalName);
        Assert.Equal("{Binding QueueStatusText}", Attribute(status, "Text"));
        Assert.Equal(
            "{Binding QueueStatusText}",
            Attribute(status, "AutomationProperties.Name"));
        Assert.Equal("{Binding QueueStatusText}", Attribute(status, "ToolTip"));
        Assert.Equal("Wrap", Attribute(status, "TextWrapping"));
        Assert.Null(status.Attributes().SingleOrDefault(attribute => attribute.Name.LocalName == "TextTrimming"));
    }

    [Fact]
    public void SignHelpDescribesTheQueueAndRetryRemainsCurrentOnly()
    {
        XElement[] signControls = AutomationElements("SignButton");
        XElement[] retryControls = AutomationElements("RetryButton");
        Assert.Equal(2, signControls.Length);
        Assert.Equal(2, retryControls.Length);
        Assert.All(signControls, control =>
            Assert.Equal("按队列顺序签名待处理文件", Attribute(control, "ToolTip")));
        Assert.All(retryControls, control =>
            Assert.Equal("重试当前失败或暂停的文件", Attribute(control, "ToolTip")));
        Assert.DoesNotContain(
            MainWindow.Descendants().SelectMany(element => element.Attributes()),
            attribute => attribute.Value.Contains("所有待处理", StringComparison.Ordinal) ||
                attribute.Value.Contains("失败或暂停的签名任务", StringComparison.Ordinal));
    }

    [Fact]
    public void OutputAndEveryRowRemoveExposeDeterministicAutomationIds()
    {
        XElement outputError = AutomationElement("OutputError");
        Assert.Equal("{Binding OutputError}", Attribute(outputError, "Text"));
        Assert.Equal(
            "{Binding OutputError}",
            Attribute(outputError, "AutomationProperties.Name"));

        XElement actionColumn = Named("ActionColumn");
        XElement remove = Assert.Single(actionColumn.Descendants(), element =>
            element.Name.LocalName == "Button");
        Assert.Equal(
            "{Binding RemoveAutomationId}",
            Attribute(remove, "AutomationProperties.AutomationId"));
        Assert.Equal("{Binding}", Attribute(remove, "CommandParameter"));
    }

    [Fact]
    public void FullAndCompactActionRailsRemainMutuallyVisibleByExistingRoute()
    {
        XElement full = Named("FullActionRail");
        XElement compact = Named("CompactActionRail");
        Assert.Null(full.Attributes().SingleOrDefault(attribute => attribute.Name.LocalName == "Visibility"));
        Assert.Equal("Collapsed", Attribute(compact, "Visibility"));

        string codeBehind = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "CodeSigner.App",
            "MainWindow.xaml.cs"));
        Assert.Contains(
            "FullActionRail.Visibility = useCondensedActionRail ? Visibility.Collapsed : Visibility.Visible",
            codeBehind,
            StringComparison.Ordinal);
        Assert.Contains(
            "CompactActionRail.Visibility = useCondensedActionRail ? Visibility.Visible : Visibility.Collapsed",
            codeBehind,
            StringComparison.Ordinal);
        Assert.Contains(
            "? nameof(SigningWorkbenchViewModel.QueueStatusText)",
            codeBehind,
            StringComparison.Ordinal);
        Assert.Contains(
            ": nameof(SigningWorkbenchViewModel.StatusMessage)",
            codeBehind,
            StringComparison.Ordinal);
    }

    [Fact]
    public void QueueDirectAddButtonOnlyOccupiesEmptyQueueSpace()
    {
        XElement queueHeader = Named("QueueHeader");
        XElement queueBody = Named("QueueBody");
        XElement directAdd = Named("QueueDirectAddButton");

        Assert.Contains(directAdd, queueBody.Descendants());
        Assert.DoesNotContain(directAdd, queueHeader.Descendants());
        Assert.DoesNotContain(MainWindow.Descendants(), element =>
            Attribute(element, "Name") == "EmptyQueueAddButton");
        Assert.Equal("AddFiles_Click", Attribute(directAdd, "Click"));
        Assert.Equal("选择一个或多个支持的签名文件并加入队列", Attribute(directAdd, "ToolTip"));
        Assert.Equal("QueueDirectAddButton", Attribute(directAdd, "AutomationProperties.AutomationId"));
        Assert.Equal("直接添加签名文件", Attribute(directAdd, "AutomationProperties.Name"));
        Assert.Equal("打开文件选择器，将一个或多个支持的签名文件加入队列", Attribute(directAdd, "AutomationProperties.HelpText"));
        Assert.Single(directAdd.Descendants(), element =>
            element.Name.LocalName == "Image" &&
            Attribute(element, "Source") == "{StaticResource Icon.Command.AddFile}");
        XElement prompt = Named("QueueDirectAddPrompt");
        Assert.Equal("添加签名文件", Attribute(prompt, "Text"));
        Assert.Equal("添加支持的签名文件或文件夹", Attribute(prompt, "AutomationProperties.Name"));
        Assert.Contains(
            directAdd.Descendants(),
            element => Attribute(element, "Name") == "QueueDirectAddPrompt");
        AssertRowsCountShowsOnlyEmptyQueueAction(directAdd);
        AssertWorkerRecoveryCollapses(directAdd);
    }

    [Fact]
    public void MainWindowHierarchyKeepsQueueDominantAndAvoidsRepeatedCardTreatment()
    {
        XElement root = Named("RootGrid");
        XElement rowDefinitions = Assert.Single(root.Elements(), element =>
            element.Name.LocalName == "Grid.RowDefinitions");
        Assert.Equal(1, rowDefinitions.Elements().Count(row => Attribute(row, "Height") == "*"));

        string[] expectedOrder =
        [
            "AppHeader",
            "ReadinessBand",
            "CommandBand",
            "ConfigurationBand",
            "QueueRegion",
            "ActionBand",
            "SummaryBand",
            "RuntimeErrorBand",
        ];
        Assert.Equal(expectedOrder, root.Elements()
            .Select(element => Attribute(element, "Name"))
            .Where(name => expectedOrder.Contains(name, StringComparer.Ordinal)));

        XElement configuration = Named("ConfigurationBand");
        XElement action = Named("ActionBand");
        Assert.Equal("{StaticResource BandBorderStyle}", Attribute(configuration, "Style"));
        Assert.Equal("{StaticResource BandBorderStyle}", Attribute(action, "Style"));
        Assert.DoesNotContain(configuration.Descendants(), UsesCardBorderStyle);
        Assert.DoesNotContain(action.Descendants(), UsesCardBorderStyle);
        Assert.DoesNotContain(MainWindow.Descendants(), element =>
            UsesCardBorderStyle(element) && element.Ancestors().Any(UsesCardBorderStyle));
    }

    [Fact]
    public void QueueHeadersAndEachResponsiveActionRailKeepExactOwners()
    {
        XElement queue = Named("QueueGrid");
        string[] actualHeaders = queue.Descendants()
            .Where(element => element.Name.LocalName.StartsWith("DataGrid", StringComparison.Ordinal) &&
                element.Name.LocalName.EndsWith("Column", StringComparison.Ordinal))
            .Select(element => Attribute(element, "Header"))
            .Where(header => header is not null)
            .Cast<string>()
            .ToArray();
        Assert.Equal(QueueHeaders, actualHeaders);

        AssertActionRailOwners(Named("FullActionRail"), "OutputRootTextBox");
        AssertActionRailOwners(Named("CompactActionRail"), "CompactOutputRootTextBox");
    }

    [Fact]
    public void QueueDoesNotContainCompanyWatermark()
    {
        Assert.DoesNotContain(MainWindow.Descendants(), element =>
            Attribute(element, "Name") == "WatermarkText" ||
            element.Name.LocalName == "AccessibleWatermarkText");
        Assert.DoesNotContain(Named("QueueBody").Descendants().Attributes(), attribute =>
            attribute.Value.Contains("安徽斯百德信息技术有限公司", StringComparison.Ordinal));
    }

    [Fact]
    public void CommandBindingEventShortcutAndIdInventoriesOnlyAllowApprovedQueuePresentationChanges()
    {
        string baselinePath = Path.Combine(
            RepositoryRoot,
            "tests",
            "fixtures",
            "ui-baseline",
            "MainWindow.xaml");
        XDocument baseline = XDocument.Load(baselinePath);
        Assert.Single(baseline.Descendants(), element =>
            Attribute(element, "Name") == "WatermarkText").Remove();
        foreach (XElement element in baseline.Descendants().Where(element =>
                     Attribute(element, "AutomationProperties.AutomationId") is
                         "SignButton" or "CancelButton" or "SelectedFileDisabledReason"))
        {
            foreach (XAttribute attribute in element.Attributes())
            {
                attribute.Value = attribute.Value switch
                {
                    "{Binding CurrentFileStatusText}" => "{Binding QueueStatusText}",
                    "签名当前文件" => "按队列顺序签名待处理文件",
                    "停止当前签名并保留原始文件" => "停止批量签名并保留后续待处理文件",
                    "停止当前签名，原始文件保持不变" => "停止批量签名，原始文件保持不变，后续文件不再启动",
                    _ => attribute.Value
                };
            }
        }

        XElement refresh = baseline.Descendants().Single(element =>
            element.Name.LocalName == "Button" &&
            Attribute(element, "AutomationProperties.AutomationId") == "RefreshButton");
        refresh.SetAttributeValue("ToolTip", "刷新并读取证书");
        refresh.SetAttributeValue("AutomationProperties.HelpText", "重新检查 Windows 签名环境、代码签名证书和时间戳");
        refresh.Add(new XElement(refresh.Name.Namespace + "TextBlock", new XAttribute("Text", "刷新证书")));
        XElement compactRefresh = baseline.Descendants().Single(element =>
            element.Name.LocalName == "MenuItem" &&
            Attribute(element, "AutomationProperties.AutomationId") == "RefreshButton");
        compactRefresh.SetAttributeValue("ToolTip", "刷新并读取证书");
        compactRefresh.SetAttributeValue("AutomationProperties.HelpText", "重新检查 Windows 签名环境、代码签名证书和时间戳");
        compactRefresh.SetAttributeValue("Header", "刷新证书");
        baseline.Root!.Add(
            new XElement(refresh.Name.Namespace + "TextBlock",
                new XAttribute("AutomationProperties.AutomationId", "CertificateRefreshHint"),
                new XAttribute("AutomationProperties.Name", "请先刷新并读取有效证书"),
                new XAttribute("Text", "{Binding CertificatePreparationHint}")),
            new XElement(refresh.Name.Namespace + "TextBlock",
                new XAttribute("AutomationProperties.AutomationId", "OutputLocationHint"),
                new XAttribute("AutomationProperties.Name", "签名前请选择文件输出位置"),
                new XAttribute("Text", "请先选择文件输出位置，再开始签名。建议使用可写的专用文件夹。")));

        XElement previousBrand = Assert.Single(baseline.Descendants(), element =>
            element.Name.LocalName == "Image" && Attribute(element, "Source") == "Assets/CodeSigner.png");
        previousBrand.Remove();
        XElement headerSymbol = Assert.Single(baseline.Descendants(), element =>
            element.Name.LocalName == "Image" && Attribute(element, "Source") == "{StaticResource Icon.Decorative.WorkbenchShield}");
        headerSymbol.SetAttributeValue("AutomationProperties.Name", "安信 SSL 证书");
        XElement providerIcon = Assert.Single(baseline.Descendants(), element =>
            Attribute(element, "AutomationProperties.AutomationId") == "ReadinessSimplySign");
        providerIcon.Parent!.Remove();
        XDocument current = XDocument.Parse(MainWindow.ToString());
        XElement actions = Assert.Single(current.Descendants(), element =>
            Attribute(element, "Name") == "CommandActionsPanel");
        foreach (string id in new[] { "ToolbarRemoveItem", "ToolbarRetryItem", "ToolbarOutputItem" })
        {
            Assert.Single(actions.Descendants(), element =>
                Attribute(element, "AutomationProperties.AutomationId") == id).Remove();
        }
        XElement more = Assert.Single(actions.Descendants(), element =>
            Attribute(element, "AutomationProperties.AutomationId") == "ToolbarMoreButton");
        more.ReplaceWith(more.Elements().ToArray());
        foreach (string label in new[] { "添加文件", "添加文件夹", "移除选中", "重试", "打开输出目录", "设置" })
        {
            Assert.Single(actions.Descendants(), element =>
                element.Name.LocalName == "TextBlock" && Attribute(element, "Text") == label).Remove();
        }
        XElement refreshLabel = Assert.Single(actions.Descendants(), element =>
            Attribute(element, "Name") == "RefreshButtonLabel");
        Assert.Equal("{Binding RefreshButtonText, FallbackValue=刷新证书}", Attribute(refreshLabel, "Text"));
        refreshLabel.SetAttributeValue("Text", "刷新证书");
        Assert.Single(current.Descendants(), element =>
            Attribute(element, "Name") == "CertificateRefreshHint").SetAttributeValue("ToolTip", null);

        string[] exactAttributeNames =
        [
            "AutomationProperties.AutomationId",
            "AutomationProperties.HelpText",
            "Click",
            "Command",
            "CurrentCellChanged",
            "LostKeyboardFocus",
            "SelectionChanged",
            "ToolTip",
            "Visibility",
        ];
        foreach (string attributeName in exactAttributeNames)
        {
            Assert.Equal(
                AttributeInventory(baseline, attributeName),
                AttributeInventory(current, attributeName));
        }
        foreach (string attributeName in new[] { "AutomationProperties.Name", "Text" })
        {
            Assert.Equal(
                AttributeInventory(baseline, attributeName)
                    .Select(value => value.Replace("代码签名工具", "安信代码签名证书工具", StringComparison.Ordinal))
                    .Order(StringComparer.Ordinal)
                    .ToArray(),
                AttributeInventory(current, attributeName));
        }
        Assert.Equal(BindingInventory(baseline), BindingInventory(current));

        string codeBehind = File.ReadAllText(MainWindowCodeBehindPath);
        Assert.Contains("var dialog = new SettingsWindow(viewModel) { Owner = this };", codeBehind, StringComparison.Ordinal);
        Assert.Contains("dialog.ShowDialog();", codeBehind, StringComparison.Ordinal);
        Assert.Contains("无法打开签名设置：{exception.Message}", codeBehind, StringComparison.Ordinal);
        Assert.Contains("SettingsButton.Focus();", codeBehind, StringComparison.Ordinal);
    }

    [Fact]
    public void ExistingResolutionScalingBranchesAreFrozenAndMutatedFixtureIsRejected()
    {
        string current = File.ReadAllText(MainWindowCodeBehindPath);
        Assert.Empty(ResolutionScalingDrift(current));

        string fixture = current.Replace(
            "private const double CompactWidth = 900;",
            "private const double CompactWidth = 901;",
            StringComparison.Ordinal);
        string violation = Assert.Single(ResolutionScalingDrift(fixture));
        Assert.Equal("resolution-scaling-drift: CompactWidth must remain 900.", violation);
    }

    private static void AssertActionRailOwners(XElement rail, string outputOwnerName)
    {
        Assert.Single(rail.Descendants(), element => Attribute(element, "Name") == outputOwnerName);
        Assert.Single(rail.Descendants(), element =>
            Attribute(element, "AutomationProperties.AutomationId") == "AggregateProgress");
        Assert.Single(rail.Descendants(), element =>
            Attribute(element, "AutomationProperties.AutomationId") == "SignButton");
        Assert.Single(rail.Descendants(), element =>
            Attribute(element, "AutomationProperties.AutomationId") == "CancelButton");
    }

    private static string[] AttributeInventory(XDocument document, string attributeName) => document
        .Descendants()
        .SelectMany(element => element.Attributes())
        .Where(attribute => attribute.Name.LocalName == attributeName)
        .Select(attribute => attribute.Value)
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static string[] BindingInventory(XDocument document) => document
        .Descendants()
        .SelectMany(element => element.Attributes())
        .Where(attribute => attribute.Value.Contains("{Binding", StringComparison.Ordinal))
        .Select(attribute => $"{attribute.Name.LocalName}={attribute.Value}")
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static string[] ResolutionScalingDrift(string codeBehind)
    {
        (string ExactText, string Message)[] frozen =
        [
            ("private const double CompactWidth = 900;", "CompactWidth must remain 900."),
            ("private const double CompactHeight = 620;", "CompactHeight must remain 620."),
            ("bool ultraCompact = compact && (width < 560 || height < 420);", "ultra thresholds must remain 560/420."),
            ("FullActionRail.Visibility = useCondensedActionRail ? Visibility.Collapsed : Visibility.Visible;", "full action visibility route changed."),
            ("CompactActionRail.Visibility = useCondensedActionRail ? Visibility.Visible : Visibility.Collapsed;", "compact action visibility route changed."),
            ("QueueGrid.RowHeight = compact && !ultraCompact ? 46 : 50;", "queue row sizing changed."),
            ("QueueGrid.ColumnHeaderHeight = compact && !ultraCompact ? 34 : 36;", "queue header sizing changed."),
        ];
        return frozen
            .Where(contract => !codeBehind.Contains(contract.ExactText, StringComparison.Ordinal))
            .Select(contract => $"resolution-scaling-drift: {contract.Message}")
            .ToArray();
    }

    private static bool UsesCardBorderStyle(XElement element) =>
        Attribute(element, "Style") == "{StaticResource CardBorderStyle}";

    private static void AssertWorkerRecoveryCollapses(XElement element)
    {
        XElement recoveryTrigger = Assert.Single(element.Descendants(), candidate =>
            candidate.Name.LocalName == "DataTrigger" &&
            Attribute(candidate, "Binding") == "{Binding IsWorkerRecoveryVisible}" &&
            Attribute(candidate, "Value") == "True");
        Assert.Contains(recoveryTrigger.Descendants(), candidate =>
            candidate.Name.LocalName == "Setter" &&
            Attribute(candidate, "Property") == "Visibility" &&
            Attribute(candidate, "Value") == "Collapsed");
    }

    private static void AssertRowsCountShowsOnlyEmptyQueueAction(XElement element)
    {
        XElement emptyQueueTrigger = Assert.Single(element.Descendants(), candidate =>
            candidate.Name.LocalName == "DataTrigger" &&
            Attribute(candidate, "Binding") == "{Binding Rows.Count}" &&
            Attribute(candidate, "Value") == "0");
        Assert.Contains(emptyQueueTrigger.Descendants(), candidate =>
            candidate.Name.LocalName == "Setter" &&
            Attribute(candidate, "Property") == "Grid.Row" &&
            Attribute(candidate, "Value") == "0");
        Assert.Contains(emptyQueueTrigger.Descendants(), candidate =>
            candidate.Name.LocalName == "Setter" &&
            Attribute(candidate, "Property") == "Visibility" &&
            Attribute(candidate, "Value") == "Visible");
        XElement style = Assert.Single(element.Descendants(), candidate => candidate.Name.LocalName == "Style");
        Assert.Contains(style.Elements(), candidate =>
            candidate.Name.LocalName == "Setter" &&
            Attribute(candidate, "Property") == "Visibility" &&
            Attribute(candidate, "Value") == "Collapsed");
    }

    private static XElement Named(string name) => Assert.Single(MainWindow.Descendants(), element =>
        Attribute(element, "Name") == name);

    private static XElement AutomationElement(string automationId) =>
        Assert.Single(AutomationElements(automationId));

    private static XElement[] AutomationElements(string automationId) => MainWindow
        .Descendants()
        .Where(element => Attribute(element, "AutomationProperties.AutomationId") == automationId)
        .ToArray();

    private static string? Attribute(XElement element, string localName) => element
        .Attributes()
        .SingleOrDefault(attribute => attribute.Name.LocalName == localName)
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
