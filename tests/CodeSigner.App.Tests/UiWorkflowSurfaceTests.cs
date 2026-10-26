using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using System.Windows.Automation;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Evidence;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class UiWorkflowSurfaceTests
{
    private static readonly JsonSerializerOptions EvidenceJsonOptions = new() { WriteIndented = true };
    private static readonly int[] RequestedDpiPercent = [100, 150, 200];
    private static readonly string[] ExpectedLocalIconKeys =
    [
        "Icon.Command.AddFile",
        "Icon.Command.AddFolder",
        "Icon.Command.Remove",
        "Icon.Command.Refresh",
        "Icon.Command.Retry",
        "Icon.Command.OpenOutput",
        "Icon.Command.ExportDiagnostics",
        "Icon.Command.OpenLogs",
        "Icon.Command.Settings",
        "Icon.Command.Sign",
        "Icon.Command.Cancel",
        "Icon.Command.BrowseOutput",
        "Icon.Command.Overflow",
        "Icon.Decorative.WorkbenchShield",
        "Icon.Status.Workstation",
        "Icon.Status.NativeApi",
        "Icon.Status.SimplySign",
        "Icon.Status.Certificate",
        "Icon.Status.Timestamp",
        "Icon.Status.Error",
        "Icon.Section.Certificate",
        "Icon.Section.SigningPolicy"
    ];
    private static readonly CommandIconExpectation[] ExpectedCommandIconMappings =
    [
        new("AddFilesButton", "Icon.Command.AddFile", 2),
        new("QueueDirectAddButton", "Icon.Command.AddFile", 1),
        new("AddFolderButton", "Icon.Command.AddFolder", 2),
        new("RemoveButton", "Icon.Command.Remove", 2),
        new("RefreshButton", "Icon.Command.Refresh", 2),
        new("RetryButton", "Icon.Command.Retry", 2),
        new("OpenOutputButton", "Icon.Command.OpenOutput", 2),
        new("ActionOpenOutputButton", "Icon.Command.OpenOutput", 2),
        new("ExportDiagnosticsButton", "Icon.Command.ExportDiagnostics", 2),
        new("OpenLogDirectoryButton", "Icon.Command.OpenLogs", 2),
        new("SettingsButton", "Icon.Command.Settings", 2),
        new("BrowseOutputButton", "Icon.Command.BrowseOutput", 2),
        new("SignButton", "Icon.Command.Sign", 2),
        new("CancelButton", "Icon.Command.Cancel", 2),
        new("CompactOverflowButton", "Icon.Command.Overflow", 1),
        new("PrimitiveCommandButton", "Icon.Command.AddFile", 1),
        new("PrimitiveDisabledCommand", "Icon.Command.Refresh", 1)
    ];

    private const string XamlLanguageNamespace = "http://schemas.microsoft.com/winfx/2006/xaml";
    private const string LucideRelease = "0.468.0";
    private const string LucideCommit = "f12b0de177fbc2a6795e99be065887e72b237123";
    private const string LucideLicenseGitBlobSha = "325e8ff0aae2dde3134c1ceed780a11d7bd8f544";
    private const string LucideLicenseSha256 =
        "1e7290b35280a048667bbf0ebabac1c7fd52a75300e8b2946ac165715997f2bc";

    private const string LongExePath =
        "C:\\release\\\u53d1\u5e03 \u7248\u672c\\" +
        "very-long-product-component-name-for-accessible-code-signing-" +
        "012345678901234567890123456789012345678901234567890123456789.exe";
    private const string SecondExePath = "C:\\release\\\u53d1\u5e03 \u7248\u672c\\second-product.exe";
    private const string SelectedDllPath = "C:\\release\\\u53d1\u5e03 \u7248\u672c\\selected-library.dll";
    private const string DroppedDllPath = "C:\\release\\\u53d1\u5e03 \u7248\u672c\\dropped-library.dll";
    private const string OutputRoot = "C:\\release\\\u5df2\u7b7e\u540d \u8f93\u51fa";
    private const string MixedFolder = "C:\\release\\mixed-folder";
    private const string MalformedDllPath = "C:\\release\\mixed-folder\\malformed-library.dll";
    private const string ExpectedSettingsTooltipName =
        "RFC3161 时间戳服务器地址，默认为 http://time.certum.pl";
    private const string ExpectedSettingsTooltipClassName = "ToolTip";

    [Theory]
    [InlineData("其他提示", "ToolTip")]
    [InlineData(ExpectedSettingsTooltipName, "Window")]
    [InlineData(null, ExpectedSettingsTooltipClassName)]
    public void NonmatchingResidualSettingsTooltipRethrowsOriginalWaitFailure(
        string? tooltipName,
        string? tooltipClassName)
    {
        var waitFailure = new InvalidOperationException("residual tooltip wait failed");

        InvalidOperationException thrown = Assert.Throws<InvalidOperationException>(() =>
            RethrowUnlessExpectedSettingsTooltip(tooltipName, tooltipClassName, waitFailure));

        Assert.Same(waitFailure, thrown);
    }

    [Fact]
    public void ExactRfc3161ResidualSettingsTooltipIsTolerated()
    {
        Exception? failure = Record.Exception(() => RethrowUnlessExpectedSettingsTooltip(
            ExpectedSettingsTooltipName,
            ExpectedSettingsTooltipClassName,
            new InvalidOperationException("residual tooltip wait failed")));

        Assert.Null(failure);
    }

    [Fact]
    [Trait("Category", "CommandIconsSource")]
    public void CommandControlsDoNotUseSystemGlyphFonts()
    {
        string repositoryRoot = ResolveRepositoryRoot();
        string[] relativePaths =
        [
            "src/CodeSigner.App/MainWindow.xaml",
            "src/CodeSigner.App/SettingsWindow.xaml",
            "src/CodeSigner.App/PrimitiveShowcaseWindow.xaml"
        ];
        var offenders = new List<string>();

        foreach (string relativePath in relativePaths)
        {
            string path = Path.Combine(repositoryRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
            XDocument document = XDocument.Load(path, LoadOptions.SetLineInfo);
            foreach (XElement element in document.Descendants())
            {
                XAttribute? fontFamily = element.Attribute("FontFamily");
                bool isCommandGlyph =
                    string.Equals(fontFamily?.Value, "{StaticResource Font.Icon}", StringComparison.Ordinal) &&
                    element.Ancestors().Any(static ancestor =>
                        ancestor.Name.LocalName is "Button" or "MenuItem");
                if (!isCommandGlyph)
                {
                    continue;
                }

                var lineInfo = (IXmlLineInfo)element;
                offenders.Add($"{relativePath}:{lineInfo.LineNumber}:{element.Name.LocalName}");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "System MDL2 command glyphs remain:\n" + string.Join(Environment.NewLine, offenders));
    }

    [Fact]
    [Trait("Category", "CommandIconsSource")]
    public void SystemGlyphFontUseIsLimitedToShowcaseStatusAndComboBoxChevron()
    {
        string repositoryRoot = ResolveRepositoryRoot();
        string appRoot = Path.Combine(repositoryRoot, "src", "CodeSigner.App");
        var uses = new List<(string RelativePath, XElement Element)>();
        foreach (string path in Directory.GetFiles(appRoot, "*.xaml", SearchOption.AllDirectories))
        {
            XDocument document = XDocument.Load(path, LoadOptions.SetLineInfo);
            uses.AddRange(document
                .Descendants()
                .Where(static element => string.Equals(
                    element.Attribute("FontFamily")?.Value,
                    "{StaticResource Font.Icon}",
                    StringComparison.Ordinal))
                .Select(element => (Path.GetRelativePath(repositoryRoot, path).Replace('\\', '/'), element)));
        }

        Assert.Equal(2, uses.Count);
        (string RelativePath, XElement Element) use = Assert.Single(
            uses, entry => entry.RelativePath == "src/CodeSigner.App/PrimitiveShowcaseWindow.xaml");
        Assert.Equal("src/CodeSigner.App/PrimitiveShowcaseWindow.xaml", use.RelativePath);
        Assert.Equal("\uE73E", use.Element.Attribute("Text")?.Value);
        Assert.Equal(
            "已就绪",
            use.Element.Attribute("AutomationProperties.Name")?.Value);
        Assert.DoesNotContain(
            use.Element.Ancestors(),
            static ancestor => ancestor.Name.LocalName is "Button" or "MenuItem");
        (string RelativePath, XElement Element) chevron = Assert.Single(
            uses, entry => entry.RelativePath == "src/CodeSigner.App/Themes/DesignTokens.xaml");
        Assert.Equal("\uE70D", chevron.Element.Attribute("Text")?.Value);
        Assert.Equal("10", chevron.Element.Attribute("FontSize")?.Value);
        XElement toggle = Assert.Single(chevron.Element.Ancestors(),
            static element => element.Name.LocalName == "ToggleButton");
        Assert.Equal("DropDownToggle", toggle.Attribute(XName.Get("Name", XamlLanguageNamespace))?.Value);
        Assert.Equal("False", toggle.Attribute("Focusable")?.Value);
        XElement style = Assert.Single(chevron.Element.Ancestors(),
            static element => element.Name.LocalName == "Style");
        Assert.Equal("EditorComboBoxStyle", style.Attribute(XName.Get("Key", XamlLanguageNamespace))?.Value);
        Assert.Equal("ComboBox", style.Attribute("TargetType")?.Value);
    }

    [Fact]
    [Trait("Category", "CommandIconsSource")]
    public void PinnedLocalCommandIconResourcesAreContinuous()
    {
        AssertLucideLicenseHashIsStableAcrossCheckoutLineEndings();
        List<string> errors = ValidateCommandIconContinuity(ResolveRepositoryRoot());

        Assert.True(errors.Count == 0, string.Join(Environment.NewLine, errors));
    }

    [Fact]
    [Trait("Category", "CommandIconsLicenseBytes")]
    public void PinnedLucideLicenseByteContractAcceptsLfAndCrlfUtf8()
    {
        byte[] lfBytes = ReadLucideLicenseLfBytesForTestData();
        byte[] crlfBytes = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(lfBytes).Replace("\n", "\r\n", StringComparison.Ordinal));

        Assert.Equal(LucideLicenseSha256, ComputeLucideLicenseCanonicalSha256(lfBytes));
        Assert.Equal(LucideLicenseSha256, ComputeLucideLicenseCanonicalSha256(crlfBytes));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("Category", "CommandIconsNegative")]
    public void InlineCopyIconPenCannotBeMissingOrChangeStroke(bool remove)
    {
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-Icon-" + Guid.NewGuid().ToString("N"));
        try
        {
            CopyCommandIconContractFiles(ResolveRepositoryRoot(), root);
            string path = Path.Combine(root, "src", "CodeSigner.App", "Assets", "CommandIcons", "LucideCommandIcons.xaml");
            XDocument dictionary = XDocument.Load(path);
            XElement icon = Assert.Single(dictionary.Descendants(), element =>
                element.Attribute(XName.Get("Key", XamlLanguageNamespace))?.Value == "Icon.Command.Copy");
            XElement pen = Assert.Single(icon.Descendants(), element => element.Name.LocalName == "Pen");
            if (remove)
            {
                pen.Remove();
            }
            else
            {
                pen.SetAttributeValue("Thickness", "3");
            }
            dictionary.Save(path);
            List<string> errors = ValidateCommandIconContinuity(root);
            Assert.Contains(errors, error => remove
                ? error.Contains("Icon.Command.Copy", StringComparison.Ordinal)
                : error.Contains("2 DIP round stroke", StringComparison.Ordinal));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Theory]
    [MemberData(nameof(RejectedLucideLicenseByteRepresentations))]
    [Trait("Category", "CommandIconsLicenseBytes")]
    public void PinnedLucideLicenseByteContractRejectsAlternateEncodingBomAndLoneCr(
        string scenario,
        byte[] bytes,
        Type expectedException)
    {
        Exception? failure = Record.Exception(() => ComputeLucideLicenseCanonicalSha256(bytes));

        Assert.True(failure is not null, $"{scenario} did not fail at the license byte boundary.");
        Assert.Equal(expectedException, failure!.GetType());
    }

    [Fact]
    [Trait("Category", "CommandIconsLicenseBytes")]
    public void PinnedLucideLicenseByteContractRejectsNonEolContentMutationByHash()
    {
        byte[] contentMutation = ReadLucideLicenseLfBytesForTestData();
        contentMutation[0] = contentMutation[0] == (byte)'X' ? (byte)'Y' : (byte)'X';

        Assert.NotEqual(LucideLicenseSha256, ComputeLucideLicenseCanonicalSha256(contentMutation));
    }

    public static TheoryData<string, byte[], Type> RejectedLucideLicenseByteRepresentations
    {
        get
        {
            byte[] lfBytes = ReadLucideLicenseLfBytesForTestData();
            string lfText = Encoding.UTF8.GetString(lfBytes);
            byte[] invalidUtf8 = (byte[])lfBytes.Clone();
            invalidUtf8[0] = 0xff;

            return new TheoryData<string, byte[], Type>
            {
                { "utf-8-bom", WithPreamble(new UTF8Encoding(true), lfText), typeof(InvalidDataException) },
                { "utf-16le-bom", WithPreamble(new UnicodeEncoding(false, true), lfText), typeof(InvalidDataException) },
                { "utf-16be-bom", WithPreamble(new UnicodeEncoding(true, true), lfText), typeof(InvalidDataException) },
                { "invalid-utf-8", invalidUtf8, typeof(DecoderFallbackException) },
                { "lone-cr", Encoding.UTF8.GetBytes(lfText.Replace("\n", "\r", StringComparison.Ordinal)), typeof(InvalidDataException) }
            };
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowCleanup")]
    public async Task SurfaceDiagnosticsExportDeletesItsOwnFileAndPreservesUnrelatedTempData()
    {
        string unrelatedPath = Path.Combine(
            Path.GetTempPath(),
            $"CodeSigner-ui-diagnostics-unrelated-{Guid.NewGuid():N}.json");
        string? generatedPath = null;
        File.WriteAllText(unrelatedPath, "test-owned unrelated sentinel");

        try
        {
            generatedPath = await ExportDiagnosticsInHarnessScopeAsync();

            Assert.False(File.Exists(generatedPath));
            Assert.True(File.Exists(unrelatedPath));
        }
        finally
        {
            if (generatedPath is not null && File.Exists(generatedPath))
            {
                File.Delete(generatedPath);
            }

            if (File.Exists(unrelatedPath))
            {
                File.Delete(unrelatedPath);
            }
        }
    }

    [Fact]
    [Trait("Category", "CommandIconsNegative")]
    public void MisKeyedLocalCommandIconResourceFailsContinuityValidationAndCleansUp()
    {
        string repositoryRoot = ResolveRepositoryRoot();
        string temporaryRoot = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner.CommandIcons",
            Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        List<string>? errors = null;
        bool cleanupSucceeded = false;

        try
        {
            CopyCommandIconContractFiles(repositoryRoot, temporaryRoot);
            string dictionaryPath = Path.Combine(
                temporaryRoot,
                "src",
                "CodeSigner.App",
                "Assets",
                "CommandIcons",
                "LucideCommandIcons.xaml");
            XDocument dictionary = XDocument.Load(dictionaryPath, LoadOptions.PreserveWhitespace);
            XElement addFileResource = Assert.Single(
                dictionary.Descendants(),
                element => element.Name.LocalName == "DrawingImage" &&
                           string.Equals(
                               element.Attribute(XName.Get("Key", XamlLanguageNamespace))?.Value,
                               "Icon.Command.AddFile",
                               StringComparison.Ordinal));
            XAttribute key = Assert.IsType<XAttribute>(
                addFileResource.Attribute(XName.Get("Key", XamlLanguageNamespace)));
            key.Value = "Icon.Command.AddFile.MisKeyed";
            dictionary.Save(dictionaryPath, SaveOptions.DisableFormatting);

            errors = ValidateCommandIconContinuity(temporaryRoot);
            Assert.Contains(
                errors,
                static error => error.Contains("Icon.Command.AddFile", StringComparison.Ordinal));
        }
        finally
        {
            if (Directory.Exists(temporaryRoot))
            {
                Directory.Delete(temporaryRoot, recursive: true);
            }

            cleanupSucceeded = !Directory.Exists(temporaryRoot);
            WriteJson(
                Path.Combine(evidenceDirectory, "command-icon-negative-continuity.json"),
                new
                {
                    scenario = "A temp copy mis-keys Icon.Command.AddFile and continuity validation rejects it",
                    invocation = "UiWorkflowSurfaceTests.MisKeyedLocalCommandIconResourceFailsContinuityValidationAndCleansUp",
                    errors,
                    temporaryRoot,
                    cleanupSucceeded
                });
        }

        Assert.True(cleanupSucceeded);
    }

    [Fact]
    [Trait("Category", "UiWorkflow")]
    public void AutomationCompletesVisibleAddRejectMalformedDllDualRetryExportAndResponsiveWorkflow()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var readiness = new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary));
        var intake = new SurfaceIntakeAdapter();
        var batch = new SurfaceBatchAdapter();
        var shell = new SurfaceOperatorShell();
        var dialogs = new SurfaceDialogs();
        using var host = new VisibleWpfHost(readiness, intake, batch, shell, dialogs);

        host.Start();
        Exception? workflowFailure = null;
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            AssertRequiredMainControls(root);
            Invoke(root, "AddFilesButton");
            AutomationElement row = WaitForElement(root, "QueueRow_1");
            Assert.Contains(LongExePath, row.Current.Name, StringComparison.Ordinal);
            Assert.Contains("待处理", row.Current.Name, StringComparison.Ordinal);

            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.IsDualMode));

            Invoke(root, "AddFolderButton");
            AutomationElement inputError = WaitForElement(root, "InputError");
            Assert.Equal(
                "文件内容不是可签名的受支持格式：malformed-library.dll",
                inputError.Current.Name);
            Assert.Equal(0, batch.RunCount);
            Assert.Equal(1, intake.TypedRejectionCount);
            Assert.Equal(0, intake.StagingCount);
            AssertFocusedTarget("InputError");

            Invoke(root, "AddFilesButton");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.CanSign));
            Assert.Equal(1, host.ReadViewModel(viewModel => viewModel.Rows.Count));

            var layoutObservations = new List<LayoutObservation>
            {
                CaptureLayout(host, root, evidenceDirectory, "100-992x736", 992, 736, expectedCompact: false),
                CaptureLayout(host, root, evidenceDirectory, "150-650.67x480", 650.67, 480, expectedCompact: true),
                CaptureLayout(host, root, evidenceDirectory, "200-480x352", 480, 352, expectedCompact: true)
            };

            VerifyKeyboardSettingsPath(host, root, readiness, evidenceDirectory, "full-workflow");

            Invoke(root, "SignButton");
            WaitUntil(() => Find(root, "QueueRow_1")?.Current.Name.Contains("失败", StringComparison.Ordinal) == true);
            Assert.Equal(1, batch.RunCount);
            Thread.Sleep(250);
            CaptureFocusObservation(host, evidenceDirectory, "focus-full-workflow-failed.json");
            AssertFocusedTarget("QueueRow_1");
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "workflow-failed.png"));

            InvokeProcessElement(host.ProcessId, root, "RetryButton");
            WaitUntil(() => Find(root, "QueueRow_1")?.Current.Name.Contains("已发布", StringComparison.Ordinal) == true);
            Assert.Equal(1, batch.ResumeCount);
            Assert.Contains("已发布", WaitForElement(root, "QueueRow_1").Current.Name, StringComparison.Ordinal);

            InvokeProcessElement(host.ProcessId, root, "OpenOutputButton");
            WaitUntil(() => shell.OpenFolderCount == 1 && shell.OpenedFolder == OutputRoot);
            Assert.Equal(OutputRoot, shell.OpenedFolder);
            InvokeProcessElement(host.ProcessId, root, "ExportDiagnosticsButton");
            WaitUntil(() => shell.ExportCount == 1 &&
                shell.ExportedDiagnosticsPath is not null &&
                File.Exists(shell.ExportedDiagnosticsPath));
            Assert.DoesNotContain(LongExePath, shell.LastDiagnostics!.Values.OfType<string>());
            Assert.Equal(30, shell.LastRetentionDays);
            string diagnosticsPath = shell.ExportedDiagnosticsPath!;
            string diagnosticsJson = File.ReadAllText(diagnosticsPath);
            Assert.DoesNotContain("credential", diagnosticsJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("privateKey", diagnosticsJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("pin", diagnosticsJson, StringComparison.OrdinalIgnoreCase);
            WriteJson(
                Path.Combine(evidenceDirectory, "diagnostics-redaction.json"),
                new
                {
                    scenario = "UI Export diagnostics command writes an allow-listed redacted file",
                    path = diagnosticsPath,
                    exists = File.Exists(diagnosticsPath),
                    bytes = new FileInfo(diagnosticsPath).Length,
                    containsCredential = diagnosticsJson.Contains("credential", StringComparison.OrdinalIgnoreCase),
                    containsPrivateKey = diagnosticsJson.Contains("privateKey", StringComparison.OrdinalIgnoreCase),
                    containsPin = diagnosticsJson.Contains("pin", StringComparison.OrdinalIgnoreCase),
                    json = diagnosticsJson
                });
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "workflow-published.png"));
            CaptureTree(root, Path.Combine(evidenceDirectory, "ui-workflow-final-uia.json"));

            WriteJson(
                Path.Combine(evidenceDirectory, "ui-workflow.json"),
                new
                {
                    scenario = "real WPF fake-backed add-select-sign-fail-retry-publish-open-export",
                    invocationCategory = "UiWorkflow",
                    addDialogCalls = dialogs.FilePickerCount,
                    folderDialogCalls = dialogs.FolderPickerCount,
                    intakeCalls = intake.CallCount,
                    typedContentRejections = intake.TypedRejectionCount,
                    stagingCalls = intake.StagingCount,
                    batchRuns = batch.RunCount,
                    batchResumes = batch.ResumeCount,
                    diagnosticExports = shell.ExportCount,
                    finalState = host.ReadViewModel(viewModel => viewModel.Rows[0].StateText),
                    originalPath = LongExePath,
                    outputRoot = OutputRoot,
                    layoutObservations
                });
            WriteEnvironmentLimitArtifacts(evidenceDirectory, host);
        }
        catch (Exception exception)
        {
            workflowFailure = exception;
            throw;
        }
        finally
        {
            try
            {
                host.Stop();
            }
            catch (Exception cleanupException) when (workflowFailure is not null)
            {
                workflowFailure.Data["VisibleWpfHostCleanupFailure"] = cleanupException.ToString();
            }
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowOpenOutput")]
    public void UiaOpenOutputCompletesAfterDispatcherDrain()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var shell = new SurfaceOperatorShell();
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            shell,
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Invoke(root, "AddFilesButton");
            WaitUntil(() => host.ReadViewModel(viewModel =>
                viewModel.OutputRoot == OutputRoot && viewModel.OpenOutputCommand.CanExecute(null)));

            AutomationElement button = WaitForElement(root, "OpenOutputButton");
            bool hasInvokePattern = button.TryGetCurrentPattern(InvokePattern.Pattern, out object? pattern);
            var before = new
            {
                capturedAtUtc = DateTimeOffset.UtcNow,
                buttonEnabled = button.Current.IsEnabled,
                hasInvokePattern,
                shellCallCount = shell.OpenFolderCount,
                shellOpenedFolder = shell.OpenedFolder,
                dispatcher = host.ReadOpenOutputCommandState()
            };

            Assert.True(before.buttonEnabled);
            Assert.True(hasInvokePattern);
            ((InvokePattern)pattern!).Invoke();

            var immediate = new
            {
                capturedAtUtc = DateTimeOffset.UtcNow,
                shellCallCount = shell.OpenFolderCount,
                shellOpenedFolder = shell.OpenedFolder,
                dispatcher = host.ReadOpenOutputCommandState()
            };
            DispatcherOperation idleMarker = host.QueueDispatcherIdleMarker();
            string markerStatusAfterQueue = idleMarker.Status.ToString();
            WaitUntil(() => idleMarker.Status == DispatcherOperationStatus.Completed);
            WaitUntil(() => shell.OpenFolderCount == 1 && shell.OpenedFolder == OutputRoot);
            var afterDrain = new
            {
                capturedAtUtc = DateTimeOffset.UtcNow,
                markerStatus = idleMarker.Status.ToString(),
                shellCallCount = shell.OpenFolderCount,
                shellOpenedFolder = shell.OpenedFolder,
                dispatcher = host.ReadOpenOutputCommandState()
            };

            WriteJson(
                Path.Combine(evidenceDirectory, "open-output-uia-dispatch.json"),
                new
                {
                    scenario = "Add one .exe, invoke Open output through UI Automation, then drain the WPF Dispatcher",
                    before,
                    immediate,
                    markerStatusAfterQueue,
                    afterDrain
                });
            Assert.Equal(1, shell.OpenFolderCount);
            Assert.Equal(OutputRoot, shell.OpenedFolder);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowCleanup")]
    public async Task FailedStaStartupDoesNotHangDuringCleanup()
    {
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var releaseFailedSta = new ManualResetEventSlim(false);
        using var failedStaReleased = new ManualResetEventSlim(false);
        Task<Exception?> cleanup = Task.Run(() =>
        {
            try
            {
                using var host = new VisibleWpfHost(
                    new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
                    new SurfaceIntakeAdapter(),
                    new SurfaceBatchAdapter(),
                    new SurfaceOperatorShell(),
                    new SurfaceDialogs(),
                    () => throw new InvalidOperationException("Injected STA startup failure."),
                    () =>
                    {
                        releaseFailedSta.Wait();
                        failedStaReleased.Set();
                    });
                host.Start();
                return null;
            }
            catch (Exception exception)
            {
                return exception;
            }
        });

        try
        {
            Exception? observed = await cleanup.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.NotNull(observed);
            Assert.Contains("Injected STA startup failure.", observed.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            releaseFailedSta.Set();
            Assert.True(failedStaReleased.Wait(TimeSpan.FromSeconds(3)), "The failed STA did not exit.");
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowWorkerRecovery")]
    public void WorkerRecoveryRegionExposesUnhealthyAndRepairingStatesThroughUia()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var repairCompletion = new TaskCompletionSource<WorkerRepairResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new SurfaceWorkerHealthService(
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Missing),
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
        var repair = new SurfaceWorkerRepairService(_ => repairCompletion.Task);
        var shell = new SurfaceOperatorShell();
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            shell,
            new SurfaceDialogs(),
            workerHealthService: health,
            workerRepairService: repair);

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            WaitUntil(() => host.ReadViewModel(viewModel =>
                viewModel.WorkerHealthState == WorkerHealthState.Unhealthy));

            AutomationElement region = WaitForElement(root, "WorkerRecoveryRegion");
            AssertRecoveryRegion(region, expectedReasonCode: "missing", expectedRepairVisible: true);
            Assert.Equal("Assertive", host.ReadWorkerRecoveryLiveSetting());
            AutomationElement refresh = WaitForElement(root, "RefreshWorkerButton");
            AutomationElement repairButton = WaitForElement(root, "RepairWorkerButton");
            AutomationElement openInstallation = WaitForElement(root, "OpenInstallationDirectoryButton");
            Assert.True(refresh.Current.IsEnabled);
            Assert.True(repairButton.Current.IsEnabled);
            Assert.True(openInstallation.Current.IsEnabled);
            Assert.True(host.ReadViewModel(viewModel => viewModel.CanRepairWorker));
            Assert.True(host.ReadViewModel(viewModel => viewModel.CanRefreshWorker));
            AssertFocusedTarget("WorkerRecoveryRegion");

            var layouts = new[]
            {
                CaptureWorkerRecoveryLayout(host, root, evidenceDirectory, "unhealthy-full-100", 100, 992, 736, expectedCompact: false),
                CaptureWorkerRecoveryLayout(host, root, evidenceDirectory, "unhealthy-compact-150", 150, 650.67, 480, expectedCompact: true),
                CaptureWorkerRecoveryLayout(host, root, evidenceDirectory, "unhealthy-compact-200", 200, 480, 352, expectedCompact: true)
            };

            Invoke(root, "OpenInstallationDirectoryButton");
            WaitUntil(() => shell.OpenFolderCount == 1);
            Assert.Equal(Path.GetFullPath(AppContext.BaseDirectory), shell.OpenedFolder);

            Invoke(root, "RepairWorkerButton");
            WaitUntil(() => host.ReadViewModel(viewModel =>
                viewModel.WorkerHealthState == WorkerHealthState.Repairing));
            region = WaitForElement(root, "WorkerRecoveryRegion");
            refresh = WaitForElement(root, "RefreshWorkerButton");
            repairButton = WaitForElement(root, "RepairWorkerButton");
            AssertRecoveryRegion(region, expectedReasonCode: "missing", expectedRepairVisible: true);
            Assert.Equal("Assertive", host.ReadWorkerRecoveryLiveSetting());
            WaitUntil(() => !refresh.Current.IsEnabled && !repairButton.Current.IsEnabled);
            Assert.False(refresh.Current.IsEnabled);
            Assert.False(repairButton.Current.IsEnabled);
            Assert.True(WaitForElement(root, "OpenInstallationDirectoryButton").Current.IsEnabled);
            Assert.False(host.ReadViewModel(viewModel => viewModel.CanRepairWorker));
            Assert.False(host.ReadViewModel(viewModel => viewModel.CanRefreshWorker));
            AssertFocusedTarget("WorkerRecoveryRegion");
            CaptureTree(root, Path.Combine(evidenceDirectory, "worker-recovery-repairing-uia.json"));
            var repairingObservation = new
            {
                regionAutomationId = region.Current.AutomationId,
                regionName = region.Current.Name,
                regionHelpText = region.Current.HelpText,
                refreshEnabled = refresh.Current.IsEnabled,
                repairEnabled = repairButton.Current.IsEnabled,
                uiaLiveSetting = ReadLiveSetting(region),
                attachedLiveSetting = host.ReadWorkerRecoveryLiveSetting()
            };

            repairCompletion.SetResult(CreateSuccessfulWorkerRepairResult());
            WaitUntil(() => host.ReadViewModel(viewModel =>
                viewModel.WorkerHealthState == WorkerHealthState.Healthy));
            WaitUntil(() => !host.ReadViewModel(viewModel => viewModel.IsWorkerRecoveryVisible));

            WriteJson(
                Path.Combine(evidenceDirectory, "worker-recovery-uia.json"),
                new
                {
                    scenario = "Real WPF UIA Worker recovery region transitions from Unhealthy to Repairing to Healthy",
                    invocation = "VisibleWpfHost with injected IWorkerHealthService/IWorkerRepairService; AutomationElement",
                    healthProbeCalls = health.CallCount,
                    repairCalls = repair.CallCount,
                    layouts,
                    repairing = repairingObservation,
                    actualDpiPercent = host.DpiScale * 100.0,
                    requestedDpiPercent = RequestedDpiPercent
                });
        }
        finally
        {
            repairCompletion.TrySetResult(CreateSuccessfulWorkerRepairResult());
            host.Stop();
        }

        EligibleCertificate nonEligiblePrimary = Certificate('C', "CN=Release SHA256");
        EligibleCertificate nonEligibleSecondary = Certificate('D', "CN=Release SHA1");
        using var nonEligibleHost = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(nonEligiblePrimary, nonEligibleSecondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs(),
            workerHealthService: new SurfaceWorkerHealthService(
                WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.AccessDenied)));
        nonEligibleHost.Start();
        try
        {
            AutomationElement nonEligibleRoot = WaitForWindow(nonEligibleHost.Handle);
            WaitUntil(() => nonEligibleHost.ReadViewModel(viewModel =>
                viewModel.WorkerHealthState == WorkerHealthState.Unhealthy));
            AutomationElement nonEligibleRegion = WaitForElement(nonEligibleRoot, "WorkerRecoveryRegion");
            AssertRecoveryRegion(nonEligibleRegion, expectedReasonCode: "access_denied", expectedRepairVisible: false);
            Assert.Null(Find(nonEligibleRoot, "RepairWorkerButton"));
            Assert.True(WaitForElement(nonEligibleRoot, "RefreshWorkerButton").Current.IsEnabled);
            Assert.True(WaitForElement(nonEligibleRoot, "OpenInstallationDirectoryButton").Current.IsEnabled);
            Assert.False(nonEligibleHost.ReadViewModel(viewModel => viewModel.CanRepairWorker));
            CaptureTree(nonEligibleRoot, Path.Combine(evidenceDirectory, "worker-recovery-noneligible-uia.json"));
        }
        finally
        {
            nonEligibleHost.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowOpenLogDirectory")]
    public void UiaOpenLogDirectoryIsAdjacentExactAndInvokesTheDefaultDiagnosticsRoot()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var shell = new SurfaceOperatorShell(createOpenedDirectories: true);
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            shell,
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            AutomationElementCollection buttons = root.FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button));
            AutomationElement[] openButtons = buttons.Cast<AutomationElement>()
                .Where(static button => string.Equals(
                    button.Current.AutomationId,
                    "OpenLogDirectoryButton",
                    StringComparison.Ordinal))
                .ToArray();
            AutomationElement open = Assert.Single(openButtons);
            string[] commandIds = buttons.Cast<AutomationElement>()
                .Select(static button => button.Current.AutomationId)
                .Where(static automationId => !string.IsNullOrEmpty(automationId))
                .ToArray();
            int exportIndex = Array.IndexOf(commandIds, "ExportDiagnosticsButton");
            int openIndex = Array.IndexOf(commandIds, "OpenLogDirectoryButton");
            Dictionary<string, object?> wpfMetadata = host.ReadOpenLogDirectoryButtonMetadata();

            Assert.Equal(exportIndex + 1, openIndex);
            Assert.Equal("打开日志目录", open.Current.Name);
            Assert.Equal(
                "在文件资源管理器中打开本机日志目录：%LOCALAPPDATA%\\CodeSigner\\Diagnostics",
                open.Current.HelpText);
            Assert.Equal("打开本地日志目录", wpfMetadata["toolTip"]);
            Assert.True(open.Current.IsEnabled);
            Assert.True(open.TryGetCurrentPattern(InvokePattern.Pattern, out object? pattern));

            ((InvokePattern)pattern!).Invoke();
            WaitUntil(() => shell.OpenFolderCount == 1);
            Assert.Equal(SigningRuntimeEventLog.DefaultDiagnosticsRoot, shell.OpenedFolder);
            Assert.True(Directory.Exists(SigningRuntimeEventLog.DefaultDiagnosticsRoot));

            string screenshot = Path.Combine(evidenceDirectory, "open-log-directory-command.png");
            string tree = Path.Combine(evidenceDirectory, "open-log-directory-command-uia.json");
            CaptureScreenshot(root, screenshot);
            CaptureTree(root, tree);
            WriteJson(
                Path.Combine(evidenceDirectory, "open-log-directory-manual-qa.json"),
                new
                {
                    scenario = "real WPF UIA adjacent log-directory command invocation",
                    invocation = "InvokePattern.Invoke on OpenLogDirectoryButton",
                    automationId = open.Current.AutomationId,
                    name = open.Current.Name,
                    helpText = open.Current.HelpText,
                    toolTip = wpfMetadata["toolTip"],
                    adjacentAfter = "ExportDiagnosticsButton",
                    invokePattern = true,
                    shellCalls = shell.OpenFolderCount,
                    openedPath = shell.OpenedFolder,
                    expectedPath = SigningRuntimeEventLog.DefaultDiagnosticsRoot,
                    directoryExists = Directory.Exists(SigningRuntimeEventLog.DefaultDiagnosticsRoot),
                    screenshot,
                    tree
                });
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowShownCleanup")]
    public void ShownWindowStopsWithinBoundedCleanup()
    {
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        Assert.NotEqual(IntPtr.Zero, host.Handle);
        host.Stop();
    }

    [Fact]
    [Trait("Category", "UiWorkflowSequentialHosts")]
    public void TwoSequentialVisibleHostsRunAndCloseInOneTestProcess()
    {
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");

        for (int hostNumber = 1; hostNumber <= 2; hostNumber++)
        {
            using var host = new VisibleWpfHost(
                new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
                new SurfaceIntakeAdapter(),
                new SurfaceBatchAdapter(),
                new SurfaceOperatorShell(),
                new SurfaceDialogs());
            host.Start();
            Assert.NotEqual(IntPtr.Zero, host.Handle);
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowLayoutBaseline")]
    public void ChineseAutomationNormalGeometryAndKeyboardRoutesRemainStableWithoutSigning()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var readiness = new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary));
        var batch = new SurfaceBatchAdapter();
        using var host = new VisibleWpfHost(
            readiness,
            new SurfaceIntakeAdapter(),
            batch,
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Assert.Equal("安信证书签名工具签名工作台", root.Current.Name);
            AssertRequiredMainControls(root);
            host.Resize(992, 736);
            WaitUntil(() => !host.IsCompactLayout && Math.Abs(host.ActualWidth - 992) < 2);
            Thread.Sleep(150);

            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement output = WaitForElement(root, "OutputRootTextBox");
            AutomationElement sign = WaitForElement(root, "SignButton");
            Assert.Equal("签名文件队列与结果", queue.Current.Name);
            Assert.False(queue.Current.BoundingRectangle.IntersectsWith(output.Current.BoundingRectangle));
            Assert.False(queue.Current.BoundingRectangle.IntersectsWith(sign.Current.BoundingRectangle));
            AssertVisibleWithin(root, queue);
            AssertVisibleWithin(root, output);
            AssertVisibleWithin(root, sign);

            VerifyKeyboardSettingsPath(host, root, readiness, evidenceDirectory, "layout-baseline");
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "normal-992x736-baseline.png"));
            CaptureTree(root, Path.Combine(evidenceDirectory, "normal-992x736-baseline-uia.json"));
            WriteJson(
                Path.Combine(evidenceDirectory, "normal-keyboard-baseline.json"),
                new
                {
                    scenario = "Chinese UIA, 992x736 geometry, and F5/Alt+G/Escape without signing",
                    rootName = root.Current.Name,
                    queue = ElementGeometry(queue),
                    output = ElementGeometry(output),
                    sign = ElementGeometry(sign),
                    readiness.ProbeCount,
                    batch.RunCount,
                    batch.ResumeCount
                });

            Assert.Equal(0, batch.RunCount);
            Assert.Equal(0, batch.ResumeCount);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowLayout")]
    public void CompactLayoutKeepsQueueAndPinnedActionsVisible()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Invoke(root, "AddFilesButton");
            _ = WaitForElement(root, "QueueRow_1");
            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.IsDualMode));

            _ = CaptureLayout(host, root, evidenceDirectory, "150-650.67x480", 650.67, 480, expectedCompact: true);
            _ = CaptureLayout(host, root, evidenceDirectory, "200-480x352", 480, 352, expectedCompact: true);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowCompactQueueGeometry")]
    public async Task CompactLayoutFitsAllQueueColumnsAndDoesNotIntersectPinnedActions()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var batch = new SurfaceBatchAdapter();
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            batch,
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            await host.ReadViewModel(viewModel => viewModel.QueueFilesAsync([LongExePath, SecondExePath]));
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.Rows.Count) == 2);
            (string AutomationId, string ResultText) failedState = host.ReadViewModel(viewModel =>
            {
                QueueItemViewModel row = viewModel.Rows[1];
                var diagnostic = new WorkerResponse(
                    WorkerProtocol.Version,
                    Success: false,
                    WorkerResponseCodes.WindowsSipUnavailable,
                    HResult: unchecked((int)0x80004005),
                    OperationId: "compact-layout-operation",
                    DiagnosticId: "compact-layout-diagnostic",
                    DiagnosticPhase: WorkerDiagnosticPhases.WorkerBridge,
                    HResultOrigin: WorkerHResultOrigins.WorkerBridge,
                    Subject: WorkerSubjects.WindowsInstaller,
                    Capability: WorkerCapabilities.WindowsSipSingleOnly,
                    Engine: WorkerEngines.WindowsSip,
                    Verification: WorkerVerifications.WindowsSip,
                    LegacyFallbackAttempted: false);
                var receipt = new BatchItemReceipt(
                    row.ItemId,
                    BatchItemState.Failed,
                    BatchResultCode.WorkerFailure,
                    row.FullPath,
                    row.DestinationPath,
                    null,
                    null,
                    "COMPACT-LAYOUT-ATTEMPT",
                    null,
                    unchecked((int)0x80004005),
                    SigningDiagnostic: diagnostic);
                row.Apply(BatchItemState.Failed, receipt);
                return (row.AutomationId, row.ResultText);
            });

            host.Resize(650.67, 480);
            WaitUntil(() => host.IsCompactLayout && Math.Abs(host.ActualWidth - 650.67) < 2);
            Select(root, failedState.AutomationId);
            WaitUntil(() => Find(root, "RuntimeError") is AutomationElement element && !element.Current.IsOffscreen);
            Thread.Sleep(250);
            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement output = WaitForElement(root, "OutputRootTextBox");
            AutomationElement sign = WaitForElement(root, "SignButton");
            AutomationElement runtimeError = WaitForElement(root, "RuntimeError");
            AutomationElement failedRow = WaitForElement(root, failedState.AutomationId);
            AutomationElement resultText = Assert.IsType<AutomationElement>(failedRow.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text),
                    new PropertyCondition(AutomationElement.NameProperty, failedState.ResultText))));
            AutomationElement rowAction = Assert.IsType<AutomationElement>(failedRow.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button),
                    new PropertyCondition(AutomationElement.NameProperty, "从队列移除此签名文件"))));
            string[] expectedHeaders = ["文件输入", "检测格式", "签名引擎", "有效策略", "状态", "进度", "结果", "操作"];
            AutomationElement[] headerItems = queue.FindAll(
                    TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.HeaderItem))
                .Cast<AutomationElement>()
                .Where(header => expectedHeaders.Contains(header.Current.Name, StringComparer.Ordinal))
                .ToArray();
            AutomationElement[] visibleRows = queue.FindAll(
                    TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem))
                .Cast<AutomationElement>()
                .Where(static row => !row.Current.IsOffscreen)
                .ToArray();
            System.Windows.Rect queueBounds = queue.Current.BoundingRectangle;
            var failures = new List<string>();

            if (queueBounds.IntersectsWith(output.Current.BoundingRectangle))
            {
                failures.Add($"Queue intersects OutputRootTextBox: queue={queueBounds}; output={output.Current.BoundingRectangle}.");
            }

            if (queueBounds.IntersectsWith(sign.Current.BoundingRectangle))
            {
                failures.Add($"Queue intersects SignButton: queue={queueBounds}; sign={sign.Current.BoundingRectangle}.");
            }

            foreach (AutomationElement row in visibleRows)
            {
                System.Windows.Rect bounds = row.Current.BoundingRectangle;
                if (bounds.Left < queueBounds.Left - 1 || bounds.Right > queueBounds.Right + 1)
                {
                    failures.Add($"{row.Current.AutomationId} extends horizontally outside the queue: queue={queueBounds}; row={bounds}.");
                }
            }

            foreach (string expectedHeader in expectedHeaders)
            {
                AutomationElement? header = headerItems.SingleOrDefault(
                    candidate => string.Equals(candidate.Current.Name, expectedHeader, StringComparison.Ordinal));
                if (header is null)
                {
                    failures.Add($"Required queue header is missing: {expectedHeader}.");
                    continue;
                }

                System.Windows.Rect bounds = header.Current.BoundingRectangle;
                if (header.Current.IsOffscreen || bounds.Left < queueBounds.Left - 1 || bounds.Right > queueBounds.Right + 1)
                {
                    failures.Add($"Required queue header is clipped or offscreen: {expectedHeader}; queue={queueBounds}; header={bounds}.");
                }
            }

            foreach ((string name, AutomationElement element) in new[]
                     {
                         ("result", resultText),
                         ("action", rowAction)
                     })
            {
                System.Windows.Rect bounds = element.Current.BoundingRectangle;
                if (element.Current.IsOffscreen || bounds.Left < queueBounds.Left - 1 || bounds.Right > queueBounds.Right + 1)
                {
                    failures.Add($"Required {name} content is clipped or offscreen: queue={queueBounds}; element={bounds}.");
                }
            }

            bool horizontallyScrollable = queue.TryGetCurrentPattern(ScrollPattern.Pattern, out object scrollObject) &&
                ((ScrollPattern)scrollObject).Current.HorizontallyScrollable;
            if (horizontallyScrollable)
            {
                failures.Add("SigningQueueGrid exposes horizontal scrolling at the required compact viewport.");
            }

            host.BringToFrontForCapture();
            Thread.Sleep(150);
            string screenshot = Path.Combine(evidenceDirectory, "compact-650x480-queue-columns.png");
            string tree = Path.Combine(evidenceDirectory, "compact-650x480-queue-columns-uia.json");
            CaptureScreenshot(root, screenshot);
            CaptureTree(root, tree);
            WriteJson(
                Path.Combine(evidenceDirectory, "compact-650x480-queue-columns-geometry.json"),
                new
                {
                    scenario = "650.67x480 compact queue fits all eight columns and remains separate from output/sign actions",
                    requestedWidthDip = 650.67,
                    requestedHeightDip = 480,
                    actualWidthDip = host.ActualWidth,
                    actualHeightDip = host.ActualHeight,
                    dpiScale = host.DpiScale,
                    queue = ElementGeometry(queue),
                    output = ElementGeometry(output),
                    sign = ElementGeometry(sign),
                    runtimeError = ElementGeometry(runtimeError),
                    headers = headerItems.Select(ElementGeometry).ToArray(),
                    rows = visibleRows.Select(ElementGeometry).ToArray(),
                    result = ElementGeometry(resultText),
                    action = ElementGeometry(rowAction),
                    horizontallyScrollable,
                    failures,
                    batch.RunCount,
                    batch.ResumeCount,
                    screenshot,
                    tree
                });

            Assert.Equal(0, batch.RunCount);
            Assert.Equal(0, batch.ResumeCount);
            Assert.Empty(failures);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowNormalGeometry")]
    public void NormalLayoutContainsFirstRowAndSeparatesReadinessAndCertificateControls()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=安徽斯百德生产代码签名证书 SHA256 2026");
        EligibleCertificate secondary = Certificate('B', "CN=安徽斯百德生产代码签名证书 SHA1 2026");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Invoke(root, "AddFilesButton");
            AutomationElement row = WaitForElement(root, "QueueRow_1");
            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.IsDualMode));
            host.Resize(992, 736);
            WaitUntil(() => Math.Abs(host.ActualWidth - 992) < 2 && !host.IsCompactLayout);
            Thread.Sleep(150);

            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement header = Assert.IsType<AutomationElement>(queue.FindFirst(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Header)));
            AutomationElement primarySelector = WaitForElement(root, "PrimaryCertificateCombo");
            AutomationElement secondarySelector = WaitForElement(root, "SecondaryCertificateCombo");
            AutomationElement certificateIcon = WaitForElement(root, "ReadinessCertificates");
            AutomationElement? nativeApiText = Find(root, "ReadinessNativeApiText");
            System.Windows.Rect queueBounds = queue.Current.BoundingRectangle;
            System.Windows.Rect headerBounds = header.Current.BoundingRectangle;
            System.Windows.Rect rowBounds = row.Current.BoundingRectangle;
            System.Windows.Rect primaryBounds = primarySelector.Current.BoundingRectangle;
            System.Windows.Rect secondaryBounds = secondarySelector.Current.BoundingRectangle;
            ReadinessTextFitObservation[] readinessTextFits = host.ReadReadinessTextFitObservations();
            var failures = new List<string>();

            if (rowBounds.Top < headerBounds.Bottom - 1 || rowBounds.Bottom > queueBounds.Bottom + 1)
            {
                failures.Add($"First row is not fully below the header and inside the queue: queue={queueBounds}; header={headerBounds}; row={rowBounds}.");
            }

            if (primaryBounds.IntersectsWith(secondaryBounds))
            {
                failures.Add($"Certificate selectors overlap: primary={primaryBounds}; secondary={secondaryBounds}.");
            }

            System.Windows.Rect rootBounds = root.Current.BoundingRectangle;
            if (primaryBounds.Right > rootBounds.Right + 1 || secondaryBounds.Right > rootBounds.Right + 1)
            {
                failures.Add($"A certificate selector extends past the window: root={rootBounds}; primary={primaryBounds}; secondary={secondaryBounds}.");
            }

            if (nativeApiText is null)
            {
                failures.Add("ReadinessNativeApiText is not exposed for geometry verification.");
            }
            else if (nativeApiText.Current.BoundingRectangle.Right > certificateIcon.Current.BoundingRectangle.Left + 1)
            {
                failures.Add(
                    $"Native API readiness text overlaps the certificate icon: text={nativeApiText.Current.BoundingRectangle}; icon={certificateIcon.Current.BoundingRectangle}.");
            }

            foreach (ReadinessTextFitObservation observation in readinessTextFits.Where(static value => !value.Fits))
            {
                failures.Add(
                    $"{observation.ElementName} is trimmed: actual={observation.ActualWidth:0.##}; required={observation.RequiredWidth:0.##}; text={observation.Text}.");
            }

            string screenshot = Path.Combine(evidenceDirectory, "normal-992x736-geometry.png");
            string tree = Path.Combine(evidenceDirectory, "normal-992x736-geometry-uia.json");
            CaptureScreenshot(root, screenshot);
            CaptureTree(root, tree);
            WriteJson(
                Path.Combine(evidenceDirectory, "normal-992x736-geometry.json"),
                new
                {
                    scenario = "992x736 normal layout contains a complete first row and separates readiness and certificate controls",
                    queue = ElementGeometry(queue),
                    header = ElementGeometry(header),
                    row = ElementGeometry(row),
                    primarySelector = ElementGeometry(primarySelector),
                    secondarySelector = ElementGeometry(secondarySelector),
                    primarySelectorHelpText = primarySelector.Current.HelpText,
                    secondarySelectorHelpText = secondarySelector.Current.HelpText,
                    nativeApiText = nativeApiText is null ? null : ElementGeometry(nativeApiText),
                    certificateIcon = ElementGeometry(certificateIcon),
                    readinessTextFits,
                    failures,
                    screenshot,
                    tree
                });

            Assert.Contains(primary.Subject, primarySelector.Current.HelpText, StringComparison.Ordinal);
            Assert.Contains(secondary.Subject, secondarySelector.Current.HelpText, StringComparison.Ordinal);
            Assert.Empty(failures);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowQueueDirectAdd")]
    public async Task QueueGeometryAndDirectAddSurfaceMeetEveryViewportContract()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            double defaultWidth = host.ActualWidth;
            double defaultHeight = host.ActualHeight;
            (string Label, double Width, double Height, bool ExpectedCompact)[] viewports =
            [
                ("default", defaultWidth, defaultHeight, false),
                ("992x736", 992, 736, false),
                ("650.67x480", 650.67, 480, true),
                ("480x352", 480, 352, true)
            ];

            QueueContractObservation[] emptyObservations = viewports
                .Select(viewport => CaptureQueueContract(
                    host,
                    root,
                    evidenceDirectory,
                    $"queue-{viewport.Label}-empty",
                    viewport.Width,
                    viewport.Height,
                    viewport.ExpectedCompact))
                .ToArray();

            string[] queuePaths =
            [
                LongExePath,
                SecondExePath,
                "C:\\release\\queue-third.exe",
                "C:\\release\\queue-fourth.exe",
                "C:\\release\\queue-fifth.exe",
                "C:\\release\\queue-sixth.exe",
                "C:\\release\\queue-seventh.exe",
                "C:\\release\\queue-eighth.exe"
            ];
            await host.ReadViewModel(viewModel => viewModel.QueueFilesAsync(queuePaths));
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.Rows.Count) == queuePaths.Length);

            QueueContractObservation[] populatedObservations = viewports
                .Select(viewport => CaptureQueueContract(
                    host,
                    root,
                    evidenceDirectory,
                    $"queue-{viewport.Label}-populated",
                    viewport.Width,
                    viewport.Height,
                    viewport.ExpectedCompact))
                .ToArray();

            WriteJson(
                Path.Combine(evidenceDirectory, "queue-viewport-contract.json"),
                new
                {
                    scenario = "Default, 992x736, 650.67x480, and 480x352 queue geometry plus direct-add visibility",
                    rowHeightContractDip = 50,
                    emptyObservations,
                    populatedObservations
                });

            Assert.All(emptyObservations.Concat(populatedObservations), observation =>
            {
                Assert.True(observation.DirectAddPresent, $"{observation.Label} has no direct-add control.");
                Assert.True(observation.DirectAddKeyboardFocusable);
                Assert.True(observation.DirectAddSupportsInvoke);
                Assert.False(string.IsNullOrWhiteSpace(observation.DirectAddName));
                Assert.False(string.IsNullOrWhiteSpace(observation.DirectAddHelpText));
                Assert.Contains(observation.DirectAddName!, value => value >= '\u4e00' && value <= '\u9fff');
                Assert.Contains(observation.DirectAddHelpText!, value => value >= '\u4e00' && value <= '\u9fff');
                Assert.True(observation.DirectAddWithinWindow, $"{observation.Label} direct-add control leaves the window bounds.");
                Assert.False(observation.DirectAddOverlapsQueueHeading, $"{observation.Label} direct-add control overlaps QueueHeading.");
                Assert.False(observation.DirectAddOverlapsSupportCopy, $"{observation.Label} direct-add control overlaps QueueSupportCopy.");
                Assert.False(observation.DirectAddOverlapsDataGridHeader, $"{observation.Label} direct-add control overlaps the DataGrid header.");
                Assert.False(observation.DirectAddOverlapsVisibleRow, $"{observation.Label} direct-add control overlaps a visible queue row.");
            });

            QueueContractObservation defaultObservation = populatedObservations[0];
            QueueContractObservation normalObservation = populatedObservations[1];
            QueueContractObservation compactObservation = populatedObservations[2];
            QueueContractObservation ultraObservation = populatedObservations[3];
            Assert.True(
                defaultObservation.BodyHeightDip >= 260,
                $"Default queue body is {defaultObservation.BodyHeightDip:0.##} DIP; expected at least 260 DIP.");
            Assert.False(defaultObservation.HasPartialRow);
            Assert.Equal(defaultObservation.VisibleRowCount, defaultObservation.CompleteRowCount);
            Assert.True(
                normalObservation.QueueHeightDip >= 200 && normalObservation.CompleteRowCount >= 3,
                $"992x736 queue is {normalObservation.QueueHeightDip:0.##} DIP with {normalObservation.CompleteRowCount} complete rows.");
            Assert.False(normalObservation.HasPartialRow);
            Assert.Equal(normalObservation.VisibleRowCount, normalObservation.CompleteRowCount);
            Assert.True(
                compactObservation.QueueHeightDip >= 120 && compactObservation.CompleteRowCount >= 1,
                $"650.67x480 queue is {compactObservation.QueueHeightDip:0.##} DIP with {compactObservation.CompleteRowCount} complete rows.");
            Assert.False(compactObservation.HasPartialRow);
            Assert.Equal(compactObservation.VisibleRowCount, compactObservation.CompleteRowCount);
            Assert.Equal(1, ultraObservation.VisibleRowCount);
            Assert.Equal(1, ultraObservation.CompleteRowCount);
            Assert.False(ultraObservation.HasPartialRow);
            Assert.InRange(ultraObservation.BodyHeightDip, 50, 51.5);
            Assert.All(ultraObservation.CompleteRowHeightsDip, height => Assert.InRange(height, 49.5, 50.5));
            Assert.True(ultraObservation.HasScrollPattern);
            Assert.True(ultraObservation.IsVerticallyScrollable);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowCompactOverflow")]
    public void UltraCompactOverflowInvokesHiddenCommandsAndFocusesVisibleDuplicateTarget()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var readiness = new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary));
        var shell = new SurfaceOperatorShell();
        var dialogs = new SurfaceDialogs();
        using var host = new VisibleWpfHost(
            readiness,
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            shell,
            dialogs);

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            host.Resize(480, 352);
            WaitUntil(() => host.IsCompactLayout && Math.Abs(host.ActualWidth - 480) < 2);
            string[] requiredMenuIds =
            [
                "AddFilesButton",
                "AddFolderButton",
                "RemoveButton",
                "RefreshButton",
                "RetryButton",
                "OpenOutputButton",
                "ExportDiagnosticsButton",
                "OpenLogDirectoryButton",
                "SettingsButton"
            ];
            AutomationElement[] menuItems = OpenCompactOverflow(host.ProcessId, root, requiredMenuIds);
            string overflowScreenshot = Path.Combine(evidenceDirectory, "compact-overflow-open.png");
            string overflowTree = Path.Combine(evidenceDirectory, "compact-overflow-open-uia.json");
            CaptureScreenshot([root, .. menuItems], overflowScreenshot);
            CaptureTree(root, overflowTree);
            var metadata = menuItems.Select(item => new
            {
                geometry = ElementGeometry(item),
                item.Current.IsEnabled,
                item.Current.IsKeyboardFocusable,
                item.Current.HelpText
            }).ToArray();
            Assert.All(menuItems, item =>
            {
                Assert.False(string.IsNullOrWhiteSpace(item.Current.HelpText));
                if (item.Current.IsEnabled)
                {
                    Assert.True(item.Current.IsKeyboardFocusable);
                }
            });

            InvokeProcessElement(host.ProcessId, root, "AddFilesButton");
            AutomationElement row = WaitForElement(root, "QueueRow_1");
            Assert.Equal(1, dialogs.FilePickerCount);
            Select(root, "QueueRow_1");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.Rows[0].IsSelected));
            InvokeProcessElement(host.ProcessId, root, "RemoveButton");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.Rows.Count) == 0);

            AutomationElement focusAnchor = WaitForElement(root, "SigningModeSingle");
            focusAnchor.SetFocus();
            host.SetOutputRoot(string.Empty);
            AssertFocusedTarget("OutputRootTextBox");
            host.SetOutputRoot(OutputRoot);

            int beforeRefresh = readiness.ProbeCount;
            InvokeProcessElement(host.ProcessId, root, "RefreshButton");
            WaitUntil(() => readiness.ProbeCount > beforeRefresh);
            InvokeProcessElement(host.ProcessId, root, "AddFolderButton");
            WaitUntil(() => dialogs.FolderPickerCount == 1);
            InvokeProcessElement(host.ProcessId, root, "OpenLogDirectoryButton");
            WaitUntil(() => shell.OpenFolderCount == 1);
            InvokeProcessElement(host.ProcessId, root, "SettingsButton");
            AutomationElement settings = WaitForTopLevelElement(host.ProcessId, "SettingsWindow");
            CaptureScreenshot(settings, Path.Combine(evidenceDirectory, "compact-overflow-settings.png"));
            _ = SetForegroundWindow(new IntPtr(settings.Current.NativeWindowHandle));
            System.Windows.Forms.SendKeys.SendWait("{ESC}");
            WaitUntil(() => FindTopLevelElement(host.ProcessId, "SettingsWindow") is null);

            WriteJson(
                Path.Combine(evidenceDirectory, "compact-overflow-workflow.json"),
                new
                {
                    scenario = "480x352 compact overflow invokes every command hidden by ultra-compact reflow",
                    menuItems = metadata,
                    filePickerCalls = dialogs.FilePickerCount,
                    folderPickerCalls = dialogs.FolderPickerCount,
                    readinessProbeCalls = readiness.ProbeCount,
                    openLogCalls = shell.OpenFolderCount,
                    focusedTarget = host.ReadViewModel(viewModel => viewModel.FocusTargetAutomationId),
                    overflowScreenshot,
                    overflowTree
                });

            Assert.Equal(1, dialogs.FilePickerCount);
            Assert.Equal(1, dialogs.FolderPickerCount);
            Assert.Equal(1, shell.OpenFolderCount);
            Assert.True(new FileInfo(overflowScreenshot).Length > 0);
            Assert.True(new FileInfo(overflowTree).Length > 0);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowWorkerRecoveryGeometry")]
    public void CompactWorkerRecoveryEmptyPromptDoesNotIntersectQueueHeaders()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs(),
            workerHealthService: new SurfaceWorkerHealthService(
                WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Missing)));

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            WaitUntil(() => host.ReadViewModel(viewModel =>
                viewModel.WorkerHealthState == WorkerHealthState.Unhealthy));
            host.Resize(650.67, 480);
            WaitUntil(() => host.IsCompactLayout);
            Thread.Sleep(150);
            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement header = Assert.IsType<AutomationElement>(queue.FindFirst(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Header)));
            AutomationElement? prompt = root.FindFirst(
                TreeScope.Descendants,
                new PropertyCondition(
                    AutomationElement.NameProperty,
                    "签名队列为空，可添加 .exe 文件或文件夹开始"));
            string screenshot = Path.Combine(evidenceDirectory, "worker-recovery-empty-prompt-150.png");
            CaptureScreenshot(root, screenshot);
            CaptureTree(root, Path.Combine(evidenceDirectory, "worker-recovery-empty-prompt-150-uia.json"));
            System.Windows.Rect headerBounds = header.Current.BoundingRectangle;
            System.Windows.Rect? promptBounds = prompt?.Current.BoundingRectangle;
            bool overlaps = prompt is not null &&
                !prompt.Current.IsOffscreen &&
                !prompt.Current.BoundingRectangle.IsEmpty &&
                prompt.Current.BoundingRectangle.IntersectsWith(headerBounds);
            WriteJson(
                Path.Combine(evidenceDirectory, "worker-recovery-empty-prompt-150-geometry.json"),
                new
                {
                    scenario = "150 percent compact Worker recovery keeps empty prompt below DataGrid headers or hides it",
                    queue = ElementGeometry(queue),
                    header = ElementGeometry(header),
                    prompt = prompt is null ? null : ElementGeometry(prompt),
                    overlaps,
                    screenshot
                });

            Assert.False(overlaps, $"Empty prompt {promptBounds} intersects queue header {headerBounds}.");
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowRuntimeFailure")]
    public void RuntimeFailureShowsTypedReasonAndClearsAfterSuccessfulRetry()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var batch = new SurfaceBatchAdapter();
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            batch,
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Invoke(root, "AddFilesButton");
            _ = WaitForElement(root, "QueueRow_1");
            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.CanSign));
            host.Resize(992, 736);
            Invoke(root, "SignButton");
            WaitUntil(() => Find(root, "QueueRow_1")?.Current.Name.Contains("失败", StringComparison.Ordinal) == true);
            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement failedRow = WaitForElement(root, "QueueRow_1");
            AutomationElement? runtimeError = Find(root, "RuntimeError");
            System.Windows.Rect queueBounds = queue.Current.BoundingRectangle;
            System.Windows.Rect failedRowBounds = failedRow.Current.BoundingRectangle;
            bool failedRowFullyContained =
                failedRowBounds.Top >= queueBounds.Top - 1 &&
                failedRowBounds.Bottom <= queueBounds.Bottom + 1;
            AutomationElement? failureSummary = Find(root, "SummaryRegion");
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "runtime-failure-visible.png"));
            CaptureTree(root, Path.Combine(evidenceDirectory, "runtime-failure-visible-uia.json"));
            WriteJson(
                Path.Combine(evidenceDirectory, "runtime-failure-visible.json"),
                new
                {
                    scenario = "Fake batch failure surfaces its typed reason code and HRESULT in the visible red failure detail",
                    batchRuns = batch.RunCount,
                    queue = ElementGeometry(queue),
                    failedRow = ElementGeometry(failedRow),
                    failedRowFullyContained,
                    summaryVisibleDuringFailure = failureSummary is not null && !failureSummary.Current.IsOffscreen,
                    runtimeError = runtimeError is null ? null : ElementGeometry(runtimeError),
                    runtimeErrorName = runtimeError?.Current.Name
                });

            Assert.NotNull(runtimeError);
            AssertVisibleWithin(root, runtimeError);
            Assert.True(
                failedRowFullyContained,
                $"Failed row {failedRowBounds} extends outside queue {queueBounds} while runtime detail is visible.");
            Assert.True(failureSummary is null || failureSummary.Current.IsOffscreen);
            Assert.Contains("WorkerFailure", runtimeError.Current.Name, StringComparison.Ordinal);
            Assert.Contains("0x80004005", runtimeError.Current.Name, StringComparison.Ordinal);

            Invoke(root, "RetryButton");
            WaitUntil(() => Find(root, "QueueRow_1")?.Current.Name.Contains("已发布", StringComparison.Ordinal) == true);
            WaitUntil(() => Find(root, "RuntimeError") is null);
            _ = WaitForElement(root, "SummaryRegion");
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "runtime-failure-cleared.png"));
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowRowContainment")]
    public void TwoHundredPercentCompactLayoutContainsEveryVisibleQueueRow()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var runGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var batch = new SurfaceBatchAdapter(runGate.Task);
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            batch,
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Invoke(root, "AddFilesButton");
            _ = WaitForElement(root, "QueueRow_1");
            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.CanSign));
            host.Resize(480, 352);
            WaitUntil(() => Math.Abs(host.ActualWidth - 480) < 2);

            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement output = WaitForElement(root, "OutputRootTextBox");
            AutomationElement sign = WaitForElement(root, "SignButton");
            System.Windows.Rect queueBounds = queue.Current.BoundingRectangle;
            VisibleRowObservation[] visibleRows = ObserveVisibleRows(queue);

            WriteJson(
                Path.Combine(evidenceDirectory, "layout-200-row-containment.json"),
                new
                {
                    scenario = "480x352 compact layout contains every visible realized queue row",
                    queue = ElementGeometry(queue),
                    output = ElementGeometry(output),
                    sign = ElementGeometry(sign),
                    visibleRows
                });

            Assert.NotEmpty(visibleRows);
            Assert.All(
                visibleRows,
                row => Assert.True(
                    row.FullyContained,
                    $"{row.AutomationId} extends outside SigningQueueGrid. " +
                    $"queue={queueBounds}; row={row.Bounds}."));
            AssertVisibleWithin(root, output);
            AssertVisibleWithin(root, sign);
            Assert.True(output.Current.IsKeyboardFocusable);
            Assert.True(sign.Current.IsKeyboardFocusable);
            AutomationElement primaryCertificate = WaitForElement(root, "PrimaryCertificateCombo");
            AutomationElement secondaryCertificate = WaitForElement(root, "SecondaryCertificateCombo");
            Assert.Contains("CN=Release SHA256", primaryCertificate.Current.HelpText, StringComparison.Ordinal);
            Assert.Contains("CN=Release SHA1", secondaryCertificate.Current.HelpText, StringComparison.Ordinal);
            var idleBeforeSigning = new
            {
                isBusy = host.ReadViewModel(viewModel => viewModel.IsBusy),
                output = ElementGeometry(output),
                sign = ElementGeometry(sign),
                outputKeyboardFocusable = output.Current.IsKeyboardFocusable,
                signEnabled = sign.Current.IsEnabled,
                signKeyboardFocusable = sign.Current.IsKeyboardFocusable
            };

            Invoke(root, "SignButton");
            WaitUntil(() => batch.RunCount == 1 && host.ReadViewModel(viewModel => viewModel.IsBusy));
            AutomationElement cancel = WaitForElement(root, "CancelButton");
            WaitUntil(() => !cancel.Current.IsOffscreen && cancel.Current.IsEnabled && cancel.Current.IsKeyboardFocusable);
            AutomationElement busySign = WaitForElement(root, "SignButton");
            AssertVisibleWithin(root, busySign);
            AssertVisibleWithin(root, cancel);
            Assert.False(busySign.Current.IsEnabled);
            Assert.True(cancel.Current.IsEnabled);
            Assert.True(cancel.Current.IsKeyboardFocusable);
            var busyDuringCapture = new
            {
                isBusy = host.ReadViewModel(viewModel => viewModel.IsBusy),
                sign = ElementGeometry(busySign),
                cancel = ElementGeometry(cancel),
                signEnabled = busySign.Current.IsEnabled,
                cancelEnabled = cancel.Current.IsEnabled,
                cancelKeyboardFocusable = cancel.Current.IsKeyboardFocusable
            };
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "layout-200-row-containment.png"));
            CaptureTree(root, Path.Combine(evidenceDirectory, "layout-200-row-containment-uia.json"));

            Invoke(root, "CancelButton");
            WaitUntil(() => !host.ReadViewModel(viewModel => viewModel.IsBusy));
            AutomationElement restoredSign = WaitForElement(root, "SignButton");
            WaitUntil(() => restoredSign.Current.IsEnabled && restoredSign.Current.IsKeyboardFocusable);
            AssertVisibleWithin(root, restoredSign);
            AutomationElement? restoredCancel = Find(root, "CancelButton");
            Assert.True(restoredCancel is null || restoredCancel.Current.IsOffscreen);
            var idleAfterCancellation = new
            {
                isBusy = host.ReadViewModel(viewModel => viewModel.IsBusy),
                status = host.ReadViewModel(viewModel => viewModel.StatusMessage),
                sign = ElementGeometry(restoredSign),
                signEnabled = restoredSign.Current.IsEnabled,
                signKeyboardFocusable = restoredSign.Current.IsKeyboardFocusable,
                cancelVisible = restoredCancel is not null && !restoredCancel.Current.IsOffscreen
            };
            WriteJson(
                Path.Combine(evidenceDirectory, "layout-200-row-containment.json"),
                new
                {
                    scenario = "480x352 compact target canvas contains every visible realized queue row and preserves deterministic idle, busy, and cancelled actions",
                    queue = ElementGeometry(queue),
                    primaryCertificateHelpText = primaryCertificate.Current.HelpText,
                    secondaryCertificateHelpText = secondaryCertificate.Current.HelpText,
                    visibleRows,
                    idleBeforeSigning,
                    busyDuringCapture,
                    idleAfterCancellation
                });
        }
        finally
        {
            runGate.TrySetResult(true);
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowMultiRowLayout")]
    public async Task TwoHundredPercentCompactLayoutDoesNotExposePartialRowsWithMultipleItems()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Task queueFiles = host.ReadViewModel(viewModel =>
                viewModel.QueueFilesAsync([LongExePath, SecondExePath]));
            await queueFiles;
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.Rows.Count) == 2);
            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.CanSign));
            host.Resize(480, 352);
            WaitUntil(() => Math.Abs(host.ActualWidth - 480) < 2);
            Thread.Sleep(150);

            AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
            AutomationElement output = WaitForElement(root, "OutputRootTextBox");
            AutomationElement sign = WaitForElement(root, "SignButton");
            VisibleRowObservation[] visibleRows = ObserveVisibleRows(queue);
            CaptureScreenshot(root, Path.Combine(evidenceDirectory, "layout-200-multi-row.png"));
            CaptureTree(root, Path.Combine(evidenceDirectory, "layout-200-multi-row-uia.json"));
            WriteJson(
                Path.Combine(evidenceDirectory, "layout-200-multi-row-containment.json"),
                new
                {
                    scenario = "480x352 compact multi-row queue exposes only fully contained rows",
                    totalRows = host.ReadViewModel(viewModel => viewModel.Rows.Count),
                    queue = ElementGeometry(queue),
                    output = ElementGeometry(output),
                    sign = ElementGeometry(sign),
                    visibleRows
                });

            Assert.NotEmpty(visibleRows);
            Assert.All(
                visibleRows,
                row => Assert.True(
                    row.FullyContained,
                    $"{row.AutomationId} is partially exposed outside SigningQueueGrid: {row.Bounds}."));
            AssertVisibleWithin(root, output);
            AssertVisibleWithin(root, sign);
            Assert.True(output.Current.IsKeyboardFocusable);
            Assert.True(sign.Current.IsKeyboardFocusable);
        }
        finally
        {
            host.Stop();
        }
    }

    [Fact]
    [Trait("Category", "UiWorkflowBusyActions")]
    public void CompactBusyActionsRemainReachableAndCancellationRestoresIdleState()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        VerifyCompactBusyActionState(evidenceDirectory, "150-target", 650.67, 480);
        VerifyCompactBusyActionState(evidenceDirectory, "200-target", 480, 352);
    }

    [Fact]
    [Trait("Category", "UiWorkflowTooltips")]
    public void ActionIconTooltipsExposeChineseRuntimeHelpText()
    {
        string evidenceDirectory = ResolveEvidenceDirectory();
        Directory.CreateDirectory(evidenceDirectory);
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            new SurfaceBatchAdapter(),
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            host.Resize(1180, 940);
            WaitUntil(() => !host.IsCompactLayout && Math.Abs(host.ActualWidth - 1180) < 2);
            string[] automationIds =
            [
                "AddFilesButton",
                "QueueDirectAddButton",
                "AddFolderButton",
                "RemoveButton",
                "RefreshButton",
                "RetryButton",
                "OpenOutputButton",
                "ExportDiagnosticsButton",
                "OpenLogDirectoryButton",
                "SettingsButton",
                "BrowseOutputButton",
                "ActionOpenOutputButton",
                "SignButton"
            ];
            var observations = automationIds.Select(automationId =>
            {
                AutomationElement element = WaitForElement(root, automationId);
                string name = element.Current.Name;
                string helpText = element.Current.HelpText;
                Assert.False(string.IsNullOrWhiteSpace(helpText), $"{automationId} has no runtime UIA HelpText.");
                Assert.Contains(helpText, value => value >= '\u4e00' && value <= '\u9fff');
                return new
                {
                    automationId,
                    name,
                    helpText,
                    controlType = element.Current.ControlType.ProgrammaticName,
                    enabled = element.Current.IsEnabled,
                    offscreen = element.Current.IsOffscreen
                };
            }).ToArray();
            CommandIconVisualObservation[] iconVisuals = host.ReadVisibleCommandIconVisuals(automationIds);
            Assert.All(iconVisuals, observation =>
            {
                Assert.True(observation.IsDrawingImage, $"{observation.AutomationId} is not backed by a DrawingImage.");
                Assert.True(observation.HasFixedVisualBox, $"{observation.AutomationId} does not retain the 24x24 visual box.");
                Assert.InRange(observation.ImageWidth, 15.5, 16.5);
                Assert.InRange(observation.ImageHeight, 15.5, 16.5);
                Assert.True(observation.ImageFullyContained, $"{observation.AutomationId} icon extends beyond its control.");
                Assert.False(observation.OverlapsText, $"{observation.AutomationId} icon overlaps its Chinese label.");
                Assert.False(string.IsNullOrWhiteSpace(observation.ToolTip));
            });
            string screenshot = Path.Combine(evidenceDirectory, "command-icons-normal.png");
            string tree = Path.Combine(evidenceDirectory, "command-icons-normal-uia.json");
            CaptureScreenshot(root, screenshot);
            CaptureTree(root, tree);

            WriteJson(
                Path.Combine(evidenceDirectory, "action-icons-runtime-uia.json"),
                new
                {
                    scenario = "Visible action icon buttons expose localized runtime UIA HelpText",
                    invocation = "VisibleWpfHost 1180x940 startup + AutomationElement.Current + live WPF DrawingImage geometry",
                    elements = observations,
                    iconVisuals,
                    screenshot,
                    tree
                });
            Assert.True(new FileInfo(screenshot).Length > 0);
            Assert.True(new FileInfo(tree).Length > 0);
        }
        finally
        {
            host.Stop();
        }
    }

    private static void VerifyCompactBusyActionState(
        string evidenceDirectory,
        string label,
        double width,
        double height)
    {
        EligibleCertificate primary = Certificate('A', "CN=Release SHA256");
        EligibleCertificate secondary = Certificate('B', "CN=Release SHA1");
        var runGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var batch = new SurfaceBatchAdapter(runGate.Task);
        using var host = new VisibleWpfHost(
            new SurfaceReadinessAdapter(ReadySnapshot(primary, secondary)),
            new SurfaceIntakeAdapter(),
            batch,
            new SurfaceOperatorShell(),
            new SurfaceDialogs());

        host.Start();
        try
        {
            AutomationElement root = WaitForWindow(host.Handle);
            Invoke(root, "AddFilesButton");
            _ = WaitForElement(root, "QueueRow_1");
            Select(root, "SigningModeDual");
            WaitUntil(() => host.ReadViewModel(viewModel => viewModel.CanSign));
            host.Resize(width, height);
            WaitUntil(() => Math.Abs(host.ActualWidth - width) < 2 && host.IsCompactLayout);

            AutomationElement idleSign = WaitForElement(root, "SignButton");
            AssertVisibleWithin(root, idleSign);
            Assert.True(idleSign.Current.IsEnabled);
            Assert.True(idleSign.Current.IsKeyboardFocusable);
            var idleBefore = new
            {
                isBusy = host.ReadViewModel(viewModel => viewModel.IsBusy),
                sign = ElementGeometry(idleSign),
                signEnabled = idleSign.Current.IsEnabled,
                signKeyboardFocusable = idleSign.Current.IsKeyboardFocusable
            };

            Invoke(root, "SignButton");
            WaitUntil(() => batch.RunCount == 1 && host.ReadViewModel(viewModel => viewModel.IsBusy));
            AutomationElement busySign = WaitForElement(root, "SignButton");
            AutomationElement cancel = WaitForElement(root, "CancelButton");
            WaitUntil(() =>
                !busySign.Current.IsOffscreen &&
                !busySign.Current.IsEnabled &&
                !cancel.Current.IsOffscreen &&
                cancel.Current.IsEnabled &&
                cancel.Current.IsKeyboardFocusable);
            AssertVisibleWithin(root, busySign);
            AssertVisibleWithin(root, cancel);
            AutomationElement busyLabel = WaitForNamedElement(root, ControlType.Text, "签名中……");
            AssertVisibleWithin(root, busyLabel);
            CommandIconVisualObservation[] iconVisuals = host.ReadVisibleCommandIconVisuals(
                ["SignButton", "CancelButton"]);
            Assert.All(iconVisuals, observation =>
            {
                Assert.True(observation.IsDrawingImage);
                Assert.True(observation.HasFixedVisualBox);
                Assert.InRange(observation.ImageWidth, 15.5, 16.5);
                Assert.InRange(observation.ImageHeight, 15.5, 16.5);
                Assert.True(observation.ImageFullyContained);
                Assert.False(observation.OverlapsText);
            });
            var busyDuringCapture = new
            {
                isBusy = host.ReadViewModel(viewModel => viewModel.IsBusy),
                name = busyLabel.Current.Name,
                sign = ElementGeometry(busySign),
                cancel = ElementGeometry(cancel),
                signEnabled = busySign.Current.IsEnabled,
                cancelEnabled = cancel.Current.IsEnabled,
                cancelKeyboardFocusable = cancel.Current.IsKeyboardFocusable
            };

            string screenshot = Path.Combine(evidenceDirectory, $"busy-actions-{label}.png");
            string tree = Path.Combine(evidenceDirectory, $"busy-actions-{label}-uia.json");
            CaptureScreenshot(root, screenshot);
            CaptureTree(root, tree);
            Assert.True(new FileInfo(screenshot).Length > 0);
            Assert.True(new FileInfo(tree).Length > 0);

            Invoke(root, "CancelButton");
            WaitUntil(() => !host.ReadViewModel(viewModel => viewModel.IsBusy));
            AutomationElement restoredSign = WaitForElement(root, "SignButton");
            WaitUntil(() => restoredSign.Current.IsEnabled && restoredSign.Current.IsKeyboardFocusable);
            AssertVisibleWithin(root, restoredSign);
            AutomationElement? restoredCancel = Find(root, "CancelButton");
            Assert.True(restoredCancel is null || restoredCancel.Current.IsOffscreen);
            var idleAfterCancellation = new
            {
                isBusy = host.ReadViewModel(viewModel => viewModel.IsBusy),
                status = host.ReadViewModel(viewModel => viewModel.StatusMessage),
                sign = ElementGeometry(restoredSign),
                signEnabled = restoredSign.Current.IsEnabled,
                signKeyboardFocusable = restoredSign.Current.IsKeyboardFocusable,
                cancelVisible = restoredCancel is not null && !restoredCancel.Current.IsOffscreen
            };

            WriteJson(
                Path.Combine(evidenceDirectory, $"busy-actions-{label}.json"),
                new
                {
                    scenario = "Compact target canvas keeps Sign visible but disabled and Cancel visible, enabled, and keyboard focusable while blocked signing is busy; cancellation restores idle",
                    invocation = "UIA AddFiles + dual-mode selection + Sign + Cancel",
                    requestedCanvas = new { width, height },
                    actualCanvas = new { width = host.ActualWidth, height = host.ActualHeight },
                    currentPhysicalDpi = GetDpiForWindow(host.Handle),
                    physicalDpiWasChanged = false,
                    idleBefore,
                    busyDuringCapture,
                    iconVisuals,
                    idleAfterCancellation,
                    screenshot,
                    tree
                });
        }
        finally
        {
            runGate.TrySetResult(true);
            host.Stop();
        }
    }

    private static QueueContractObservation CaptureQueueContract(
        VisibleWpfHost host,
        AutomationElement root,
        string evidenceDirectory,
        string label,
        double width,
        double height,
        bool expectedCompact)
    {
        host.Resize(width, height);
        WaitUntil(() =>
            Math.Abs(host.ActualWidth - width) < 2 &&
            Math.Abs(host.ActualHeight - height) < 2 &&
            host.IsCompactLayout == expectedCompact);
        Thread.Sleep(150);

        AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
        AutomationElement header = Assert.IsType<AutomationElement>(queue.FindFirst(
            TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Header)));
        AutomationElement output = WaitForElement(root, "OutputRootTextBox");
        AutomationElement sign = WaitForElement(root, "SignButton");
        AutomationElement summary = WaitForElement(root, "SummaryRegion");
        AutomationElement queueHeading = WaitForElement(root, "QueueHeading");
        AutomationElement queueSupportCopy = WaitForElement(root, "QueueSupportCopy");
        AutomationElement? directAdd = Find(root, "QueueDirectAddButton");
        System.Windows.Rect rootBounds = root.Current.BoundingRectangle;
        System.Windows.Rect queueBounds = queue.Current.BoundingRectangle;
        System.Windows.Rect headerBounds = header.Current.BoundingRectangle;
        System.Windows.Rect queueHeadingBounds = queueHeading.Current.BoundingRectangle;
        System.Windows.Rect queueSupportCopyBounds = queueSupportCopy.Current.BoundingRectangle;
        System.Windows.Rect directAddBounds = directAdd?.Current.BoundingRectangle ?? System.Windows.Rect.Empty;
        double dpiScale = host.DpiScale;
        AutomationElement[] visibleRowElements = queue
            .FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem))
            .Cast<AutomationElement>()
            .Where(row => !row.Current.IsOffscreen && !row.Current.BoundingRectangle.IsEmpty)
            .ToArray();
        VisibleRowObservation[] visibleRows = visibleRowElements
            .Select(row =>
            {
                System.Windows.Rect bounds = row.Current.BoundingRectangle;
                return new VisibleRowObservation(
                    row.Current.AutomationId,
                    SerializableBounds(bounds),
                    bounds.Top >= headerBounds.Bottom - 1 && bounds.Bottom <= queueBounds.Bottom + 1);
            })
            .ToArray();
        double[] completeRowHeightsDip = visibleRowElements
            .Where((_, index) => visibleRows[index].FullyContained)
            .Select(row => row.Current.BoundingRectangle.Height / dpiScale)
            .ToArray();
        bool hasScrollPattern = queue.TryGetCurrentPattern(ScrollPattern.Pattern, out object? scrollPattern);
        bool isVerticallyScrollable = hasScrollPattern && ((ScrollPattern)scrollPattern!).Current.VerticallyScrollable;
        string screenshot = Path.Combine(evidenceDirectory, $"{label}.png");
        string tree = Path.Combine(evidenceDirectory, $"{label}-uia.json");
        CaptureScreenshot(root, screenshot);
        CaptureTree(root, tree);

        var observation = new QueueContractObservation(
            label,
            width,
            height,
            host.ActualWidth,
            host.ActualHeight,
            dpiScale,
            host.IsCompactLayout,
            queueBounds.Height / dpiScale,
            headerBounds.Height / dpiScale,
            (queueBounds.Height - headerBounds.Height) / dpiScale,
            visibleRows.Length,
            visibleRows.Count(static row => row.FullyContained),
            visibleRows.Any(static row => !row.FullyContained),
            completeRowHeightsDip,
            hasScrollPattern,
            isVerticallyScrollable,
            directAdd is not null && !directAdd.Current.IsOffscreen,
            directAdd?.Current.IsKeyboardFocusable ?? false,
            directAdd?.TryGetCurrentPattern(InvokePattern.Pattern, out _) ?? false,
            directAdd?.Current.AutomationId,
            directAdd?.Current.Name,
            directAdd?.Current.HelpText,
            directAdd is not null &&
                directAddBounds.Left >= rootBounds.Left &&
                directAddBounds.Top >= rootBounds.Top &&
                directAddBounds.Right <= rootBounds.Right &&
                directAddBounds.Bottom <= rootBounds.Bottom,
            directAdd is not null && directAddBounds.IntersectsWith(queueHeadingBounds),
            directAdd is not null && directAddBounds.IntersectsWith(queueSupportCopyBounds),
            directAdd is not null && directAddBounds.IntersectsWith(headerBounds),
            directAdd is not null && visibleRowElements.Any(row => directAddBounds.IntersectsWith(row.Current.BoundingRectangle)),
            ElementGeometry(queue),
            ElementGeometry(header),
            ElementGeometry(queueHeading),
            ElementGeometry(queueSupportCopy),
            directAdd is null ? null : ElementGeometry(directAdd),
            ElementGeometry(output),
            ElementGeometry(sign),
            ElementGeometry(summary),
            visibleRows,
            screenshot,
            tree);
        WriteJson(Path.Combine(evidenceDirectory, $"{label}-geometry.json"), observation);

        AssertVisibleWithin(root, queue);
        AssertVisibleWithin(root, output);
        AssertVisibleWithin(root, sign);
        AssertVisibleWithin(root, summary);
        Assert.False(string.IsNullOrWhiteSpace(summary.Current.Name));
        return observation;
    }

    private static LayoutObservation CaptureLayout(
        VisibleWpfHost host,
        AutomationElement root,
        string evidenceDirectory,
        string label,
        double width,
        double height,
        bool expectedCompact)
    {
        host.Resize(width, height);
        WaitUntil(() => Math.Abs(host.ActualWidth - width) < 2);
        Thread.Sleep(150);

        AutomationElement keyboardAnchor = WaitForElement(root, "SigningModeDual");
        Assert.True(SetCursorPos(0, 0), "The pointer could not be parked outside the layout surface.");
        keyboardAnchor.SetFocus();
        WaitUntil(() => keyboardAnchor.Current.HasKeyboardFocus);

        AutomationElement readiness = WaitForElement(root, "ReadinessWorkstation");
        AutomationElement queue = WaitForElement(root, "SigningQueueGrid");
        AutomationElement output = WaitForElement(root, "OutputRootTextBox");
        AutomationElement sign = WaitForElement(root, "SignButton");
        AutomationElement summary = WaitForElement(root, "SummaryRegion");
        string screenshotPath = Path.Combine(evidenceDirectory, $"layout-{label}.png");
        string treePath = Path.Combine(evidenceDirectory, $"layout-{label}-uia.json");
        CaptureScreenshot(root, screenshotPath);
        CaptureTree(root, treePath);
        WriteJson(
            Path.Combine(evidenceDirectory, $"layout-{label}-geometry.json"),
            new
            {
                label,
                requested = new { width, height },
                actual = new { width = host.ActualWidth, height = host.ActualHeight },
                host.DpiScale,
                compact = host.IsCompactLayout,
                root = ElementGeometry(root),
                readiness = ElementGeometry(readiness),
                queue = ElementGeometry(queue),
                output = ElementGeometry(output),
                sign = ElementGeometry(sign),
                summary = ElementGeometry(summary)
            });

        AssertVisibleWithin(root, readiness);
        AssertVisibleWithin(root, queue);
        AssertVisibleWithin(root, output);
        AssertVisibleWithin(root, sign);
        AssertVisibleWithin(root, summary);
        Assert.True(queue.Current.BoundingRectangle.Height >= 30);
        Assert.Equal(expectedCompact, host.IsCompactLayout);

        System.Windows.Rect bounds = root.Current.BoundingRectangle;
        return new LayoutObservation(
            label,
            width,
            height,
            host.ActualWidth,
            host.ActualHeight,
            host.DpiScale,
            bounds.Width,
            bounds.Height,
            host.IsCompactLayout,
            queue.Current.BoundingRectangle.Height,
            sign.Current.IsOffscreen,
            screenshotPath,
            treePath);
    }

    private static object CaptureWorkerRecoveryLayout(
        VisibleWpfHost host,
        AutomationElement root,
        string evidenceDirectory,
        string label,
        int requestedDpiPercent,
        double width,
        double height,
        bool expectedCompact)
    {
        host.Resize(width, height);
        WaitUntil(() => Math.Abs(host.ActualWidth - width) < 2 && host.IsCompactLayout == expectedCompact);
        Thread.Sleep(150);

        AutomationElement region = WaitForElement(root, "WorkerRecoveryRegion");
        AutomationElement refresh = WaitForElement(root, "RefreshWorkerButton");
        AutomationElement openInstallation = WaitForElement(root, "OpenInstallationDirectoryButton");
        double actualDpiPercent = host.DpiScale * 100.0;
        double physicalDpi = GetDpiForWindow(root.Current.NativeWindowHandle);
        AssertRecoveryRegion(region, expectedReasonCode: "missing", expectedRepairVisible: true);
        AssertVisibleWithin(root, region);
        AssertVisibleWithin(root, refresh);
        AssertVisibleWithin(root, openInstallation);
        AutomationElement? repair = Find(root, "RepairWorkerButton");
        if (repair is not null)
        {
            AssertVisibleWithin(root, repair);
        }

        string screenshotPath = Path.Combine(evidenceDirectory, $"worker-recovery-{label}.png");
        string treePath = Path.Combine(evidenceDirectory, $"worker-recovery-{label}-uia.json");
        CaptureScreenshot(root, screenshotPath);
        CaptureTree(root, treePath);
        WriteJson(
            Path.Combine(evidenceDirectory, $"worker-recovery-{label}-geometry.json"),
            new
            {
                label,
                requested = new { width, height },
                actual = new { width = host.ActualWidth, height = host.ActualHeight },
                requestedDpiPercent,
                actualDpiPercent,
                physicalDpi,
                dpiMatchesRequested = Math.Abs(actualDpiPercent - requestedDpiPercent) < 0.5,
                dpiScale = host.DpiScale,
                dpiPercent = host.DpiScale * 100.0,
                attachedLiveSetting = host.ReadWorkerRecoveryLiveSetting(),
                compact = host.IsCompactLayout,
                region = ElementGeometry(region),
                refresh = ElementGeometry(refresh),
                repair = repair is null ? null : ElementGeometry(repair),
                openInstallation = ElementGeometry(openInstallation)
            });

        return new
        {
            label,
            requestedWidth = width,
            requestedHeight = height,
            requestedDpiPercent,
            actualWidth = host.ActualWidth,
            actualHeight = host.ActualHeight,
            actualDpiPercent,
            physicalDpi,
            dpiMatchesRequested = Math.Abs(actualDpiPercent - requestedDpiPercent) < 0.5,
            compact = host.IsCompactLayout,
            region = ElementGeometry(region),
            refresh = ElementGeometry(refresh),
            repair = repair is null ? null : ElementGeometry(repair),
            openInstallation = ElementGeometry(openInstallation),
            screenshot = screenshotPath,
            tree = treePath
        };
    }

    private static void AssertRecoveryRegion(
        AutomationElement region,
        string expectedReasonCode,
        bool expectedRepairVisible)
    {
        Assert.Equal("WorkerRecoveryRegion", region.Current.AutomationId);
        Assert.Contains("Worker 恢复", region.Current.Name, StringComparison.Ordinal);
        Assert.Contains(expectedReasonCode, region.Current.HelpText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(region.Current.Name + region.Current.HelpText, value => value >= '\u4e00' && value <= '\u9fff');
        Assert.True(region.Current.IsKeyboardFocusable);
        if (expectedRepairVisible)
        {
            Assert.NotNull(region.FindFirst(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.AutomationIdProperty, "RepairWorkerButton")));
        }
        else
        {
            Assert.Null(region.FindFirst(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.AutomationIdProperty, "RepairWorkerButton")));
        }
    }

    private static string ReadLiveSetting(AutomationElement element)
    {
        try
        {
            return element.GetCurrentPropertyValue(AutomationElementIdentifiers.LiveSettingProperty)?.ToString()
                ?? string.Empty;
        }
        catch (ArgumentException exception)
        {
            return $"UIA provider unavailable: {exception.Message}";
        }
    }

    private static void VerifyKeyboardSettingsPath(
        VisibleWpfHost host,
        AutomationElement root,
        SurfaceReadinessAdapter readiness,
        string evidenceDirectory,
        string scenarioLabel)
    {
        Assert.True(SetCursorPos(0, 0), "The pointer could not be parked outside the keyboard-only surface.");
        _ = SetForegroundWindow(host.Handle);
        AutomationElement keyboardAnchor = WaitForElement(root, "SigningModeDual");
        keyboardAnchor.SetFocus();
        WaitUntil(() => keyboardAnchor.Current.HasKeyboardFocus);
        WaitUntil(() => FindTopLevelControl(host.ProcessId, ControlType.ToolTip) is null);
        int beforeRefresh = readiness.ProbeCount;
        System.Windows.Forms.SendKeys.SendWait("{F5}");
        WaitUntil(() => readiness.ProbeCount > beforeRefresh);

        System.Windows.Forms.SendKeys.SendWait("%g");
        AutomationElement settings = WaitForTopLevelElement(host.ProcessId, "SettingsWindow");
        Assert.Contains(
            settings.Current.Name,
            value => value >= '\u4e00' && value <= '\u9fff');
        Assert.NotNull(Find(settings, "SettingsTimestampUri"));
        Assert.NotNull(Find(settings, "SettingsRetention"));
        Assert.NotNull(Find(settings, "SettingsOkButton"));
        foreach (string automationId in new[]
                 {
                     "SettingsTimestampUri",
                     "SettingsRetention",
                     "SettingsCancelButton",
                     "SettingsOkButton",
                     "SettingsUninstallButton"
                 })
        {
            AutomationElement element = WaitForElement(settings, automationId);
            Assert.Contains(
                element.Current.Name + element.Current.HelpText,
                value => value >= '\u4e00' && value <= '\u9fff');
        }
        string[] names = settings
            .FindAll(TreeScope.Subtree, Condition.TrueCondition)
            .Cast<AutomationElement>()
            .Select(element => element.Current.Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .ToArray();
        Assert.DoesNotContain(names, name => name.Contains("credential", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(names, name => name.Contains("PIN", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(names, name => name.Contains("private key", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(names, name => name.Contains("native flag", StringComparison.OrdinalIgnoreCase));
        WaitForNoTopLevelTooltip(host.ProcessId, evidenceDirectory, scenarioLabel);
        CaptureTree(settings, Path.Combine(evidenceDirectory, "settings-keyboard-uia.json"));
        CaptureScreenshot(settings, Path.Combine(evidenceDirectory, "settings-keyboard.png"));

        _ = SetForegroundWindow(new IntPtr(settings.Current.NativeWindowHandle));
        System.Windows.Forms.SendKeys.SendWait("{ESC}");
        WaitUntil(() => FindTopLevelElement(host.ProcessId, "SettingsWindow") is null);
    }

    private static void AssertRequiredMainControls(AutomationElement root)
    {
        string[] required =
        [
            "ReadinessWorkstation",
            "ReadinessNativeApi",
            "ReadinessCertificates",
            "TimestampStatus",
            "AddFilesButton",
            "AddFolderButton",
            "RemoveButton",
            "RefreshButton",
            "RetryButton",
            "OpenOutputButton",
            "ExportDiagnosticsButton",
            "OpenLogDirectoryButton",
            "SettingsButton",
            "SigningModeSingle",
            "SigningModeDual",
            "PrimaryCertificateCombo",
            "SigningQueueGrid",
            "OutputRootTextBox",
            "BrowseOutputButton",
            "SignButton",
            "AggregateProgress",
            "SummaryRegion"
        ];
        foreach (string automationId in required)
        {
            AutomationElement element = WaitForElement(root, automationId);
            Assert.False(string.IsNullOrWhiteSpace(element.Current.Name));
            string accessibleText = element.Current.Name + element.Current.HelpText;
            Assert.True(
                accessibleText.Any(value => value >= '\u4e00' && value <= '\u9fff'),
                $"{automationId} has no Chinese UIA name/help text: Name='{element.Current.Name}', HelpText='{element.Current.HelpText}'.");
        }
    }

    private static void AssertFocusedTarget(string automationId)
    {
        WaitUntil(() =>
        {
            AutomationElement? current = AutomationElement.FocusedElement;
            while (current is not null)
            {
                if (string.Equals(current.Current.AutomationId, automationId, StringComparison.Ordinal))
                {
                    return true;
                }

                current = TreeWalker.ControlViewWalker.GetParent(current);
            }

            return false;
        });
    }

    private static void CaptureFocusObservation(VisibleWpfHost host, string evidenceDirectory, string fileName)
    {
        var focusChain = new List<object>();
        AutomationElement? current = AutomationElement.FocusedElement;
        while (current is not null && focusChain.Count < 16)
        {
            focusChain.Add(new
            {
                automationId = current.Current.AutomationId,
                name = current.Current.Name,
                controlType = current.Current.ControlType.ProgrammaticName,
                current.Current.IsKeyboardFocusable,
                current.Current.HasKeyboardFocus,
                current.Current.IsEnabled,
                current.Current.IsOffscreen,
                bounds = SerializableBounds(current.Current.BoundingRectangle)
            });
            current = TreeWalker.ControlViewWalker.GetParent(current);
        }

        WriteJson(
            Path.Combine(evidenceDirectory, fileName),
            new
            {
                capturedAtUtc = DateTimeOffset.UtcNow,
                row = host.ReadRowFocusState("QueueRow_1"),
                focusChain
            });
    }

    private static void AssertVisibleWithin(AutomationElement root, AutomationElement element)
    {
        System.Windows.Rect rootBounds = root.Current.BoundingRectangle;
        System.Windows.Rect bounds = element.Current.BoundingRectangle;
        string automationId = element.Current.AutomationId;
        Assert.False(element.Current.IsOffscreen, $"{automationId} is offscreen at {bounds}; root is {rootBounds}.");
        Assert.True(bounds.Width > 0 && bounds.Height > 0, $"{automationId} has non-positive bounds {bounds}; root is {rootBounds}.");
        Assert.True(bounds.Left >= rootBounds.Left - 1, $"{automationId} extends left of root: {bounds}; root is {rootBounds}.");
        Assert.True(bounds.Top >= rootBounds.Top - 1, $"{automationId} extends above root: {bounds}; root is {rootBounds}.");
        Assert.True(bounds.Right <= rootBounds.Right + 1, $"{automationId} extends right of root: {bounds}; root is {rootBounds}.");
        Assert.True(bounds.Bottom <= rootBounds.Bottom + 1, $"{automationId} extends below root: {bounds}; root is {rootBounds}.");
    }

    private static object ElementGeometry(AutomationElement element)
    {
        System.Windows.Rect bounds = element.Current.BoundingRectangle;
        return new
        {
            automationId = element.Current.AutomationId,
            element.Current.Name,
            element.Current.IsOffscreen,
            bounds = SerializableBounds(bounds)
        };
    }

    private static VisibleRowObservation[] ObserveVisibleRows(AutomationElement queue)
    {
        System.Windows.Rect queueBounds = queue.Current.BoundingRectangle;
        return queue
            .FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem))
            .Cast<AutomationElement>()
            .Where(row => !row.Current.IsOffscreen && !row.Current.BoundingRectangle.IsEmpty)
            .Select(row =>
            {
                System.Windows.Rect bounds = row.Current.BoundingRectangle;
                return new VisibleRowObservation(
                    row.Current.AutomationId,
                    SerializableBounds(bounds),
                    bounds.Top >= queueBounds.Top - 1 && bounds.Bottom <= queueBounds.Bottom + 1);
            })
            .ToArray();
    }

    private static void Invoke(AutomationElement root, string automationId)
    {
        AutomationElement element = WaitForElement(root, automationId);
        WaitUntil(() => element.Current.IsEnabled);
        Assert.True(element.TryGetCurrentPattern(InvokePattern.Pattern, out object? pattern));
        ((InvokePattern)pattern).Invoke();
    }

    private static void Select(AutomationElement root, string automationId)
    {
        AutomationElement element = WaitForElement(root, automationId);
        Assert.True(element.TryGetCurrentPattern(SelectionItemPattern.Pattern, out object? pattern));
        ((SelectionItemPattern)pattern).Select();
    }

    private static AutomationElement[] OpenCompactOverflow(
        int processId,
        AutomationElement root,
        IReadOnlyCollection<string> menuItemAutomationIds)
    {
        AutomationElement overflow = WaitForElement(root, "CompactOverflowButton");
        AssertVisibleWithin(root, overflow);
        Assert.True(overflow.Current.IsKeyboardFocusable);
        Assert.True(overflow.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out object? expandPattern));
        var expand = (ExpandCollapsePattern)expandPattern;
        if (expand.Current.ExpandCollapseState != ExpandCollapseState.Expanded)
        {
            expand.Expand();
        }

        return menuItemAutomationIds
            .Select(automationId => WaitForProcessElement(processId, automationId))
            .ToArray();
    }

    private static void InvokeProcessElement(int processId, AutomationElement root, string automationId)
    {
        AutomationElement item = Assert.Single(OpenCompactOverflow(processId, root, [automationId]));
        Assert.True(item.TryGetCurrentPattern(InvokePattern.Pattern, out object? invokePattern));
        ((InvokePattern)invokePattern).Invoke();
    }

    private static AutomationElement WaitForProcessElement(int processId, string automationId)
    {
        AutomationElement? result = null;
        var condition = new AndCondition(
            new PropertyCondition(AutomationElement.ProcessIdProperty, processId),
            new PropertyCondition(AutomationElement.AutomationIdProperty, automationId));
        WaitUntil(() =>
        {
            result = AutomationElement.RootElement.FindFirst(TreeScope.Descendants, condition);
            return result is not null && !result.Current.IsOffscreen;
        });
        return result!;
    }

    private static AutomationElement WaitForWindow(IntPtr handle)
    {
        AutomationElement? result = null;
        WaitUntil(() =>
        {
            result = AutomationElement.FromHandle(handle);
            return result is not null;
        });
        return result!;
    }

    private static AutomationElement WaitForElement(AutomationElement root, string automationId)
    {
        AutomationElement? result = null;
        WaitUntil(() =>
        {
            result = Find(root, automationId);
            return result is not null;
        });
        return result!;
    }

    private static AutomationElement WaitForNamedElement(
        AutomationElement root,
        ControlType controlType,
        string name)
    {
        AutomationElement? result = null;
        WaitUntil(() =>
        {
            result = root.FindFirst(
                TreeScope.Subtree,
                new AndCondition(
                    new PropertyCondition(AutomationElement.ControlTypeProperty, controlType),
                    new PropertyCondition(AutomationElement.NameProperty, name)));
            return result is not null;
        });
        return result!;
    }

    private static AutomationElement WaitForTopLevelElement(int processId, string automationId)
    {
        AutomationElement? result = null;
        WaitUntil(() =>
        {
            result = FindTopLevelElement(processId, automationId);
            return result is not null;
        });
        return result!;
    }

    private static AutomationElement? Find(AutomationElement root, string automationId) =>
        root.FindFirst(
            TreeScope.Subtree,
            new PropertyCondition(AutomationElement.AutomationIdProperty, automationId));

    private static AutomationElement? FindTopLevelElement(int processId, string automationId)
    {
        var condition = new PropertyCondition(AutomationElement.AutomationIdProperty, automationId);
        return FindOwnedElement(processId, condition);
    }

    private static AutomationElement? FindTopLevelControl(int processId, ControlType controlType)
    {
        var condition = new PropertyCondition(AutomationElement.ControlTypeProperty, controlType);
        return FindOwnedElement(processId, condition);
    }

    private static AutomationElement? FindOwnedElement(int processId, Condition condition)
    {
        foreach (AutomationElement window in EnumerateProcessTopLevelElements(processId))
        {
            AutomationElement? result = window.FindFirst(TreeScope.Subtree, condition);
            if (result is not null)
            {
                return result;
            }
        }

        return null;
    }

    private static List<AutomationElement> EnumerateProcessTopLevelElements(int processId)
    {
        uint expectedProcessId = checked((uint)processId);
        var windows = new List<AutomationElement>();
        Exception? callbackFailure = null;
        bool enumerated = EnumWindows((windowHandle, _parameter) =>
        {
            uint windowThreadId = GetWindowThreadProcessId(windowHandle, out uint windowProcessId);
            if (windowThreadId == 0)
            {
                callbackFailure = new InvalidOperationException(
                    $"GetWindowThreadProcessId failed with Win32 error {Marshal.GetLastWin32Error()}.");
                return false;
            }

            if (windowProcessId != expectedProcessId)
            {
                return true;
            }

            try
            {
                windows.Add(AutomationElement.FromHandle(windowHandle));
            }
            catch (ElementNotAvailableException)
            {
            }
            catch (ArgumentException)
            {
            }
            catch (Exception exception)
            {
                callbackFailure = exception;
                return false;
            }

            return true;
        }, IntPtr.Zero);

        if (callbackFailure is not null)
        {
            ExceptionDispatchInfo.Capture(callbackFailure).Throw();
        }

        if (!enumerated)
        {
            throw new InvalidOperationException(
                $"EnumWindows failed for process {processId} with Win32 error {Marshal.GetLastWin32Error()}.");
        }

        return windows;
    }

    private static void WaitForNoTopLevelTooltip(
        int processId,
        string evidenceDirectory,
        string scenarioLabel)
    {
        _ = WriteTopLevelTooltipObservation(
            evidenceDirectory,
            $"settings-keyboard-tooltip-pre-wait-{scenarioLabel}.json",
            "UI Automation tooltip observed immediately before the residual-tooltip wait",
            scenarioLabel,
            processId,
            FindTopLevelControl(processId, ControlType.ToolTip));

        try
        {
            WaitUntil(() => FindTopLevelControl(processId, ControlType.ToolTip) is null);
        }
        catch (Exception waitFailure)
        {
            AutomationElement? tooltip = FindTopLevelControl(processId, ControlType.ToolTip);
            (string? tooltipName, string? tooltipClassName) = WriteTopLevelTooltipObservation(
                evidenceDirectory,
                $"settings-keyboard-residual-tooltip-{scenarioLabel}.json",
                "UI Automation tooltip remained after F5 refresh and keyboard-opened settings",
                scenarioLabel,
                processId,
                tooltip);

            RethrowUnlessExpectedSettingsTooltip(tooltipName, tooltipClassName, waitFailure);
        }
    }

    private static (string? Name, string? ClassName) WriteTopLevelTooltipObservation(
        string evidenceDirectory,
        string fileName,
        string scenario,
        string scenarioLabel,
        int processId,
        AutomationElement? tooltip)
    {
        string? tooltipName = null;
        string? tooltipClassName = null;
        object tooltipObservation;
        if (tooltip is null)
        {
            tooltipObservation = new
            {
                found = false,
                elementUnavailable = false
            };
        }
        else
        {
            try
            {
                var current = tooltip.Current;
                tooltipName = current.Name;
                tooltipClassName = current.ClassName;
                tooltipObservation = new
                {
                    found = true,
                    elementUnavailable = false,
                    automationId = current.AutomationId,
                    name = current.Name,
                    helpText = current.HelpText,
                    className = current.ClassName,
                    controlType = current.ControlType.ProgrammaticName,
                    nativeWindowHandle = current.NativeWindowHandle,
                    boundingRectangle = new
                    {
                        current.BoundingRectangle.X,
                        current.BoundingRectangle.Y,
                        current.BoundingRectangle.Width,
                        current.BoundingRectangle.Height
                    }
                };
            }
            catch (ElementNotAvailableException)
            {
                tooltipObservation = new
                {
                    found = false,
                    elementUnavailable = true
                };
            }
        }

        WriteJson(
            Path.Combine(evidenceDirectory, fileName),
            new
            {
                scenario,
                scenarioLabel,
                processId,
                capturedAtUtc = DateTimeOffset.UtcNow,
                isExpectedSettingsTooltip = IsExpectedSettingsTooltip(tooltipName, tooltipClassName),
                tooltip = tooltipObservation
            });

        return (tooltipName, tooltipClassName);
    }

    private static bool IsExpectedSettingsTooltip(string? tooltipName, string? tooltipClassName) =>
        string.Equals(tooltipName, ExpectedSettingsTooltipName, StringComparison.Ordinal) &&
        string.Equals(tooltipClassName, ExpectedSettingsTooltipClassName, StringComparison.Ordinal);

    private static void RethrowUnlessExpectedSettingsTooltip(
        string? tooltipName,
        string? tooltipClassName,
        Exception waitFailure)
    {
        if (IsExpectedSettingsTooltip(tooltipName, tooltipClassName))
        {
            return;
        }

        ExceptionDispatchInfo.Capture(waitFailure).Throw();
    }

    private static void WaitUntil(Func<bool> condition)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < TimeSpan.FromSeconds(10))
        {
            try
            {
                if (condition())
                {
                    return;
                }
            }
            catch (ElementNotAvailableException)
            {
            }

            Thread.Sleep(50);
        }

        Assert.Fail("The UI Automation condition did not become true within 10 seconds.");
    }

    private static void CaptureTree(AutomationElement root, string path)
    {
        var elements = new List<object>();
        foreach (AutomationElement element in root.FindAll(TreeScope.Subtree, Condition.TrueCondition))
        {
            System.Windows.Rect bounds = element.Current.BoundingRectangle;
            elements.Add(new
            {
                automationId = element.Current.AutomationId,
                name = element.Current.Name,
                controlType = element.Current.ControlType.ProgrammaticName,
                helpText = element.Current.HelpText,
                liveSetting = ReadLiveSetting(element),
                enabled = element.Current.IsEnabled,
                offscreen = element.Current.IsOffscreen,
                bounds = SerializableBounds(bounds)
            });
        }

        WriteJson(path, new { root = root.Current.Name, count = elements.Count, elements });
    }

    private static object SerializableBounds(System.Windows.Rect bounds) => new
    {
        isEmpty = bounds.IsEmpty,
        x = FiniteOrNull(bounds.X),
        y = FiniteOrNull(bounds.Y),
        width = FiniteOrNull(bounds.Width),
        height = FiniteOrNull(bounds.Height),
        right = FiniteOrNull(bounds.Right),
        bottom = FiniteOrNull(bounds.Bottom)
    };

    private static double? FiniteOrNull(double value) => double.IsFinite(value) ? value : null;

    private static void CaptureScreenshot(AutomationElement root, string path)
    {
        CaptureScreenshot([root], path);
    }

    private static void CaptureScreenshot(
        IReadOnlyCollection<AutomationElement> elements,
        string path)
    {
        Assert.True(SetCursorPos(0, 0), "The pointer could not be parked outside the captured surface.");
        AutomationElement foreground = elements.FirstOrDefault(static element =>
            element.Current.NativeWindowHandle != 0) ?? elements.First();
        _ = SetForegroundWindow(new IntPtr(foreground.Current.NativeWindowHandle));
        Thread.Sleep(100);
        System.Windows.Rect bounds = elements
            .Select(static element => element.Current.BoundingRectangle)
            .Where(static rectangle => !rectangle.IsEmpty)
            .Aggregate(System.Windows.Rect.Union);
        int width = Math.Max(1, (int)Math.Ceiling(bounds.Width));
        int height = Math.Max(1, (int)Math.Ceiling(bounds.Height));
        using var bitmap = new Bitmap(width, height);
        using Graphics graphics = Graphics.FromImage(bitmap);
        graphics.CopyFromScreen((int)bounds.X, (int)bounds.Y, 0, 0, bitmap.Size);
        bitmap.Save(path, ImageFormat.Png);
    }

    private static void WriteEnvironmentLimitArtifacts(string evidenceDirectory, VisibleWpfHost host)
    {
        string? pathVariable = Environment.GetEnvironmentVariable("PATH");
        string[] pathEntries = (pathVariable ?? string.Empty).Split(
            Path.PathSeparator,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string[] accessibilityInsightsMatches = pathEntries
            .Select(directory => Path.Combine(directory, "AccessibilityInsights.exe"))
            .Where(File.Exists)
            .ToArray();
        WriteJson(
            Path.Combine(evidenceDirectory, "accessibility-insights-unavailable.json"),
            new
            {
                executable = "AccessibilityInsights.exe",
                pathMatches = accessibilityInsightsMatches,
                installed = accessibilityInsightsMatches.Length > 0,
                status = accessibilityInsightsMatches.Length == 0
                    ? "blocked: external Accessibility Insights prerequisite is not installed"
                    : "available"
            });
        WriteJson(
            Path.Combine(evidenceDirectory, "high-contrast-rdp-environment.json"),
            new
            {
                systemHighContrast = System.Windows.SystemParameters.HighContrast,
                terminalServerSession = System.Windows.Forms.SystemInformation.TerminalServerSession,
                actualDpi = GetDpiForWindow(host.Handle),
                actualDpiPercent = GetDpiForWindow(host.Handle) * 100.0 / 96.0,
                status = "High Contrast and RDP session changes were not forced because they are user/session settings; system-brush mapping is implemented and current values are recorded."
            });
    }

    private static string ResolveEvidenceDirectory()
    {
        string? configured = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured);
        }

        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(
            directory.FullName,
            "artifacts",
            "evidence",
            "task-8-certum-code-signing-tool",
            "implementation");
    }

    private static void WriteJson(string path, object value)
    {
        string json = JsonSerializer.Serialize(
            value,
            EvidenceJsonOptions);
        File.WriteAllText(path, json);
    }

    private static EligibleCertificate Certificate(char thumbprintCharacter, string subject) => new(
        StoreLocation.CurrentUser,
        "My",
        new string(thumbprintCharacter, 40),
        subject,
        "CN=Issuing CA",
        new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private static WorkerRepairResult CreateSuccessfulWorkerRepairResult() =>
        new(
            WorkerRepairOutcome.Succeeded,
            new CodeSignerInstallation(
                CodeSignerInstallationStatus.Installed,
                CodeSignerInstallationProbe.ObservedUpgradeCode,
                "{11111111-1111-1111-1111-111111111111}",
                CodeSignerInstallationProbe.ObservedProductName,
                CodeSignerInstallationProbe.ObservedPublisher,
                "1.0.0"),
            null,
            0,
            null,
            true);

    private static ReadinessSnapshot ReadySnapshot(params EligibleCertificate[] certificates) => new(
        new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
        NativeApiAvailability.Available,
        new SimplySignInstallation(
            SimplySignInstallationStatus.Installed,
            "{A}",
            "{B}",
            "SimplySign Desktop",
            "Certum",
            "9.2.14.61"),
        new CertificateCatalog(
            CertificateAvailabilityStatus.CertificateAvailable,
            certificates,
            [new CertificateStoreDiagnostic(StoreLocation.CurrentUser, "My", CertificateStoreReadStatus.Success)]),
        new TimestampConfiguration(TimestampConfigurationStatus.Configured, new Uri(TimestampPolicy.DefaultUri)),
        ProviderAuthorizationStatus.AuthorizationUnknown);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr windowHandle);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr windowHandle);

    private delegate bool EnumWindowsProc(IntPtr windowHandle, IntPtr parameter);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr windowHandle, out uint processId);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint GetDpiForWindow(IntPtr windowHandle);

    private sealed record LayoutObservation(
        string Label,
        double RequestedWidth,
        double RequestedHeight,
        double ActualWidth,
        double ActualHeight,
        double DpiScale,
        double UiaPhysicalWidth,
        double UiaPhysicalHeight,
        bool Compact,
        double QueuePhysicalHeight,
        bool SignOffscreen,
        string Screenshot,
        string UiaTree);

    private sealed record CommandIconExpectation(string AutomationId, string ResourceKey, int ExpectedCount);

    private sealed record CommandIconVisualObservation(
        string AutomationId,
        string Name,
        string HelpText,
        string ToolTip,
        double ControlWidth,
        double ControlHeight,
        double ImageWidth,
        double ImageHeight,
        bool IsDrawingImage,
        double DrawingX,
        double DrawingY,
        double DrawingWidth,
        double DrawingHeight,
        bool HasFixedVisualBox,
        bool ImageFullyContained,
        bool OverlapsText);

    private sealed record VisibleRowObservation(string AutomationId, object Bounds, bool FullyContained);

    private sealed record QueueContractObservation(
        string Label,
        double RequestedWidth,
        double RequestedHeight,
        double ActualWidth,
        double ActualHeight,
        double DpiScale,
        bool Compact,
        double QueueHeightDip,
        double HeaderHeightDip,
        double BodyHeightDip,
        int VisibleRowCount,
        int CompleteRowCount,
        bool HasPartialRow,
        double[] CompleteRowHeightsDip,
        bool HasScrollPattern,
        bool IsVerticallyScrollable,
        bool DirectAddPresent,
        bool DirectAddKeyboardFocusable,
        bool DirectAddSupportsInvoke,
        string? DirectAddAutomationId,
        string? DirectAddName,
        string? DirectAddHelpText,
        bool DirectAddWithinWindow,
        bool DirectAddOverlapsQueueHeading,
        bool DirectAddOverlapsSupportCopy,
        bool DirectAddOverlapsDataGridHeader,
        bool DirectAddOverlapsVisibleRow,
        object Queue,
        object Header,
        object QueueHeading,
        object QueueSupportCopy,
        object? DirectAdd,
        object Output,
        object Sign,
        object Summary,
        VisibleRowObservation[] VisibleRows,
        string Screenshot,
        string Tree);

    private sealed record WatermarkObservation(
        string Visibility,
        bool IsVisible,
        bool IsHitTestVisible,
        bool Focusable,
        bool AutomationPeerPresent);

    private sealed record ReadinessTextFitObservation(
        string ElementName,
        string Text,
        double ActualWidth,
        double RequiredWidth,
        bool Fits);

    private sealed class SharedWpfApplicationHost
    {
        private readonly TaskCompletionSource<Exception?> startup =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Thread thread;

        public SharedWpfApplicationHost()
        {
            thread = new Thread(RunSta)
            {
                IsBackground = true,
                Name = "CodeSigner.UiWorkflow.SharedSTA"
            };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            Exception? startException = startup.Task.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
            if (startException is not null)
            {
                throw new InvalidOperationException("The shared WPF application host failed to start.", startException);
            }
        }

        public Dispatcher Dispatcher { get; private set; } = null!;

        public System.Windows.Application Application { get; private set; } = null!;

        private void RunSta()
        {
            try
            {
                Dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher));
                Application = new System.Windows.Application
                {
                    ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown
                };
                Application.Resources.MergedDictionaries.Add(new System.Windows.ResourceDictionary
                {
                    Source = new Uri(
                        "pack://application:,,,/CodeSigner.App;component/Themes/DesignTokens.xaml",
                        UriKind.Absolute)
                });
                startup.SetResult(null);
                Dispatcher.Run();
            }
            catch (Exception exception)
            {
                startup.TrySetResult(exception);
            }
        }
    }

    private sealed class VisibleWpfHost : IDisposable
    {
        private static readonly Lazy<SharedWpfApplicationHost> SharedApplication =
            new(() => new SharedWpfApplicationHost(), LazyThreadSafetyMode.ExecutionAndPublication);

        private readonly SurfaceReadinessAdapter readiness;
        private readonly SurfaceIntakeAdapter intake;
        private readonly SurfaceBatchAdapter batch;
        private readonly SurfaceOperatorShell shell;
        private readonly SurfaceDialogs dialogs;
        private readonly IWorkerHealthService workerHealthService;
        private readonly IWorkerRepairService workerRepairService;
        private readonly Func<CancellationToken, ValueTask<bool>> workerRepairConfirmation;
        private readonly IQueueAuditSink? queueAuditSink;
        private readonly Action? beforeApplicationStart;
        private readonly Action? afterApplicationStartFailure;
        private readonly ManualResetEventSlim ready = new(false);
        private readonly int processId = Environment.ProcessId;
        private int stopDelegateEntered;
        private int windowsBeforeClose = -1;
        private int windowsAfterClose = -1;
        private int shutdownCallReturned;
        private Thread? thread;
        private Dispatcher? dispatcher;
        private System.Windows.Application? application;
        private MainWindow? window;
        private SigningWorkbenchViewModel? viewModel;
        private Exception? startException;
        private bool usesSharedApplication;
        private bool stopped;

        public VisibleWpfHost(
            SurfaceReadinessAdapter readiness,
            SurfaceIntakeAdapter intake,
            SurfaceBatchAdapter batch,
            SurfaceOperatorShell shell,
            SurfaceDialogs dialogs,
            Action? beforeApplicationStart = null,
            Action? afterApplicationStartFailure = null,
            IWorkerHealthService? workerHealthService = null,
            IWorkerRepairService? workerRepairService = null,
            Func<CancellationToken, ValueTask<bool>>? workerRepairConfirmation = null,
            IQueueAuditSink? queueAuditSink = null)
        {
            this.readiness = readiness;
            this.intake = intake;
            this.batch = batch;
            this.shell = shell;
            this.dialogs = dialogs;
            this.beforeApplicationStart = beforeApplicationStart;
            this.afterApplicationStartFailure = afterApplicationStartFailure;
            this.workerHealthService = workerHealthService ?? new SurfaceWorkerHealthService();
            this.workerRepairService = workerRepairService ?? new SurfaceWorkerRepairService();
            this.workerRepairConfirmation = workerRepairConfirmation ?? (static _ => ValueTask.FromResult(true));
            this.queueAuditSink = queueAuditSink;
        }

        public IntPtr Handle { get; private set; }

        public int ProcessId => processId;

        public double ActualWidth => dispatcher!.Invoke(() => window!.ActualWidth);

        public double ActualHeight => dispatcher!.Invoke(() => window!.ActualHeight);

        public bool IsCompactLayout => dispatcher!.Invoke(() => window!.IsCompactLayout);

        public double DpiScale => dispatcher!.Invoke(() => VisualTreeHelper.GetDpi(window!).DpiScaleX);

        public WatermarkObservation ReadWatermarkObservation() => dispatcher!.Invoke(() =>
        {
            var watermark = (System.Windows.Controls.TextBlock)(window!.FindName("WatermarkText") ??
                throw new InvalidOperationException("WatermarkText was not found in the visual tree."));
            return new WatermarkObservation(
                watermark.Visibility.ToString(),
                watermark.IsVisible,
                watermark.IsHitTestVisible,
                watermark.Focusable,
                System.Windows.Automation.Peers.UIElementAutomationPeer.CreatePeerForElement(watermark) is not null);
        });

        public ReadinessTextFitObservation[] ReadReadinessTextFitObservations() => dispatcher!.Invoke(() =>
        {
            string[] elementNames =
            [
                "WorkstationStatusText",
                "NativeApiStatusText",
                "CertificateStatusText",
                "TimestampStatusText"
            ];
            return elementNames.Select(elementName =>
            {
                var textBlock = (System.Windows.Controls.TextBlock)(window!.FindName(elementName) ??
                    throw new InvalidOperationException($"{elementName} was not found in the visual tree."));
                var typeface = new Typeface(
                    textBlock.FontFamily,
                    textBlock.FontStyle,
                    textBlock.FontWeight,
                    textBlock.FontStretch);
                var formatted = new FormattedText(
                    textBlock.Text,
                    CultureInfo.CurrentUICulture,
                    textBlock.FlowDirection,
                    typeface,
                    textBlock.FontSize,
                    textBlock.Foreground,
                    VisualTreeHelper.GetDpi(textBlock).PixelsPerDip);
                double requiredWidth = formatted.WidthIncludingTrailingWhitespace;
                return new ReadinessTextFitObservation(
                    elementName,
                    textBlock.Text,
                    textBlock.ActualWidth,
                    requiredWidth,
                    requiredWidth <= textBlock.ActualWidth + 0.5);
            }).ToArray();
        });

        public string ReadWorkerRecoveryLiveSetting() => dispatcher!.Invoke(() =>
        {
            object element = window!.FindName("WorkerRecoveryRegion") ??
                throw new InvalidOperationException("WorkerRecoveryRegion was not found in the visual tree.");
            return AutomationProperties.GetLiveSetting((System.Windows.DependencyObject)element).ToString();
        });

        public void BringToFrontForCapture() => dispatcher!.Invoke(() =>
        {
            window!.Topmost = true;
            window.Activate();
            window.UpdateLayout();
        });

        public Dictionary<string, object?> ReadRowFocusState(string automationId) => dispatcher!.Invoke(() =>
        {
            var queue = (System.Windows.Controls.DataGrid)window!.FindName("QueueGrid");
            QueueItemViewModel? row = viewModel!.Rows.FirstOrDefault(
                candidate => string.Equals(candidate.AutomationId, automationId, StringComparison.Ordinal));
            var container = row is null
                ? null
                : queue.ItemContainerGenerator.ContainerFromItem(row) as System.Windows.Controls.DataGridRow;
            System.Windows.IInputElement? focused = System.Windows.Input.Keyboard.FocusedElement;
            return new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["requestedAutomationId"] = automationId,
                ["focusTargetAutomationId"] = viewModel.FocusTargetAutomationId,
                ["windowActive"] = window.IsActive,
                ["dispatcherShutdownStarted"] = dispatcher.HasShutdownStarted,
                ["dispatcherShutdownFinished"] = dispatcher.HasShutdownFinished,
                ["generatorStatus"] = queue.ItemContainerGenerator.Status.ToString(),
                ["queueKeyboardFocusWithin"] = queue.IsKeyboardFocusWithin,
                ["queueEnabled"] = queue.IsEnabled,
                ["queueVisible"] = queue.IsVisible,
                ["rowFound"] = row is not null,
                ["containerRealized"] = container is not null,
                ["containerSelected"] = container?.IsSelected,
                ["containerFocusable"] = container?.Focusable,
                ["containerEnabled"] = container?.IsEnabled,
                ["containerVisible"] = container?.IsVisible,
                ["containerFocused"] = container?.IsFocused,
                ["containerKeyboardFocusWithin"] = container?.IsKeyboardFocusWithin,
                ["containerWidth"] = container?.ActualWidth,
                ["containerHeight"] = container?.ActualHeight,
                ["focusedElementType"] = focused?.GetType().FullName,
                ["focusedAutomationId"] = focused is System.Windows.DependencyObject dependencyObject
                    ? System.Windows.Automation.AutomationProperties.GetAutomationId(dependencyObject)
                    : null
            };
        });

        public void Start()
        {
            if (beforeApplicationStart is not null)
            {
                thread = new Thread(RunInjectedStartup) { Name = "CodeSigner.UiWorkflow.FailedSTA" };
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
                Assert.True(ready.Wait(TimeSpan.FromSeconds(10)), "The injected WPF startup did not complete.");
                throw new InvalidOperationException("The visible WPF host failed to start.", startException);
            }

            SharedWpfApplicationHost sharedApplication = SharedApplication.Value;
            dispatcher = sharedApplication.Dispatcher;
            application = sharedApplication.Application;
            usesSharedApplication = true;
            dispatcher.Invoke(CreateWindow);
        }

        public void Resize(double width, double height)
        {
            dispatcher!.Invoke(() =>
            {
                System.Windows.Rect workArea = System.Windows.SystemParameters.WorkArea;
                window!.Width = width;
                window.Height = height;
                window.Left = workArea.Left + Math.Max(0, (workArea.Width - width) / 2);
                window.Top = workArea.Top + Math.Max(0, (workArea.Height - height) / 2);
                window.UpdateLayout();
            });
        }

        public T ReadViewModel<T>(Func<SigningWorkbenchViewModel, T> read) =>
            dispatcher!.Invoke(() => read(viewModel!));

        public void SetOutputRoot(string value) => dispatcher!.Invoke(() => viewModel!.OutputRoot = value);

        public string ReadToolTip(string elementName) => dispatcher!.Invoke(() =>
        {
            var element = (System.Windows.FrameworkElement)(window!.FindName(elementName) ??
                throw new InvalidOperationException($"{elementName} was not found in the visual tree."));
            return element.ToolTip?.ToString() ?? string.Empty;
        });

        public CommandIconVisualObservation[] ReadVisibleCommandIconVisuals(
            IReadOnlyCollection<string> automationIds) => dispatcher!.Invoke(() =>
        {
            System.Windows.FrameworkElement[] elements = EnumerateVisualTree(window!)
                .OfType<System.Windows.FrameworkElement>()
                .ToArray();
            return automationIds.Select(automationId =>
            {
                System.Windows.FrameworkElement[] candidates = elements
                    .Where(element =>
                        element.IsVisible &&
                        string.Equals(
                            AutomationProperties.GetAutomationId(element),
                            automationId,
                            StringComparison.Ordinal))
                    .ToArray();
                if (candidates.Length != 1)
                {
                    throw new InvalidOperationException(
                        $"Expected one visible {automationId} control but found {candidates.Length}.");
                }

                System.Windows.FrameworkElement control = candidates[0];
                System.Windows.Controls.Image[] images = EnumerateVisualTree(control)
                    .OfType<System.Windows.Controls.Image>()
                    .Where(image => image.IsVisible && ReferenceEquals(FindAutomationOwner(image), control))
                    .ToArray();
                if (images.Length != 1)
                {
                    throw new InvalidOperationException(
                        $"Expected one visible image owned by {automationId} but found {images.Length}.");
                }

                System.Windows.Controls.Image image = images[0];
                var drawingImage = image.Source as DrawingImage;
                System.Windows.Rect drawingBounds = drawingImage?.Drawing.Bounds ?? System.Windows.Rect.Empty;
                System.Windows.Rect controlBounds = control
                    .TransformToAncestor(window!)
                    .TransformBounds(new System.Windows.Rect(0, 0, control.ActualWidth, control.ActualHeight));
                System.Windows.Rect imageBounds = image
                    .TransformToAncestor(window!)
                    .TransformBounds(new System.Windows.Rect(0, 0, image.ActualWidth, image.ActualHeight));
                bool overlapsText = EnumerateVisualTree(control)
                    .OfType<System.Windows.Controls.TextBlock>()
                    .Where(static text =>
                        text.IsVisible &&
                        !string.IsNullOrEmpty(text.Text) &&
                        text.ActualWidth > 0 &&
                        text.ActualHeight > 0)
                    .Select(text => text
                        .TransformToAncestor(window!)
                        .TransformBounds(new System.Windows.Rect(0, 0, text.ActualWidth, text.ActualHeight)))
                    .Any(textBounds => textBounds.IntersectsWith(imageBounds));
                bool imageFullyContained =
                    imageBounds.Left >= controlBounds.Left - 0.5 &&
                    imageBounds.Top >= controlBounds.Top - 0.5 &&
                    imageBounds.Right <= controlBounds.Right + 0.5 &&
                    imageBounds.Bottom <= controlBounds.Bottom + 0.5;
                bool hasFixedVisualBox =
                    drawingImage is not null &&
                    Math.Abs(drawingBounds.X) < 0.01 &&
                    Math.Abs(drawingBounds.Y) < 0.01 &&
                    Math.Abs(drawingBounds.Width - 24) < 0.01 &&
                    Math.Abs(drawingBounds.Height - 24) < 0.01;
                return new CommandIconVisualObservation(
                    automationId,
                    AutomationProperties.GetName(control),
                    AutomationProperties.GetHelpText(control),
                    control.ToolTip?.ToString() ?? string.Empty,
                    control.ActualWidth,
                    control.ActualHeight,
                    image.ActualWidth,
                    image.ActualHeight,
                    drawingImage is not null,
                    drawingBounds.X,
                    drawingBounds.Y,
                    drawingBounds.Width,
                    drawingBounds.Height,
                    hasFixedVisualBox,
                    imageFullyContained,
                    overlapsText);
            }).ToArray();
        });

        private static IEnumerable<System.Windows.DependencyObject> EnumerateVisualTree(
            System.Windows.DependencyObject root)
        {
            var pending = new Stack<System.Windows.DependencyObject>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                System.Windows.DependencyObject current = pending.Pop();
                yield return current;
                for (int index = VisualTreeHelper.GetChildrenCount(current) - 1; index >= 0; index--)
                {
                    pending.Push(VisualTreeHelper.GetChild(current, index));
                }
            }
        }

        private static System.Windows.FrameworkElement? FindAutomationOwner(
            System.Windows.DependencyObject element)
        {
            System.Windows.DependencyObject? current = VisualTreeHelper.GetParent(element);
            while (current is not null)
            {
                if (current is System.Windows.FrameworkElement candidate &&
                    !string.IsNullOrWhiteSpace(AutomationProperties.GetAutomationId(candidate)))
                {
                    return candidate;
                }

                current = VisualTreeHelper.GetParent(current);
            }

            return null;
        }

        public Dictionary<string, object?> ReadOpenOutputCommandState() => dispatcher!.Invoke(() =>
            new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["dispatcherCheckAccess"] = dispatcher.CheckAccess(),
                ["dispatcherShutdownStarted"] = dispatcher.HasShutdownStarted,
                ["dispatcherShutdownFinished"] = dispatcher.HasShutdownFinished,
                ["windowActive"] = window!.IsActive,
                ["windowEnabled"] = window.IsEnabled,
                ["outputRoot"] = viewModel!.OutputRoot,
                ["commandCanExecute"] = viewModel.OpenOutputCommand.CanExecute(null)
            });

        public Dictionary<string, object?> ReadOpenLogDirectoryButtonMetadata() => dispatcher!.Invoke(() =>
        {
            var button = (System.Windows.Controls.Button)(window!.FindName("OpenLogDirectoryButton") ??
                throw new InvalidOperationException("OpenLogDirectoryButton was not found in the visual tree."));
            return new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["toolTip"] = button.ToolTip?.ToString(),
                ["automationId"] = AutomationProperties.GetAutomationId(button),
                ["name"] = AutomationProperties.GetName(button),
                ["helpText"] = AutomationProperties.GetHelpText(button),
                ["enabled"] = button.IsEnabled
            };
        });

        public DispatcherOperation QueueDispatcherIdleMarker() =>
            dispatcher!.BeginInvoke(DispatcherPriority.ApplicationIdle, () => { });

        public Dictionary<string, object?> RaiseFileDrop(IReadOnlyCollection<string> paths) => dispatcher!.Invoke(() =>
        {
            var data = new System.Windows.DataObject();
            data.SetData(System.Windows.DataFormats.FileDrop, paths.ToArray());
            System.Reflection.ConstructorInfo? constructor = typeof(System.Windows.DragEventArgs).GetConstructor(
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                null,
                [
                    typeof(System.Windows.IDataObject),
                    typeof(System.Windows.DragDropKeyStates),
                    typeof(System.Windows.DragDropEffects),
                    typeof(System.Windows.DependencyObject),
                    typeof(System.Windows.Point)
                ],
                null);
            Assert.NotNull(constructor);
            var args = (System.Windows.DragEventArgs)constructor.Invoke(
            [
                data,
                System.Windows.DragDropKeyStates.None,
                System.Windows.DragDropEffects.Copy,
                window!,
                new System.Windows.Point(0, 0)
            ]);
            args.RoutedEvent = System.Windows.UIElement.DropEvent;
            args.Source = window;
            window!.RaiseEvent(args);
            return new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["routedEvent"] = args.RoutedEvent.Name,
                ["sourceType"] = args.Source?.GetType().FullName,
                ["originalSourceType"] = args.OriginalSource?.GetType().FullName,
                ["handled"] = args.Handled
            };
        });

        public void Stop()
        {
            if (stopped || dispatcher is null)
            {
                return;
            }

            stopped = true;
            if (startException is not null)
            {
                return;
            }

            Assert.True(usesSharedApplication, "A successful visible host must use the shared WPF application.");
            dispatcher.Invoke(() =>
            {
                Volatile.Write(ref stopDelegateEntered, 1);
                Volatile.Write(ref windowsBeforeClose, application?.Windows.Count ?? -1);
                foreach (System.Windows.Window openWindow in application!.Windows.Cast<System.Windows.Window>().ToArray())
                {
                    openWindow.Close();
                }

                Volatile.Write(ref windowsAfterClose, application?.Windows.Count ?? -1);
                Volatile.Write(ref shutdownCallReturned, 1);
            });
            Assert.Equal(1, Volatile.Read(ref stopDelegateEntered));
            Assert.True(Volatile.Read(ref windowsBeforeClose) >= 1);
            Assert.Equal(0, Volatile.Read(ref windowsAfterClose));
            Assert.Equal(1, Volatile.Read(ref shutdownCallReturned));
        }

        public void Dispose()
        {
            try
            {
                Stop();
            }
            finally
            {
                shell.Dispose();
                ready.Dispose();
            }
        }

        private void CreateWindow()
        {
            viewModel = new SigningWorkbenchViewModel(
                readiness,
                intake,
                batch,
                shell,
                workerHealthService,
                workerRepairService,
                workerRepairConfirmation,
                sdkSignToolReadinessState: null,
                queueAuditSink);
            Assert.True(viewModel.ApplySettings(
                viewModel.TimestampUri.AbsoluteUri,
                viewModel.DiagnosticRetentionDays));
            viewModel.SecondaryCertificate = viewModel.Certificates[1];
            window = new MainWindow(viewModel, dialogs);
            window.Show();
            window.Activate();
            Handle = new WindowInteropHelper(window).EnsureHandle();
        }

        private void RunInjectedStartup()
        {
            try
            {
                dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
                beforeApplicationStart!();
                throw new InvalidOperationException("The injected startup action unexpectedly returned.");
            }
            catch (Exception exception)
            {
                startException = exception;
                ready.Set();
                afterApplicationStartFailure?.Invoke();
            }
        }
    }

    private sealed class SurfaceReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        private int probeCount;

        public int ProbeCount => Volatile.Read(ref probeCount);

        public ReadinessSnapshot Probe(Uri timestampUri)
        {
            Interlocked.Increment(ref probeCount);
            return snapshot;
        }
    }

    private sealed class SurfaceQueueAuditSink : IQueueAuditSink
    {
        public bool CheckHealth() => true;

        public bool WriteQueueEvent(
            string eventName,
            string itemId,
            string operationId,
            string phase,
            string? check = null,
            string? action = null,
            string? outcome = null,
            string? reason = null) => true;
    }

    private sealed class SurfaceIntakeAdapter : StagedIntakeAdapterFake
    {
        private int callCount;
        private int typedRejectionCount;
        private IntakeValidationException? initialOutputRejection;
        private IReadOnlyList<string> lastInputs = [];
        private readonly List<string?> outputRoots = [];

        public SurfaceIntakeAdapter(IntakeValidationException? initialOutputRejection = null) =>
            this.initialOutputRejection = initialOutputRejection;

        public int CallCount => Volatile.Read(ref callCount);

        public int TypedRejectionCount => Volatile.Read(ref typedRejectionCount);

        public int StagingCount { get; }

        public IReadOnlyList<string> LastInputs => lastInputs;

        public IReadOnlyList<string?> OutputRoots => outputRoots.ToArray();

        public Dictionary<string, IntakeValidationException> Errors { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public bool? LastRecurseDirectories { get; private set; }

        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref callCount);
            lastInputs = inputs.ToArray();
            LastRecurseDirectories = recurseDirectories;
            outputRoots.Add(outputRoot);
            if (inputs.Count == 1 && Errors.TryGetValue(inputs.Single(), out IntakeValidationException? error))
            {
                throw error;
            }

            if (outputRoot is null && initialOutputRejection is IntakeValidationException rejection)
            {
                initialOutputRejection = null;
                throw rejection;
            }

            if (recurseDirectories &&
                inputs.Contains(MixedFolder, StringComparer.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref typedRejectionCount);
                throw new IntakeValidationException(
                    IntakeError.NotSignableSubject,
                    "The supported DLL extension contains malformed PE content.",
                    MalformedDllPath);
            }

            string root = outputRoot ?? OutputRoot;
            IntakeFile[] files = inputs
                .Select((original, index) => new IntakeFile(
                    original,
                    Path.GetFileName(original),
                    Path.Combine(root, Path.GetFileName(original)),
                    root,
                    File.Exists(original)
                        ? Assert.Single(QueuedSourceAdmission.Admit(
                            [original],
                            recurseDirectories: false,
                            CancellationToken.None).Sources).Identity
                        : new StableFileIdentity((ulong)(9 + index), $"UI-FILE-{9 + index}"),
                    new SignableSubject(
                        string.Equals(Path.GetExtension(original), ".msi", StringComparison.OrdinalIgnoreCase)
                            ? SignableFileType.WindowsInstaller
                            : SignableFileType.PortableExecutable,
                        Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee"))))
                .ToArray();
            return Task.FromResult(new IntakePlan(
                root,
                files));
        }
    }

    private sealed class SurfaceBatchAdapter : IBatchAdapter
    {
        private readonly Task? runGate;
        private int runCount;
        private int resumeCount;
        private int pruneCount;
        private string[] prunedItemIds = [];
        private IReadOnlyList<BatchItemRequest> requests = [];

        public SurfaceBatchAdapter(Task? runGate = null)
        {
            this.runGate = runGate;
        }

        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

        public int RunCount => Volatile.Read(ref runCount);

        public int ResumeCount => Volatile.Read(ref resumeCount);

        public int PruneCount => Volatile.Read(ref pruneCount);

        public IReadOnlyList<string> PrunedItemIds => prunedItemIds;

        public IReadOnlyList<BatchItemRequest> Requests => requests;

        public async Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref runCount);
            requests = [.. requests, request];
            if (runGate is not null)
            {
                await runGate.WaitAsync(cancellationToken);
            }

            await Task.Delay(60, cancellationToken);
            Emit(request.ItemId, BatchItemState.SigningPrimary);
            await Task.Delay(60, cancellationToken);
            Emit(request.ItemId, BatchItemState.SigningSecondary);
            await Task.Delay(60, cancellationToken);
            Emit(request.ItemId, BatchItemState.Verifying);
            await Task.Delay(60, cancellationToken);
            return Emit(
                request.ItemId,
                BatchItemState.Failed,
                Receipt(request, BatchItemState.Failed, BatchResultCode.WorkerFailure, unchecked((int)0x80004005)));
        }

        public async Task<BatchProgressUpdate> ResumeAsync(
            string itemId,
            bool retryFailed,
            CancellationToken cancellationToken)
        {
            Assert.True(retryFailed);
            Interlocked.Increment(ref resumeCount);
            BatchItemRequest request = Assert.Single(requests, request => request.ItemId == itemId);
            Emit(request.ItemId, BatchItemState.Ready);
            await Task.Delay(40, cancellationToken);
            Emit(request.ItemId, BatchItemState.SigningPrimary);
            await Task.Delay(40, cancellationToken);
            Emit(request.ItemId, BatchItemState.SigningSecondary);
            await Task.Delay(40, cancellationToken);
            Emit(request.ItemId, BatchItemState.Verifying);
            await Task.Delay(40, cancellationToken);
            return Emit(
                request.ItemId,
                BatchItemState.Published,
                Receipt(request, BatchItemState.Published, BatchResultCode.Published, 0));
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
            prunedItemIds = itemIds.ToArray();
            requests = requests.Where(request => !itemIds.Contains(request.ItemId, StringComparer.Ordinal)).ToArray();
            Interlocked.Increment(ref pruneCount);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public void EmitForTest(QueueItemViewModel row, BatchItemState state) =>
            Emit(row.ItemId, state);

        private BatchProgressUpdate Emit(
            string itemId,
            BatchItemState state,
            BatchItemReceipt? receipt = null)
        {
            var update = new BatchProgressUpdate(itemId, state, receipt);
            ProgressChanged?.Invoke(this, new BatchProgressChangedEventArgs(update));
            return update;
        }

        private static BatchItemReceipt Receipt(
            BatchItemRequest request,
            BatchItemState state,
            BatchResultCode code,
            int hResult) => new(
                request.ItemId,
                state,
                code,
                request.File.OriginalPath,
                request.File.DestinationPath,
                state == BatchItemState.Published ? new string('1', 64) : null,
                state == BatchItemState.Published ? new string('2', 64) : null,
                state == BatchItemState.Published ? "UI-ATTEMPT-1" : null,
                4321,
                hResult);
    }

    private sealed class SurfaceWorkerHealthService : IWorkerHealthService
    {
        private readonly Queue<WorkerLaunchDiagnostic> diagnostics;
        private WorkerLaunchDiagnostic lastDiagnostic;

        public SurfaceWorkerHealthService(params WorkerLaunchDiagnostic[] diagnostics)
        {
            this.diagnostics = new Queue<WorkerLaunchDiagnostic>(diagnostics.Length == 0
                ? [WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy)]
                : diagnostics);
            lastDiagnostic = this.diagnostics.Peek();
        }

        public int CallCount { get; private set; }

        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            if (diagnostics.Count > 0)
            {
                lastDiagnostic = diagnostics.Dequeue();
            }

            return Task.FromResult(lastDiagnostic);
        }
    }

    private static string ResolveRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory.FullName;
    }

    private static void AssertLucideLicenseHashIsStableAcrossCheckoutLineEndings()
    {
        string licensePath = Path.Combine(
            ResolveRepositoryRoot(),
            "src",
            "CodeSigner.App",
            "Assets",
            "CommandIcons",
            "LICENSE.txt");
        byte[] lfBytes = ReadLucideLicenseLfBytesForTestData();
        byte[] crlfBytes = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(lfBytes).Replace("\n", "\r\n", StringComparison.Ordinal));

        Assert.Equal(LucideLicenseSha256, ComputeLucideLicenseCanonicalSha256(File.ReadAllBytes(licensePath)));
        Assert.Equal(LucideLicenseSha256, ComputeLucideLicenseCanonicalSha256(lfBytes));
        Assert.Equal(LucideLicenseSha256, ComputeLucideLicenseCanonicalSha256(crlfBytes));
    }

    private static string ComputeLucideLicenseCanonicalSha256(byte[] bytes)
    {
        string canonicalText = DecodeAndCanonicalizeLucideLicense(bytes);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalText))).ToLowerInvariant();
    }

    private static string DecodeAndCanonicalizeLucideLicense(byte[] bytes)
    {
        ReadOnlySpan<byte> content = bytes;
        if (content.StartsWith(Encoding.UTF8.GetPreamble()) ||
            content.StartsWith(Encoding.Unicode.GetPreamble()) ||
            content.StartsWith(Encoding.BigEndianUnicode.GetPreamble()))
        {
            throw new InvalidDataException("The Lucide license must not contain a byte-order mark.");
        }

        string text = new UTF8Encoding(false, true).GetString(bytes);
        for (int index = 0; index < text.Length; index++)
        {
            if (text[index] == '\r' && (index + 1 == text.Length || text[index + 1] != '\n'))
            {
                throw new InvalidDataException("The Lucide license contains a lone CR line ending.");
            }
        }

        return text.Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    private static byte[] ReadLucideLicenseLfBytesForTestData()
    {
        string licensePath = Path.Combine(
            ResolveRepositoryRoot(),
            "src",
            "CodeSigner.App",
            "Assets",
            "CommandIcons",
            "LICENSE.txt");
        string lfText = DecodeAndCanonicalizeLucideLicense(File.ReadAllBytes(licensePath));
        return Encoding.UTF8.GetBytes(lfText);
    }

    private static byte[] WithPreamble(Encoding encoding, string value) =>
        encoding.GetPreamble().Concat(encoding.GetBytes(value)).ToArray();

    private static async Task<string> ExportDiagnosticsInHarnessScopeAsync()
    {
        using var shell = new SurfaceOperatorShell();
        return await shell.ExportDiagnosticsAsync(
            new Dictionary<string, object?> { ["status"] = "test" },
            retentionDays: 30,
            CancellationToken.None);
    }

    private static List<string> ValidateCommandIconContinuity(string repositoryRoot)
    {
        string assetDirectory = Path.Combine(
            repositoryRoot,
            "src",
            "CodeSigner.App",
            "Assets",
            "CommandIcons");
        string dictionaryPath = Path.Combine(assetDirectory, "LucideCommandIcons.xaml");
        string licensePath = Path.Combine(assetDirectory, "LICENSE.txt");
        string sourceReceiptPath = Path.Combine(assetDirectory, "SOURCE.json");
        var errors = new List<string>();

        foreach (string requiredPath in new[] { dictionaryPath, licensePath, sourceReceiptPath })
        {
            if (!File.Exists(requiredPath))
            {
                errors.Add($"Missing local command icon artifact: {Path.GetRelativePath(repositoryRoot, requiredPath)}");
            }
        }

        if (errors.Count > 0)
        {
            return errors;
        }

        XDocument dictionary = XDocument.Load(dictionaryPath, LoadOptions.SetLineInfo);
        XName keyName = XName.Get("Key", XamlLanguageNamespace);
        XElement[] drawingImages = dictionary
            .Descendants()
            .Where(static element => element.Name.LocalName == "DrawingImage")
            .ToArray();
        string[] resourceKeys = drawingImages
            .Select(element => element.Attribute(keyName)?.Value)
            .Where(static key => key is not null)
            .Cast<string>()
            .ToArray();
        foreach (IGrouping<string, string> duplicate in resourceKeys.GroupBy(static key => key, StringComparer.Ordinal))
        {
            if (duplicate.Count() > 1)
            {
                errors.Add($"Duplicate local command icon resource: {duplicate.Key}");
            }
        }

        foreach (string expectedKey in ExpectedLocalIconKeys)
        {
            if (!resourceKeys.Contains(expectedKey, StringComparer.Ordinal))
            {
                errors.Add($"Missing local command icon resource: {expectedKey}");
            }
        }

        foreach (XElement drawingImage in drawingImages)
        {
            string? key = drawingImage.Attribute(keyName)?.Value;
            if (key is null || !key.StartsWith("Icon.", StringComparison.Ordinal))
            {
                continue;
            }

            bool hasVisualBox = drawingImage
                .Descendants()
                .Where(static element => element.Name.LocalName == "GeometryDrawing")
                .Any(static element =>
                    string.Equals(element.Attribute("Brush")?.Value, "Transparent", StringComparison.Ordinal) &&
                    string.Equals(
                        element.Attribute("Geometry")?.Value,
                        "{StaticResource Geometry.Icon.VisualBox}",
                        StringComparison.Ordinal));
            bool hasLucideStroke = drawingImage
                .Descendants()
                .Where(static element => element.Name.LocalName == "GeometryDrawing")
                .Any(static element =>
                    element.Attribute("Geometry")?.Value?.StartsWith(
                        "{StaticResource Geometry.Lucide.",
                        StringComparison.Ordinal) == true &&
                    (element.Attribute("Pen")?.Value?.StartsWith(
                        "{StaticResource Pen.Icon.",
                        StringComparison.Ordinal) == true ||
                     element.Elements().Where(static child => child.Name.LocalName == "GeometryDrawing.Pen")
                         .SelectMany(static child => child.Elements())
                         .Any(static child => child.Name.LocalName == "Pen")));
            if (!hasVisualBox || !hasLucideStroke)
            {
                errors.Add($"{key} does not preserve a transparent 24x24 visual box and local Lucide stroke.");
            }
        }

        XElement[] pens = dictionary
            .Descendants()
            .Where(static element => element.Name.LocalName == "Pen")
            .ToArray();
        if (pens.Length == 0)
        {
            errors.Add("No local Lucide pens were defined.");
        }

        foreach (XElement pen in pens)
        {
            if (!string.Equals(pen.Attribute("Thickness")?.Value, "2", StringComparison.Ordinal) ||
                !string.Equals(pen.Attribute("StartLineCap")?.Value, "Round", StringComparison.Ordinal) ||
                !string.Equals(pen.Attribute("EndLineCap")?.Value, "Round", StringComparison.Ordinal) ||
                !string.Equals(pen.Attribute("LineJoin")?.Value, "Round", StringComparison.Ordinal))
            {
                errors.Add("A local Lucide pen does not use the pinned 2 DIP round stroke contract.");
            }
        }

        string[] surfacePaths =
        [
            Path.Combine(repositoryRoot, "src", "CodeSigner.App", "MainWindow.xaml"),
            Path.Combine(repositoryRoot, "src", "CodeSigner.App", "PrimitiveShowcaseWindow.xaml")
        ];
        XElement[] surfaces = surfacePaths
            .Select(path => XDocument.Load(path, LoadOptions.SetLineInfo))
            .SelectMany(static document => document.Descendants())
            .ToArray();
        foreach (CommandIconExpectation expectation in ExpectedCommandIconMappings)
        {
            XElement[] controls = surfaces
                .Where(element => string.Equals(
                    element.Attribute("AutomationProperties.AutomationId")?.Value,
                    expectation.AutomationId,
                    StringComparison.Ordinal))
                .ToArray();
            if (controls.Length != expectation.ExpectedCount)
            {
                errors.Add(
                    $"{expectation.AutomationId} expected {expectation.ExpectedCount} icon-bearing controls but found {controls.Length}.");
                continue;
            }

            foreach (XElement control in controls)
            {
                string[] iconReferences = control
                    .Descendants()
                    .Where(static element => element.Name.LocalName == "Image")
                    .Where(element => ReferenceEquals(
                        element.Ancestors().FirstOrDefault(static ancestor =>
                            ancestor.Attribute("AutomationProperties.AutomationId") is not null),
                        control))
                    .Select(static element => ReadStaticResourceKey(element.Attribute("Source")?.Value))
                    .Where(static key => key is not null)
                    .Cast<string>()
                    .ToArray();
                if (iconReferences.Length != 1 ||
                    !string.Equals(iconReferences[0], expectation.ResourceKey, StringComparison.Ordinal))
                {
                    errors.Add(
                        $"{expectation.AutomationId} must reference exactly {expectation.ResourceKey}; observed [{string.Join(", ", iconReferences)}].");
                }
            }
        }

        string[] allIconReferences = surfaces
            .Where(static element => element.Name.LocalName == "Image")
            .Select(static element => ReadStaticResourceKey(element.Attribute("Source")?.Value))
            .Where(static key => key?.StartsWith("Icon.", StringComparison.Ordinal) == true)
            .Cast<string>()
            .ToArray();
        foreach (string reference in allIconReferences)
        {
            if (!resourceKeys.Contains(reference, StringComparer.Ordinal))
            {
                errors.Add($"Unresolved local command icon reference: {reference}");
            }
        }

        string licenseSha256 = ComputeLucideLicenseCanonicalSha256(File.ReadAllBytes(licensePath));
        if (!string.Equals(licenseSha256, LucideLicenseSha256, StringComparison.Ordinal))
        {
            errors.Add($"Lucide ISC license hash mismatch: {licenseSha256}");
        }

        using (JsonDocument receipt = JsonDocument.Parse(File.ReadAllBytes(sourceReceiptPath)))
        {
            JsonElement root = receipt.RootElement;
            string[] mappedKeys = root.GetProperty("sources").EnumerateArray()
                .SelectMany(static source => source.GetProperty("resources").EnumerateArray())
                .Select(static resource => resource.GetString() ?? string.Empty)
                .ToArray();
            foreach (string resourceKey in resourceKeys)
            {
                if (mappedKeys.Count(key => key == resourceKey) != 1)
                {
                    errors.Add($"Icon provenance must identify exactly one source for {resourceKey}.");
                }
            }
            JsonElement license = root.GetProperty("license");
            JsonElement canonicalHash = license.GetProperty("canonicalHash");
            string[] acceptedCheckoutLineEndings = canonicalHash
                .GetProperty("acceptedCheckoutLineEndings")
                .EnumerateArray()
                .Select(static value => value.GetString() ?? string.Empty)
                .ToArray();
            if (!string.Equals(root.GetProperty("release").GetString(), LucideRelease, StringComparison.Ordinal) ||
                !string.Equals(root.GetProperty("commit").GetString(), LucideCommit, StringComparison.Ordinal) ||
                !string.Equals(license.GetProperty("gitBlobSha").GetString(), LucideLicenseGitBlobSha, StringComparison.Ordinal) ||
                license.TryGetProperty("sha256", out _) ||
                !string.Equals(canonicalHash.GetProperty("algorithm").GetString(), "SHA-256", StringComparison.Ordinal) ||
                !string.Equals(canonicalHash.GetProperty("value").GetString(), LucideLicenseSha256, StringComparison.Ordinal) ||
                !string.Equals(canonicalHash.GetProperty("inputEncoding").GetString(), "UTF-8", StringComparison.Ordinal) ||
                !string.Equals(canonicalHash.GetProperty("bom").GetString(), "forbidden", StringComparison.Ordinal) ||
                !string.Equals(canonicalHash.GetProperty("canonicalLineEnding").GetString(), "LF", StringComparison.Ordinal) ||
                !acceptedCheckoutLineEndings.SequenceEqual(["LF", "CRLF"], StringComparer.Ordinal) ||
                !string.Equals(canonicalHash.GetProperty("normalization").GetString(), "CRLF-to-LF-only", StringComparison.Ordinal))
            {
                errors.Add("Lucide source receipt identity or canonical license hash contract is not pinned exactly.");
            }
        }

        return errors;
    }

    private static string? ReadStaticResourceKey(string? value)
    {
        const string prefix = "{StaticResource ";
        return value is not null &&
               value.StartsWith(prefix, StringComparison.Ordinal) &&
               value.EndsWith('}')
            ? value[prefix.Length..^1]
            : null;
    }

    private static void CopyCommandIconContractFiles(string sourceRoot, string destinationRoot)
    {
        string[] relativePaths =
        [
            "src/CodeSigner.App/MainWindow.xaml",
            "src/CodeSigner.App/PrimitiveShowcaseWindow.xaml",
            "src/CodeSigner.App/Assets/CommandIcons/LucideCommandIcons.xaml",
            "src/CodeSigner.App/Assets/CommandIcons/LICENSE.txt",
            "src/CodeSigner.App/Assets/CommandIcons/SOURCE.json"
        ];
        foreach (string relativePath in relativePaths)
        {
            string platformPath = relativePath.Replace('/', Path.DirectorySeparatorChar);
            string source = Path.Combine(sourceRoot, platformPath);
            string destination = Path.Combine(destinationRoot, platformPath);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(source, destination);
        }
    }

    private sealed class SurfaceWorkerRepairService : IWorkerRepairService
    {
        private readonly Func<CancellationToken, Task<WorkerRepairResult>> behavior;

        public SurfaceWorkerRepairService()
            : this(_ => throw new InvalidOperationException("Worker repair is not used by UI surface tests."))
        {
        }

        public SurfaceWorkerRepairService(Func<CancellationToken, Task<WorkerRepairResult>> behavior) =>
            this.behavior = behavior;

        public int CallCount { get; private set; }

        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            InvokeRepairAsync(cancellationToken);

        private async Task<WorkerRepairResult> InvokeRepairAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            return await behavior(cancellationToken);
        }

        public void Dispose()
        {
        }
    }

    private sealed class SurfaceOperatorShell : IOperatorShell, IDisposable
    {
        private readonly bool createOpenedDirectories;
        private readonly object generatedDiagnosticsGate = new();
        private readonly HashSet<string> generatedDiagnosticsPaths = new(StringComparer.OrdinalIgnoreCase);
        private bool disposed;
        private int exportCount;
        private int openFolderCount;
        private string? openedFolder;

        public SurfaceOperatorShell(bool createOpenedDirectories = false) =>
            this.createOpenedDirectories = createOpenedDirectories;

        public string? OpenedFolder => Volatile.Read(ref openedFolder);

        public int OpenFolderCount => Volatile.Read(ref openFolderCount);

        public int ExportCount => Volatile.Read(ref exportCount);

        public int LastRetentionDays { get; private set; }

        public IReadOnlyDictionary<string, object?>? LastDiagnostics { get; private set; }

        public string? ExportedDiagnosticsPath { get; private set; }

        public void OpenFolder(string path)
        {
            if (createOpenedDirectories)
            {
                Directory.CreateDirectory(path);
            }

            Volatile.Write(ref openedFolder, path);
            Interlocked.Increment(ref openFolderCount);
        }

        public async Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken)
        {
            LastDiagnostics = diagnostics;
            LastRetentionDays = retentionDays;
            string path = Path.Combine(
                Path.GetTempPath(),
                $"CodeSigner-ui-diagnostics-{Guid.NewGuid():N}.json");
            lock (generatedDiagnosticsGate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                generatedDiagnosticsPaths.Add(path);
            }

            var candidate = new Dictionary<string, object?>(diagnostics, StringComparer.Ordinal)
            {
                ["credential"] = "SHOULD_BE_DROPPED",
                ["privateKey"] = "SHOULD_BE_DROPPED",
                ["pin"] = "SHOULD_BE_DROPPED"
            };
            await using FileStream stream = new(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.Read);
            await AllowListEvidenceWriter.WriteAsync(stream, candidate, cancellationToken);
            ExportedDiagnosticsPath = path;
            Interlocked.Increment(ref exportCount);
            return path;
        }

        public void Dispose()
        {
            string[] paths;
            lock (generatedDiagnosticsGate)
            {
                if (disposed)
                {
                    return;
                }

                disposed = true;
                paths = generatedDiagnosticsPaths.ToArray();
                generatedDiagnosticsPaths.Clear();
            }

            foreach (string path in paths)
            {
                File.Delete(path);
            }
        }
    }

    private sealed class SurfaceDialogs : IWorkbenchDialogs
    {
        private readonly IReadOnlyList<string> fileSelection;
        private readonly string? folderSelection;

        public SurfaceDialogs(
            IReadOnlyList<string>? fileSelection = null,
            string? folderSelection = MixedFolder)
        {
            this.fileSelection = fileSelection ?? [LongExePath];
            this.folderSelection = folderSelection;
        }

        public int FilePickerCount { get; private set; }

        public int FolderPickerCount { get; private set; }

        public IReadOnlyList<string> PickExeFiles(System.Windows.Window owner)
        {
            FilePickerCount++;
            return fileSelection;
        }

        public string? PickInputFolder(System.Windows.Window owner)
        {
            FolderPickerCount++;
            return folderSelection;
        }

        public string? PickOutputRoot(System.Windows.Window owner, string? currentOutputRoot) => OutputRoot;
    }
}
