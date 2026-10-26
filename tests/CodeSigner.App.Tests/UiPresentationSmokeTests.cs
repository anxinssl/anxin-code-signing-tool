using System.IO;
using System.Reflection;
using System.ComponentModel;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Xml.Linq;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;
using ComboBox = System.Windows.Controls.ComboBox;
using Image = System.Windows.Controls.Image;
using Size = System.Windows.Size;
using TextBox = System.Windows.Controls.TextBox;
using DataGrid = System.Windows.Controls.DataGrid;
using MenuItem = System.Windows.Controls.MenuItem;

namespace CodeSigner.App.Tests;

// Load the production view markup without windows, event handlers or product services.
[Collection("WpfPresentation")]
public sealed class UiPresentationSmokeTests
{
    private static readonly string Root = FindRoot();
    private static readonly int[] RetentionDays = [7, 30, 90];
    private static readonly XNamespace Wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    [Fact]
    public void WebsiteUsesOnlyTheOfficialHttpsAddressAndDefaultBrowser()
    {
        var start = BrandSupportFooter.CreateWebsiteStartInfo();
        Assert.Equal("https://www.anxinssl.com/code-signing-certificate/", start.FileName);
        Assert.True(start.UseShellExecute);
        Assert.Empty(start.Arguments);
    }

    [Theory]
    [InlineData(480)]
    [InlineData(650)]
    [InlineData(1000)]
    public void FooterAndSupportImageRenderWithoutShowingAWindow(int width)
    {
        RunOnSta(() =>
        {
            var footer = new BrandSupportFooter { Resources = LoadResources() };
            footer.Measure(new Size(width, 50));
            footer.Arrange(new Rect(0, 0, width, 50));
            footer.UpdateLayout();
            var website = (StackPanel)footer.FindName("WebsitePanel");
            var support = (Button)footer.FindName("SupportButton");
            Rect websiteBounds = website.TransformToAncestor(footer).TransformBounds(new Rect(website.RenderSize));
            Rect supportBounds = support.TransformToAncestor(footer).TransformBounds(new Rect(support.RenderSize));
            Assert.True(websiteBounds.Right <= supportBounds.Left);
            Assert.InRange(supportBounds.Right, 1, width);
            Assert.InRange(footer.DesiredSize.Height, 1, 50);
            var popup = (System.Windows.Controls.Primitives.Popup)footer.FindName("SupportPopup");
            Assert.False(popup.IsOpen);
            Assert.False(popup.StaysOpen);
            Assert.Null(popup.Parent);
            Assert.Null(VisualTreeHelper.GetParent(popup));
            Assert.Equal(System.Windows.Controls.Primitives.PlacementMode.Top, popup.Placement);
            Assert.Same(support, popup.PlacementTarget);
            var image = (Image)footer.FindName("SupportQrImage");
            var bitmap = Assert.IsAssignableFrom<BitmapSource>(image.Source);
            Assert.Equal(248, bitmap.PixelWidth);
            Assert.Equal(244, bitmap.PixelHeight);
            byte[] actual = new byte[bitmap.PixelWidth * bitmap.PixelHeight * 4];
            var normalized = new FormatConvertedBitmap(bitmap, PixelFormats.Bgra32, null, 0);
            normalized.CopyPixels(actual, bitmap.PixelWidth * 4, 0);
            var original = new BitmapImage(new Uri(Path.Combine(Root, "src", "CodeSigner.App", "Assets", "anxin-support-qr.png")));
            byte[] expected = new byte[actual.Length];
            new FormatConvertedBitmap(original, PixelFormats.Bgra32, null, 0).CopyPixels(expected, bitmap.PixelWidth * 4, 0);
            Assert.Equal(expected, actual);
            // Render the popup child offscreen, without opening its HWND or product services.
            var panel = (Border)popup.Child;
            popup.Child = null;
            panel.Resources = LoadResources();
            panel.Measure(new Size(280, 360));
            panel.Arrange(new Rect(0, 0, 280, panel.DesiredSize.Height));
            panel.UpdateLayout();
            Rect imageBounds = image.TransformToAncestor(panel).TransformBounds(new Rect(image.RenderSize));
            Assert.True(imageBounds.Left >= 0 && imageBounds.Right <= 280);
            Assert.True(imageBounds.Bottom <= panel.ActualHeight);
            Assert.Equal(248, image.ActualWidth);
            Assert.Equal(244, image.ActualHeight);
            SavePreview(panel, 280, (int)Math.Ceiling(panel.ActualHeight), $"support-panel-{width}.png");
            SavePreview(footer, width, 50, $"footer-{width}.png");
        });
    }

    private static void SavePreview(FrameworkElement element, int width, int height, string name)
    {
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(element);
        string directory = Path.Combine(Root, "artifacts", "queue-link-1.0.40");
        Directory.CreateDirectory(directory);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream stream = File.Create(Path.Combine(directory, name));
        encoder.Save(stream);
    }

    [Fact]
    public void SettingsSpacingResourceIsThicknessNotScalar()
    {
        RunOnSta(() =>
        {
            ResourceDictionary resources = LoadResources();
            Assert.IsType<double>(resources["Space.6"]);
            Assert.Equal(new Thickness(24), Assert.IsType<Thickness>(resources["Inset.Settings.Content"]));
            Grid view = LoadView("SettingsWindow.xaml");
            Assert.Equal(new Thickness(24), Assert.IsType<Grid>(view.Children[0]).Margin);
        });
    }

    [Theory]
    [InlineData("SettingsWindow.xaml", 520, 660, false, false)]
    [InlineData("MainWindow.xaml", 1180, 940, false, false)]
    [InlineData("MainWindow.xaml", 1000, 900, false, false)]
    [InlineData("MainWindow.xaml", 1180, 940, true, false)]
    [InlineData("MainWindow.xaml", 1000, 900, true, false)]
    [InlineData("MainWindow.xaml", 1000, 760, true, false)]
    [InlineData("MainWindow.xaml", 1180, 940, false, true)]
    [InlineData("MainWindow.xaml", 1000, 760, false, true)]
    public void ActualViewMarkupLoadsMeasuresAndRendersWithoutProductServices(string file, int width, int height, bool dual, bool missingCertificate)
    {
        RunOnSta(() =>
        {
            Grid view = LoadView(file);
            var preview = new PreviewState
            {
                IsSingleMode = !dual,
                IsDualMode = dual,
                MissingCertificate = missingCertificate,
                CurrentItem = file == "MainWindow.xaml" && height == 760 ? new FailurePreview() : null
            };
            preview.SecondaryCertificate = preview.PrimaryCertificate;
            view.DataContext = preview;
            if (file == "SettingsWindow.xaml")
            {
                Find<TextBox>(view, "TimestampUriTextBox").Text = "http://time.certum.pl";
                ComboBox retention = Find<ComboBox>(view, "RetentionComboBox");
                retention.ItemsSource = RetentionDays;
                retention.SelectedItem = 30;
                Find<TextBlock>(view, "ProductVersionText").Text = SettingsWindow.ProductVersionDisplayText;
            }
            if (file == "MainWindow.xaml" && height == 760)
            {
                Find<Grid>(view, "FullActionRail").Visibility = Visibility.Collapsed;
                Find<Grid>(view, "CompactActionRail").Visibility = Visibility.Visible;
            }
            view.Measure(new Size(width, height));
            view.Arrange(new Rect(0, 0, width, height));
            view.UpdateLayout();
            Assert.InRange(view.DesiredSize.Width, 1, width);
            Assert.InRange(view.DesiredSize.Height, 1, height);
            if (file == "MainWindow.xaml")
            {
                BrandSupportFooter footer = Find<BrandSupportFooter>(view, "SupportFooter");
                Rect footerBounds = footer.TransformToAncestor(view).TransformBounds(new Rect(footer.RenderSize));
                FrameworkElement actionBand = Find<FrameworkElement>(view, "ActionBand");
                Rect actionBounds = actionBand.TransformToAncestor(view).TransformBounds(new Rect(actionBand.RenderSize));
                Assert.True(footerBounds.Bottom <= height && footerBounds.Right <= width);
                Assert.True(actionBounds.Bottom <= footerBounds.Top);
                TextBlock certificateHint = Find<TextBlock>(view, "CertificateRefreshHint");
                TextBlock outputHint = Find<TextBlock>(view, "OutputLocationHint");
                if (missingCertificate)
                {
                    Assert.Contains("SafeNet", certificateHint.Text, StringComparison.Ordinal);
                    Assert.Contains("SimplySign", certificateHint.Text, StringComparison.Ordinal);
                }
                else
                {
                    Assert.Contains("刷新证书", certificateHint.Text, StringComparison.Ordinal);
                    Assert.Contains("有效证书", certificateHint.Text, StringComparison.Ordinal);
                }
                Assert.Contains("输出位置", outputHint.Text, StringComparison.Ordinal);
                Assert.Equal(TextWrapping.Wrap, certificateHint.TextWrapping);
                Assert.Equal(TextWrapping.Wrap, outputHint.TextWrapping);
                foreach (TextBlock hint in new[] { certificateHint, outputHint })
                {
                    Rect hintBounds = hint.TransformToAncestor(view).TransformBounds(new Rect(hint.RenderSize));
                    Assert.Equal(Visibility.Visible, hint.Visibility);
                    Assert.True(hint.RenderSize.Width > 0 && hint.RenderSize.Height > 0);
                    Assert.True(hintBounds.Right <= width && hintBounds.Bottom <= height);
                }
                if (height == 760)
                {
                    TextBlock errorText = Find<TextBlock>(view, "RuntimeError");
                    Assert.Contains("移除并重新添加", errorText.Text, StringComparison.Ordinal);
                    Rect errorBounds = errorText.TransformToAncestor(view).TransformBounds(new Rect(errorText.RenderSize));
                    Assert.True(errorBounds.Right <= width && errorBounds.Bottom <= height);
                }
                ComboBox secondary = Find<ComboBox>(view, "SecondaryCertificateCombo");
                Assert.Equal(dual ? Visibility.Visible : Visibility.Collapsed, secondary.Visibility);
                if (dual)
                {
                    Assert.Same(preview.PrimaryCertificate, secondary.SelectedItem);
                    Rect bounds = secondary.TransformToAncestor(view).TransformBounds(new Rect(secondary.RenderSize));
                    Assert.True(bounds.Width > 0 && bounds.Right <= width && bounds.Bottom <= height);
                }
            }
            if (file == "SettingsWindow.xaml")
            {
                FrameworkElement version = Find<TextBlock>(view, "ProductVersionText");
                FrameworkElement uninstall = Find<Button>(view, "UninstallButton");
                Rect left = version.TransformToAncestor(view).TransformBounds(new Rect(version.RenderSize));
                Rect right = uninstall.TransformToAncestor(view).TransformBounds(new Rect(uninstall.RenderSize));
                Assert.True(left.Right <= right.Left, "Settings version text must not overlap uninstall.");
                Assert.True(right.Right <= width);
            }
            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(view);
            byte[] pixels = new byte[width * height * 4];
            bitmap.CopyPixels(pixels, width * 4, 0);
            Assert.True(pixels.Distinct().Count() > 20, "The rendered view must not be blank.");
            string output = Path.Combine(Root, "artifacts", "queue-link-1.0.40", $"{Path.GetFileNameWithoutExtension(file)}-{width}-{height}{(dual ? "-dual" : "")}{(missingCertificate ? "-empty" : "")}.png");
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using FileStream stream = File.Create(output);
            encoder.Save(stream);
        });
    }

    [Fact]
    public void FormerScalarSettingsMarginReproducesTheReportedLoadFailure()
    {
        RunOnSta(() =>
        {
            var error = Assert.Throws<XamlParseException>(() => LoadView("SettingsWindow.xaml", useScalarSettingsMargin: true));
            Assert.Contains("Margin", error.ToString(), StringComparison.Ordinal);
        });
    }

    [Fact]
    public void SettingsEditorTemplatesPreserveSelectionAndTextHosts()
    {
        RunOnSta(() =>
        {
            Grid view = LoadView("SettingsWindow.xaml");
            ComboBox retention = Find<ComboBox>(view, "RetentionComboBox");
            retention.ItemsSource = RetentionDays;
            retention.SelectedItem = 30;
            TextBox timestamp = Find<TextBox>(view, "TimestampUriTextBox");
            timestamp.Text = "http://time.certum.pl";
            view.Measure(new Size(520, 660));
            view.Arrange(new Rect(0, 0, 520, 660));
            view.UpdateLayout();
            Assert.IsType<System.Windows.Controls.Primitives.Popup>(
                retention.Template.FindName("PART_Popup", retention));
            var toggle = Assert.IsType<System.Windows.Controls.Primitives.ToggleButton>(
                retention.Template.FindName("DropDownToggle", retention));
            Assert.False(toggle.Focusable);
            Assert.NotNull(System.Windows.Data.BindingOperations.GetBindingExpression(
                toggle, System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty));
            Assert.IsType<ScrollViewer>(timestamp.Template.FindName("PART_ContentHost", timestamp));
            retention.SelectedItem = 90;
            Assert.Equal(90, retention.SelectedItem);
            timestamp.AppendText("/test");
            Assert.Equal("http://time.certum.pl/test", timestamp.Text);
            retention.IsEnabled = false;
            Assert.Equal(0.5, retention.Opacity);
        });
    }

    private static Grid LoadView(string file, bool useScalarSettingsMargin = false)
    {
        // Initialize WPF resource handling before constructing an absolute pack URI.
        ResourceDictionary tokens = LoadResources();
        XElement window = XDocument.Load(Path.Combine(Root, "src", "CodeSigner.App", file)).Root!;
        var wrapper = new XElement(Wpf + "Grid",
            window.Attributes().Where(attribute => attribute.IsNamespaceDeclaration).Select(attribute => new XAttribute(attribute)));
        wrapper.SetAttributeValue(XNamespace.Xmlns + "local", "clr-namespace:CodeSigner.App;assembly=CodeSigner.App");
        var resources = new XElement(Wpf + "ResourceDictionary",
            new XElement(Wpf + "ResourceDictionary.MergedDictionaries",
                new XElement(Wpf + "ResourceDictionary",
                    new XAttribute("Source", "/CodeSigner.App;component/Themes/DesignTokens.xaml"))));
        XElement? localResources = window.Element(Wpf + "Window.Resources");
        if (localResources is not null)
        {
            resources.Add(localResources.Elements().Select(element => new XElement(element)));
        }
        wrapper.Add(new XElement(Wpf + "Grid.Resources", resources));
        wrapper.Add(new XElement(window.Elements().Single(element => element.Name.LocalName == "Grid")));
        if (useScalarSettingsMargin)
        {
            wrapper.Elements(Wpf + "Grid").Single().SetAttributeValue("Margin", "{StaticResource Space.6}");
        }
        foreach (XElement element in wrapper.Descendants().Where(element => element.Name.NamespaceName == "clr-namespace:CodeSigner.App"))
        {
            if (element.Name.LocalName == "BrandSupportFooter")
            {
                element.Name = XName.Get("BrandSupportFooter", "clr-namespace:CodeSigner.App;assembly=CodeSigner.App");
                continue;
            }
            // The two internal accessibility-only controls cannot be created by loose XAML.
            string name = element.Name.LocalName
                .Replace("WorkerRecoveryGroupBox", "GroupBox", StringComparison.Ordinal)
                .Replace("AccessibleWatermarkText", "TextBlock", StringComparison.Ordinal);
            element.Name = Wpf + name;
        }
        foreach (XAttribute handler in wrapper.Descendants().Attributes()
                     .Where(attribute => attribute.Name.LocalName is "Click" or "CurrentCellChanged" or "SelectionChanged" or "LostKeyboardFocus").ToArray())
        {
            handler.Remove();
        }
        var view = (Grid)XamlReader.Parse(wrapper.ToString(), new ParserContext
        {
            BaseUri = new Uri("pack://application:,,,/CodeSigner.App;component/", UriKind.Absolute)
        });
        view.Background = (Brush)tokens["Brush.PageBackground"];
        view.SetValue(TextElement.FontFamilyProperty, tokens["Font.Body"]);
        view.SetValue(TextElement.FontSizeProperty, tokens["Typography.Body.Size"]);
        view.SetValue(TextElement.ForegroundProperty, tokens["Color.Text.Primary"]);
        view.UseLayoutRounding = true;
        TextOptions.SetTextFormattingMode(view, TextFormattingMode.Display);
        return view;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FooterButtonsRouteClicksToBrowserAndCopyWithoutProductServices(bool fail)
    {
        RunOnSta(() =>
        {
            var launches = new List<string>();
            var copies = new List<string>();
            var messages = new List<string>();
            var footer = new BrandSupportFooter(start =>
            {
                launches.Add(start.FileName);
                Assert.True(start.UseShellExecute);
                if (fail) throw new Win32Exception("Test: browser unavailable");
            }, text =>
            {
                copies.Add(text);
                if (fail) throw new Win32Exception("Test: clipboard busy");
            }, messages.Add) { Resources = LoadResources() };
            Assert.Empty(launches);
            Assert.Empty(copies);
            ((Button)footer.FindName("WebsiteButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            ((MenuItem)footer.FindName("CopyWebsiteMenuItem")).RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            Assert.Equal(["https://www.anxinssl.com/code-signing-certificate/"], launches);
            Assert.Equal(["https://www.anxinssl.com/code-signing-certificate/"], copies);
            Assert.Null(footer.FindName("WebsiteText"));
            if (fail)
            {
                Assert.Equal(2, messages.Count);
                Assert.Contains("复制地址", messages[0], StringComparison.Ordinal);
                Assert.Contains("剪贴板", messages[1], StringComparison.Ordinal);
            }
            else
            {
                Assert.Empty(messages);
                Assert.Equal("官网地址已复制", ((MenuItem)footer.FindName("CopyWebsiteMenuItem")).ToolTip);
            }
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BrokenDefaultBrowserUsesExistingEdgeWithoutChangingAssociations(bool fallbackFails)
    {
        RunOnSta(() =>
        {
            var attempts = new List<System.Diagnostics.ProcessStartInfo>();
            var messages = new List<string>();
            const string edge = @"C:\Test Browser\msedge.exe";
            var footer = new BrandSupportFooter(start =>
            {
                attempts.Add(start);
                if (attempts.Count == 1 || fallbackFails) throw new Win32Exception("Test: missing browser");
            }, _ => throw new InvalidOperationException("Opening must not copy"), messages.Add, () => edge);
            ((Button)footer.FindName("WebsiteButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Assert.Equal(2, attempts.Count);
            Assert.Equal("https://www.anxinssl.com/code-signing-certificate/", attempts[0].FileName);
            Assert.Equal(edge, attempts[1].FileName);
            Assert.Equal(["https://www.anxinssl.com/code-signing-certificate/"], attempts[1].ArgumentList);
            Assert.True(attempts[1].UseShellExecute);
            if (fallbackFails)
            {
                Assert.Contains("默认浏览器设置", Assert.Single(messages), StringComparison.Ordinal);
            }
            else
            {
                Assert.Empty(messages);
                Assert.Contains("Microsoft Edge", ((Button)footer.FindName("WebsiteButton")).ToolTip.ToString(), StringComparison.Ordinal);
            }
        });
    }

    [Fact]
    public void BrowserFallbackUsesOnlyAnExistingEdgeExecutable()
    {
        Assert.Null(BrandSupportFooter.FindFallbackBrowser(_ => false));
        string? path = BrandSupportFooter.FindFallbackBrowser(candidate =>
        {
            Assert.True(Path.IsPathFullyQualified(candidate));
            Assert.EndsWith(@"\Microsoft\Edge\Application\msedge.exe", candidate, StringComparison.Ordinal);
            return true;
        });
        Assert.NotNull(path);
    }

    [Theory]
    [InlineData(1180, 940, false, false)]
    [InlineData(1180, 940, true, false)]
    [InlineData(1000, 900, true, false)]
    [InlineData(992, 736, true, true)]
    [InlineData(650, 480, true, false)]
    [InlineData(480, 352, true, false)]
    [InlineData(1180, 1100, true, false)]
    public void PopulatedQueueUsesRealResponsiveLayoutAndScrollsToLastFile(int width, int height, bool dual, bool error)
    {
        RunOnSta(() =>
        {
            var model = new SigningWorkbenchViewModel(
                NoProductServices.Create<IReadinessAdapter>(),
                NoProductServices.Create<IIntakeAdapter>(),
                NoProductServices.Create<IBatchAdapter>(),
                NoProductServices.Create<IOperatorShell>(),
                NoProductServices.Create<IWorkerHealthService>(),
                NoProductServices.Create<IWorkerRepairService>(),
                _ => throw new InvalidOperationException("No repair in layout tests"));
            var window = new MainWindow(model, NoProductServices.Create<IWorkbenchDialogs>(), LoadResources());
            // Never Show or initialize the product. Render only its detached content.
            var content = (Grid)window.Content;
            window.Content = null;
            content.Resources = window.Resources;
            var state = new PreviewState
            {
                IsSingleMode = !dual,
                IsDualMode = dual,
                Rows = Enumerable.Range(1, 20).Select(index => new RowPreview(index)).Cast<object>().ToArray(),
                CurrentItem = error ? new FailurePreview() : null
            };
            state.SecondaryCertificate = state.PrimaryCertificate;
            model.IsDualMode = dual;
            content.DataContext = state;
            window.UpdateResponsiveLayout(width, height);
            var wrapper = new Grid { Background = (Brush)content.Resources["Brush.PageBackground"] };
            wrapper.SetValue(TextElement.FontFamilyProperty, content.Resources["Font.Body"]);
            wrapper.SetValue(TextElement.FontSizeProperty, content.Resources["Typography.Body.Size"]);
            wrapper.SetValue(TextElement.ForegroundProperty, content.Resources["Color.Text.Primary"]);
            wrapper.UseLayoutRounding = true;
            wrapper.Children.Add(content);
            wrapper.Measure(new Size(width, height));
            wrapper.Arrange(new Rect(0, 0, width, height));
            wrapper.UpdateLayout();
            var queue = (DataGrid)window.FindName("QueueGrid");
            var directAdd = (Button)window.FindName("QueueDirectAddButton");
            Assert.Equal(Visibility.Collapsed, directAdd.Visibility);
            Assert.Equal(20, queue.Items.Count);
            var scroll = VisualDescendants(queue).OfType<ScrollViewer>().First();
            Assert.True(scroll.ViewportHeight >= (height >= 700 ? 2 : 1),
                $"Queue viewport {scroll.ViewportHeight} rows at {width}x{height}; grid height {queue.ActualHeight}");
            var first = Assert.IsType<DataGridRow>(queue.ItemContainerGenerator.ContainerFromIndex(0));
            Rect firstBounds = first.TransformToAncestor(queue).TransformBounds(new Rect(first.RenderSize));
            Assert.True(firstBounds.Top >= 0 && firstBounds.Bottom <= queue.ActualHeight,
                $"First file is clipped at {width}x{height}");
            Rect queueBounds = queue.TransformToAncestor(wrapper).TransformBounds(new Rect(queue.RenderSize));
            var action = (FrameworkElement)window.FindName("ActionBand");
            Rect actionBounds = action.TransformToAncestor(wrapper).TransformBounds(new Rect(action.RenderSize));
            Assert.True(queueBounds.Bottom <= actionBounds.Top);
            Assert.True(actionBounds.Bottom <= height);
            SavePreview(wrapper, width, height, $"populated-{width}-{height}-{dual}-{error}.png");
            scroll.ScrollToEnd();
            wrapper.UpdateLayout();
            var last = Assert.IsType<DataGridRow>(queue.ItemContainerGenerator.ContainerFromIndex(19));
            Rect lastBounds = last.TransformToAncestor(queue).TransformBounds(new Rect(last.RenderSize));
            Assert.True(lastBounds.Top >= 0 && lastBounds.Bottom <= queue.ActualHeight,
                $"Last file is clipped at {width}x{height}: {lastBounds}, grid {queue.ActualHeight}");
            Assert.True(scroll.VerticalOffset > 0);
            model.DisposeAsync().AsTask().GetAwaiter().GetResult();
        });
    }

    private static IEnumerable<DependencyObject> VisualDescendants(DependencyObject parent)
    {
        for (int index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, index);
            yield return child;
            foreach (DependencyObject descendant in VisualDescendants(child)) yield return descendant;
        }
    }

    public class NoProductServices : DispatchProxy
    {
        internal static T Create<T>() where T : class => Create<T, NoProductServices>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name.StartsWith("add_", StringComparison.Ordinal) ||
                targetMethod.Name.StartsWith("remove_", StringComparison.Ordinal) ||
                targetMethod.Name == "Dispose") return null;
            if (targetMethod.Name == "DisposeAsync") return ValueTask.CompletedTask;
            throw new InvalidOperationException($"Layout test invoked product service: {targetMethod.Name}");
        }
    }

    private static T Find<T>(DependencyObject root, string name) where T : FrameworkElement
    {
        if (root is T element && element.Name == name) return element;
        foreach (object child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is DependencyObject dependency && TryFind<T>(dependency, name) is T match) return match;
        }
        throw new InvalidOperationException($"Missing view element: {name}");
    }

    private static T? TryFind<T>(DependencyObject root, string name) where T : FrameworkElement
    {
        if (root is T element && element.Name == name) return element;
        foreach (object child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is DependencyObject dependency && TryFind<T>(dependency, name) is T match) return match;
        }
        return null;
    }

    private static ResourceDictionary LoadResources() => (ResourceDictionary)Application.LoadComponent(
        new Uri("/CodeSigner.App;component/Themes/DesignTokens.xaml", UriKind.Relative));

    private static void RunOnSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception exception) { failure = exception; }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Offscreen view test exceeded its time limit.");
        if (failure is not null) throw new InvalidOperationException("Offscreen view test failed.", failure);
    }

    private static string FindRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln"))) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException();
    }

    public sealed class PreviewState
    {
        public string WorkstationStatus { get; } = "Windows x64 支持";
        public string NativeApiStatus { get; } = "PE 双签可用；Windows 单签可用";
        public string SimplySignStatus { get; } = "SimplySign 已安装";
        public bool MissingCertificate { get; set; }
        public string CertificateStatus => MissingCertificate ? "未发现可用证书" : "已读取 1 张代码签名证书";
        public string CertificatePreparationHint => MissingCertificate
            ? "未发现可用的代码签名证书。云证书请检查 SimplySign 等对应客户端的登录状态；硬件 UKey 请检查 SafeNet 等驱动是否识别到设备和证书，然后重新刷新。"
            : "云证书请先登录对应客户端；硬件 UKey 请先插入设备并确认驱动已识别。准备完成后，点击“刷新证书”，读取到有效证书后再签名。";
        public string TimestampStatus { get; } = "时间戳已配置";
        public string SdkSignToolStatusText { get; } = "尚未检测";
        public string StatusMessage { get; } = "就绪";
        public string CurrentFileStatusText { get; } = "请选择一个签名文件项目";
        public string QueueStatusText => Rows.Length == 0 ? "队列中没有待签文件" : $"{Rows.Length} 个签名文件等待处理";
        public string SignButtonText { get; } = "签名";
        public string InputError { get; } = "";
        public string OutputError { get; } = "";
        public string OutputRoot { get; set; } = "";
        public bool IsBusy { get; }
        public bool IsWorkerRecoveryVisible { get; }
        public bool CanEditConfiguration { get; } = true;
        public bool IsSingleMode { get; set; } = true;
        public bool IsDualMode { get; set; }
        public bool CanSign { get; }
        public object[] Rows { get; set; } = [];
        public FailurePreview? CurrentItem { get; set; }
        public CertificatePreview PrimaryCertificate { get; set; } = new();
        public CertificatePreview SecondaryCertificate { get; set; } = new();
        public CertificatePreview[] Certificates => [PrimaryCertificate];
    }

    public sealed class RowPreview(int index)
    {
        public string FullPath => $@"D:\待签名文件\客户软件安装程序-{index:00}-long-file-name.msi";
        public string FormatText { get; } = "MSI 安装包";
        public string EngineText { get; } = "Windows SIP";
        public string EffectivePolicyText { get; } = "SHA-256 单签";
        public string StateText { get; } = "等待签名";
        public int ProgressPercent { get; }
        public string ResultText { get; } = "尚未开始";
        public string AutomationId => $"row-{index}";
        public string AutomationName => FullPath;
        public string RemoveAutomationId => $"remove-{index}";
        public string DetailText { get; } = "";
    }

    public sealed class FailurePreview
    {
        public string DetailText { get; } = ViewModels.QueueItemViewModel.OutputSaveRecoveryMessage;
    }

    public sealed class CertificatePreview
    {
        public string Subject { get; } = "CN=示例软件有限公司";
        public string Issuer { get; } = "示例代码签名 CA";
        public string Expiry { get; } = "2027-09-17";
        public string Store { get; } = "当前用户 / My";
        public string Thumbprint { get; } = "0123456789ABCDEF0123456789ABCDEF01234567";
        public string DisplayName => Subject;
        public string AutomationName => Subject;
    }
}
