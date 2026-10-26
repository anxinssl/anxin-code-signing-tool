using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace CodeSigner.App;

public partial class BrandSupportFooter : UserControl
{
    private const string WebsiteAddress = "https://www.anxinssl.com/code-signing-certificate/";
    private readonly Action<ProcessStartInfo> openWebsite;
    private readonly Action<string> copyAddress;
    private readonly Action<string> showMessage;
    private readonly Func<string?> findFallbackBrowser;

    public BrandSupportFooter() : this(
        start => Process.Start(start)?.Dispose(),
        text => Clipboard.SetText(text),
        null,
        () => FindFallbackBrowser(File.Exists))
    {
    }

    internal BrandSupportFooter(
        Action<ProcessStartInfo> openWebsite,
        Action<string> copyAddress,
        Action<string>? showMessage,
        Func<string?>? findFallbackBrowser = null)
    {
        this.openWebsite = openWebsite;
        this.copyAddress = copyAddress;
        this.findFallbackBrowser = findFallbackBrowser ?? (() => null);
        this.showMessage = showMessage ?? (message => MessageBox.Show(
            Window.GetWindow(this), message, "安信官网",
            MessageBoxButton.OK, MessageBoxImage.Information));
        InitializeComponent();
        // A detached popup keeps its keyboard input out of workbench shortcuts.
        SupportBar.Children.Remove(SupportPopup);
        SupportPopup.PlacementTarget = SupportButton;
    }

    internal static ProcessStartInfo CreateWebsiteStartInfo() => new(WebsiteAddress)
    {
        UseShellExecute = true,
    };

    internal static string? FindFallbackBrowser(Func<string, bool> fileExists)
    {
        string[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        ];
        return roots.Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(root => Path.Combine(root, "Microsoft", "Edge", "Application", "msedge.exe"))
            .FirstOrDefault(fileExists);
    }

    private void Website_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        try
        {
            openWebsite(CreateWebsiteStartInfo());
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            // A removed browser can leave a broken HTTPS association behind.
            string? fallback = findFallbackBrowser();
            if (fallback is not null)
            {
                try
                {
                    var start = new ProcessStartInfo(fallback) { UseShellExecute = true };
                    start.ArgumentList.Add(WebsiteAddress);
                    openWebsite(start);
                    WebsiteButton.ToolTip = "默认浏览器不可用，已使用 Microsoft Edge 打开安信官网";
                    return;
                }
                catch (Exception fallbackException) when (fallbackException is Win32Exception or InvalidOperationException)
                {
                    // Preserve the address even when all browser launch attempts fail.
                }
            }
            showMessage("无法启动浏览器。请检查 Windows 的默认浏览器设置，或右键“安信官网”复制地址，在浏览器中访问：" + WebsiteAddress);
        }
    }

    private void CopyWebsite_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        CopyWebsiteAddress(WebsiteAddress);
    }

    private void CopyWebsiteAddress(string text)
    {
        try
        {
            copyAddress(text);
            CopyWebsiteMenuItem.ToolTip = "官网地址已复制";
        }
        catch (Exception exception) when (exception is ExternalException or InvalidOperationException)
        {
            CopyWebsiteMenuItem.ToolTip = "复制官网地址";
            showMessage("暂时无法写入剪贴板，请稍后重试，或手动输入：" + WebsiteAddress);
        }
    }

    private void Support_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        SupportPopup.IsOpen = !SupportPopup.IsOpen;
    }

    private void Footer_SizeChanged(object sender, SizeChangedEventArgs e) =>
        SupportHint.Visibility = ActualWidth >= 720 ? Visibility.Visible : Visibility.Collapsed;

    private void SupportPopup_Opened(object? sender, EventArgs e) => CloseSupportButton.Focus();

    private void CloseSupport_Click(object sender, RoutedEventArgs e) => CloseSupport();

    private void SupportPanel_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            e.Handled = true;
            CloseSupport();
        }
    }

    private void CloseSupport()
    {
        SupportPopup.IsOpen = false;
        SupportButton.Focus();
    }

    private void Footer_Unloaded(object sender, RoutedEventArgs e) => SupportPopup.IsOpen = false;
}
