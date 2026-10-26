using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using CodeSigner.App.ViewModels;

namespace CodeSigner.App;

public partial class SettingsWindow : Window
{
    private const string ProductCodeMetadataKey = "CodeSignerProductCode";
    private readonly SigningWorkbenchViewModel viewModel;

    internal static string ProductVersionDisplayText
    {
        get
        {
            AssemblyInformationalVersionAttribute metadata =
                typeof(SettingsWindow).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?? throw new InvalidOperationException("CodeSigner informational version metadata is missing.");
            return $"安信代码签名证书工具 v{metadata.InformationalVersion}";
        }
    }

    internal static string InstalledProductCode
    {
        get
        {
            AssemblyMetadataAttribute metadata = typeof(SettingsWindow).Assembly
                .GetCustomAttributes<AssemblyMetadataAttribute>()
                .Single(attribute => string.Equals(
                    attribute.Key,
                    ProductCodeMetadataKey,
                    StringComparison.Ordinal));
            return metadata.Value
                ?? throw new InvalidOperationException("CodeSigner ProductCode metadata is empty.");
        }
    }

    public SettingsWindow(SigningWorkbenchViewModel viewModel)
    {
        this.viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        InitializeComponent();
        DataContext = viewModel;
        ProductVersionText.Text = ProductVersionDisplayText;
        TimestampUriTextBox.Text = viewModel.TimestampUri.OriginalString;
        RetentionComboBox.ItemsSource = new[] { 7, 30, 90 };
        RetentionComboBox.SelectedItem = viewModel.DiagnosticRetentionDays;
        Loaded += OnLoaded;
        ContentRendered += OnContentRendered;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        TimestampUriTextBox.Focus();
        TimestampUriTextBox.SelectAll();
    }

    private void OnContentRendered(object? sender, EventArgs e)
    {
        Activate();
        Topmost = true;
        Topmost = false;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        int retentionDays = RetentionComboBox.SelectedItem is int selected ? selected : 0;
        if (!viewModel.ApplySettings(TimestampUriTextBox.Text, retentionDays))
        {
            ValidationText.Text = viewModel.SettingsValidationError;
            if (string.Equals(
                viewModel.FocusTargetAutomationId,
                "SettingsTimestampUri",
                StringComparison.Ordinal))
            {
                TimestampUriTextBox.Focus();
            }
            else
            {
                RetentionComboBox.Focus();
            }

            return;
        }

        DialogResult = true;
    }

    private void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        MessageBoxResult result = MessageBox.Show(
            "确定要卸载安信代码签名证书工具吗？\n\n此操作将移除程序，保留您的原文件和签名输出。",
            "确认卸载",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            Process.Start(CreateUninstallStartInfo());
            Application.Current.Shutdown();
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                $"无法启动卸载程序：{exception.Message}",
                "卸载错误",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    internal static ProcessStartInfo CreateUninstallStartInfo()
    {
        return Services.NsisMaintenance.CreateUninstallStartInfo();
    }
}
