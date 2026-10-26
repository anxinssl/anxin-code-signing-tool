using System.ComponentModel;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;

namespace CodeSigner.App;

public partial class MainWindow : Window
{
    private const double CompactWidth = 900;
    private const double CompactHeight = 620;
    private const double CondensedHeight = 1000;

    private readonly SigningWorkbenchViewModel viewModel;
    private readonly IWorkbenchDialogs dialogs;
    private readonly QueueGridSelectionSynchronizer queueSelectionSynchronizer;
    private bool closeAfterCancellation;
    private bool isDisposed;
    private bool? summaryUsesCurrentFileStatus;

    public MainWindow()
        : this(ProductionComposition.CreateViewModel(), new WindowsWorkbenchDialogs())
    {
    }

    public MainWindow(SigningWorkbenchViewModel viewModel, IWorkbenchDialogs? dialogs = null)
        : this(viewModel, dialogs, null)
    {
    }

    internal MainWindow(SigningWorkbenchViewModel viewModel, IWorkbenchDialogs? dialogs, ResourceDictionary? resources)
    {
        this.viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        this.dialogs = dialogs ?? new WindowsWorkbenchDialogs();
        if (resources is not null)
        {
            Resources.MergedDictionaries.Add(resources);
        }
        InitializeComponent();
        queueSelectionSynchronizer = new QueueGridSelectionSynchronizer(QueueGrid, viewModel);
        DataContext = viewModel;
        Loaded += OnLoaded;
        SizeChanged += OnSizeChanged;
        Closing += OnClosing;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    public bool IsCompactLayout { get; private set; }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Rect workArea = SystemParameters.WorkArea;
        MaxWidth = workArea.Width;
        MaxHeight = workArea.Height;
        Width = Math.Min(Width, workArea.Width);
        Height = Math.Min(Height, workArea.Height);
        Left = Math.Max(workArea.Left, Math.Min(Left, workArea.Right - Width));
        Top = Math.Max(workArea.Top, Math.Min(Top, workArea.Bottom - Height));
        UpdateResponsiveLayout();
        await viewModel.InitializeAsync();
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e) => UpdateResponsiveLayout();

    private void UpdateResponsiveLayout() => UpdateResponsiveLayout(ActualWidth, ActualHeight);

    internal void UpdateResponsiveLayout(double width, double height)
    {
        bool compact = width < CompactWidth || height < CompactHeight;
        bool ultraCompact = compact && (width < 560 || height < 420);
        bool heightCondensed = height < CondensedHeight;
        bool condensedCertificateSelection = compact || heightCondensed;
        bool useCondensedActionRail = compact || heightCondensed;
        IsCompactLayout = compact;
        UpdateSummaryBindings(useCondensedActionRail);
        Visibility statusVisibility = compact ? Visibility.Collapsed : Visibility.Visible;
        RootGrid.Margin = compact ? new Thickness(0) : new Thickness(16);
        AppHeader.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        AppHeader.Margin = heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 12);
        WorkstationStatusText.Visibility = statusVisibility;
        NativeApiStatusText.Visibility = statusVisibility;
        CertificateStatusText.Visibility = statusVisibility;
        TimestampStatusText.Visibility = statusVisibility;
        CertificateDetailsPanel.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        ConfigurationColumn.Width = new GridLength(1, GridUnitType.Star);
        DetailsColumn.Width = compact ? new GridLength(0) : new GridLength(400);
        Grid.SetColumn(ConfigurationPanel, compact ? 0 : 1);
        Grid.SetColumnSpan(ConfigurationPanel, compact ? 2 : 1);
        ConfigurationPanel.Margin = compact ? new Thickness(0) : new Thickness(16, 0, 0, 0);
        ReadinessBand.Padding = compact ? new Thickness(8, 4, 8, 4) : new Thickness(12, 8, 12, 8);
        ReadinessBand.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;
        ReadinessBand.Margin = compact
            ? new Thickness(0, 0, 0, 4)
            : heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 12);
        CommandBand.Padding = compact ? new Thickness(8, 4, 8, 4) : new Thickness(12, 6, 12, 6);
        CommandBand.Margin = compact
            ? new Thickness(0, 0, 0, 4)
            : heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 12);
        CommandActionsPanel.Visibility = Visibility.Visible;
        bool showExtendedActions = width >= 1000;
        ExtendedActionsPanel.Visibility = showExtendedActions ? Visibility.Visible : Visibility.Collapsed;
        Visibility overflowVisibility = showExtendedActions ? Visibility.Collapsed : Visibility.Visible;
        OverflowRemove.Visibility = overflowVisibility;
        OverflowRetry.Visibility = overflowVisibility;
        OverflowOutput.Visibility = overflowVisibility;
        OverflowSeparator.Visibility = overflowVisibility;
        CertificateRefreshHint.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;
        CertificateRefreshHint.Height = 36;
        OutputLocationHint.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;
        ConfigurationBand.Padding = new Thickness(0);
        ConfigurationBand.Height = ultraCompact ? 78 : compact ? 84 : heightCondensed ? 128 : 260;
        ConfigurationBand.Margin = compact
            ? new Thickness(0, 0, 0, 4)
            : heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 8);
        CertificateDetailsContent.Margin = compact
            ? new Thickness(0)
            : heightCondensed ? new Thickness(8) : new Thickness(14);
        ConfigurationContent.Margin = ultraCompact
            ? new Thickness(6, 0, 6, 0)
            : compact ? new Thickness(8, 4, 8, 4)
            : heightCondensed ? new Thickness(10) : new Thickness(14);
        ActionBand.Padding = ultraCompact
            ? new Thickness(0)
            : useCondensedActionRail ? new Thickness(8, 4, 8, 4) : new Thickness(12, 8, 12, 8);
        ActionBand.Margin = compact
            ? new Thickness(0, 0, 0, 4)
            : heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 8);
        SummaryBand.Padding = ultraCompact
            ? new Thickness(6, 2, 6, 2)
            : compact ? new Thickness(8, 2, 8, 2) : new Thickness(12, 6, 12, 6);
        SummaryBand.Margin = compact
            ? new Thickness(0)
            : heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 8);
        QueueRegion.Margin = compact
            ? new Thickness(0, 0, 0, 4)
            : heightCondensed ? new Thickness(0, 0, 0, 4) : new Thickness(0, 0, 0, 12);
        QueueHeader.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;
        QueueHeader.Margin = compact || heightCondensed
            ? new Thickness(0, 0, 0, 4)
            : new Thickness(0, 0, 0, 6);
        QueueGrid.Height = double.NaN;
        QueueBody.Height = double.NaN;
        QueueHeading.Margin = compact ? new Thickness(0) : new Thickness(0, 0, 0, 4);
        QueueHeading.FontSize = compact ? 14 : 16;
        FullActionRail.Visibility = useCondensedActionRail ? Visibility.Collapsed : Visibility.Visible;
        CompactActionRail.Visibility = useCondensedActionRail ? Visibility.Visible : Visibility.Collapsed;
        Grid.SetRow(WorkerRecoveryActionsPanel, compact ? 1 : 0);
        Grid.SetColumn(WorkerRecoveryActionsPanel, compact ? 0 : 1);
        Grid.SetColumnSpan(WorkerRecoveryActionsPanel, compact ? 2 : 1);
        WorkerRecoveryActionsPanel.Margin = compact
            ? new Thickness(0, 4, 0, 0)
            : new Thickness(12, 0, 0, 0);
        WorkerRecoveryActionsPanel.HorizontalAlignment = compact
            ? HorizontalAlignment.Left
            : HorizontalAlignment.Right;
        Grid.SetColumnSpan(WorkerRecoveryMessageText, compact ? 2 : 1);
        SigningPolicyHeading.Visibility = statusVisibility;
        PrimaryCertificateLabel.Visibility = condensedCertificateSelection ? Visibility.Collapsed : Visibility.Visible;
        SecondaryCertificateLabel.Visibility = !condensedCertificateSelection && viewModel.IsDualMode
            ? Visibility.Visible
            : Visibility.Collapsed;
        SecondaryCertificateLabel.Margin = condensedCertificateSelection ? new Thickness(0) : new Thickness(0, 8, 0, 0);
        SigningModePanel.Margin = compact ? new Thickness(0) : new Thickness(0, 6, 0, 0);
        PrimaryCertificateCombo.Margin = ultraCompact
            ? new Thickness(0)
            : condensedCertificateSelection ? new Thickness(0, 4, 4, 0) : new Thickness(0, 4, 0, 0);
        SecondaryCertificateCombo.Margin = ultraCompact
            ? new Thickness(4, 0, 0, 0)
            : condensedCertificateSelection ? new Thickness(4, 4, 0, 0) : new Thickness(0, 4, 0, 0);
        PrimaryCertificateCombo.MinWidth = condensedCertificateSelection ? 0 : 320;
        SecondaryCertificateCombo.MinWidth = condensedCertificateSelection ? 0 : 320;
        Grid.SetRow(SigningModePanel, compact ? 0 : 1);
        Grid.SetRow(PrimaryCertificateCombo, compact ? 1 : heightCondensed ? 2 : 3);
        Grid.SetRow(SecondaryCertificateCombo, condensedCertificateSelection ? (compact ? 1 : 2) : 5);
        Grid.SetColumn(PrimaryCertificateCombo, 0);
        Grid.SetColumn(SecondaryCertificateCombo, condensedCertificateSelection ? 1 : 0);
        Grid.SetColumnSpan(SecondaryCertificateCombo, condensedCertificateSelection ? 1 : 2);
        QueueGrid.RowHeight = compact && !ultraCompact ? 46 : 50;
        QueueGrid.ColumnHeaderHeight = compact && !ultraCompact ? 34 : 36;
        QueueGrid.ColumnHeaderStyle = compact
            ? (Style)FindResource("CompactQueueHeaderStyle")
            : null;
        Style? compactCellStyle = compact
            ? (Style)FindResource("CompactQueueCellTextStyle")
            : null;
        FormatColumn.ElementStyle = compactCellStyle;
        EngineColumn.ElementStyle = compactCellStyle;
        PolicyColumn.ElementStyle = compactCellStyle;
        StateColumn.ElementStyle = compactCellStyle;
        FileColumn.MinWidth = compact ? 128 : 180;
        FileColumn.Width = compact ? new DataGridLength(128) : new DataGridLength(2, DataGridLengthUnitType.Star);
        FormatColumn.MinWidth = compact ? 70 : 112;
        FormatColumn.Width = compact ? new DataGridLength(70) : new DataGridLength(132);
        EngineColumn.MinWidth = compact ? 76 : 108;
        EngineColumn.Width = compact ? new DataGridLength(76) : new DataGridLength(124);
        PolicyColumn.MinWidth = compact ? 64 : 108;
        PolicyColumn.Width = compact ? new DataGridLength(64) : new DataGridLength(124);
        StateColumn.MinWidth = compact ? 52 : 20;
        StateColumn.Width = compact ? new DataGridLength(52) : new DataGridLength(144);
        ProgressColumn.MinWidth = compact ? 74 : 20;
        ProgressColumn.Width = compact ? new DataGridLength(74) : new DataGridLength(136);
        ResultColumn.MinWidth = compact ? 92 : 180;
        CompactProgress.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;
        CompactOpenOutputButton.Visibility = ultraCompact ? Visibility.Collapsed : Visibility.Visible;
        UltraCommandButtons.Visibility = Visibility.Collapsed;
        UpdateCertificateColumnSpan(height);
        AutomationProperties.SetHelpText(
            this,
            FormattableString.Invariant(
                $"布局：{(compact ? "紧凑" : "完整")}；当前大小 {ActualWidth:0.##} × {ActualHeight:0.##} DIP"));
    }

    private void UpdateCertificateColumnSpan() => UpdateCertificateColumnSpan(ActualHeight);

    private void UpdateCertificateColumnSpan(double height)
    {
        bool sideBySideCertificateSelection = IsCompactLayout || height < CondensedHeight;
        Grid.SetColumnSpan(
            PrimaryCertificateCombo,
            sideBySideCertificateSelection && viewModel.IsDualMode ? 1 : 2);
        SecondaryCertificateLabel.Visibility = !IsCompactLayout && height >= CondensedHeight && viewModel.IsDualMode
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private async void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        IReadOnlyList<string> paths = dialogs.PickExeFiles(this);
        if (paths.Count > 0)
        {
            await viewModel.QueueFilesAsync(paths);
        }
    }

    private async void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        string? path = dialogs.PickInputFolder(this);
        if (path is not null)
        {
            await viewModel.QueueFolderAsync(path);
        }
    }

    private async void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        string? path = dialogs.PickOutputRoot(this, viewModel.OutputRoot);
        if (path is not null)
        {
            await viewModel.ReplanOutputRootAsync(path);
        }
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new SettingsWindow(viewModel) { Owner = this };
            dialog.ShowDialog();
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                $"无法打开签名设置：{exception.Message}",
                "安信代码签名证书工具",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            if (IsLoaded)
            {
                SettingsButton.Focus();
            }
        }
    }

    private async void OutputRootTextBox_LostKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (sender is not TextBox outputRootTextBox ||
            !string.Equals(viewModel.OutputRoot, outputRootTextBox.Text, StringComparison.Ordinal))
        {
            return;
        }

        await viewModel.ReplanOutputRootAsync(outputRootTextBox.Text);
    }

    private void Window_PreviewDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths)
        {
            await viewModel.QueueDroppedInputsAsync(paths);
        }
    }

    private async void QueueGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        await queueSelectionSynchronizer.SynchronizeAsync(Keyboard.Modifiers);
    }

    private void UpdateSummaryBindings(bool compact)
    {
        if (summaryUsesCurrentFileStatus == compact)
        {
            return;
        }

        summaryUsesCurrentFileStatus = compact;
        string propertyName = compact
            ? nameof(SigningWorkbenchViewModel.QueueStatusText)
            : nameof(SigningWorkbenchViewModel.StatusMessage);
        SummaryRegion.SetBinding(TextBlock.TextProperty, new Binding(propertyName));
        SummaryRegion.SetBinding(ToolTipProperty, new Binding(propertyName));
        BindingOperations.SetBinding(
            SummaryRegion,
            AutomationProperties.NameProperty,
            new Binding(propertyName));
    }

    private async void QueueGrid_CurrentCellChanged(object? sender, EventArgs e)
    {
        await queueSelectionSynchronizer.SynchronizeAsync(Keyboard.Modifiers);
    }

    private async void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        Key key = e.Key == Key.System ? e.SystemKey : e.Key;
        ModifierKeys modifiers = Keyboard.Modifiers;
        if (key == Key.Delete && QueueGrid.IsKeyboardFocusWithin)
        {
            viewModel.RemoveSelected();
            e.Handled = true;
        }
        else if (key == Key.F5)
        {
            await viewModel.RefreshReadinessAsync();
            e.Handled = true;
        }
        else if (key == Key.O && modifiers == ModifierKeys.Control)
        {
            AddFilesButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            e.Handled = true;
        }
        else if (key == Key.O && modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            AddFolderButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            e.Handled = true;
        }
        else if (key == Key.R && modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            await ((IAsyncCommand)viewModel.RefreshWorkerCommand).ExecuteAsync(null);
            e.Handled = true;
        }
        else if (key == Key.W && modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            await ((IAsyncCommand)viewModel.RepairWorkerCommand).ExecuteAsync(null);
            e.Handled = true;
        }
        else if (key == Key.R && modifiers == ModifierKeys.Control)
        {
            await ((IAsyncCommand)viewModel.RetryCommand).ExecuteAsync(null);
            e.Handled = true;
        }
        else if (key == Key.E && modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            await ((IAsyncCommand)viewModel.ExportDiagnosticsCommand).ExecuteAsync(null);
            e.Handled = true;
        }
        else if (key == Key.A && modifiers == ModifierKeys.Alt)
        {
            AddFilesButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            e.Handled = true;
        }
        else if (key == Key.L && modifiers == ModifierKeys.Alt)
        {
            AddFolderButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            e.Handled = true;
        }
        else if (key == Key.O && modifiers == ModifierKeys.Alt)
        {
            BrowseOutput_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (key == Key.G && modifiers == ModifierKeys.Alt)
        {
            Settings_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (key == Key.S && modifiers == ModifierKeys.Alt)
        {
            await ((IAsyncCommand)viewModel.SignCommand).ExecuteAsync(null);
            e.Handled = true;
        }
        else if (key == Key.Escape && viewModel.IsBusy)
        {
            await viewModel.CancelAsync();
            e.Handled = true;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(
            e.PropertyName,
            nameof(SigningWorkbenchViewModel.CurrentItem),
            StringComparison.Ordinal))
        {
            queueSelectionSynchronizer.SynchronizeCurrentItem();
        }

        if (string.Equals(e.PropertyName, nameof(SigningWorkbenchViewModel.IsDualMode), StringComparison.Ordinal))
        {
            UpdateCertificateColumnSpan();
        }

        if (!string.Equals(
            e.PropertyName,
            nameof(SigningWorkbenchViewModel.FocusTargetAutomationId),
            StringComparison.Ordinal))
        {
            return;
        }

        string target = viewModel.FocusTargetAutomationId;
        if (string.IsNullOrEmpty(target))
        {
            return;
        }

        Dispatcher.BeginInvoke(
            DispatcherPriority.Input,
            () => FocusAutomationTarget(target));
    }

    private void FocusAutomationTarget(string automationId)
    {
        if (IsLoaded && automationId == "OpenLogDirectoryButton")
        {
            ToolbarMore.IsSubmenuOpen = true;
            OpenLogDirectoryButton.Focus();
            return;
        }
        QueueItemViewModel? row = viewModel.Rows.FirstOrDefault(
            candidate => string.Equals(candidate.AutomationId, automationId, StringComparison.Ordinal));
        if (row is not null)
        {
            QueueGrid.SelectedItem = row;
            QueueGrid.ScrollIntoView(row);
            QueueGrid.UpdateLayout();
            if (QueueGrid.ItemContainerGenerator.ContainerFromItem(row) is DataGridRow container)
            {
                container.Focus();
            }

            return;
        }

        if (FindAutomationElement(this, automationId) is FrameworkElement element)
        {
            element.Focus();
        }
    }

    private static FrameworkElement? FindAutomationElement(DependencyObject parent, string automationId)
    {
        int childCount = VisualTreeHelper.GetChildrenCount(parent);
        for (int index = 0; index < childCount; index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, index);
            if (child is FrameworkElement element && element.IsVisible && string.Equals(
                AutomationProperties.GetAutomationId(element),
                automationId,
                StringComparison.Ordinal))
            {
                return element;
            }

            FrameworkElement? descendant = FindAutomationElement(child, automationId);
            if (descendant is not null)
            {
                return descendant;
            }
        }

        return null;
    }

    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!viewModel.CanClose)
        {
            e.Cancel = true;
            return;
        }

        if (!viewModel.IsBusy || closeAfterCancellation)
        {
            return;
        }

        e.Cancel = true;
        await viewModel.CancelAsync();
        closeAfterCancellation = true;
        Close();
    }

    protected override async void OnClosed(EventArgs e)
    {
        viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        if (!isDisposed)
        {
            isDisposed = true;
            await viewModel.DisposeAsync();
        }

        base.OnClosed(e);
    }
}

internal sealed class QueueGridSelectionSynchronizer(
    DataGrid queueGrid,
    SigningWorkbenchViewModel viewModel)
{
    private long selectionGeneration;
    private bool isRestoringSelection;

    internal void SynchronizeCurrentItem()
    {
        if (isRestoringSelection)
        {
            return;
        }

        Interlocked.Increment(ref selectionGeneration);
        QueueItemViewModel? intended = viewModel.CurrentItem;
        if (ReferenceEquals(queueGrid.SelectedItem, intended) &&
            ReferenceEquals(queueGrid.CurrentItem, intended))
        {
            return;
        }

        QueueItemViewModel[] selectedRows = queueGrid.SelectedItems
            .OfType<QueueItemViewModel>()
            .Where(viewModel.Rows.Contains)
            .ToArray();
        isRestoringSelection = true;
        try
        {
            queueGrid.SelectedItem = intended;
            queueGrid.CurrentItem = intended;
            if (intended is not null)
            {
                foreach (QueueItemViewModel row in selectedRows)
                {
                    if (!ReferenceEquals(row, intended) && !queueGrid.SelectedItems.Contains(row))
                    {
                        queueGrid.SelectedItems.Add(row);
                    }
                }
            }

            SynchronizeMembership();
        }
        finally
        {
            isRestoringSelection = false;
        }
    }

    internal async Task SynchronizeAsync(ModifierKeys modifiers)
    {
        if (isRestoringSelection)
        {
            return;
        }

        long generation = Interlocked.Increment(ref selectionGeneration);
        SynchronizeMembership();
        if (IsMembershipOnly(modifiers))
        {
            return;
        }

        QueueItemViewModel? intended = queueGrid.SelectedItem as QueueItemViewModel;
        await viewModel.SetCurrentItemAsync(intended?.ItemId);
        if (generation != Volatile.Read(ref selectionGeneration))
        {
            return;
        }

        if (ReferenceEquals(viewModel.CurrentItem, intended))
        {
            queueGrid.CurrentItem = intended;
            return;
        }

        isRestoringSelection = true;
        try
        {
            queueGrid.SelectedItem = viewModel.CurrentItem;
            queueGrid.CurrentItem = viewModel.CurrentItem;
            SynchronizeMembership();
        }
        finally
        {
            isRestoringSelection = false;
        }
    }

    private void SynchronizeMembership()
    {
        foreach (QueueItemViewModel row in viewModel.Rows)
        {
            row.IsSelected = queueGrid.SelectedItems.Contains(row);
        }

        viewModel.RemoveCommand.RaiseCanExecuteChanged();
    }

    internal static bool IsMembershipOnly(ModifierKeys modifiers) =>
        (modifiers & (ModifierKeys.Control | ModifierKeys.Shift)) != ModifierKeys.None;
}
