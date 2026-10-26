using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows.Input;
using CodeSigner.App.ViewModels;
using DataGrid = System.Windows.Controls.DataGrid;
using DataGridSelectionMode = System.Windows.Controls.DataGridSelectionMode;
using DataGridSelectionUnit = System.Windows.Controls.DataGridSelectionUnit;

namespace CodeSigner.App.Tests;

public sealed partial class FileTaskQueueStateMachineTests
{
    [Fact]
    public void WpfSelectionViewModelFirstAddSynchronizesLiveGridCurrentAndSelectedItem()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);
            viewModel.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(SigningWorkbenchViewModel.CurrentItem))
                {
                    synchronizer.SynchronizeCurrentItem();
                }
            };

            Assert.Null(grid.SelectedItem);
            Assert.Null(grid.CurrentItem);

            await viewModel.QueueFilesAsync([@"C:\queue\first.exe"]);

            QueueItemViewModel first = Assert.Single(viewModel.Rows);
            Assert.Same(first, viewModel.CurrentItem);
            Assert.Same(first, grid.SelectedItem);
            Assert.Same(first, grid.CurrentItem);
            Assert.Equal(0, batch.ProductionCalls);
        });
    }

    [Fact]
    public void WpfSelectionViewModelCurrentRemovalSynchronizesLiveGridNextPreviousAndNull()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);
            viewModel.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(SigningWorkbenchViewModel.CurrentItem))
                {
                    synchronizer.SynchronizeCurrentItem();
                }
            };
            int nestedSelectionEvents = 0;
            grid.SelectionChanged += (_, _) => nestedSelectionEvents++;

            await viewModel.QueueFilesAsync(
                [@"C:\queue\first.exe", @"C:\queue\second.exe", @"C:\queue\third.exe"]);
            QueueItemViewModel first = viewModel.Rows[0];
            QueueItemViewModel second = viewModel.Rows[1];
            QueueItemViewModel third = viewModel.Rows[2];

            await viewModel.SetCurrentItemAsync(second.ItemId);
            viewModel.RemoveQueueItemCommand.Execute(second);

            Assert.Same(third, viewModel.CurrentItem);
            Assert.Same(third, grid.SelectedItem);
            Assert.Same(third, grid.CurrentItem);
            Assert.DoesNotContain(second, grid.SelectedItems.Cast<QueueItemViewModel>());

            viewModel.RemoveQueueItemCommand.Execute(third);

            Assert.Same(first, viewModel.CurrentItem);
            Assert.Same(first, grid.SelectedItem);
            Assert.Same(first, grid.CurrentItem);
            Assert.DoesNotContain(third, grid.SelectedItems.Cast<QueueItemViewModel>());

            viewModel.RemoveQueueItemCommand.Execute(first);

            Assert.Null(viewModel.CurrentItem);
            Assert.Null(grid.SelectedItem);
            Assert.Null(grid.CurrentItem);
            Assert.Empty(grid.SelectedItems.Cast<QueueItemViewModel>());
            Assert.InRange(nestedSelectionEvents, 1, 8);
            Assert.Equal(0, batch.ProductionCalls);
        });
    }

    [Fact]
    public void WpfSelectionViewModelCurrentSynchronizationPreservesCtrlMembershipAndConvergesRapidChanges()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);
            viewModel.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(SigningWorkbenchViewModel.CurrentItem))
                {
                    synchronizer.SynchronizeCurrentItem();
                }
            };

            await viewModel.QueueFilesAsync(
                [@"C:\queue\first.exe", @"C:\queue\second.exe", @"C:\queue\third.exe"]);
            QueueItemViewModel first = viewModel.Rows[0];
            QueueItemViewModel second = viewModel.Rows[1];
            QueueItemViewModel third = viewModel.Rows[2];

            grid.SelectedItems.Add(second);
            await synchronizer.SynchronizeAsync(ModifierKeys.Control);

            Assert.Same(first, viewModel.CurrentItem);
            Assert.Contains(second, grid.SelectedItems.Cast<QueueItemViewModel>());

            await viewModel.SetCurrentItemAsync(third.ItemId);
            await viewModel.SetCurrentItemAsync(second.ItemId);
            await viewModel.SetCurrentItemAsync(first.ItemId);

            Assert.Same(first, viewModel.CurrentItem);
            Assert.Same(first, grid.SelectedItem);
            Assert.Same(first, grid.CurrentItem);
            Assert.Contains(second, grid.SelectedItems.Cast<QueueItemViewModel>());
            Assert.Equal(0, batch.ProductionCalls);
        });
    }

    [Fact]
    public void WpfSelectionCtrlAndShiftChangeMembershipWithoutChangingCurrentItem()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            await viewModel.QueueFilesAsync(
                [@"C:\queue\first.exe", @"C:\queue\second.exe", @"C:\queue\third.exe"]);
            QueueItemViewModel first = viewModel.Rows[0];
            QueueItemViewModel second = viewModel.Rows[1];
            QueueItemViewModel third = viewModel.Rows[2];
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);

            grid.SelectedItem = second;
            grid.SelectedItems.Add(first);
            await synchronizer.SynchronizeAsync(ModifierKeys.Control);

            Assert.Same(first, viewModel.CurrentItem);
            Assert.Same(second, grid.SelectedItem);
            Assert.True(first.IsSelected);
            Assert.True(second.IsSelected);

            grid.SelectedItems.Clear();
            grid.SelectedItem = third;
            grid.SelectedItems.Add(second);
            await synchronizer.SynchronizeAsync(ModifierKeys.Shift);

            Assert.Same(first, viewModel.CurrentItem);
            Assert.Same(third, grid.SelectedItem);
            Assert.False(first.IsSelected);
            Assert.True(second.IsSelected);
            Assert.True(third.IsSelected);
            Assert.Equal(0, batch.ProductionCalls);
        });
    }

    [Fact]
    public void WpfSelectionNormalMouseOrKeyboardTransitionUsesExactFocusedRow()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            await viewModel.QueueFilesAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
            QueueItemViewModel second = viewModel.Rows[1];
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);

            grid.SelectedItem = second;
            await synchronizer.SynchronizeAsync(ModifierKeys.None);

            Assert.Same(second, viewModel.CurrentItem);
            Assert.Same(second, grid.SelectedItem);
            Assert.True(second.IsSelected);
            Assert.Equal(0, batch.ProductionCalls);
        });
    }

    [Fact]
    public void WpfSelectionBusyRejectionRestoresVisibleCurrentRowAndTerminatesReentrancy()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            await viewModel.QueueFilesAsync([@"C:\queue\first.exe", @"C:\queue\second.exe"]);
            QueueItemViewModel first = viewModel.Rows[0];
            QueueItemViewModel second = viewModel.Rows[1];
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);
            grid.SelectedItem = first;
            SetBusy(viewModel, true);
            int selectionChangedCount = 0;
            grid.SelectionChanged += async (_, _) =>
            {
                selectionChangedCount++;
                await synchronizer.SynchronizeAsync(ModifierKeys.None);
            };

            grid.SelectedItem = second;

            Assert.Same(first, viewModel.CurrentItem);
            Assert.Same(first, grid.SelectedItem);
            Assert.Same(first, grid.CurrentItem);
            Assert.True(first.IsSelected);
            Assert.False(second.IsSelected);
            Assert.InRange(selectionChangedCount, 1, 2);
            Assert.Equal(0, batch.ProductionCalls);
            SetBusy(viewModel, false);
        });
    }

    [Fact]
    public void WpfSelectionRapidTransitionsEndAtLatestExactRowWithoutStaleRestore()
    {
        RunOnSta(async () =>
        {
            var batch = new RecordingBatchAdapter();
            await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch);
            await viewModel.QueueFilesAsync(
                [@"C:\queue\first.exe", @"C:\queue\second.exe", @"C:\queue\third.exe"]);
            DataGrid grid = CreateGrid(viewModel);
            var synchronizer = new QueueGridSelectionSynchronizer(grid, viewModel);

            foreach (QueueItemViewModel row in viewModel.Rows.Reverse())
            {
                grid.SelectedItem = row;
                await synchronizer.SynchronizeAsync(ModifierKeys.None);
            }

            QueueItemViewModel latest = viewModel.Rows[0];
            Assert.Same(latest, viewModel.CurrentItem);
            Assert.Same(latest, grid.SelectedItem);
            Assert.Same(latest, grid.CurrentItem);
            Assert.Equal(0, batch.ProductionCalls);
        });
    }

    [Theory]
    [InlineData(ModifierKeys.Control, true)]
    [InlineData(ModifierKeys.Shift, true)]
    [InlineData(ModifierKeys.Control | ModifierKeys.Shift, true)]
    [InlineData(ModifierKeys.None, false)]
    [InlineData(ModifierKeys.Alt, false)]
    public void WpfSelectionModifierIntentCoversMouseAndKeyboardModifierStates(
        ModifierKeys modifiers,
        bool membershipOnly)
    {
        Assert.Equal(membershipOnly, QueueGridSelectionSynchronizer.IsMembershipOnly(modifiers));
    }

    private static DataGrid CreateGrid(SigningWorkbenchViewModel viewModel) => new()
    {
        ItemsSource = viewModel.Rows,
        SelectionMode = DataGridSelectionMode.Extended,
        SelectionUnit = DataGridSelectionUnit.FullRow
    };

    private static void SetBusy(SigningWorkbenchViewModel viewModel, bool value)
    {
        MethodInfo setter = typeof(SigningWorkbenchViewModel)
            .GetProperty(nameof(SigningWorkbenchViewModel.IsBusy))!
            .GetSetMethod(nonPublic: true)!;
        setter.Invoke(viewModel, [value]);
    }

    private static void RunOnSta(Func<Task> action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action().GetAwaiter().GetResult();
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        })
        {
            IsBackground = true,
            Name = "CodeSigner.QueueSelection.STA"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "The queue selection STA did not terminate.");
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }
}
