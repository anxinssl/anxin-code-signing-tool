using CodeSigner.App.ViewModels;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;

namespace CodeSigner.App.Tests;

public sealed class SignButtonOutputRecoveryTests
{
    [Fact]
    public async Task InvalidThenValidOutputRootRecoversTheSameCurrentRow()
    {
        await using SigningWorkbenchViewModel viewModel = CreateReadyViewModel();
        await SignButtonAvailabilityRecoveryTests.QueuePendingAsync(viewModel, ".exe");
        QueueItemViewModel current = Assert.IsType<QueueItemViewModel>(viewModel.CurrentItem);
        string itemId = current.ItemId;

        await viewModel.ReplanOutputRootAsync(string.Empty);

        Assert.False(viewModel.CanSign);
        Assert.Equal("选择有效的输出目录", viewModel.SignDisabledReason);
        Assert.Equal("OutputRootTextBox", viewModel.FocusTargetAutomationId);

        await viewModel.ReplanOutputRootAsync(@"C:\matrix\recovered-output");

        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal(itemId, current.ItemId);
        Assert.Equal(QueueItemPreflightState.Ready, current.PreflightState);
        Assert.Equal(@"C:\matrix\recovered-output\item-1.exe", current.DestinationPath);
        Assert.True(viewModel.CanSign);
    }

    [Fact]
    public async Task FailedHistoryDoesNotDisableRecoveredCurrentRow()
    {
        await using SigningWorkbenchViewModel viewModel = CreateReadyViewModel();
        await SignButtonAvailabilityRecoveryTests.QueuePendingAsync(viewModel, ".exe", ".msi");
        QueueItemViewModel history = viewModel.Rows[0];
        QueueItemViewModel current = viewModel.Rows[1];
        history.Apply(BatchItemState.Failed, receipt: null);
        await viewModel.SetCurrentItemAsync(current.ItemId);

        await viewModel.ReplanOutputRootAsync(string.Empty);
        await viewModel.ReplanOutputRootAsync(@"C:\matrix\second-output");

        Assert.Equal(BatchItemState.Failed, history.State);
        Assert.Same(current, viewModel.CurrentItem);
        Assert.Equal(QueueItemPreflightState.Ready, current.PreflightState);
        Assert.True(viewModel.CanSign);
    }

    [Fact]
    public async Task OutputRecoveryDoesNotRemoveOrReAddTheCurrentRow()
    {
        await using SigningWorkbenchViewModel viewModel = CreateReadyViewModel();
        await SignButtonAvailabilityRecoveryTests.QueuePendingAsync(viewModel, ".exe");
        QueueItemViewModel current = Assert.Single(viewModel.Rows);
        long rowGeneration = current.RowGeneration;

        await viewModel.ReplanOutputRootAsync(string.Empty);
        await viewModel.ReplanOutputRootAsync(@"C:\matrix\third-output");

        Assert.Single(viewModel.Rows);
        Assert.Same(current, viewModel.Rows[0]);
        Assert.False(viewModel.IsRemovedItemTombstoned(current.ItemId));
        Assert.True(current.RowGeneration > rowGeneration);
    }

    private static SigningWorkbenchViewModel CreateReadyViewModel()
    {
        SigningWorkbenchViewModel viewModel = SignButtonAvailabilityRecoveryTests.CreateViewModel(
            SignButtonAvailabilityRecoveryTests.ReadySnapshot(),
            WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
        Assert.True(viewModel.ApplySettings(
            viewModel.TimestampUri.AbsoluteUri,
            viewModel.DiagnosticRetentionDays));
        return viewModel;
    }
}
