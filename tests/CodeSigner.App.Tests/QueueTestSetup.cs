using CodeSigner.App.ViewModels;

namespace CodeSigner.App.Tests;

internal static class QueueTestSetup
{
    internal static async Task QueueFilesAndWaitAsync(
        this SigningWorkbenchViewModel viewModel,
        IReadOnlyCollection<string> paths)
    {
        await viewModel.QueueFilesAsync(paths);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (viewModel.Rows.Any(row => row.DetectionState is
                   QueueItemDetectionState.Pending or QueueItemDetectionState.Running))
        {
            await Task.Delay(10, timeout.Token);
        }
        await viewModel.InvalidateCurrentPreflightAsync().WaitAsync(timeout.Token);
    }
}
