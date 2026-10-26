using System.Reflection;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;

namespace CodeSigner.IntegrationTests;

public sealed class Todo7BatchRedTests
{
    [Fact]
    [Trait("Category", "Todo7Red")]
    public void TypedSequentialBatchAndPersistentWorkerContractsExist()
    {
        Assembly windows = typeof(TransactionalStaging).Assembly;
        Type? state = windows.GetType(
            "CodeSigner.Windows.Batch.BatchItemState",
            throwOnError: false);
        Assert.NotNull(state);

        Assert.Equal(
            [
                "Pending",
                "Ready",
                "SigningPrimary",
                "SigningSecondary",
                "Verifying",
                "Published",
                "SkippedAlreadySigned",
                "Failed",
                "PausedProvider",
                "PausedTimestamp",
                "Cancelled"
            ],
            Enum.GetNames(state));
        Assert.NotNull(windows.GetType(
            "CodeSigner.Windows.Batch.SequentialBatchOrchestrator",
            throwOnError: false));
        Assert.NotNull(typeof(WorkerProtocolHost).GetMethod(
            "RunLoopAsync",
            BindingFlags.Public | BindingFlags.Static));
    }
}
