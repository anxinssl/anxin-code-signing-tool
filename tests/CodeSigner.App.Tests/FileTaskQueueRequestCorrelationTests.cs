using CodeSigner.App.Services;
using CodeSigner.Windows.Batch;

namespace CodeSigner.App.Tests;

public sealed class FileTaskQueueRequestCorrelationTests
{
    [Fact]
    public void MatchingContextAppliesAndSupersededOrWrongOperationIsIgnored()
    {
        var attempts = new ExecutionAttemptContextFactory();
        var registry = new ExecutionAttemptRegistry();
        registry.RegisterLiveItem("item-a");
        ExecutionAttemptContext first = attempts.Next("item-a");
        registry.Begin(first);
        ExecutionAttemptContext second = attempts.Next("item-a");
        registry.Begin(second);

        Assert.Equal(
            ExecutionProgressDisposition.IgnoreStaleGeneration,
            registry.Classify(Update(first)));
        Assert.Equal(
            ExecutionProgressDisposition.IgnoreWrongOperation,
            registry.Classify(Update(new ExecutionAttemptContext(
                second.ItemId,
                new string('a', 32),
                second.ExecutionGeneration))));
        Assert.Equal(ExecutionProgressDisposition.Apply, registry.Classify(Update(second)));
    }

    [Fact]
    public void CompletedTombstonedAndUnregisteredLiveCallbacksCannotApply()
    {
        var attempts = new ExecutionAttemptContextFactory();
        var registry = new ExecutionAttemptRegistry();
        registry.RegisterLiveItem("completed");
        ExecutionAttemptContext completed = attempts.Next("completed");
        registry.Begin(completed);
        registry.Complete(completed);
        registry.RegisterLiveItem("removed");
        ExecutionAttemptContext removed = attempts.Next("removed");
        registry.Begin(removed);
        registry.Tombstone("removed");
        registry.RegisterLiveItem("unregistered-live");

        Assert.Equal(
            ExecutionProgressDisposition.IgnoreCompleted,
            registry.Classify(Update(completed)));
        Assert.Equal(
            ExecutionProgressDisposition.IgnoreTombstoned,
            registry.Classify(Update(removed)));
        Assert.Equal(
            ExecutionProgressDisposition.AdapterContractViolation,
            registry.Classify(Update(attempts.Next("unregistered-live"))));
    }

    [Fact]
    public void ContextRejectsNonCanonicalOperationAndNonPositiveGeneration()
    {
        Assert.Throws<ArgumentException>(() =>
            new ExecutionAttemptContext("item-a", new string('A', 32), 1));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ExecutionAttemptContext("item-a", new string('a', 32), 0));
    }

    private static BatchProgressUpdate Update(ExecutionAttemptContext context) =>
        new(context, BatchItemState.Pending, null);
}
