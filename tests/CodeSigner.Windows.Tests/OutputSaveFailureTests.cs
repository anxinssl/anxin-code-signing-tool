using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class OutputSaveFailureTests
{
    [Theory]
    [InlineData(".exe")]
    [InlineData(".msi")]
    public async Task OutputDirectoryIoFailureIsTypedAndPreservesOriginalAndCleanup(string extension)
    {
        using TestTree tree = new();
        string original = tree.Write("source" + extension, "original");
        var planner = new IntakePlanner(new FixtureProbe());
        IntakePlan plan = await planner.CreateAsync([original], false, tree.PathOf("out"), CancellationToken.None);
        IntakeFile file = plan.Files[0] with
        {
            RelativePath = Path.Combine("blocked", "result" + extension),
            DestinationPath = tree.PathOf(Path.Combine("out", "blocked", "result" + extension))
        };
        tree.Write("out/blocked", "not a directory");
        var events = new List<string>();
        var publisher = TestTransactionalFilePublishers.Create(
            new FixtureSigner(), new FixtureVerifier(), runtimeEventSink: events.Add);

        FilePipelineException error = await Assert.ThrowsAsync<FilePipelineException>(() =>
            publisher.PublishAsync(file, CancellationToken.None));

        Assert.Equal(FilePipelineError.OutputSaveFailed, error.Error);
        Assert.IsAssignableFrom<IOException>(error.InnerException);
        Assert.Contains("publish-start", events);
        Assert.DoesNotContain("publish-done", events);
        Assert.Equal("original", File.ReadAllText(original));
        Assert.Equal("not a directory", File.ReadAllText(tree.PathOf("out/blocked")));
        Assert.False(File.Exists(file.DestinationPath));
        Assert.Empty(Directory.GetDirectories(plan.OutputRoot, ".codesigner-staging-*"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SigningOrVerificationIoErrorIsNeverRelabeledAsOutputFailure(bool duringVerification)
    {
        using TestTree tree = new();
        string original = tree.Write("source.exe", "original");
        IntakePlan plan = await new IntakePlanner(new FixtureProbe()).CreateAsync(
            [original], false, tree.PathOf("out"), CancellationToken.None);
        var expected = new IOException("synthetic pre-publication error");
        var publisher = TestTransactionalFilePublishers.Create(
            new FixtureSigner(duringVerification ? null : expected),
            new FixtureVerifier(duringVerification ? expected : null));

        IOException actual = await Assert.ThrowsAsync<IOException>(() =>
            publisher.PublishAsync(plan.Files[0], CancellationToken.None));

        Assert.Same(expected, actual);
        Assert.Equal("original", File.ReadAllText(original));
        Assert.False(File.Exists(plan.Files[0].DestinationPath));
        Assert.Empty(Directory.GetDirectories(plan.OutputRoot, ".codesigner-staging-*"));
    }

    private sealed class FixtureProbe : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => new(
            SigningSubject.TryCreateForExtension(Path.GetExtension(path)).Value!,
            Guid.Parse("11111111-1111-1111-1111-111111111111"), null);
    }

    private sealed class FixtureSigner(IOException? error = null) : IStagedFileSigner
    {
        public Task SignAsync(string stagedPath, CancellationToken cancellationToken)
        {
            if (error is not null) throw error;
            File.AppendAllText(stagedPath, "|synthetic");
            return Task.CompletedTask;
        }
    }

    private sealed class FixtureVerifier(IOException? error = null) : IStagedFileVerifier
    {
        public Task VerifyAsync(string stagedPath, CancellationToken cancellationToken)
        {
            if (error is not null) throw error;
            Assert.Equal("original|synthetic", File.ReadAllText(stagedPath));
            return Task.CompletedTask;
        }
    }
}
