using System.Diagnostics;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class TransactionalStagedPathGuardTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "CodeSigner-StagedGuard-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> attempts = [];

    [Fact]
    public void AcceptsExistingDirectFileInCurrentActiveOwnedAttempt()
    {
        string attempt = CreateActiveAttempt();
        string staged = Path.Combine(attempt, "payload.exe");
        File.WriteAllText(staged, "payload");

        string canonical = TransactionalStaging.EnsureActiveOwnedStagedFile(staged);

        Assert.Equal(Path.GetFullPath(staged), canonical, ignoreCase: true);
    }

    [Fact]
    public void AcceptsActiveAttemptOwnedByExplicitParentIdentity()
    {
        using Process parent = Process.GetCurrentProcess();
        DateTimeOffset parentStartUtc = parent.StartTime.ToUniversalTime();
        string attempt = TransactionalStaging.CreateAttemptDirectory(root, parent.Id, parentStartUtc);
        attempts.Add(attempt);
        string staged = Path.Combine(attempt, "payload.exe");
        File.WriteAllText(staged, "payload");

        string canonical = TransactionalStaging.EnsureActiveOwnedStagedFile(
            staged,
            parent.Id,
            parentStartUtc);

        Assert.Equal(Path.GetFullPath(staged), canonical, ignoreCase: true);
    }

    [Fact]
    public void RejectsOutsideNestedManifestAndMissingPaths()
    {
        string attempt = CreateActiveAttempt();
        string outside = Path.Combine(root, "outside.exe");
        File.WriteAllText(outside, "outside");
        string nested = Path.Combine(attempt, "nested", "payload.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(nested)!);
        File.WriteAllText(nested, "nested");

        Assert.Throws<FilePipelineException>(() => TransactionalStaging.EnsureActiveOwnedStagedFile(outside));
        Assert.Throws<FilePipelineException>(() => TransactionalStaging.EnsureActiveOwnedStagedFile(nested));
        Assert.Throws<FilePipelineException>(() => TransactionalStaging.EnsureActiveOwnedStagedFile(
            Path.Combine(attempt, TransactionalStaging.ManifestFileName)));
        Assert.Throws<FilePipelineException>(() => TransactionalStaging.EnsureActiveOwnedStagedFile(
            Path.Combine(attempt, "missing.exe")));
    }

    [Fact]
    public void RejectsStaleAttemptEvenWhenManifestAndPayloadAreWellFormed()
    {
        string attempt = TransactionalStaging.CreateAttemptDirectory(
            root,
            ownerProcessId: int.MaxValue,
            ownerProcessStartUtc: DateTimeOffset.UnixEpoch);
        attempts.Add(attempt);
        string staged = Path.Combine(attempt, "payload.exe");
        File.WriteAllText(staged, "payload");

        FilePipelineException failure = Assert.Throws<FilePipelineException>(
            () => TransactionalStaging.EnsureActiveOwnedStagedFile(staged));

        Assert.Equal(FilePipelineError.InvalidPlan, failure.Error);
    }

    [Fact]
    public void RejectsAttemptOwnedByPidWithDifferentStartTime()
    {
        using Process current = Process.GetCurrentProcess();
        string attempt = TransactionalStaging.CreateAttemptDirectory(
            root,
            current.Id,
            current.StartTime.ToUniversalTime().AddMinutes(-5));
        attempts.Add(attempt);
        string staged = Path.Combine(attempt, "payload.exe");
        File.WriteAllText(staged, "payload");

        Assert.Throws<FilePipelineException>(() => TransactionalStaging.EnsureActiveOwnedStagedFile(staged));
    }

    public void Dispose()
    {
        foreach (string attempt in attempts)
        {
            TransactionalStaging.DeleteAttempt(attempt);
        }

        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private string CreateActiveAttempt()
    {
        string attempt = TransactionalStaging.CreateAttemptDirectory(root);
        attempts.Add(attempt);
        return attempt;
    }
}
