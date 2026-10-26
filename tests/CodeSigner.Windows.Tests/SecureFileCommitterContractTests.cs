using System.Security.Cryptography;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class SecureFileCommitterContractTests
{
    [Fact]
    public void ProductionCommitterContractExposesOnlyOwnedStagingCommit()
    {
        string[] methodNames = typeof(ISecureFileCommitter)
            .GetMethods()
            .Select(static method => method.Name)
            .ToArray();

        Assert.Contains(nameof(ISecureFileCommitter.CommitAsync), methodNames);
        Assert.DoesNotContain("PublishAsync", methodNames);
        Assert.DoesNotContain("PublishNew", methodNames);
        Assert.DoesNotContain("Replace", methodNames);
    }

    [Fact]
    public async Task VerifiedCandidateReplacesOwnedStagingWithExactHashAndLength()
    {
        using TestTree tree = new();
        string staging = tree.Write("owned.exe", "unsigned");
        string candidate = tree.Write("candidate.exe", "signed-content");
        byte[] bytes = File.ReadAllBytes(candidate);
        string hash = Convert.ToHexString(SHA256.HashData(bytes));

        SecureFileCommitReceipt receipt = await LocalStagingFileCommitter.Instance.CommitAsync(
            new SecureFileCommitRequest(candidate, staging, ".exe", hash, bytes.LongLength),
            CancellationToken.None);

        Assert.Equal(staging, receipt.PublishedPath, ignoreCase: true);
        Assert.Equal(hash, receipt.PublishedSha256);
        Assert.Equal(bytes.LongLength, receipt.PublishedLength);
        Assert.Equal(bytes, File.ReadAllBytes(staging));
        Assert.False(File.Exists(candidate));
    }

    [Fact]
    public async Task HashMismatchLeavesOwnedStagingAndCandidateUnchanged()
    {
        using TestTree tree = new();
        string staging = tree.Write("owned.exe", "unsigned");
        string candidate = tree.Write("candidate.exe", "signed-content");
        byte[] stagingBefore = File.ReadAllBytes(staging);
        byte[] candidateBefore = File.ReadAllBytes(candidate);

        FilePipelineException failure = await Assert.ThrowsAsync<FilePipelineException>(() =>
            LocalStagingFileCommitter.Instance.CommitAsync(
                new SecureFileCommitRequest(candidate, staging, ".exe", new string('0', 64), candidateBefore.LongLength),
                CancellationToken.None));

        Assert.Equal(FilePipelineError.InvalidPlan, failure.Error);
        Assert.Equal(stagingBefore, File.ReadAllBytes(staging));
        Assert.Equal(candidateBefore, File.ReadAllBytes(candidate));
    }

    [Fact]
    public async Task PreCancelledCommitLeavesBothFilesUnchanged()
    {
        using TestTree tree = new();
        string staging = tree.Write("owned.exe", "unsigned");
        string candidate = tree.Write("candidate.exe", "signed-content");
        byte[] stagingBefore = File.ReadAllBytes(staging);
        byte[] candidateBefore = File.ReadAllBytes(candidate);
        string hash = Convert.ToHexString(SHA256.HashData(candidateBefore));
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            LocalStagingFileCommitter.Instance.CommitAsync(
                new SecureFileCommitRequest(candidate, staging, ".exe", hash, candidateBefore.LongLength),
                cancellation.Token));

        Assert.Equal(stagingBefore, File.ReadAllBytes(staging));
        Assert.Equal(candidateBefore, File.ReadAllBytes(candidate));
    }
}
