using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Files;

internal interface ISecureFileCommitter
{
    bool IsAvailable { get; }

    Task<SecureFileCommitReceipt> CommitAsync(
        SecureFileCommitRequest request,
        CancellationToken cancellationToken);
}

internal sealed record SecureFileCommitRequest(
    string CandidatePath,
    string StagingPath,
    string CandidateExtension,
    string CandidateSha256,
    long CandidateLength);

public sealed record SecureFileCommitReceipt(
    string PublishedPath,
    string PublishedSha256,
    long PublishedLength);

internal sealed class LocalStagingFileCommitter : ISecureFileCommitter
{
    public static LocalStagingFileCommitter Instance { get; } = new();

    private LocalStagingFileCommitter()
    {
    }

    public bool IsAvailable => true;

    public async Task<SecureFileCommitReceipt> CommitAsync(
        SecureFileCommitRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        string candidatePath = Path.GetFullPath(request.CandidatePath);
        string stagingPath = Path.GetFullPath(request.StagingPath);
        string? candidateDirectory = Path.GetDirectoryName(candidatePath);
        string? stagingDirectory = Path.GetDirectoryName(stagingPath);
        if (!candidatePath.Equals(request.CandidatePath, StringComparison.OrdinalIgnoreCase) ||
            !stagingPath.Equals(request.StagingPath, StringComparison.OrdinalIgnoreCase) ||
            candidateDirectory is null ||
            !candidateDirectory.Equals(stagingDirectory, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetExtension(candidatePath).Equals(request.CandidateExtension, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetExtension(stagingPath).Equals(request.CandidateExtension, StringComparison.OrdinalIgnoreCase) ||
            request.CandidateLength < 0 ||
            request.CandidateSha256.Length != 64)
        {
            throw InvalidCommit();
        }

        EnsureSafePath(candidatePath);
        EnsureSafePath(stagingPath);
        StableFileIdentity candidateIdentity;
        string candidateHash;
        long candidateLength;
        await using (FileStream candidate = OpenForStableRead(candidatePath))
        {
            candidateIdentity = WindowsFileIdentity.FromHandle(candidate.SafeFileHandle);
            (candidateHash, candidateLength) = await ReadIdentityAsync(candidate, cancellationToken)
                .ConfigureAwait(false);
        }
        if (candidateLength != request.CandidateLength ||
            !candidateHash.Equals(request.CandidateSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidCommit();
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!candidatePath.Equals(stagingPath, StringComparison.OrdinalIgnoreCase))
        {
            using SafeFileHandle moveHandle = WindowsFileIdentity.OpenForMove(candidatePath);
            if (WindowsFileIdentity.FromHandle(moveHandle) != candidateIdentity)
            {
                throw InvalidCommit();
            }

            WindowsFileIdentity.MoveByHandleReplace(
                moveHandle,
                stagingPath,
                usePosixSemantics: true);
        }

        EnsureSafePath(stagingPath);
        await using FileStream published = OpenForStableRead(stagingPath);
        if (WindowsFileIdentity.FromHandle(published.SafeFileHandle) != candidateIdentity)
        {
            throw InvalidCommit();
        }

        (string publishedHash, long publishedLength) = await ReadIdentityAsync(published, CancellationToken.None)
            .ConfigureAwait(false);
        if (publishedLength != candidateLength ||
            !publishedHash.Equals(candidateHash, StringComparison.Ordinal))
        {
            throw InvalidCommit();
        }

        return new SecureFileCommitReceipt(stagingPath, publishedHash, publishedLength);
    }

    private static FileStream OpenForStableRead(string path) => new(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read | FileShare.Delete,
        bufferSize: 64 * 1024,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static void EnsureSafePath(string path)
    {
        try
        {
            PathSafety.EnsureNoReparsePoints(path);
        }
        catch (IntakeValidationException exception)
        {
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The verified candidate path is not safe for local staging commit.",
                exception);
        }
    }

    private static async Task<(string Sha256, long Length)> ReadIdentityAsync(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        stream.Position = 0;
        string hash = Convert.ToHexString(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        return (hash, stream.Length);
    }

    private static FilePipelineException InvalidCommit() => new(
        FilePipelineError.InvalidPlan,
        "The verified candidate cannot be committed to the owned staging file.");
}
