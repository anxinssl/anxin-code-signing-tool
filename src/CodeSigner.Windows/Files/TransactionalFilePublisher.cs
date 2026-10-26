using System.Security.Cryptography;
using System.Runtime.ExceptionServices;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Files;

public sealed class TransactionalFilePublisher
{
    private readonly IStagedFileSigner signer;
    private readonly IStagedFileVerifier verifier;
    private readonly TransactionalFilePipelineHooks? hooks;
    private readonly Action<string>? runtimeEventSink;
    private readonly Action<string>? afterPublishedVerification;
    private readonly Action<string>? beforePublishedOutputDelete;

    public TransactionalFilePublisher(IStagedFileSigner signer, IStagedFileVerifier verifier)
        : this(signer, verifier, null, null)
    {
    }

    internal TransactionalFilePublisher(
        IStagedFileSigner signer,
        IStagedFileVerifier verifier,
        TransactionalFilePipelineHooks? hooks)
        : this(signer, verifier, hooks, null)
    {
    }

    internal TransactionalFilePublisher(
        IStagedFileSigner signer,
        IStagedFileVerifier verifier,
        TransactionalFilePipelineHooks? hooks,
        Action<string>? runtimeEventSink,
        Action<string>? afterPublishedVerification = null,
        Action<string>? beforePublishedOutputDelete = null)
    {
        this.signer = signer ?? throw new ArgumentNullException(nameof(signer));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.hooks = hooks;
        this.runtimeEventSink = runtimeEventSink;
        this.afterPublishedVerification = afterPublishedVerification;
        this.beforePublishedOutputDelete = beforePublishedOutputDelete;
    }

    public async Task<PublishReceipt> PublishAsync(IntakeFile file, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(file);
        ValidatePlan(file);
        cancellationToken.ThrowIfCancellationRequested();

        string attemptDirectory;
        runtimeEventSink?.Invoke("staging-create-start");
        try
        {
            attemptDirectory = TransactionalStaging.CreateAttemptDirectory(file.OutputRoot);
            runtimeEventSink?.Invoke("staging-create-done");
        }
        catch (FilePipelineException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new FilePipelineException(
                FilePipelineError.StagingUnavailable,
                "A restricted same-volume staging directory could not be created.",
                exception);
        }

        PublishReceipt? receipt = null;
        Exception? operationFailure = null;
        AttemptCleanupState cleanupState = new();
        try
        {
            receipt = await ExecuteAttemptAsync(file, attemptDirectory, cleanupState, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            operationFailure = cleanupState.IsPublishingOutput &&
                exception is IOException or UnauthorizedAccessException
                    ? new FilePipelineException(
                        FilePipelineError.OutputSaveFailed,
                        "The signed output could not be saved to the selected destination.",
                        exception)
                    : exception;
        }

        Exception? cleanupFailure = null;
        try
        {
            if (cleanupState.AllowRecursiveCleanup)
            {
                TransactionalStaging.DeleteAttempt(attemptDirectory);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            cleanupFailure = exception;
        }

        if (cleanupFailure is not null)
        {
            Exception detail = operationFailure is null
                ? cleanupFailure
                : new AggregateException(operationFailure, cleanupFailure);
            throw new FilePipelineException(
                FilePipelineError.CleanupFailed,
                "The staging attempt could not be cleaned.",
                detail);
        }

        if (operationFailure is not null)
        {
            ExceptionDispatchInfo.Capture(operationFailure).Throw();
        }

        return receipt
            ?? throw new FilePipelineException(FilePipelineError.InvalidPlan, "The publish attempt produced no receipt.");
    }

    private async Task<PublishReceipt> ExecuteAttemptAsync(
        IntakeFile file,
        string attemptDirectory,
        AttemptCleanupState cleanupState,
        CancellationToken cancellationToken)
    {
        runtimeEventSink?.Invoke("source-hash-start");
        await using FileStream source = OpenStableSource(file);
        string originalHash = await HashAsync(source, cancellationToken).ConfigureAwait(false);
        runtimeEventSink?.Invoke("source-hash-done");
        source.Position = 0;

        string stagedPath = Path.Combine(attemptDirectory, $"payload{Path.GetExtension(file.OriginalPath)}");
        runtimeEventSink?.Invoke("copy-to-staging-start");
        await CopySourceAsync(source, stagedPath, cancellationToken).ConfigureAwait(false);
        runtimeEventSink?.Invoke("copy-to-staging-done");
        cancellationToken.ThrowIfCancellationRequested();

        runtimeEventSink?.Invoke("signer-enter");
        await signer.SignAsync(stagedPath, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        PathSafety.EnsureNoReparsePoints(stagedPath);
        await using FileStream staged = new(
            stagedPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        StableFileIdentity stagedIdentity = WindowsFileIdentity.FromHandle(staged.SafeFileHandle);

        await verifier.VerifyAsync(stagedPath, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateOriginalPathAndIdentity(file, source);
        string finalOriginalHash = await HashAsync(source, cancellationToken).ConfigureAwait(false);
        if (!originalHash.Equals(finalOriginalHash, StringComparison.Ordinal))
        {
            throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original file changed during the signing attempt.");
        }

        string publishedHash = await HashAsync(staged, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        using SafeFileHandle publishHandle = WindowsFileIdentity.OpenForMove(stagedPath);
        if (WindowsFileIdentity.FromHandle(publishHandle) != stagedIdentity)
        {
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The staged path no longer identifies the verified file before publication.");
        }

        hooks?.BeforeCommit?.Invoke(stagedPath);
        if (!PathIdentifiesFile(stagedPath, stagedIdentity))
        {
            cleanupState.AllowRecursiveCleanup = false;
            DeleteVerifiedStagedFile(publishHandle);
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The staged path no longer identifies the verified file at the commit boundary.");
        }

        runtimeEventSink?.Invoke("publish-start");
        string postCommitOriginalHash = await HashAsync(source, CancellationToken.None).ConfigureAwait(false);
        if (!originalHash.Equals(postCommitOriginalHash, StringComparison.Ordinal))
        {
            throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original file changed at the commit boundary.");
        }

        // Classify only output I/O here; signing and source checks keep their own failures.
        cleanupState.IsPublishingOutput = true;
        string destinationDirectory = Path.GetDirectoryName(file.DestinationPath)
            ?? throw new FilePipelineException(FilePipelineError.InvalidPlan, "The destination has no parent directory.");
        Directory.CreateDirectory(destinationDirectory);
        PathSafety.EnsureNoReparsePoints(destinationDirectory);
        if (File.Exists(file.DestinationPath) || Directory.Exists(file.DestinationPath))
        {
            throw DestinationCollision(file.DestinationPath, null);
        }

        try
        {
            WindowsFileIdentity.MoveByHandleNoReplace(
                publishHandle,
                file.DestinationPath,
                usePosixSemantics: true);
        }
        catch (Win32Exception exception) when (File.Exists(file.DestinationPath) || Directory.Exists(file.DestinationPath))
        {
            throw DestinationCollision(file.DestinationPath, exception);
        }
        catch (Win32Exception exception)
        {
            throw new IOException("The verified staged file could not be published by identity.", exception);
        }

        if (File.Exists(stagedPath) || Directory.Exists(stagedPath))
        {
            cleanupState.AllowRecursiveCleanup = false;
            DeleteVerifiedStagedFile(publishHandle);
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The staged path was replaced while the verified file was being published.");
        }

        await using FileStream published = new(
            file.DestinationPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (WindowsFileIdentity.FromHandle(published.SafeFileHandle) != stagedIdentity ||
            !publishedHash.Equals(await HashAsync(published, CancellationToken.None).ConfigureAwait(false), StringComparison.Ordinal))
        {
            throw new FilePipelineException(FilePipelineError.InvalidPlan, "The published file does not match the verified staged file.");
        }

        cleanupState.IsPublishingOutput = false;
        await source.DisposeAsync().ConfigureAwait(false);
        afterPublishedVerification?.Invoke(file.DestinationPath);
        await using FileStream publicationSource = OpenStableSource(file);
        string publicationOriginalHash = await HashAsync(publicationSource, CancellationToken.None).ConfigureAwait(false);
        if (!originalHash.Equals(publicationOriginalHash, StringComparison.Ordinal))
        {
            DeletePublishedOutputIfOwned(file.DestinationPath, stagedIdentity);
            throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original file changed at the publication boundary.");
        }

        PublishReceipt receipt = new(
            PublishStatus.Published,
            file.OriginalPath,
            file.DestinationPath,
            originalHash,
            publishedHash,
            Path.GetFileName(attemptDirectory)[".codesigner-staging-".Length..]);
        runtimeEventSink?.Invoke("publish-done");
        hooks?.AfterCommit();
        return receipt;
    }

    private void DeletePublishedOutputIfOwned(string destinationPath, StableFileIdentity expectedIdentity)
    {
        try
        {
            using SafeFileHandle current = WindowsFileIdentity.OpenForMove(destinationPath);
            if (WindowsFileIdentity.FromHandle(current) != expectedIdentity)
            {
                throw new FilePipelineException(
                    FilePipelineError.CleanupFailed,
                    "The published path no longer identifies the output created by this attempt.");
            }

            beforePublishedOutputDelete?.Invoke(destinationPath);
            WindowsFileIdentity.DeleteByHandle(current);
        }
        catch (FilePipelineException)
        {
            throw;
        }
        catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException)
        {
            throw new FilePipelineException(
                FilePipelineError.CleanupFailed,
                "The output created by the failed publication attempt could not be removed.",
                exception);
        }
    }

    private static bool PathIdentifiesFile(string path, StableFileIdentity expectedIdentity)
    {
        try
        {
            PathSafety.EnsureNoReparsePoints(path);
            using FileStream current = new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            return WindowsFileIdentity.FromHandle(current.SafeFileHandle) == expectedIdentity;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or IntakeValidationException)
        {
            return false;
        }
    }

    private static void DeleteVerifiedStagedFile(SafeFileHandle handle)
    {
        try
        {
            WindowsFileIdentity.DeleteByHandle(handle);
        }
        catch (Win32Exception exception)
        {
            throw new FilePipelineException(
                FilePipelineError.CleanupFailed,
                "The verified staged file could not be removed by identity.",
                exception);
        }
    }

    private static FileStream OpenStableSource(IntakeFile file)
    {
        try
        {
            FileStream source = new(
                file.OriginalPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            StableFileIdentity currentIdentity = WindowsFileIdentity.FromHandle(source.SafeFileHandle);
            if (currentIdentity != file.Identity)
            {
                source.Dispose();
                throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original file identity changed after intake.");
            }

            return source;
        }
        catch (FilePipelineException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original file is no longer available for a stable read.", exception);
        }
    }

    private static void ValidateOriginalPathAndIdentity(IntakeFile file, FileStream stableSource)
    {
        PathSafety.EnsureNoReparsePoints(file.OriginalPath);
        try
        {
            using FileStream currentPath = new(file.OriginalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            StableFileIdentity pathIdentity = WindowsFileIdentity.FromHandle(currentPath.SafeFileHandle);
            StableFileIdentity handleIdentity = WindowsFileIdentity.FromHandle(stableSource.SafeFileHandle);
            if (pathIdentity != handleIdentity || pathIdentity != file.Identity)
            {
                throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original path no longer names the intake file.");
            }
        }
        catch (FilePipelineException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new FilePipelineException(FilePipelineError.OriginalChanged, "The original path could not be revalidated.", exception);
        }
    }

    private static async Task CopySourceAsync(
        FileStream source,
        string stagedPath,
        CancellationToken cancellationToken)
    {
        await using FileStream destination = new(
            stagedPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> HashAsync(FileStream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        using SHA256 algorithm = SHA256.Create();
        byte[] hash = await algorithm.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }

    private static void ValidatePlan(IntakeFile file)
    {
        string original = Path.GetFullPath(file.OriginalPath);
        string outputRoot = Path.GetFullPath(file.OutputRoot);
        string destination = Path.GetFullPath(file.DestinationPath);
        if (!original.Equals(file.OriginalPath, StringComparison.OrdinalIgnoreCase) ||
            !outputRoot.Equals(file.OutputRoot, StringComparison.OrdinalIgnoreCase) ||
            !destination.Equals(file.DestinationPath, StringComparison.OrdinalIgnoreCase) ||
            !PathSafety.IsWithinOrEqual(destination, outputRoot) ||
            PathSafety.IsWithinOrEqual(original, outputRoot))
        {
            throw new FilePipelineException(FilePipelineError.InvalidPlan, "The intake plan contains unsafe or non-canonical paths.");
        }

        PathSafety.EnsureNoReparsePoints(original);
        PathSafety.EnsureNoReparsePoints(outputRoot);
    }

    private static FilePipelineException DestinationCollision(string destination, Exception? innerException) =>
        new(
            FilePipelineError.DestinationCollision,
            $"The destination already exists and will not be overwritten: {destination}",
            innerException);

    private sealed class AttemptCleanupState
    {
        public bool AllowRecursiveCleanup { get; set; } = true;

        public bool IsPublishingOutput { get; set; }
    }
}
