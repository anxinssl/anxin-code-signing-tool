using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using CodeSigner.Core.Signing;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Files;

public sealed record QueuedSource(
    string CanonicalPath,
    string RelativePath,
    StableFileIdentity Identity)
{
    public QueuedSource(string canonicalPath, StableFileIdentity identity)
        : this(canonicalPath, Path.GetFileName(canonicalPath), identity)
    {
    }
}

public sealed record SourceFingerprint(
    StableFileIdentity Identity,
    long Length,
    DateTime LastWriteTimeUtc,
    string Sha256);

public sealed record DetectedQueuedSource(
    QueuedSource Source,
    SignableSubject Subject,
    SourceFingerprint Fingerprint);

public enum QueuedSourceDetectionStatus
{
    Supported,
    Blocked,
    Unavailable,
    Changed
}

public sealed record QueuedSourceDetectionResult(
    QueuedSourceDetectionStatus Status,
    DetectedQueuedSource? DetectedSource,
    IntakeError? Error);

public enum QueuedSourceAdmissionError
{
    InvalidInput,
    InputNotFound,
    ReparsePoint,
    InaccessibleInput
}

public sealed record QueuedSourceAdmissionFailure(QueuedSourceAdmissionError Error, string Path);

public sealed record QueuedSourceAdmissionResult(
    IReadOnlyList<QueuedSource> Sources,
    IReadOnlyList<QueuedSourceAdmissionFailure> Failures);

internal enum QueuedSourceAdmissionTestPoint
{
    BeforeFileOpen,
    BeforeDirectoryEnumeration
}

public static class QueuedSourceAdmission
{
    public static QueuedSourceAdmissionResult Admit(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        CancellationToken cancellationToken) =>
        Admit(inputs, recurseDirectories, existingSources: [], filterDirectoryExtensions: true, testHook: null, cancellationToken);

    public static QueuedSourceAdmissionResult Admit(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        IReadOnlyCollection<QueuedSource> existingSources,
        CancellationToken cancellationToken) =>
        Admit(inputs, recurseDirectories, existingSources, filterDirectoryExtensions: true, testHook: null, cancellationToken);

    internal static QueuedSourceAdmissionResult AdmitForCreateAsync(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        CancellationToken cancellationToken) =>
        Admit(inputs, recurseDirectories, existingSources: [], filterDirectoryExtensions: false, testHook: null, cancellationToken);

    internal static QueuedSourceAdmissionResult Admit(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        Action<QueuedSourceAdmissionTestPoint, string>? testHook,
        CancellationToken cancellationToken)
        => Admit(inputs, recurseDirectories, existingSources: [], filterDirectoryExtensions: true, testHook, cancellationToken);

    private static QueuedSourceAdmissionResult Admit(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        IReadOnlyCollection<QueuedSource> existingSources,
        bool filterDirectoryExtensions,
        Action<QueuedSourceAdmissionTestPoint, string>? testHook,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(existingSources);

        var sources = new List<QueuedSource>();
        var failures = new List<QueuedSourceAdmissionFailure>();
        var paths = new HashSet<string>(
            existingSources.Select(source => source.CanonicalPath),
            StringComparer.OrdinalIgnoreCase);
        var identities = new HashSet<StableFileIdentity>(
            existingSources.Select(source => source.Identity));

        foreach (string input in inputs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AdmitInput(
                input,
                recurseDirectories,
                filterDirectoryExtensions,
                sources,
                failures,
                paths,
                identities,
                testHook,
                cancellationToken);
        }

        return new QueuedSourceAdmissionResult(sources.AsReadOnly(), failures.AsReadOnly());
    }

    private static void AdmitInput(
        string input,
        bool recurseDirectories,
        bool filterDirectoryExtensions,
        List<QueuedSource> sources,
        List<QueuedSourceAdmissionFailure> failures,
        HashSet<string> paths,
        HashSet<StableFileIdentity> identities,
        Action<QueuedSourceAdmissionTestPoint, string>? testHook,
        CancellationToken cancellationToken)
    {
        string canonicalPath;
        try
        {
            canonicalPath = PathSafety.Canonicalize(input);
            PathSafety.EnsureNoReparsePoints(canonicalPath);
        }
        catch (IntakeValidationException exception)
        {
            failures.Add(new QueuedSourceAdmissionFailure(MapError(exception.Error), exception.Path ?? input));
            return;
        }
        catch (UnauthorizedAccessException)
        {
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, input));
            return;
        }
        catch (IOException)
        {
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, input));
            return;
        }

        if (!TryGetAttributes(canonicalPath, failures, out FileAttributes attributes))
        {
            return;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.ReparsePoint, canonicalPath));
            return;
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            AdmitDirectory(
                canonicalPath,
                recurseDirectories,
                filterDirectoryExtensions,
                sources,
                failures,
                paths,
                identities,
                testHook,
                cancellationToken);
            return;
        }

        AdmitFile(
            canonicalPath,
            Path.GetFileName(canonicalPath),
            includeUnknownExtension: true,
            sources,
            failures,
            paths,
            identities,
            testHook);
    }

    private static void AdmitDirectory(
        string inputRoot,
        bool recurseDirectories,
        bool filterDirectoryExtensions,
        List<QueuedSource> sources,
        List<QueuedSourceAdmissionFailure> failures,
        HashSet<string> paths,
        HashSet<StableFileIdentity> identities,
        Action<QueuedSourceAdmissionTestPoint, string>? testHook,
        CancellationToken cancellationToken)
    {
        var directories = new Stack<DirectoryFrame>();
        if (!TryOpenDirectory(inputRoot, failures, testHook, out DirectoryFrame? root))
        {
            return;
        }

        directories.Push(root);
        try
        {
            while (directories.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                DirectoryFrame directory = directories.Peek();
                if (!directory.TryTakeNext(out string? entry))
                {
                    directories.Pop().Dispose();
                    continue;
                }

                if (!TryGetAttributes(entry, failures, out FileAttributes attributes))
                {
                    continue;
                }

                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.ReparsePoint, entry));
                    continue;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (recurseDirectories)
                    {
                        if (TryOpenDirectory(entry, failures, testHook, out DirectoryFrame? child))
                        {
                            directories.Push(child);
                        }
                    }

                    continue;
                }

                AdmitFile(
                    entry,
                    Path.GetRelativePath(inputRoot, entry),
                    includeUnknownExtension: !filterDirectoryExtensions,
                    sources,
                    failures,
                    paths,
                    identities,
                    testHook);
            }
        }
        finally
        {
            while (directories.TryPop(out DirectoryFrame? directory))
            {
                directory.Dispose();
            }
        }
    }

    private static bool TryOpenDirectory(
        string path,
        List<QueuedSourceAdmissionFailure> failures,
        Action<QueuedSourceAdmissionTestPoint, string>? testHook,
        [NotNullWhen(true)] out DirectoryFrame? directory)
    {
        SafeFileHandle? handle = null;
        try
        {
            testHook?.Invoke(QueuedSourceAdmissionTestPoint.BeforeDirectoryEnumeration, path);
            handle = WindowsFileIdentity.OpenDirectoryNoFollow(path);
            WindowsFileHandleInformation information = WindowsFileIdentity.GetInformation(handle);
            if ((information.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.ReparsePoint, path));
                handle.Dispose();
                directory = null;
                return false;
            }

            if ((information.Attributes & FileAttributes.Directory) == 0)
            {
                failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, path));
                handle.Dispose();
                directory = null;
                return false;
            }

            string[] entries = Directory.GetFileSystemEntries(path);
            Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
            directory = new DirectoryFrame(handle, entries);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            handle?.Dispose();
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, path));
            directory = null;
            return false;
        }
    }

    private static void AdmitFile(
        string canonicalPath,
        string relativePath,
        bool includeUnknownExtension,
        List<QueuedSource> sources,
        List<QueuedSourceAdmissionFailure> failures,
        HashSet<string> paths,
        HashSet<StableFileIdentity> identities,
        Action<QueuedSourceAdmissionTestPoint, string>? testHook)
    {
        if (!includeUnknownExtension && SigningSubject.TryCreateForExtension(Path.GetExtension(canonicalPath)).Value is null)
        {
            return;
        }

        if (paths.Contains(canonicalPath))
        {
            return;
        }

        WindowsFileHandleInformation information;
        try
        {
            testHook?.Invoke(QueuedSourceAdmissionTestPoint.BeforeFileOpen, canonicalPath);
            using SafeFileHandle handle = WindowsFileIdentity.OpenForReadNoFollow(canonicalPath);
            information = WindowsFileIdentity.GetInformation(handle);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, canonicalPath));
            return;
        }

        if ((information.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.ReparsePoint, canonicalPath));
            return;
        }

        if ((information.Attributes & FileAttributes.Directory) != 0)
        {
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, canonicalPath));
            return;
        }

        if (!identities.Add(information.Identity))
        {
            return;
        }

        paths.Add(canonicalPath);
        sources.Add(new QueuedSource(
            canonicalPath,
            NormalizeRelativePath(relativePath),
            information.Identity));
    }

    private static string NormalizeRelativePath(string relativePath)
    {
        string normalized = relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(normalized) ||
            Path.IsPathRooted(normalized) ||
            normalized.Equals("..", StringComparison.Ordinal) ||
            normalized.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new IntakeValidationException(
                IntakeError.InvalidInput,
                "A queued source relative path must remain below its input root.");
        }

        return normalized;
    }

    private static bool TryGetAttributes(
        string path,
        List<QueuedSourceAdmissionFailure> failures,
        out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            attributes = default;
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InaccessibleInput, path));
            return false;
        }
        catch (IOException)
        {
            attributes = default;
            failures.Add(new QueuedSourceAdmissionFailure(QueuedSourceAdmissionError.InputNotFound, path));
            return false;
        }
    }

    private static QueuedSourceAdmissionError MapError(IntakeError error) => error switch
    {
        IntakeError.InvalidInput => QueuedSourceAdmissionError.InvalidInput,
        IntakeError.InputNotFound => QueuedSourceAdmissionError.InputNotFound,
        IntakeError.ReparsePoint => QueuedSourceAdmissionError.ReparsePoint,
        _ => QueuedSourceAdmissionError.InaccessibleInput
    };

    private sealed class DirectoryFrame(SafeFileHandle handle, string[] entries) : IDisposable
    {
        private int nextIndex = entries.Length - 1;

        public bool TryTakeNext([NotNullWhen(true)] out string? entry)
        {
            if (nextIndex < 0)
            {
                entry = null;
                return false;
            }

            entry = Path.GetFullPath(entries[nextIndex]);
            nextIndex--;
            return true;
        }

        public void Dispose() => handle.Dispose();
    }
}
