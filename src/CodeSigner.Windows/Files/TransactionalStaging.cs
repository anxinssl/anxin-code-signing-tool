using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace CodeSigner.Windows.Files;

public static class TransactionalStaging
{
    private const string DirectoryPrefix = ".codesigner-staging-";
    private const string ProductId = "CodeSigner.Windows.TransactionalStaging.v1";

    internal const string ManifestFileName = ".codesigner-owner.json";

    public static string CreateAttemptDirectory(string outputRoot)
    {
        using Process current = Process.GetCurrentProcess();
        return CreateAttemptDirectory(outputRoot, current.Id, current.StartTime.ToUniversalTime());
    }

    public static string EnsureActiveOwnedStagedFile(string stagedPath)
    {
        using Process current = Process.GetCurrentProcess();
        return EnsureActiveOwnedStagedFile(
            stagedPath,
            current.Id,
            current.StartTime.ToUniversalTime());
    }

    public static string EnsureActiveOwnedStagedFile(
        string stagedPath,
        int ownerProcessId,
        DateTimeOffset ownerProcessStartUtc)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(stagedPath) ||
                ownerProcessId <= 0 ||
                ownerProcessStartUtc == default)
            {
                throw StagedPathFailure();
            }

            string canonicalPath = Path.GetFullPath(stagedPath);
            if (!File.Exists(canonicalPath) ||
                Path.GetFileName(canonicalPath).Equals(ManifestFileName, StringComparison.Ordinal))
            {
                throw StagedPathFailure();
            }

            string attemptDirectory = Path.GetDirectoryName(canonicalPath)
                ?? throw StagedPathFailure();
            PathSafety.EnsureNoReparsePoints(canonicalPath);
            if (!HasProductAcl(attemptDirectory))
            {
                throw StagedPathFailure();
            }

            string directoryName = Path.GetFileName(attemptDirectory);
            if (!directoryName.StartsWith(DirectoryPrefix, StringComparison.Ordinal) ||
                !Guid.TryParseExact(directoryName[DirectoryPrefix.Length..], "N", out Guid attemptGuid))
            {
                throw StagedPathFailure();
            }

            string json = File.ReadAllText(Path.Combine(attemptDirectory, ManifestFileName));
            StagingManifest? manifest = JsonSerializer.Deserialize<StagingManifest>(json);
            if (manifest is null ||
                manifest.ProductId != ProductId ||
                manifest.Version != 1 ||
                !manifest.AttemptId.Equals(attemptGuid.ToString("N"), StringComparison.Ordinal))
            {
                throw StagedPathFailure();
            }

            string outputRoot = Path.GetFullPath(manifest.OutputRoot);
            string boundDirectory = Path.Combine(outputRoot, $"{DirectoryPrefix}{manifest.AttemptId}");
            if (!attemptDirectory.Equals(Path.GetFullPath(boundDirectory), StringComparison.OrdinalIgnoreCase) ||
                manifest.OwnerProcessId != ownerProcessId ||
                Math.Abs((manifest.OwnerProcessStartUtc.ToUniversalTime() - ownerProcessStartUtc.ToUniversalTime()).TotalSeconds) >= 1 ||
                !IsOwnerActive(manifest.OwnerProcessId, manifest.OwnerProcessStartUtc))
            {
                throw StagedPathFailure();
            }

            return canonicalPath;
        }
        catch (FilePipelineException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or ArgumentException or NotSupportedException or System.Security.SecurityException or IntakeValidationException)
        {
            throw StagedPathFailure(exception);
        }
    }

    internal static string CreateAttemptDirectory(
        string outputRoot,
        int ownerProcessId,
        DateTimeOffset ownerProcessStartUtc)
    {
        string canonicalRoot = Path.GetFullPath(outputRoot);
        Directory.CreateDirectory(canonicalRoot);
        PathSafety.EnsureNoReparsePoints(canonicalRoot);

        string attemptId = Guid.NewGuid().ToString("N");
        string attemptDirectory = Path.Combine(canonicalRoot, $"{DirectoryPrefix}{attemptId}");
        try
        {
            CreateRestrictedDirectory(attemptDirectory);
            EnsureSameVolume(canonicalRoot, attemptDirectory);
            StagingManifest manifest = new(
                ProductId,
                1,
                attemptId,
                canonicalRoot,
                ownerProcessId,
                ownerProcessStartUtc.ToUniversalTime());
            string manifestJson = JsonSerializer.Serialize(manifest);
            File.WriteAllText(Path.Combine(attemptDirectory, ManifestFileName), manifestJson);
            return attemptDirectory;
        }
        catch
        {
            SafeDeleteAttempt(attemptDirectory);
            throw;
        }
    }

    public static StagingRecoveryReceipt Recover(string outputRoot)
    {
        string canonicalRoot = Path.GetFullPath(outputRoot);
        if (!Directory.Exists(canonicalRoot))
        {
            return new StagingRecoveryReceipt(0, 0);
        }

        PathSafety.EnsureNoReparsePoints(canonicalRoot);
        int removed = 0;
        int skipped = 0;
        foreach (string candidate in Directory.GetDirectories(canonicalRoot, $"{DirectoryPrefix}*", SearchOption.TopDirectoryOnly))
        {
            if (!TryReadAbandonedManifest(canonicalRoot, candidate, out _))
            {
                skipped++;
                continue;
            }

            try
            {
                SafeDeleteAttempt(candidate);
                removed++;
            }
            catch (IOException)
            {
                skipped++;
            }
            catch (UnauthorizedAccessException)
            {
                skipped++;
            }
        }

        return new StagingRecoveryReceipt(removed, skipped);
    }

    internal static void DeleteAttempt(string attemptDirectory) => SafeDeleteAttempt(attemptDirectory);

    private static FilePipelineException StagedPathFailure(Exception? innerException = null) =>
        new(
            FilePipelineError.InvalidPlan,
            "The signing target is not a direct file in the active staging attempt owned by the authorized process.",
            innerException);

    private static bool TryReadAbandonedManifest(
        string expectedRoot,
        string attemptDirectory,
        out StagingManifest? manifest)
    {
        manifest = null;
        try
        {
            if ((File.GetAttributes(attemptDirectory) & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            if (!HasProductAcl(attemptDirectory))
            {
                return false;
            }

            string directoryName = Path.GetFileName(attemptDirectory);
            if (!directoryName.StartsWith(DirectoryPrefix, StringComparison.Ordinal) ||
                !Guid.TryParseExact(directoryName[DirectoryPrefix.Length..], "N", out Guid attemptGuid))
            {
                return false;
            }

            string json = File.ReadAllText(Path.Combine(attemptDirectory, ManifestFileName));
            manifest = JsonSerializer.Deserialize<StagingManifest>(json);
            if (manifest is null ||
                manifest.ProductId != ProductId ||
                manifest.Version != 1 ||
                !manifest.AttemptId.Equals(attemptGuid.ToString("N"), StringComparison.Ordinal) ||
                !Path.GetFullPath(manifest.OutputRoot).Equals(expectedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string boundPath = Path.Combine(expectedRoot, $"{DirectoryPrefix}{manifest.AttemptId}");
            if (!Path.GetFullPath(attemptDirectory).Equals(boundPath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return !IsOwnerActive(manifest.OwnerProcessId, manifest.OwnerProcessStartUtc);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            manifest = null;
            return false;
        }
    }

    private static bool IsOwnerActive(int processId, DateTimeOffset expectedStartUtc)
    {
        try
        {
            using Process process = Process.GetProcessById(processId);
            DateTimeOffset actualStartUtc = process.StartTime.ToUniversalTime();
            return Math.Abs((actualStartUtc - expectedStartUtc).TotalSeconds) < 1;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static bool HasProductAcl(string attemptDirectory)
    {
        DirectorySecurity security = new DirectoryInfo(attemptDirectory).GetAccessControl(AccessControlSections.Access);
        if (!security.AreAccessRulesProtected)
        {
            return false;
        }

        SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new UnauthorizedAccessException("The current Windows user has no security identifier.");
        AuthorizationRule[] rules = security
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<AuthorizationRule>()
            .ToArray();
        return rules.Length == 1 &&
            rules[0] is FileSystemAccessRule fileRule &&
            fileRule.AccessControlType == AccessControlType.Allow &&
            fileRule.IdentityReference == currentUser &&
            (fileRule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl;
    }

    private static void EnsureSameVolume(string outputRoot, string attemptDirectory)
    {
        string? rootVolume = Path.GetPathRoot(outputRoot);
        string? attemptVolume = Path.GetPathRoot(attemptDirectory);
        if (rootVolume is null || !rootVolume.Equals(attemptVolume, StringComparison.OrdinalIgnoreCase))
        {
            throw new FilePipelineException(
                FilePipelineError.StagingUnavailable,
                "The staging directory is not on the destination volume.");
        }
    }

    private static void CreateRestrictedDirectory(string attemptDirectory)
    {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User
            ?? throw new FilePipelineException(FilePipelineError.StagingUnavailable, "The current Windows user has no security identifier.");
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        GCHandle descriptorHandle = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            SecurityAttributes attributes = new()
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptorHandle.AddrOfPinnedObject(),
                InheritHandle = false
            };
            if (!CreateDirectoryW(attemptDirectory, ref attributes))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create a restricted staging directory.");
            }
        }
        finally
        {
            descriptorHandle.Free();
        }
    }

    private static void SafeDeleteAttempt(string attemptDirectory)
    {
        if (!Directory.Exists(attemptDirectory))
        {
            return;
        }

        FileAttributes rootAttributes = File.GetAttributes(attemptDirectory);
        if ((rootAttributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("Refusing to delete a reparse-point staging directory.");
        }

        DeleteDirectoryContents(attemptDirectory);
        Directory.Delete(attemptDirectory, recursive: false);
    }

    private static void DeleteDirectoryContents(string directory)
    {
        foreach (string entry in Directory.GetFileSystemEntries(directory))
        {
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.Directory) != 0)
            {
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    Directory.Delete(entry, recursive: false);
                }
                else
                {
                    DeleteDirectoryContents(entry);
                    Directory.Delete(entry, recursive: false);
                }

                continue;
            }

            if ((attributes & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(entry, attributes & ~FileAttributes.ReadOnly);
            }

            File.Delete(entry);
        }
    }

    private sealed record StagingManifest(
        string ProductId,
        int Version,
        string AttemptId,
        string OutputRoot,
        int OwnerProcessId,
        DateTimeOffset OwnerProcessStartUtc);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes securityAttributes);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }
}
