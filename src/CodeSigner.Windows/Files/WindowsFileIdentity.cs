using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Files;

internal static class WindowsFileIdentity
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileRenameFlagReplaceIfExists = 0x00000001;
    private const int FileRenameFlagPosixSemantics = 0x00000002;

    public static StableFileIdentity FromHandle(SafeFileHandle handle) => GetInformation(handle).Identity;

    public static WindowsFileHandleInformation GetInformation(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read the stable Windows file identity.");
        }

        string fileId = $"{information.FileIndexHigh:X8}{information.FileIndexLow:X8}";
        return new WindowsFileHandleInformation(
            new StableFileIdentity(information.VolumeSerialNumber, fileId),
            (FileAttributes)information.FileAttributes,
            ((long)information.FileSizeHigh << 32) | information.FileSizeLow,
            DateTime.FromFileTimeUtc(((long)information.LastWriteTime.dwHighDateTime << 32) |
                (uint)information.LastWriteTime.dwLowDateTime));
    }

    public static SafeFileHandle OpenForReadNoFollow(string path) => OpenHandle(
        path,
        GenericRead,
        FileShare.Read,
        FileFlagOpenReparsePoint);

    public static SafeFileHandle OpenDirectoryNoFollow(string path) => OpenHandle(
        path,
        desiredAccess: 0,
        FileShare.Read,
        FileFlagOpenReparsePoint | FileFlagBackupSemantics);

    public static SafeFileHandle OpenForMove(string path) => OpenHandle(
        path,
        DeleteAccess,
        FileShare.Read | FileShare.Delete,
        flagsAndAttributes: 0);

    public static void MoveByHandleNoReplace(
        SafeFileHandle handle,
        string destinationPath,
        bool usePosixSemantics = false) =>
        MoveByHandle(handle, destinationPath, replaceExisting: false, usePosixSemantics);

    public static void MoveByHandleReplace(
        SafeFileHandle handle,
        string destinationPath,
        bool usePosixSemantics = false) =>
        MoveByHandle(handle, destinationPath, replaceExisting: true, usePosixSemantics);

    private static void MoveByHandle(
        SafeFileHandle handle,
        string destinationPath,
        bool replaceExisting,
        bool usePosixSemantics)
    {
        string canonicalDestination = Path.GetFullPath(destinationPath);
        byte[] fileName = System.Text.Encoding.Unicode.GetBytes(canonicalDestination);
        int rootDirectoryOffset = Marshal.OffsetOf<FileRenameInformationHeader>(
            nameof(FileRenameInformationHeader.RootDirectory)).ToInt32();
        int fileNameLengthOffset = Marshal.OffsetOf<FileRenameInformationHeader>(
            nameof(FileRenameInformationHeader.FileNameLength)).ToInt32();
        int fileNameOffset = fileNameLengthOffset + sizeof(uint);
        int bufferSize = fileNameOffset + fileName.Length + sizeof(char);
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            int flags = (replaceExisting ? FileRenameFlagReplaceIfExists : 0) |
                (usePosixSemantics ? FileRenameFlagPosixSemantics : 0);
            Marshal.WriteInt32(buffer, 0, flags);
            Marshal.WriteIntPtr(buffer, rootDirectoryOffset, IntPtr.Zero);
            Marshal.WriteInt32(buffer, fileNameLengthOffset, fileName.Length);
            Marshal.Copy(fileName, 0, IntPtr.Add(buffer, fileNameOffset), fileName.Length);
            Marshal.WriteInt16(buffer, fileNameOffset + fileName.Length, 0);
            if (!SetFileInformationByHandle(
                    handle,
                    flags == 0 ? FileInformationClass.FileRenameInfo : FileInformationClass.FileRenameInfoEx,
                    buffer,
                    (uint)bufferSize))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to publish the verified staged file by identity.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void DeleteByHandle(SafeFileHandle handle)
    {
        FileDispositionInformation disposition = new() { DeleteFile = 1 };
        if (!SetFileInformationByHandle(
                handle,
                FileInformationClass.FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to remove the verified staged file by identity.");
        }
    }

    private static SafeFileHandle OpenHandle(
        string path,
        uint desiredAccess,
        FileShare shareMode,
        uint flagsAndAttributes)
    {
        string canonicalPath = Path.GetFullPath(path);
        // Native file APIs need an extended path independently of the host's manifest.
        string nativePath = canonicalPath.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? canonicalPath
            : canonicalPath.StartsWith(@"\\", StringComparison.Ordinal)
                ? @"\\?\UNC\" + canonicalPath[2..]
                : @"\\?\" + canonicalPath;
        SafeFileHandle handle = CreateFileW(
            nativePath,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            OpenExisting,
            flagsAndAttributes,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        int error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new Win32Exception(error, "Unable to open the staged file for identity-bound publication.");
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle fileHandle,
        FileInformationClass fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle fileHandle,
        FileInformationClass fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle fileHandle,
        out ByHandleFileInformation fileInformation);

    private enum FileInformationClass
    {
        FileRenameInfo = 3,
        FileDispositionInfo = 4,
        FileRenameInfoEx = 22
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileRenameInformationHeader
    {
        public uint Flags;
        public IntPtr RootDirectory;
        public uint FileNameLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        public byte DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}

internal sealed record WindowsFileHandleInformation(
    StableFileIdentity Identity,
    FileAttributes Attributes,
    long Length,
    DateTime LastWriteTimeUtc);
