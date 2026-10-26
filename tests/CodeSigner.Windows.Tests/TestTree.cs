using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CodeSigner.Windows.Tests;

internal sealed class TestTree : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "CodeSigner-Todo5-Tests", Guid.NewGuid().ToString("N"));

    public string PathOf(string relativePath) => Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar));

    public string Write(string relativePath, string content) => WriteRelative(PathOf(relativePath), content);

    public string CreateHardLink(string relativePath, string existingPath)
    {
        string linkPath = PathOf(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(linkPath)!);
        if (!CreateHardLinkW(linkPath, existingPath, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create a test hard link.");
        }

        return linkPath;
    }

    public string WriteRelative(string fullPath, string content)
    {
        string canonicalPath = Path.GetFullPath(fullPath);
        string relative = Path.GetRelativePath(root, canonicalPath);
        if (Path.IsPathRooted(relative) || relative.Equals("..", StringComparison.Ordinal) ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("TestTree writes must remain inside the disposable test root.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(canonicalPath)!);
        File.WriteAllText(canonicalPath, content);
        return canonicalPath;
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);
}
