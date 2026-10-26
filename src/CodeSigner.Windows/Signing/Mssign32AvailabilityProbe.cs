using System.Runtime.InteropServices;

namespace CodeSigner.Windows.Signing;

public enum NativeApiAvailability
{
    Available,
    UnsupportedOperatingSystem,
    LibraryUnavailable,
    SignerSignEx3Unavailable,
    CleanupExportUnavailable
}

public interface INativeLibraryLoader
{
    bool TryLoad(string path, out nint handle);
    bool TryGetExport(nint handle, string exportName, out nint address);
    void Free(nint handle);
}

public sealed class SystemNativeLibraryLoader : INativeLibraryLoader
{
    public bool TryLoad(string path, out nint handle) => NativeLibrary.TryLoad(path, out handle);

    public bool TryGetExport(nint handle, string exportName, out nint address) =>
        NativeLibrary.TryGetExport(handle, exportName, out address);

    public void Free(nint handle) => NativeLibrary.Free(handle);
}

public static class Mssign32AvailabilityProbe
{
    public static NativeApiAvailability Probe()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Mssign32.dll");
        return Probe(new SystemNativeLibraryLoader(), OperatingSystem.IsWindowsVersionAtLeast(10), path);
    }

    public static NativeApiAvailability Probe(INativeLibraryLoader loader, bool isSupportedOs, string libraryPath)
    {
        ArgumentNullException.ThrowIfNull(loader);
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);
        if (!isSupportedOs)
        {
            return NativeApiAvailability.UnsupportedOperatingSystem;
        }

        if (!loader.TryLoad(libraryPath, out nint handle))
        {
            return NativeApiAvailability.LibraryUnavailable;
        }

        try
        {
            if (!loader.TryGetExport(handle, "SignerSignEx3", out _))
            {
                return NativeApiAvailability.SignerSignEx3Unavailable;
            }

            return loader.TryGetExport(handle, "SignerFreeSignerContext", out _)
                ? NativeApiAvailability.Available
                : NativeApiAvailability.CleanupExportUnavailable;
        }
        finally
        {
            loader.Free(handle);
        }
    }
}
