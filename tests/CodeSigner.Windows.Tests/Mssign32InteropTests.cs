using System.Runtime.InteropServices;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class Mssign32InteropTests
{
    [Fact]
    [Trait("Category", "NativeSigning")]
    public void NativeLayoutsMatchMicrosoftX64Contract()
    {
        Assert.Equal(24, Marshal.SizeOf<SignerFileInfo>());
        Assert.Equal(32, Marshal.SizeOf<SignerSubjectInfo>());
        Assert.Equal(32, Marshal.SizeOf<SignerCertStoreInfo>());
        Assert.Equal(24, Marshal.SizeOf<SignerCert>());
        Assert.Equal(40, Marshal.SizeOf<SignerSignatureInfo>());
        Assert.Equal(8, Marshal.OffsetOf<SignerSubjectInfo>(nameof(SignerSubjectInfo.SubjectIndex)).ToInt32());
        Assert.Equal(24, Marshal.OffsetOf<SignerSubjectInfo>(nameof(SignerSubjectInfo.SubjectUnion)).ToInt32());
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void AvailabilityRejectsUnsupportedOsWithoutLoadingLibrary()
    {
        RecordingNativeLibraryLoader loader = new(loadSucceeds: true, signerExport: true, cleanupExport: true);

        NativeApiAvailability result = Mssign32AvailabilityProbe.Probe(loader, isSupportedOs: false, "C:/Windows/System32/Mssign32.dll");

        Assert.Equal(NativeApiAvailability.UnsupportedOperatingSystem, result);
        Assert.Equal(0, loader.LoadCalls);
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void RealSystem32ExportsAreAvailableOnSupportedWindows()
    {
        Assert.Equal(NativeApiAvailability.Available, Mssign32AvailabilityProbe.Probe());
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void SignerContextSafeHandleReleasesExactlyOnce()
    {
        int releaseCalls = 0;
        SignerFreeSignerContextDelegate release = _ =>
        {
            releaseCalls++;
            return 0;
        };
        SafeSignerContextHandle context = new(new nint(42), release);

        context.Dispose();
        context.Dispose();

        Assert.Equal(1, releaseCalls);
    }

    [Theory]
    [InlineData(false, false, false, NativeApiAvailability.LibraryUnavailable)]
    [InlineData(true, false, true, NativeApiAvailability.SignerSignEx3Unavailable)]
    [InlineData(true, true, false, NativeApiAvailability.CleanupExportUnavailable)]
    [InlineData(true, true, true, NativeApiAvailability.Available)]
    [Trait("Category", "NativeSigning")]
    public void AvailabilityFailsClosedOnMissingExports(
        bool loadSucceeds,
        bool signerExport,
        bool cleanupExport,
        NativeApiAvailability expected)
    {
        RecordingNativeLibraryLoader loader = new(loadSucceeds, signerExport, cleanupExport);

        NativeApiAvailability result = Mssign32AvailabilityProbe.Probe(loader, isSupportedOs: true, "C:/Windows/System32/Mssign32.dll");

        Assert.Equal(expected, result);
        Assert.Equal(loadSucceeds ? 1 : 0, loader.FreeCalls);
    }

    private sealed class RecordingNativeLibraryLoader(bool loadSucceeds, bool signerExport, bool cleanupExport) : INativeLibraryLoader
    {
        public int LoadCalls { get; private set; }
        public int FreeCalls { get; private set; }

        public bool TryLoad(string path, out nint handle)
        {
            LoadCalls++;
            handle = loadSucceeds ? new nint(1) : nint.Zero;
            return loadSucceeds;
        }

        public bool TryGetExport(nint handle, string exportName, out nint address)
        {
            bool exists = exportName == "SignerSignEx3" ? signerExport : cleanupExport;
            address = exists ? new nint(2) : nint.Zero;
            return exists;
        }

        public void Free(nint handle) => FreeCalls++;
    }
}
