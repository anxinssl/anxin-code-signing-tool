using System.Runtime.InteropServices;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class AuthenticodeSignatureInspectorTests
{
    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void NativeLayoutsMatchWindowsSdkX64Contract()
    {
        Assert.Equal(32, Marshal.SizeOf<WinTrustFileInfo>());
        Assert.Equal(32, Marshal.SizeOf<WinTrustSignatureSettings>());
        Assert.Equal(88, Marshal.SizeOf<WinTrustData>());
        Assert.Equal(64, Marshal.SizeOf<NativeProviderSigner>());
        Assert.Equal(136, Marshal.SizeOf<NativeSignerInfo>());
        Assert.Equal(80, Marshal.SizeOf<NativeTimestampInfo>());
        Assert.Equal(32, Marshal.OffsetOf<NativeProviderSigner>(nameof(NativeProviderSigner.SignerInfo)).ToInt32());
        Assert.Equal(120, Marshal.OffsetOf<NativeSignerInfo>(nameof(NativeSignerInfo.UnauthenticatedAttributes)).ToInt32());
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void ReadOnlyDualSignedReferenceEnumeratesStableOrderAndTimestampKinds()
    {
        string path = GetRepositoryFile("pc端签名软件.exe");
        AuthenticodeSignatureInspector inspector = new();

        AuthenticodeSignatureCountInspection count = inspector.GetSignatureCount(path);
        AuthenticodeSignatureCountInspection repeatedCount = inspector.GetSignatureCount(path);
        AuthenticodeSignatureInspection primary = inspector.InspectSignature(path, 0);
        AuthenticodeSignatureInspection secondary = inspector.InspectSignature(path, 1);

        Assert.Equal(0, count.TrustStatus);
        Assert.Equal(1U, count.SecondarySignatureCount);
        Assert.Equal(count, repeatedCount);
        Assert.Equal(0, primary.TrustStatus);
        Assert.Equal(0U, primary.VerifiedSignatureIndex);
        Assert.Equal(AuthenticodeOids.Sha1, primary.FileDigestAlgorithmOid);
        Assert.Equal("29C049FFCC62DD47B88EABC72BE3F3399ADBC12E", primary.SignerThumbprint);
        Assert.Equal(AuthenticodeTimestampKind.LegacyCounterSignature, primary.Timestamp.Kind);
        Assert.Equal(0, secondary.TrustStatus);
        Assert.Equal(1U, secondary.VerifiedSignatureIndex);
        Assert.Equal(AuthenticodeOids.Sha256, secondary.FileDigestAlgorithmOid);
        Assert.Equal("2ACF0E035386FAB75768F4E8B2EF43A652054B6F", secondary.SignerThumbprint);
        Assert.Equal(AuthenticodeTimestampKind.Rfc3161, secondary.Timestamp.Kind);
        Assert.True(secondary.Timestamp.CryptographicallyValid);
        Assert.Equal(AuthenticodeOids.Sha256, secondary.Timestamp.MessageImprintAlgorithmOid);
        Assert.True(secondary.Timestamp.ChainValid);
        Assert.True(secondary.Timestamp.TimeValid);
        Assert.True(secondary.Timestamp.TimestampingEkuValid);
    }

    private static string GetRepositoryFile(string fileName)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        string path = Path.Combine(
            directory.FullName,
            "references",
            "vendor",
            "binaries",
            fileName);
        Assert.True(File.Exists(path), $"Expected read-only reference file was missing: {path}");
        return path;
    }
}
