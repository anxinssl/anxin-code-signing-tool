using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.CompatibilityProbe.Oracle;

public sealed partial class WindowsExternalExecutableProbe : IExternalExecutableProbe
{
    public FileProbeResult Probe(string path)
    {
        if (!File.Exists(path))
        {
            return FileProbeResult.Missing;
        }

        string sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
        if (!IsPortableExecutable(path))
        {
            return new FileProbeResult(true, false, AuthenticodeState.NotSigned, null, null, null, null, null, sha256);
        }

        AuthenticodeState signatureState = VerifyAuthenticode(path);
        FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(path);
        string? publisher = signatureState == AuthenticodeState.Valid ? ReadPublisher(path) : null;
        Version? version = Version.TryParse(versionInfo.ProductVersion, out Version? productVersion)
            ? productVersion
            : Version.TryParse(versionInfo.FileVersion, out Version? fileVersion)
                ? fileVersion
                : null;
        return new FileProbeResult(
            Exists: true,
            IsPortableExecutable: true,
            SignatureState: signatureState,
            Publisher: publisher,
            CompanyName: versionInfo.CompanyName,
            OriginalFileName: versionInfo.OriginalFilename,
            FileDescription: versionInfo.FileDescription,
            Version: version,
            Sha256: sha256);
    }

    private static bool IsPortableExecutable(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length < 64)
        {
            return false;
        }

        Span<byte> header = stackalloc byte[64];
        stream.ReadExactly(header);
        if (header[0] != (byte)'M' || header[1] != (byte)'Z')
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(header[60..64]);
        if (peOffset < 64 || peOffset > stream.Length - 4)
        {
            return false;
        }

        stream.Position = peOffset;
        Span<byte> signature = stackalloc byte[4];
        stream.ReadExactly(signature);
        return signature.SequenceEqual("PE\0\0"u8);
    }

    private static AuthenticodeState VerifyAuthenticode(string path)
    {
        Guid action = NativeMethods.WintrustActionGenericVerifyV2;
        IntPtr filePath = Marshal.StringToCoTaskMemUni(path);
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            WinTrustFileInfoNative fileInfo = new()
            {
                StructureSize = (uint)Marshal.SizeOf<WinTrustFileInfoNative>(),
                FilePath = filePath
            };
            fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfoNative>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            WinTrustDataNative trustData = new()
            {
                StructureSize = (uint)Marshal.SizeOf<WinTrustDataNative>(),
                UiChoice = 2,
                UnionChoice = 1,
                FileInfo = fileInfoPointer
            };
            int result = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            return result switch
            {
                0 => AuthenticodeState.Valid,
                NativeMethods.TrustENoSignature => AuthenticodeState.NotSigned,
                _ => AuthenticodeState.Invalid
            };
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(fileInfoPointer);
            }

            Marshal.FreeCoTaskMem(filePath);
        }
    }

    private static string ReadPublisher(string path)
    {
#pragma warning disable SYSLIB0057
        using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
        using X509Certificate2 certificate2 = new(certificate);
#pragma warning restore SYSLIB0057
        return certificate2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
    }

    private static partial class NativeMethods
    {
        internal const int TrustENoSignature = unchecked((int)0x800B0100);
        internal static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

        [LibraryImport("wintrust.dll")]
        internal static partial int WinVerifyTrust(IntPtr windowHandle, ref Guid actionId, ref WinTrustDataNative trustData);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfoNative
    {
        internal uint StructureSize;
        internal IntPtr FilePath;
        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustDataNative
    {
        internal uint StructureSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr FileInfo;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
    }
}
