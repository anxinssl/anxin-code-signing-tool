using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace CodeSigner.Windows.Signing;

internal static class AuthenticodeSignatureInspectorInterop
{
    internal static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    internal const uint WtdUiNone = 2;
    internal const uint WtdChoiceFile = 1;
    internal const uint WtdStateActionVerify = 1;
    internal const uint WtdStateActionClose = 2;
    internal const uint WssVerifySpecific = 1;
    internal const uint WssGetSecondarySignatureCount = 2;

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    internal static extern int WinVerifyTrust(nint windowHandle, ref Guid actionId, nint trustData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern nint WTHelperProvDataFromStateData(nint stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern nint WTHelperGetProvSignerFromChain(
        nint providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern nint WTHelperGetProvCertFromChain(nint signer, uint certificateIndex);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptVerifyTimeStampSignature(
        byte[] timestampContentInfo,
        uint timestampContentInfoSize,
        byte[] signedData,
        uint signedDataSize,
        nint additionalStore,
        out SafeTimestampContextHandle timestampContext,
        out SafeCertificateContextHandle timestampSigner,
        out SafeCertificateStoreHandle timestampStore);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern nint CertEnumCertificatesInStore(SafeCertificateStoreHandle store, nint previousContext);

    [DllImport("crypt32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CertFreeCertificateContext(nint certificateContext);

    [DllImport("crypt32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CertCloseStore(nint certificateStore, uint flags);

    [DllImport("crypt32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMemFree(nint buffer);
}

internal sealed class SafeTimestampContextHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeTimestampContextHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => AuthenticodeSignatureInspectorInterop.CryptMemFree(handle);
}

internal sealed class SafeCertificateContextHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeCertificateContextHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => AuthenticodeSignatureInspectorInterop.CertFreeCertificateContext(handle);
}

internal sealed class SafeCertificateStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeCertificateStoreHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => AuthenticodeSignatureInspectorInterop.CertCloseStore(handle, 0);
}

[StructLayout(LayoutKind.Sequential)]
internal struct WinTrustFileInfo
{
    internal uint Size;
    internal nint FilePath;
    internal nint FileHandle;
    internal nint KnownSubject;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WinTrustSignatureSettings
{
    internal uint Size;
    internal uint Index;
    internal uint Flags;
    internal uint SecondarySignatures;
    internal uint VerifiedSignatureIndex;
    internal nint CryptoPolicy;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WinTrustData
{
    internal uint Size;
    internal nint PolicyCallbackData;
    internal nint SipClientData;
    internal uint UiChoice;
    internal uint RevocationChecks;
    internal uint UnionChoice;
    internal nint FileInfo;
    internal uint StateAction;
    internal nint StateData;
    internal nint UrlReference;
    internal uint ProviderFlags;
    internal uint UiContext;
    internal nint SignatureSettings;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeFileTime
{
    internal uint LowDateTime;
    internal uint HighDateTime;

    internal readonly long ToInt64() => unchecked((long)(((ulong)HighDateTime << 32) | LowDateTime));
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeBlob
{
    internal uint Size;
    internal nint Data;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeAlgorithmIdentifier
{
    internal nint ObjectId;
    internal NativeBlob Parameters;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCryptAttributes
{
    internal uint Count;
    internal nint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCryptAttribute
{
    internal nint ObjectId;
    internal uint ValueCount;
    internal nint Values;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeSignerInfo
{
    internal uint Version;
    internal NativeBlob Issuer;
    internal NativeBlob SerialNumber;
    internal NativeAlgorithmIdentifier HashAlgorithm;
    internal NativeAlgorithmIdentifier HashEncryptionAlgorithm;
    internal NativeBlob EncryptedHash;
    internal NativeCryptAttributes AuthenticatedAttributes;
    internal NativeCryptAttributes UnauthenticatedAttributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeProviderSigner
{
    internal uint Size;
    internal NativeFileTime VerifyAsOf;
    internal uint CertificateChainCount;
    internal nint CertificateChain;
    internal uint SignerType;
    internal nint SignerInfo;
    internal uint Error;
    internal uint CounterSignerCount;
    internal nint CounterSigners;
    internal nint ChainContext;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeProviderCertificate
{
    internal uint Size;
    internal nint CertificateContext;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCertificateContext
{
    internal uint EncodingType;
    internal nint EncodedCertificate;
    internal uint EncodedCertificateSize;
    internal nint CertificateInfo;
    internal nint CertificateStore;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeTimestampContext
{
    internal uint EncodedSize;
    internal nint Encoded;
    internal nint TimestampInfo;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeTimestampInfo
{
    internal uint Version;
    internal nint PolicyId;
    internal NativeAlgorithmIdentifier HashAlgorithm;
    internal NativeBlob HashedMessage;
    internal NativeBlob SerialNumber;
    internal NativeFileTime Time;
}
