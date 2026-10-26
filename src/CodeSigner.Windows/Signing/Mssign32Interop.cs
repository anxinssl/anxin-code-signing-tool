using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Signing;

[StructLayout(LayoutKind.Sequential)]
internal struct SignerFileInfo
{
    internal uint Size;
    internal nint FileName;
    internal nint FileHandle;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SignerSubjectInfo
{
    internal uint Size;
    internal nint SubjectIndex;
    internal uint SubjectChoice;
    internal nint SubjectUnion;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SignerCertStoreInfo
{
    internal uint Size;
    internal nint SigningCertificate;
    internal uint CertificatePolicy;
    internal nint CertificateStore;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SignerCert
{
    internal uint Size;
    internal uint CertificateChoice;
    internal nint CertificateUnion;
    internal nint WindowHandle;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SignerSignatureInfo
{
    internal uint Size;
    internal uint HashAlgorithmId;
    internal uint AttributeChoice;
    internal nint AuthenticodeAttributes;
    internal nint AuthenticatedAttributes;
    internal nint UnauthenticatedAttributes;
}

internal static class Mssign32Constants
{
    internal const uint SignerSubjectFile = 1;
    internal const uint SignerCertStore = 2;
    internal const uint SignerCertPolicyChainNoRoot = 8;
    internal const uint SignerNoAttributes = 0;
    internal const uint SignerTimestampRfc3161 = 2;
    internal const uint SignatureAppend = 0x1000;
    internal const uint CalgSha1 = 0x8004;
    internal const uint CalgSha256 = 0x800C;
    internal const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
}

[UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
internal delegate int SignerSignEx3Delegate(
    uint flags,
    ref SignerSubjectInfo subjectInfo,
    ref SignerCert signerCert,
    ref SignerSignatureInfo signatureInfo,
    nint providerInfo,
    uint timestampFlags,
    [MarshalAs(UnmanagedType.LPStr)] string timestampAlgorithmOid,
    [MarshalAs(UnmanagedType.LPWStr)] string timestampUri,
    nint requestAttributes,
    nint sipData,
    out nint signerContext,
    nint cryptoPolicy,
    nint digestSignInfo,
    nint reserved);

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate int SignerFreeSignerContextDelegate(nint signerContext);

internal sealed class SafeSignerContextHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private readonly SignerFreeSignerContextDelegate release;

    internal SafeSignerContextHandle(nint handle, SignerFreeSignerContextDelegate release)
        : base(ownsHandle: true)
    {
        this.release = release;
        SetHandle(handle);
    }

    protected override bool ReleaseHandle() => release(handle) >= 0;
}

internal sealed class SafeNativeLibraryHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeNativeLibraryHandle(nint handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeLibrary.Free(handle);
        return true;
    }
}
