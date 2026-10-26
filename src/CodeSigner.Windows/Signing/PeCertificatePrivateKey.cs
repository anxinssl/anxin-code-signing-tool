using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

internal enum PePrivateKeyFamily
{
    LegacyCsp,
    Cng
}

internal enum PeRsaPadding
{
    Pkcs1
}

internal sealed class PeCertificatePrivateKeyLease : IDisposable
{
    private readonly ICertificatePrivateKeyNativeApi nativeApi;
    private readonly bool callerMustFree;
    private bool disposed;

    internal PeCertificatePrivateKeyLease(
        SigningCertificateSelection selection,
        nint keyHandle,
        uint keySpec,
        PePrivateKeyFamily family,
        bool callerMustFree,
        ICertificatePrivateKeyNativeApi nativeApi)
    {
        Selection = selection;
        KeyHandle = keyHandle;
        KeySpec = keySpec;
        Family = family;
        Padding = PeRsaPadding.Pkcs1;
        this.callerMustFree = callerMustFree;
        this.nativeApi = nativeApi;
    }

    internal SigningCertificateSelection Selection { get; }

    internal X509Certificate2 Certificate => Selection.Certificate;

    internal nint KeyHandle { get; }

    internal uint KeySpec { get; }

    internal PePrivateKeyFamily Family { get; }

    internal PeRsaPadding Padding { get; }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        try
        {
            if (callerMustFree && KeyHandle != nint.Zero)
            {
                if (Family == PePrivateKeyFamily.Cng)
                {
                    _ = nativeApi.FreeCngKey(KeyHandle);
                }
                else
                {
                    _ = nativeApi.ReleaseCsp(KeyHandle);
                }
            }
        }
        finally
        {
            Selection.Dispose();
            disposed = true;
        }
    }
}

internal sealed record PePrivateKeyAcquisition(
    NativeSigningResult Result,
    PeCertificatePrivateKeyLease? Lease)
{
    internal static PePrivateKeyAcquisition Success(PeCertificatePrivateKeyLease lease) =>
        new(NativeSigningResult.Success(), lease);

    internal static PePrivateKeyAcquisition Failure(NativeSigningReasonCode reason, int hResult) =>
        new(NativeSigningResult.Failure(reason, hResult), null);
}

internal interface IPeCertificatePrivateKeyAcquirer
{
    PePrivateKeyAcquisition Acquire(CertificateReference reference, nint providerWindowHandle);
}

internal interface ICertificatePrivateKeyNativeApi
{
    bool TryAcquire(
        nint certificateContext,
        uint flags,
        nint parameters,
        out nint keyHandle,
        out uint keySpec,
        out bool callerMustFree,
        out int error);

    bool ReleaseCsp(nint keyHandle);

    int FreeCngKey(nint keyHandle);
}

internal sealed class WindowsCertificatePrivateKeyAcquirer : IPeCertificatePrivateKeyAcquirer
{
    internal const uint CertificateNcryptKeySpec = 0xffffffff;
    internal const uint AtKeyExchange = 1;
    internal const uint AtSignature = 2;
    internal const uint AcquireCompareKey = 0x00000004;
    internal const uint AcquireWindowHandle = 0x00000080;
    internal const uint AcquireAllowNcryptKey = 0x00010000;
    internal const string RsaPublicKeyOid = "1.2.840.113549.1.1.1";

    private const int ErrorCancelled = 1223;
    private const int CryptENotFound = unchecked((int)0x80092004);
    private const int NteNoKey = unchecked((int)0x8009000D);
    private const int NteBadKeyset = unchecked((int)0x80090016);
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);

    private readonly ISigningCertificateSource certificateSource;
    private readonly ICertificatePrivateKeyNativeApi nativeApi;

    internal WindowsCertificatePrivateKeyAcquirer()
        : this(new X509StoreSigningCertificateSource(), new SystemCertificatePrivateKeyNativeApi())
    {
    }

    internal WindowsCertificatePrivateKeyAcquirer(
        ISigningCertificateSource certificateSource,
        ICertificatePrivateKeyNativeApi nativeApi)
    {
        this.certificateSource = certificateSource;
        this.nativeApi = nativeApi;
    }

    public PePrivateKeyAcquisition Acquire(
        CertificateReference reference,
        nint providerWindowHandle)
    {
        ArgumentNullException.ThrowIfNull(reference);
        SigningCertificateSelection? selection = certificateSource.Select(
            reference,
            CertificateStoreLifetime.RetainThroughNativeCall);
        if (selection is null)
        {
            return PePrivateKeyAcquisition.Failure(
                NativeSigningReasonCode.CertificateNotFound,
                CryptENotFound);
        }

        if (!string.Equals(
            selection.Certificate.PublicKey.Oid.Value,
            RsaPublicKeyOid,
            StringComparison.Ordinal))
        {
            selection.Dispose();
            return PePrivateKeyAcquisition.Failure(
                NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                InvalidArgumentHResult);
        }

        uint flags = AcquireCompareKey | AcquireAllowNcryptKey;
        nint windowPointer = nint.Zero;
        try
        {
            if (providerWindowHandle != nint.Zero)
            {
                windowPointer = Marshal.AllocHGlobal(nint.Size);
                Marshal.WriteIntPtr(windowPointer, providerWindowHandle);
                flags |= AcquireWindowHandle;
            }

            bool acquired = nativeApi.TryAcquire(
                selection.Certificate.Handle,
                flags,
                windowPointer,
                out nint keyHandle,
                out uint keySpec,
                out bool callerMustFree,
                out int error);
            if (!acquired || keyHandle == nint.Zero)
            {
                selection.Dispose();
                int hResult = ToHResult(error);
                return PePrivateKeyAcquisition.Failure(MapFailure(error, hResult), hResult);
            }

            PePrivateKeyFamily family;
            if (keySpec == CertificateNcryptKeySpec)
            {
                family = PePrivateKeyFamily.Cng;
            }
            else if (keySpec is AtKeyExchange or AtSignature)
            {
                family = PePrivateKeyFamily.LegacyCsp;
            }
            else
            {
                if (callerMustFree)
                {
                    _ = nativeApi.ReleaseCsp(keyHandle);
                }

                selection.Dispose();
                return PePrivateKeyAcquisition.Failure(
                    NativeSigningReasonCode.UnsupportedKeyAlgorithm,
                    InvalidArgumentHResult);
            }

            return PePrivateKeyAcquisition.Success(new PeCertificatePrivateKeyLease(
                selection,
                keyHandle,
                keySpec,
                family,
                callerMustFree,
                nativeApi));
        }
        finally
        {
            Marshal.FreeHGlobal(windowPointer);
        }
    }

    private static NativeSigningReasonCode MapFailure(int error, int hResult)
    {
        if (error == ErrorCancelled || hResult == unchecked((int)0x800704C7))
        {
            return NativeSigningReasonCode.OperatorCancelled;
        }

        return hResult is NteNoKey or NteBadKeyset or CryptENotFound
            ? NativeSigningReasonCode.CertificateHasNoPrivateKey
            : NativeSigningReasonCode.NativeSigningFailed;
    }

    private static int ToHResult(int error)
    {
        if (error < 0)
        {
            return error;
        }

        return error == 0
            ? unchecked((int)0x80004005)
            : unchecked((int)(0x80070000U | (uint)error));
    }
}

internal sealed class SystemCertificatePrivateKeyNativeApi : ICertificatePrivateKeyNativeApi
{
    public bool TryAcquire(
        nint certificateContext,
        uint flags,
        nint parameters,
        out nint keyHandle,
        out uint keySpec,
        out bool callerMustFree,
        out int error)
    {
        bool acquired = CryptAcquireCertificatePrivateKey(
            certificateContext,
            flags,
            parameters,
            out keyHandle,
            out keySpec,
            out callerMustFree);
        error = acquired ? 0 : Marshal.GetLastWin32Error();
        return acquired;
    }

    public bool ReleaseCsp(nint keyHandle) => CryptReleaseContext(keyHandle, 0);

    public int FreeCngKey(nint keyHandle) => NCryptFreeObject(keyHandle);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptAcquireCertificatePrivateKey(
        nint certificateContext,
        uint flags,
        nint parameters,
        out nint keyHandle,
        out uint keySpec,
        [MarshalAs(UnmanagedType.Bool)] out bool callerMustFree);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptReleaseContext(nint provider, uint flags);

    [DllImport("ncrypt.dll", ExactSpelling = true)]
    private static extern int NCryptFreeObject(nint handle);
}
