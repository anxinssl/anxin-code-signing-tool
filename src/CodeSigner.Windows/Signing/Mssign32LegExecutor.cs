using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

public sealed class Mssign32LegExecutor : INativeSigningLegExecutor, IDisposable
{
    private readonly SafeNativeLibraryHandle library;
    private readonly SignerSignEx3Delegate sign;
    private readonly SignerFreeSignerContextDelegate freeContext;
    private readonly ISigningCertificateSource certificateSource;
    private readonly CertificateStoreLifetime certificateStoreLifetime;
    private bool disposed;

    private Mssign32LegExecutor(
        SafeNativeLibraryHandle library,
        SignerSignEx3Delegate sign,
        SignerFreeSignerContextDelegate freeContext,
        ISigningCertificateSource certificateSource,
        CertificateStoreLifetime certificateStoreLifetime)
    {
        this.library = library;
        this.sign = sign;
        this.freeContext = freeContext;
        this.certificateSource = certificateSource;
        this.certificateStoreLifetime = certificateStoreLifetime;
    }

    internal static CertificateStoreLifetime DefaultCertificateStoreLifetime =>
        CertificateStoreLifetime.RetainThroughNativeCall;

    public static Mssign32LegExecutor Create() => Create(DefaultCertificateStoreLifetime);

    internal static Mssign32LegExecutor CreateStoreRetainedSha1Diagnostic() =>
        Create(CertificateStoreLifetime.RetainThroughNativeCall);

    private static Mssign32LegExecutor Create(CertificateStoreLifetime certificateStoreLifetime)
    {
        NativeApiAvailability availability = Mssign32AvailabilityProbe.Probe();
        if (availability != NativeApiAvailability.Available)
        {
            throw new PlatformNotSupportedException($"Mssign32 compatibility gate failed: {availability}.");
        }

        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Mssign32.dll");
        nint module = NativeLibrary.Load(path);
        SafeNativeLibraryHandle library = new(module);
        try
        {
            SignerSignEx3Delegate sign = Marshal.GetDelegateForFunctionPointer<SignerSignEx3Delegate>(
                NativeLibrary.GetExport(module, "SignerSignEx3"));
            SignerFreeSignerContextDelegate freeContext = Marshal.GetDelegateForFunctionPointer<SignerFreeSignerContextDelegate>(
                NativeLibrary.GetExport(module, "SignerFreeSignerContext"));
            return new Mssign32LegExecutor(
                library,
                sign,
                freeContext,
                new X509StoreSigningCertificateSource(),
                certificateStoreLifetime);
        }
        catch
        {
            library.Dispose();
            throw;
        }
    }

    public Task<NativeSigningResult> ExecuteAsync(string path, SignatureLeg leg, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Execute(path, leg));
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        library.Dispose();
        disposed = true;
    }

    private NativeSigningResult Execute(string path, SignatureLeg leg)
    {
        if (!File.Exists(path))
        {
            return NativeSigningResult.Failure(NativeSigningReasonCode.InvalidInput, unchecked((int)0x80070002));
        }

        return SigningCertificateLifetime.Execute(
            certificateSource,
            leg.Certificate,
            certificateStoreLifetime,
            certificate => ExecuteWithCertificate(path, leg, certificate));
    }

    private NativeSigningResult ExecuteWithCertificate(string path, SignatureLeg leg, X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            return NativeSigningResult.Failure(NativeSigningReasonCode.CertificateHasNoPrivateKey, unchecked((int)0x8009000D));
        }

        nint fileName = Marshal.StringToCoTaskMemUni(Path.GetFullPath(path));
        nint subjectIndexPointer = Marshal.AllocCoTaskMem(sizeof(uint));
        nint fileInfoPointer = nint.Zero;
        nint certStoreInfoPointer = nint.Zero;
        try
        {
            Marshal.WriteInt32(subjectIndexPointer, 0);
            SignerFileInfo fileInfo = new()
            {
                Size = checked((uint)Marshal.SizeOf<SignerFileInfo>()),
                FileName = fileName,
                FileHandle = nint.Zero
            };
            fileInfoPointer = AllocateStructure(fileInfo);
            SignerSubjectInfo subjectInfo = new()
            {
                Size = checked((uint)Marshal.SizeOf<SignerSubjectInfo>()),
                SubjectIndex = subjectIndexPointer,
                SubjectChoice = Mssign32Constants.SignerSubjectFile,
                SubjectUnion = fileInfoPointer
            };
            SignerCertStoreInfo certStoreInfo = new()
            {
                Size = checked((uint)Marshal.SizeOf<SignerCertStoreInfo>()),
                SigningCertificate = certificate.Handle,
                CertificatePolicy = Mssign32Constants.SignerCertPolicyChainNoRoot,
                CertificateStore = nint.Zero
            };
            certStoreInfoPointer = AllocateStructure(certStoreInfo);
            SignerCert signerCert = new()
            {
                Size = checked((uint)Marshal.SizeOf<SignerCert>()),
                CertificateChoice = Mssign32Constants.SignerCertStore,
                CertificateUnion = certStoreInfoPointer,
                WindowHandle = nint.Zero
            };
            SignerSignatureInfo signatureInfo = new()
            {
                Size = checked((uint)Marshal.SizeOf<SignerSignatureInfo>()),
                HashAlgorithmId = leg.FileDigest == NativeDigestAlgorithm.Sha1
                    ? Mssign32Constants.CalgSha1
                    : Mssign32Constants.CalgSha256,
                AttributeChoice = Mssign32Constants.SignerNoAttributes
            };

            int hresult = sign(
                leg.Append ? Mssign32Constants.SignatureAppend : 0,
                ref subjectInfo,
                ref signerCert,
                ref signatureInfo,
                nint.Zero,
                Mssign32Constants.SignerTimestampRfc3161,
                Mssign32Constants.Sha256Oid,
                leg.TimestampUri.AbsoluteUri,
                nint.Zero,
                nint.Zero,
                out nint context,
                nint.Zero,
                nint.Zero,
                nint.Zero);
            using SafeSignerContextHandle? safeContext = context == nint.Zero
                ? null
                : new SafeSignerContextHandle(context, freeContext);
            return hresult >= 0
                ? NativeSigningResult.Success()
                : NativeSigningResult.Failure(ClassifyFailure(hresult), hresult);
        }
        finally
        {
            if (certStoreInfoPointer != nint.Zero)
            {
                Marshal.FreeCoTaskMem(certStoreInfoPointer);
            }

            if (fileInfoPointer != nint.Zero)
            {
                Marshal.FreeCoTaskMem(fileInfoPointer);
            }

            Marshal.FreeCoTaskMem(fileName);
            Marshal.FreeCoTaskMem(subjectIndexPointer);
        }
    }

    private static nint AllocateStructure<T>(T value)
        where T : struct
    {
        nint pointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, pointer, fDeleteOld: false);
        return pointer;
    }

    private static NativeSigningReasonCode ClassifyFailure(int hresult)
    {
        uint code = unchecked((uint)hresult);
        return code switch
        {
            0x800704C7 => NativeSigningReasonCode.OperatorCancelled,
            0x80072EE2 or 0x80072EFD or 0x80072EFE => NativeSigningReasonCode.TimestampUnavailable,
            _ => NativeSigningReasonCode.NativeSigningFailed
        };
    }
}
