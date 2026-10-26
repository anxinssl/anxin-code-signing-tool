using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

internal enum CertificateStoreLifetime
{
    ReleaseBeforeNativeCall,
    RetainThroughNativeCall
}

internal interface ISigningCertificateSource
{
    SigningCertificateSelection? Select(
        CertificateReference reference,
        CertificateStoreLifetime storeLifetime);
}

internal interface ISigningCertificateStoreFactory
{
    ISigningCertificateStore Create(string storeName, StoreLocation storeLocation);
}

internal interface ISigningCertificateStore : IDisposable
{
    X509Certificate2Collection Certificates { get; }

    void Open(OpenFlags openFlags);
}

internal sealed class SigningCertificateSelection(
    X509Certificate2 certificate,
    IDisposable? storeLease) : IDisposable
{
    private readonly IDisposable? storeLease = storeLease;

    internal X509Certificate2 Certificate { get; } = certificate;

    internal bool IsDisposed { get; private set; }

    public void Dispose()
    {
        if (IsDisposed)
        {
            return;
        }

        try
        {
            Certificate.Dispose();
        }
        finally
        {
            storeLease?.Dispose();
            IsDisposed = true;
        }
    }
}

internal static class SigningCertificateLifetime
{
    internal static NativeSigningResult Execute(
        ISigningCertificateSource source,
        CertificateReference reference,
        CertificateStoreLifetime storeLifetime,
        Func<X509Certificate2, NativeSigningResult> nativeCall)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(nativeCall);

        SigningCertificateSelection? selection = source.Select(reference, storeLifetime);
        if (selection is null)
        {
            return NativeSigningResult.Failure(NativeSigningReasonCode.CertificateNotFound, unchecked((int)0x80092004));
        }

        NativeSigningResult? primaryResult = null;
        ExceptionDispatchInfo? primaryException = null;
        try
        {
            primaryResult = nativeCall(selection.Certificate);
        }
        catch (Exception exception)
        {
            primaryException = ExceptionDispatchInfo.Capture(exception);
        }

        try
        {
            selection.Dispose();
        }
        catch (Exception) when (primaryException is not null || primaryResult is { Succeeded: false })
        {
        }

        primaryException?.Throw();
        return primaryResult ?? throw new InvalidOperationException("The native signing call completed without a result.");
    }
}

internal sealed class X509StoreSigningCertificateSource : ISigningCertificateSource
{
    private readonly ISigningCertificateStoreFactory storeFactory;

    internal X509StoreSigningCertificateSource()
        : this(new SystemSigningCertificateStoreFactory())
    {
    }

    internal X509StoreSigningCertificateSource(ISigningCertificateStoreFactory storeFactory)
    {
        ArgumentNullException.ThrowIfNull(storeFactory);
        this.storeFactory = storeFactory;
    }

    public SigningCertificateSelection? Select(
        CertificateReference reference,
        CertificateStoreLifetime storeLifetime)
    {
        ISigningCertificateStore store = storeFactory.Create(reference.StoreName, reference.StoreLocation);
        X509Certificate2? match = null;
        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certificates = store.Certificates;
            foreach (X509Certificate2 certificate in certificates)
            {
                string candidate = CertificateReference.NormalizeThumbprint(certificate.Thumbprint);
                if (match is null && string.Equals(candidate, reference.Thumbprint, StringComparison.Ordinal))
                {
                    match = certificate;
                }
                else
                {
                    certificate.Dispose();
                }
            }

            if (match is null)
            {
                store.Dispose();
                return null;
            }

            if (storeLifetime == CertificateStoreLifetime.ReleaseBeforeNativeCall)
            {
                store.Dispose();
                return new SigningCertificateSelection(match, null);
            }

            return new SigningCertificateSelection(match, store);
        }
        catch
        {
            match?.Dispose();
            store.Dispose();
            throw;
        }
    }
}

internal sealed class SystemSigningCertificateStoreFactory : ISigningCertificateStoreFactory
{
    public ISigningCertificateStore Create(string storeName, StoreLocation storeLocation) =>
        new SystemSigningCertificateStore(new X509Store(storeName, storeLocation));
}

internal sealed class SystemSigningCertificateStore(X509Store store) : ISigningCertificateStore
{
    public X509Certificate2Collection Certificates => store.Certificates;

    public void Open(OpenFlags openFlags) => store.Open(openFlags);

    public void Dispose() => store.Dispose();
}
