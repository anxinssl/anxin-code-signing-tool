using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class StoreRetainedCertificateLifetimeTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private static readonly CertificateReference Certificate =
        CertificateReference.Create(StoreLocation.CurrentUser, "My", Thumbprint);

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void DefaultExecutorKeepsCertificateStoreOpenThroughNativeCompletion()
    {
        Assert.Equal(
            CertificateStoreLifetime.RetainThroughNativeCall,
            Mssign32LegExecutor.DefaultCertificateStoreLifetime);
        (X509StoreSigningCertificateSource source, CertificateReference reference, RecordingCertificateStore store) =
            CreateProductionSource();

        NativeSigningResult result = SigningCertificateLifetime.Execute(
            source,
            reference,
            Mssign32LegExecutor.DefaultCertificateStoreLifetime,
            certificate =>
            {
                Assert.False(store.IsDisposed);
                Assert.False(store.Certificate.IsDisposed);
                Assert.NotEqual(nint.Zero, certificate.Handle);
                return NativeSigningResult.Success();
            });

        Assert.True(result.Succeeded);
        Assert.True(store.Certificate.IsDisposed);
        Assert.True(store.IsDisposed);
        Assert.Equal(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly, store.OpenFlags);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("Category", "NativeSigning")]
    public void DiagnosticLeaseStaysAliveThroughNativeCompletionAndDisposesAfter(bool nativeSucceeds)
    {
        (X509StoreSigningCertificateSource source, CertificateReference reference, RecordingCertificateStore store) =
            CreateProductionSource();

        NativeSigningResult result = SigningCertificateLifetime.Execute(
            source,
            reference,
            CertificateStoreLifetime.RetainThroughNativeCall,
            certificate =>
            {
                Assert.False(store.IsDisposed);
                Assert.False(store.Certificate.IsDisposed);
                Assert.NotEqual(nint.Zero, certificate.Handle);
                return nativeSucceeds
                    ? NativeSigningResult.Success()
                    : NativeSigningResult.Failure(NativeSigningReasonCode.NativeSigningFailed, unchecked((int)0x80090020));
            });

        Assert.Equal(nativeSucceeds, result.Succeeded);
        Assert.True(store.Certificate.IsDisposed);
        Assert.True(store.IsDisposed);
    }

    [Fact]
    [Trait("Category", "NativeSigning")]
    public void DiagnosticLeaseDisposesAfterNativeException()
    {
        (X509StoreSigningCertificateSource source, CertificateReference reference, RecordingCertificateStore store) =
            CreateProductionSource();

        Assert.Throws<InvalidOperationException>(() => SigningCertificateLifetime.Execute(
            source,
            reference,
            CertificateStoreLifetime.RetainThroughNativeCall,
            certificate =>
            {
                Assert.False(store.IsDisposed);
                Assert.False(store.Certificate.IsDisposed);
                Assert.NotEqual(nint.Zero, certificate.Handle);
                throw new InvalidOperationException("Synthetic native failure.");
            }));

        Assert.True(store.Certificate.IsDisposed);
        Assert.True(store.IsDisposed);
    }

    [Theory]
    [InlineData(CleanupFailureTarget.Certificate)]
    [InlineData(CleanupFailureTarget.Store)]
    [Trait("Category", "NativeSigning")]
    public void CleanupFailureNeverOverwritesReturnedNativeFailure(CleanupFailureTarget target)
    {
        using X509Certificate2 sourceCertificate = CreateCertificate();
        SigningCertificateSelection selection = CreateThrowingSelection(sourceCertificate, target);
        FixedSelectionSource source = new(selection);
        NativeSigningResult expected = NativeSigningResult.Failure(
            NativeSigningReasonCode.TimestampUnavailable,
            unchecked((int)0x80072EE7));

        NativeSigningResult actual = SigningCertificateLifetime.Execute(
            source,
            Certificate,
            CertificateStoreLifetime.RetainThroughNativeCall,
            _ => expected);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(CleanupFailureTarget.Certificate)]
    [InlineData(CleanupFailureTarget.Store)]
    [Trait("Category", "NativeSigning")]
    public void CleanupFailureNeverOverwritesThrownNativeException(CleanupFailureTarget target)
    {
        using X509Certificate2 sourceCertificate = CreateCertificate();
        SigningCertificateSelection selection = CreateThrowingSelection(sourceCertificate, target);
        FixedSelectionSource source = new(selection);
        InvalidOperationException primary = new("Synthetic native exception.");

        InvalidOperationException actual = Assert.Throws<InvalidOperationException>(() =>
            SigningCertificateLifetime.Execute(
                source,
                Certificate,
                CertificateStoreLifetime.RetainThroughNativeCall,
                _ => throw primary));

        Assert.Same(primary, actual);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=Store Retained Diagnostic Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
    }

    private static SigningCertificateSelection CreateThrowingSelection(
        X509Certificate2 sourceCertificate,
        CleanupFailureTarget target)
    {
        X509Certificate2 certificate = target == CleanupFailureTarget.Certificate
            ? new ThrowingCertificate(sourceCertificate)
            : new X509Certificate2(sourceCertificate);
        IDisposable storeLease = target == CleanupFailureTarget.Store
            ? new ThrowingDisposable()
            : new TrackingDisposable();
        return new SigningCertificateSelection(certificate, storeLease);
    }

    private static (
        X509StoreSigningCertificateSource Source,
        CertificateReference Reference,
        RecordingCertificateStore Store) CreateProductionSource()
    {
        using X509Certificate2 sourceCertificate = CreateCertificate();
        TrackingCertificate certificate = new(sourceCertificate);
        RecordingCertificateStore store = new(certificate);
        RecordingCertificateStoreFactory factory = new(store);
        CertificateReference reference = CertificateReference.Create(
            StoreLocation.CurrentUser,
            "My",
            certificate.Thumbprint);
        return (new X509StoreSigningCertificateSource(factory), reference, store);
    }

    private sealed class RecordingCertificateStoreFactory(RecordingCertificateStore store)
        : ISigningCertificateStoreFactory
    {
        public ISigningCertificateStore Create(string storeName, StoreLocation storeLocation)
        {
            Assert.Equal("My", storeName);
            Assert.Equal(StoreLocation.CurrentUser, storeLocation);
            return store;
        }
    }

    private sealed class RecordingCertificateStore(TrackingCertificate certificate)
        : ISigningCertificateStore
    {
        public TrackingCertificate Certificate { get; } = certificate;
        public OpenFlags? OpenFlags { get; private set; }
        public bool IsDisposed { get; private set; }
        public X509Certificate2Collection Certificates { get; } = [certificate];

        public void Open(OpenFlags openFlags)
        {
            Assert.False(IsDisposed);
            OpenFlags = openFlags;
        }

        public void Dispose() => IsDisposed = true;
    }

    private sealed class TrackingDisposable : IDisposable
    {
        public bool IsDisposed { get; private set; }

        public void Dispose() => IsDisposed = true;
    }

    private sealed class FixedSelectionSource(SigningCertificateSelection selection) : ISigningCertificateSource
    {
        public SigningCertificateSelection? Select(
            CertificateReference reference,
            CertificateStoreLifetime storeLifetime) => selection;
    }

    private sealed class ThrowingCertificate(X509Certificate2 source) : X509Certificate2(source)
    {
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                throw new CleanupException("Certificate cleanup failed.");
            }
        }
    }

    private sealed class TrackingCertificate(X509Certificate2 source) : X509Certificate2(source)
    {
        public bool IsDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class ThrowingDisposable : IDisposable
    {
        public void Dispose() => throw new CleanupException("Store cleanup failed.");
    }

    private sealed class CleanupException(string message) : Exception(message);

    public enum CleanupFailureTarget
    {
        Certificate,
        Store
    }
}
