using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.CompatibilityProbe.Signing;

internal sealed class DisposableCodeSigningCertificate : IDisposable
{
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";
    private static readonly TimeSpan RootStorePollInterval = TimeSpan.FromMilliseconds(250);
    private static readonly CngProvider KeyProvider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
    private readonly string keyName;
    private bool disposed;

    private DisposableCodeSigningCertificate(X509Certificate2 certificate, string keyName)
    {
        Certificate = certificate;
        this.keyName = keyName;
    }

    internal X509Certificate2 Certificate { get; }

    internal static DisposableCodeSigningCertificate Create()
    {
        string keyName = "CodeSigner-Todo2-" + Guid.NewGuid().ToString("N");
        CngKeyCreationParameters parameters = new()
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None,
            KeyUsage = CngKeyUsages.Signing,
            Provider = KeyProvider
        };
        parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
        using CngKey key = CngKey.Create(CngAlgorithm.Rsa, keyName, parameters);
        using RSACng rsa = new(key);
        CertificateRequest request = new(
            "CN=CodeSigner Todo2 Disposable",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(CreateBasicConstraintsExtension());
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        OidCollection usages = new();
        usages.Add(new Oid(CodeSigningEku));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
        return new DisposableCodeSigningCertificate(certificate, keyName);
    }

    internal static X509BasicConstraintsExtension CreateBasicConstraintsExtension()
    {
        return new X509BasicConstraintsExtension(false, false, 0, true);
    }

    internal void AddToCurrentUserMy()
    {
        AddToStore(StoreName.My, Certificate);
    }

    internal async Task<string> WritePublicCertificateAsync(
        string workDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workDirectory);
        string publicCertificatePath = Path.Combine(workDirectory, keyName + ".cer");
        await using FileStream destination = new(
            publicCertificatePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await destination.WriteAsync(
            Certificate.Export(X509ContentType.Cert),
            cancellationToken).ConfigureAwait(false);
        return publicCertificatePath;
    }

    internal async Task<bool> WaitForCurrentUserRootAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        long started = Stopwatch.GetTimestamp();
        while (Stopwatch.GetElapsedTime(started) < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ContainsExact(StoreName.Root, Certificate.Thumbprint))
            {
                return true;
            }

            TimeSpan remaining = timeout - Stopwatch.GetElapsedTime(started);
            TimeSpan delay = remaining < RootStorePollInterval ? remaining : RootStorePollInterval;
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        return ContainsExact(StoreName.Root, Certificate.Thumbprint);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        List<Exception> failures = [];
        TryCleanup(() => RemoveExact(StoreName.My, Certificate.Thumbprint), failures);
        TryCleanup(() => RemoveExact(StoreName.Root, Certificate.Thumbprint), failures);
        Certificate.Dispose();
        TryCleanup(DeleteKey, failures);
        disposed = true;
        if (failures.Count != 0)
        {
            throw new AggregateException("Disposable signing certificate cleanup failed.", failures);
        }
    }

    private static void AddToStore(StoreName storeName, X509Certificate2 certificate)
    {
        using X509Store store = new(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
    }

    private static void RemoveExact(StoreName storeName, string thumbprint)
    {
        using X509Store store = new(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (X509Certificate2 certificate in store.Certificates)
        {
            using (certificate)
            {
                if (string.Equals(certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    store.Remove(certificate);
                }
            }
        }
    }

    private static bool ContainsExact(StoreName storeName, string thumbprint)
    {
        using X509Store store = new(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (X509Certificate2 certificate in store.Certificates)
        {
            using (certificate)
            {
                if (string.Equals(certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private void DeleteKey()
    {
        if (!CngKey.Exists(keyName, KeyProvider, CngKeyOpenOptions.UserKey))
        {
            return;
        }

        using CngKey key = CngKey.Open(keyName, KeyProvider, CngKeyOpenOptions.UserKey);
        key.Delete();
    }

    private static void TryCleanup(Action action, List<Exception> failures)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException)
        {
            failures.Add(exception);
        }
    }
}
