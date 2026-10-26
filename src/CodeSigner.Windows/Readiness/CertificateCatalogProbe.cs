using System.Security;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Readiness;

internal interface ICertificateStoreSource
{
    CertificateStoreReadResult Read(StoreLocation storeLocation, StoreName storeName);
}

internal interface ICertificateStoreSessionFactory
{
    ICertificateStoreSession Open(StoreLocation storeLocation, StoreName storeName);
}

internal interface ICertificateStoreSession : IDisposable
{
    IReadOnlyList<CertificateCandidate> ReadCandidates();
}

public sealed class CertificateCatalogProbe
{
    public const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";

    private static readonly (StoreLocation Location, StoreName Name)[] Stores =
    [
        (StoreLocation.CurrentUser, StoreName.My),
        (StoreLocation.LocalMachine, StoreName.My)
    ];

    private readonly ICertificateStoreSource storeSource;

    public CertificateCatalogProbe()
        : this(new WindowsCertificateStoreSource())
    {
    }

    internal CertificateCatalogProbe(ICertificateStoreSource storeSource)
    {
        this.storeSource = storeSource ?? throw new ArgumentNullException(nameof(storeSource));
    }

    public CertificateCatalog Probe() => Probe(DateTimeOffset.UtcNow);

    internal CertificateCatalog Probe(DateTimeOffset observedAt)
    {
        List<EligibleCertificate> certificates = [];
        List<CertificateStoreDiagnostic> diagnostics = [];
        HashSet<(StoreLocation Location, string Name, string Thumbprint)> identities = [];

        foreach ((StoreLocation location, StoreName name) in Stores)
        {
            CertificateStoreReadResult result = storeSource.Read(location, name);
            diagnostics.Add(new(location, name.ToString(), result.Status, result.FailureDetail));
            if (result.Status != CertificateStoreReadStatus.Success)
            {
                continue;
            }

            AddEligibleCertificates(result, observedAt, identities, certificates);
        }

        EligibleCertificate[] ordered = certificates
            .OrderBy(certificate => certificate.StoreLocation)
            .ThenBy(certificate => certificate.StoreName, StringComparer.Ordinal)
            .ThenBy(certificate => certificate.Thumbprint, StringComparer.Ordinal)
            .ToArray();
        return new(
            ordered.Length == 0
                ? CertificateAvailabilityStatus.Unavailable
                : CertificateAvailabilityStatus.CertificateAvailable,
            ordered,
            diagnostics.ToArray());
    }

    private static void AddEligibleCertificates(
        CertificateStoreReadResult result,
        DateTimeOffset observedAt,
        HashSet<(StoreLocation Location, string Name, string Thumbprint)> identities,
        List<EligibleCertificate> output)
    {
        foreach (CertificateCandidate candidate in result.Certificates)
        {
            if (!candidate.HasPrivateKey
                || candidate.NotBefore > observedAt
                || candidate.NotAfter < observedAt
                || !candidate.EnhancedKeyUsageOids.Contains(CodeSigningEkuOid, StringComparer.Ordinal))
            {
                continue;
            }

            string thumbprint;
            try
            {
                thumbprint = CertificateReference.Create(
                    result.StoreLocation,
                    result.StoreName,
                    candidate.Thumbprint).Thumbprint;
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (!identities.Add((result.StoreLocation, result.StoreName, thumbprint)))
            {
                continue;
            }

            output.Add(new(
                result.StoreLocation,
                result.StoreName,
                thumbprint,
                candidate.Subject,
                candidate.Issuer,
                candidate.NotBefore,
                candidate.NotAfter,
                candidate.HasPrivateKey,
                candidate.EnhancedKeyUsageOids.ToArray()));
        }
    }
}

internal sealed class WindowsCertificateStoreSource : ICertificateStoreSource
{
    private const int ErrorAccessDenied = 5;
    private const int HResultAccessDenied = unchecked((int)0x80070005);

    private readonly ICertificateStoreSessionFactory sessionFactory;

    public WindowsCertificateStoreSource()
        : this(new WindowsCertificateStoreSessionFactory())
    {
    }

    internal WindowsCertificateStoreSource(ICertificateStoreSessionFactory sessionFactory)
    {
        this.sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));
    }

    public CertificateStoreReadResult Read(StoreLocation storeLocation, StoreName storeName)
    {
        try
        {
            using ICertificateStoreSession session = sessionFactory.Open(storeLocation, storeName);
            return new(
                storeLocation,
                storeName.ToString(),
                CertificateStoreReadStatus.Success,
                session.ReadCandidates());
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException)
        {
            return AccessDenied(storeLocation, storeName);
        }
        catch (CryptographicException exception) when (IsAccessDenied(exception))
        {
            return AccessDenied(storeLocation, storeName);
        }
        catch (CryptographicException)
        {
            return new(
                storeLocation,
                storeName.ToString(),
                CertificateStoreReadStatus.Unavailable,
                [],
                CertificateStoreFailureDetail.CryptographicFailure);
        }
    }

    private static CertificateStoreReadResult AccessDenied(StoreLocation storeLocation, StoreName storeName) =>
        new(
            storeLocation,
            storeName.ToString(),
            CertificateStoreReadStatus.AccessDenied,
            [],
            CertificateStoreFailureDetail.AccessDenied);

    private static bool IsAccessDenied(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is UnauthorizedAccessException
                || current.HResult is ErrorAccessDenied or HResultAccessDenied
                || current is Win32Exception { NativeErrorCode: ErrorAccessDenied })
            {
                return true;
            }
        }

        return false;
    }
}

internal sealed class WindowsCertificateStoreSessionFactory : ICertificateStoreSessionFactory
{
    public ICertificateStoreSession Open(StoreLocation storeLocation, StoreName storeName) =>
        new WindowsCertificateStoreSession(storeLocation, storeName);
}

internal sealed class WindowsCertificateStoreSession : ICertificateStoreSession
{
    private readonly X509Store store;

    public WindowsCertificateStoreSession(StoreLocation storeLocation, StoreName storeName)
    {
        store = new(storeName, storeLocation);
        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    public IReadOnlyList<CertificateCandidate> ReadCandidates()
    {
        List<CertificateCandidate> certificates = [];
        foreach (X509Certificate2 certificate in store.Certificates)
        {
            using (certificate)
            {
                certificates.Add(CreateCandidate(certificate));
            }
        }

        return certificates;
    }

    public void Dispose() => store.Dispose();

    private static CertificateCandidate CreateCandidate(X509Certificate2 certificate)
    {
        string[] ekuOids = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .Select(oid => oid.Value)
            .Where(value => value is not null)
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return new(
            certificate.Thumbprint,
            certificate.Subject,
            certificate.Issuer,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            certificate.HasPrivateKey,
            ekuOids);
    }
}
