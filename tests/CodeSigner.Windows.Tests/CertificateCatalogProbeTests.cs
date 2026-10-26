using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.Windows.Tests;

public sealed class CertificateCatalogProbeTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RetainsExactIdentitiesAndFiltersIneligibleCertificates()
    {
        FakeCertificateStoreSource source = new(
            Success(StoreLocation.CurrentUser,
                Candidate('A', "CN=Duplicate", [CertificateCatalogProbe.CodeSigningEkuOid]),
                Candidate('B', "CN=Duplicate", [CertificateCatalogProbe.CodeSigningEkuOid]),
                Candidate('C', "CN=Expired", [CertificateCatalogProbe.CodeSigningEkuOid], notAfter: Now.AddMinutes(-1)),
                Candidate('D', "CN=Wrong Eku", ["1.3.6.1.5.5.7.3.2"]),
                Candidate('E', "CN=Public Only", [CertificateCatalogProbe.CodeSigningEkuOid], hasPrivateKey: false),
                Candidate('A', "CN=Duplicate", [CertificateCatalogProbe.CodeSigningEkuOid])),
            Success(StoreLocation.LocalMachine,
                Candidate('A', "CN=Duplicate", [CertificateCatalogProbe.CodeSigningEkuOid])));

        CertificateCatalog result = new CertificateCatalogProbe(source).Probe(Now);

        Assert.Equal(CertificateAvailabilityStatus.CertificateAvailable, result.Status);
        Assert.Equal(3, result.Certificates.Count);
        Assert.Equal(2, result.Certificates.Count(item => item.Subject == "CN=Duplicate" && item.StoreLocation == StoreLocation.CurrentUser));
        Assert.Contains(result.Certificates, item => item.StoreLocation == StoreLocation.LocalMachine && item.Thumbprint == new string('A', 40));
        Assert.All(result.Certificates, item =>
        {
            Assert.Equal(StoreName.My.ToString(), item.StoreName);
            Assert.True(item.HasPrivateKey);
            Assert.Contains(CertificateCatalogProbe.CodeSigningEkuOid, item.EnhancedKeyUsageOids);
        });
    }

    [Fact]
    public void LocalMachineAccessDenialPreservesStableCurrentUserResult()
    {
        FakeCertificateStoreSource source = new(
            Success(StoreLocation.CurrentUser),
            new(StoreLocation.LocalMachine, StoreName.My.ToString(), CertificateStoreReadStatus.AccessDenied, []));
        CertificateCatalogProbe probe = new(source);

        CertificateCatalog first = probe.Probe(Now);
        CertificateCatalog second = probe.Probe(Now);

        Assert.Equal(CertificateAvailabilityStatus.Unavailable, first.Status);
        Assert.Empty(first.Certificates);
        Assert.Equal(first.Status, second.Status);
        Assert.Empty(second.Certificates);
        Assert.Equal(first.Stores.Count, second.Stores.Count);
        for (int index = 0; index < first.Stores.Count; index++)
        {
            Assert.Equal(first.Stores[index], second.Stores[index]);
        }
        Assert.Contains(first.Stores, store =>
            store.StoreLocation == StoreLocation.LocalMachine && store.Status == CertificateStoreReadStatus.AccessDenied);
        Assert.Equal(
            [(StoreLocation.CurrentUser, StoreName.My), (StoreLocation.LocalMachine, StoreName.My)],
            source.Requests.Take(2));
    }

    [Fact]
    public void AccessDenialKeepsEligibleCertificatesAndTypedStoreFailure()
    {
        FakeCertificateStoreSource source = new(
            Success(StoreLocation.CurrentUser,
                Candidate('A', "CN=Eligible", [CertificateCatalogProbe.CodeSigningEkuOid])),
            new(
                StoreLocation.LocalMachine,
                StoreName.My.ToString(),
                CertificateStoreReadStatus.AccessDenied,
                [],
                CertificateStoreFailureDetail.AccessDenied));

        CertificateCatalog result = new CertificateCatalogProbe(source).Probe(Now);

        Assert.Equal(CertificateAvailabilityStatus.CertificateAvailable, result.Status);
        Assert.Single(result.Certificates);
        CertificateStoreDiagnostic denied = Assert.Single(
            result.Stores,
            store => store.StoreLocation == StoreLocation.LocalMachine);
        Assert.Equal(CertificateStoreReadStatus.AccessDenied, denied.Status);
        Assert.Equal(CertificateStoreFailureDetail.AccessDenied, denied.FailureDetail);
    }

    [Fact]
    public void WindowsSourceClassifiesExactAccessDeniedErrors()
    {
        int[] accessDeniedErrors = [5, unchecked((int)0x80070005)];

        foreach (int errorCode in accessDeniedErrors)
        {
            ThrowingSessionFactory factory = new(new CryptographicException(errorCode));
            WindowsCertificateStoreSource source = new(factory);

            CertificateStoreReadResult result = source.Read(StoreLocation.LocalMachine, StoreName.My);

            Assert.Equal(CertificateStoreReadStatus.AccessDenied, result.Status);
            Assert.Equal(CertificateStoreFailureDetail.AccessDenied, result.FailureDetail);
        }
    }

    [Fact]
    public void WindowsSourceDisposesOpenedSessionExactlyOnceWhenEnumerationFails()
    {
        ThrowingSession session = new(new CryptographicException(unchecked((int)0x80090016)));
        WindowsCertificateStoreSource source = new(new SingleSessionFactory(session));

        CertificateStoreReadResult result = source.Read(StoreLocation.LocalMachine, StoreName.My);

        Assert.Equal(CertificateStoreReadStatus.Unavailable, result.Status);
        Assert.Equal(CertificateStoreFailureDetail.CryptographicFailure, result.FailureDetail);
        Assert.Equal(1, session.DisposeCalls);
    }

    [Fact]
    public void MalformedThumbprintIsExcludedWithoutLosingStoreDiagnostic()
    {
        FakeCertificateStoreSource source = new(
            Success(StoreLocation.CurrentUser,
                Candidate('F', "CN=Malformed", [CertificateCatalogProbe.CodeSigningEkuOid]) with { Thumbprint = "bad" }),
            Success(StoreLocation.LocalMachine));

        CertificateCatalog result = new CertificateCatalogProbe(source).Probe(Now);

        Assert.Equal(CertificateAvailabilityStatus.Unavailable, result.Status);
        Assert.Empty(result.Certificates);
        Assert.All(result.Stores, store => Assert.Equal(CertificateStoreReadStatus.Success, store.Status));
    }

    [Fact]
    public void RereadsCertificateSourceInsteadOfReturningStaleCatalog()
    {
        MutableCertificateStoreSource source = new();
        CertificateCatalogProbe probe = new(source);

        CertificateCatalog empty = probe.Probe(Now);
        source.CurrentUserCertificates =
        [
            Candidate('A', "CN=New", [CertificateCatalogProbe.CodeSigningEkuOid])
        ];
        CertificateCatalog refreshed = probe.Probe(Now);

        Assert.Equal(CertificateAvailabilityStatus.Unavailable, empty.Status);
        Assert.Equal(CertificateAvailabilityStatus.CertificateAvailable, refreshed.Status);
        Assert.Single(refreshed.Certificates);
        Assert.Equal(4, source.ReadCalls);
    }

    [Fact]
    public void AppliesValidityBoundariesAndStableNormalizedIdentityOrdering()
    {
        string spacedLowerThumbprint = string.Join(' ', Enumerable.Repeat("dd", 20));
        FakeCertificateStoreSource source = new(
            new(
                StoreLocation.CurrentUser,
                StoreName.My.ToString(),
                CertificateStoreReadStatus.Success,
                [
                    Candidate('C', "CN=Third", [CertificateCatalogProbe.CodeSigningEkuOid]),
                    Candidate('B', "CN=Future", [CertificateCatalogProbe.CodeSigningEkuOid], notBefore: Now.AddTicks(1)),
                    Candidate('B', "CN=Ends Now", [CertificateCatalogProbe.CodeSigningEkuOid], notAfter: Now),
                    Candidate('A', "CN=Starts Now", [CertificateCatalogProbe.CodeSigningEkuOid], notBefore: Now),
                    Candidate('D', "CN=Spaced", [CertificateCatalogProbe.CodeSigningEkuOid]) with { Thumbprint = spacedLowerThumbprint }
                ]),
            Success(StoreLocation.LocalMachine));

        CertificateCatalog result = new CertificateCatalogProbe(source).Probe(Now);

        Assert.Equal(4, result.Certificates.Count);
        Assert.Equal(
            [new string('A', 40), new string('B', 40), new string('C', 40), new string('D', 40)],
            result.Certificates.Select(certificate => certificate.Thumbprint));
        Assert.DoesNotContain(result.Certificates, certificate => certificate.Subject == "CN=Future");
        Assert.Contains(result.Certificates, certificate => certificate.Subject == "CN=Starts Now");
        Assert.Contains(result.Certificates, certificate => certificate.Subject == "CN=Ends Now");
    }

    private static CertificateStoreReadResult Success(
        StoreLocation location,
        params CertificateCandidate[] certificates) =>
        new(location, StoreName.My.ToString(), CertificateStoreReadStatus.Success, certificates);

    private static CertificateCandidate Candidate(
        char thumbprintCharacter,
        string subject,
        IReadOnlyList<string> enhancedKeyUsageOids,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool hasPrivateKey = true) =>
        new(
            new string(thumbprintCharacter, 40),
            subject,
            "CN=Issuer",
            notBefore ?? Now.AddDays(-1),
            notAfter ?? Now.AddDays(1),
            hasPrivateKey,
            enhancedKeyUsageOids);

    private sealed class FakeCertificateStoreSource(params CertificateStoreReadResult[] results)
        : ICertificateStoreSource
    {
        public List<(StoreLocation, StoreName)> Requests { get; } = [];

        public CertificateStoreReadResult Read(StoreLocation storeLocation, StoreName storeName)
        {
            Requests.Add((storeLocation, storeName));
            return results.Single(result => result.StoreLocation == storeLocation);
        }
    }

    private sealed class ThrowingSessionFactory(Exception exception) : ICertificateStoreSessionFactory
    {
        public ICertificateStoreSession Open(StoreLocation storeLocation, StoreName storeName) => throw exception;
    }

    private sealed class SingleSessionFactory(ThrowingSession session) : ICertificateStoreSessionFactory
    {
        public ICertificateStoreSession Open(StoreLocation storeLocation, StoreName storeName) => session;
    }

    private sealed class ThrowingSession(Exception exception) : ICertificateStoreSession
    {
        public int DisposeCalls { get; private set; }

        public IReadOnlyList<CertificateCandidate> ReadCandidates() => throw exception;

        public void Dispose() => DisposeCalls++;
    }

    private sealed class MutableCertificateStoreSource : ICertificateStoreSource
    {
        public IReadOnlyList<CertificateCandidate> CurrentUserCertificates { get; set; } = [];
        public int ReadCalls { get; private set; }

        public CertificateStoreReadResult Read(StoreLocation storeLocation, StoreName storeName)
        {
            ReadCalls++;
            return new(
                storeLocation,
                storeName.ToString(),
                CertificateStoreReadStatus.Success,
                storeLocation == StoreLocation.CurrentUser ? CurrentUserCertificates : []);
        }
    }
}
