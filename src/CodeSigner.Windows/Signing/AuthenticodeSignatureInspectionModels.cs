using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

internal static class AuthenticodeOids
{
    internal const string Sha1 = "1.3.14.3.2.26";
    internal const string Sha256 = "2.16.840.1.101.3.4.2.1";
    internal const string Rfc3161CounterSignature = "1.3.6.1.4.1.311.3.3.1";
    internal const string LegacyCounterSignature = "1.2.840.113549.1.9.6";
    internal const string TimestampingEku = "1.3.6.1.5.5.7.3.8";
}

internal enum AuthenticodeTimestampKind
{
    Missing,
    LegacyCounterSignature,
    Rfc3161
}

internal sealed record AuthenticodeSignatureCountInspection(int TrustStatus, uint SecondarySignatureCount);

internal sealed record AuthenticodeTimestampInspection(
    AuthenticodeTimestampKind Kind,
    string? MessageImprintAlgorithmOid,
    bool CryptographicallyValid,
    bool ChainValid,
    bool TimeValid,
    bool TimestampingEkuValid);

internal sealed record AuthenticodeSignatureInspection(
    int TrustStatus,
    uint VerifiedSignatureIndex,
    string? FileDigestAlgorithmOid,
    string? SignerThumbprint,
    byte[] SignerCertificateDer,
    AuthenticodeTimestampInspection Timestamp);

internal interface IAuthenticodeSignatureInspector
{
    AuthenticodeSignatureCountInspection GetSignatureCount(string path);

    AuthenticodeSignatureInspection InspectSignature(string path, uint index);
}

internal interface ICertificateStoreMembership
{
    bool ContainsExact(CertificateReference reference, byte[] certificateDer);
}

internal sealed class WindowsCertificateStoreMembership : ICertificateStoreMembership
{
    public bool ContainsExact(CertificateReference reference, byte[] certificateDer)
    {
        try
        {
            using X509Store store = new(reference.StoreName, reference.StoreLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection matches = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                reference.Thumbprint,
                validOnly: false);
            try
            {
                return matches.OfType<X509Certificate2>()
                    .Any(certificate => certificate.RawDataMemory.Span.SequenceEqual(certificateDer));
            }
            finally
            {
                foreach (X509Certificate2 certificate in matches)
                {
                    certificate.Dispose();
                }
            }
        }
        catch (Exception exception) when (exception is
            System.Security.Cryptography.CryptographicException or
            System.Security.SecurityException or
            UnauthorizedAccessException)
        {
            return false;
        }
    }
}
