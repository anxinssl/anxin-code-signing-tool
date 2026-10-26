using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Core.Evidence;
using CodeSigner.Windows.Signing;

namespace CodeSigner.CompatibilityProbe.Signing;

internal sealed record CertificatePublicMetadata(
    StoreLocation StoreLocation,
    string StoreName,
    string Thumbprint,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool HasPrivateKey,
    IReadOnlyList<string> EnhancedKeyUsageOids,
    string SerialNumber = "",
    string PublicKeyAlgorithm = "");

internal interface ICertificateMetadataSource
{
    IReadOnlyList<CertificatePublicMetadata> Read(StoreLocation location, string storeName);
}

internal sealed class WindowsCertificateMetadataSource : ICertificateMetadataSource
{
    public IReadOnlyList<CertificatePublicMetadata> Read(StoreLocation location, string storeName)
    {
        using X509Store store = new(storeName, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        List<CertificatePublicMetadata> certificates = [];
        foreach (X509Certificate2 certificate in store.Certificates)
        {
            using (certificate)
            {
                certificates.Add(
                    new CertificatePublicMetadata(
                        location,
                        storeName,
                        certificate.Thumbprint.ToUpperInvariant(),
                        certificate.Subject,
                        certificate.Issuer,
                        certificate.NotBefore,
                        certificate.NotAfter,
                        certificate.HasPrivateKey,
                        certificate.Extensions
                            .OfType<X509EnhancedKeyUsageExtension>()
                            .SelectMany(static extension => extension.EnhancedKeyUsages.Cast<Oid>())
                            .Select(static oid => oid.Value ?? string.Empty)
                            .Where(static value => value.Length > 0)
                            .ToArray(),
                        certificate.SerialNumber,
                        certificate.PublicKey.Oid.Value ?? string.Empty));
            }
        }

        return certificates;
    }
}

internal static class CertificateReadinessCommand
{
    internal const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";

    internal static Task<int> RunAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken) =>
        RunAsync(arguments, output, new WindowsCertificateMetadataSource(), DateTimeOffset.Now, cancellationToken);

    internal static async Task<int> RunAsync(
        string[] arguments,
        Stream output,
        ICertificateMetadataSource source,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (arguments.Length != 4 ||
            !TryParseReference(arguments[1], arguments[2], arguments[3], out CertificateReference? reference))
        {
            return await WriteAsync(output, "failed", "InvalidArguments", null, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            IReadOnlyList<CertificatePublicMetadata> certificates = source.Read(reference.StoreLocation, reference.StoreName);
            CertificatePublicMetadata[] matches = certificates
                .Where(candidate => string.Equals(candidate.Thumbprint, reference.Thumbprint, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (matches.Length == 0)
            {
                CertificatePublicMetadata missing = new(
                    reference.StoreLocation,
                    reference.StoreName,
                    reference.Thumbprint,
                    string.Empty,
                    string.Empty,
                    default,
                    default,
                    false,
                    []);
                return await WriteAsync(output, "blocked", "CertificateNotFound", missing, cancellationToken).ConfigureAwait(false);
            }

            if (matches.Length != 1)
            {
                return await WriteAsync(output, "blocked", "CertificateAmbiguous", matches[0], cancellationToken).ConfigureAwait(false);
            }

            CertificatePublicMetadata certificate = matches[0];
            string reasonCode = Evaluate(certificate, now);
            string status = reasonCode == "CertificateReady" ? "passed" : "blocked";
            return await WriteAsync(output, status, reasonCode, certificate, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException)
        {
            return await WriteAsync(output, "failed", "CertificateStoreUnavailable", null, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string Evaluate(CertificatePublicMetadata certificate, DateTimeOffset now)
    {
        if (certificate.NotBefore > now)
        {
            return "CertificateNotYetValid";
        }

        if (certificate.NotAfter < now)
        {
            return "CertificateExpired";
        }

        if (!certificate.EnhancedKeyUsageOids.Contains(CodeSigningEkuOid, StringComparer.Ordinal))
        {
            return "CertificateWrongEku";
        }

        return certificate.HasPrivateKey ? "CertificateReady" : "CertificateHasNoPrivateKey";
    }

    private static bool TryParseReference(
        string storeLocation,
        string storeName,
        string thumbprint,
        [NotNullWhen(true)] out CertificateReference? reference)
    {
        StoreLocation? location = storeLocation switch
        {
            "CurrentUser" => StoreLocation.CurrentUser,
            "LocalMachine" => StoreLocation.LocalMachine,
            _ => null
        };
        if (location is null)
        {
            reference = null;
            return false;
        }

        try
        {
            reference = CertificateReference.Create(location.Value, storeName, thumbprint);
            return true;
        }
        catch (ArgumentException)
        {
            reference = null;
            return false;
        }
    }

    private static async Task<int> WriteAsync(
        Stream output,
        string status,
        string reasonCode,
        CertificatePublicMetadata? certificate,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = "certificate-readiness",
            ["status"] = status,
            ["reasonCode"] = reasonCode,
            ["publicCertificateSubject"] = EmptyToNull(certificate?.Subject),
            ["publicCertificateIssuer"] = EmptyToNull(certificate?.Issuer),
            ["publicCertificateThumbprint"] = EmptyToNull(certificate?.Thumbprint),
            ["publicCertificateSerialNumber"] = EmptyToNull(certificate?.SerialNumber),
            ["publicCertificateNotBefore"] = certificate is null || certificate.NotBefore == default ? null : certificate.NotBefore,
            ["publicCertificateNotAfter"] = certificate is null || certificate.NotAfter == default ? null : certificate.NotAfter,
            ["publicCertificateHasPrivateKey"] = certificate?.HasPrivateKey,
            ["publicCertificateEnhancedKeyUsages"] = certificate is null ? null : string.Join(",", certificate.EnhancedKeyUsageOids),
            ["certificateStoreLocation"] = certificate?.StoreLocation.ToString(),
            ["certificateStoreName"] = certificate?.StoreName,
            ["publicKeyAlgorithm"] = EmptyToNull(certificate?.PublicKeyAlgorithm)
        };
        await AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken).ConfigureAwait(false);
        return status switch
        {
            "passed" => 0,
            "blocked" => 20,
            "failed" when reasonCode == "InvalidArguments" => 64,
            "failed" => 1,
            _ => 70
        };
    }

    private static string? EmptyToNull(string? value) => string.IsNullOrEmpty(value) ? null : value;
}
