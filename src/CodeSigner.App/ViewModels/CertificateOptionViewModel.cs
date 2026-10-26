using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.App.ViewModels;

public sealed class CertificateOptionViewModel(EligibleCertificate certificate)
{
    public EligibleCertificate Certificate { get; } = certificate;

    public string Subject => Certificate.Subject;

    public string Issuer => Certificate.Issuer;

    public string Expiry => Certificate.NotAfter.ToLocalTime().ToString(
        "yyyy-MM-dd HH:mm:ss zzz",
        CultureInfo.InvariantCulture);

    public string Store => $"{Certificate.StoreLocation}\\{Certificate.StoreName}";

    public string Thumbprint => Certificate.Thumbprint;

    public string DisplayName => $"{Subject}，到期 {Certificate.NotAfter.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}";

    public string AutomationName =>
        $"{Subject}；颁发者 {Issuer}；到期 {Expiry}；存储位置 {Store}；指纹 {Thumbprint}";

    public CertificateRef ToCertificateRef()
    {
        CertificateStoreLocation location = Certificate.StoreLocation switch
        {
            StoreLocation.CurrentUser => CertificateStoreLocation.CurrentUser,
            StoreLocation.LocalMachine => CertificateStoreLocation.LocalMachine,
            _ => throw new InvalidOperationException("The certificate store location is unsupported.")
        };
        PolicyResult<CertificateRef> result = CertificateRef.TryCreate(
            location,
            Certificate.StoreName,
            Certificate.Thumbprint);
        return result.IsSuccess
            ? result.Value!
            : throw new InvalidOperationException(result.Errors[0].Message);
    }
}
