using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Readiness;

public enum WorkstationSupportStatus
{
    Supported,
    Unsupported
}

public enum SimplySignInstallationStatus
{
    Installed,
    NotInstalled
}

public enum CodeSignerInstallationStatus
{
    Installed,
    NotInstalled,
    Ambiguous,
    Advertised,
    Malformed,
    WindowsInstallerUnavailable
}

public enum WindowsInstallerInstallState
{
    Unknown = -1,
    BadConfig = -6,
    Incomplete = -5,
    SourceAbsent = -4,
    MoreData = -3,
    InvalidArg = -2,
    Advertised = 1,
    Absent = 2,
    Local = 3,
    Source = 4,
    Default = 5
}

public enum CertificateAvailabilityStatus
{
    CertificateAvailable,
    Unavailable
}

public enum ProviderAuthorizationStatus
{
    AuthorizationUnknown
}

public enum TimestampConfigurationStatus
{
    Configured,
    Invalid
}

public enum CertificateStoreReadStatus
{
    Success,
    AccessDenied,
    Unavailable
}

public enum CertificateStoreFailureDetail
{
    None,
    AccessDenied,
    CryptographicFailure
}

public enum WindowsPowerShellBridgeStatus
{
    Available,
    Unavailable,
    ExecutionDenied,
    UnsupportedVersion
}

public sealed record WorkstationReadiness(WorkstationSupportStatus Status, string DiagnosticCode);

public sealed record SimplySignInstallation(
    SimplySignInstallationStatus Status,
    string UpgradeCode,
    string? ProductCode,
    string? ProductName,
    string? Publisher,
    string? Version,
    string DiagnosticCode = "None");

public sealed record CodeSignerInstallation(
    CodeSignerInstallationStatus Status,
    string UpgradeCode,
    string? ProductCode,
    string? ProductName,
    string? Publisher,
    string? Version,
    string DiagnosticCode = "None")
{
    public bool IsInstalled => Status == CodeSignerInstallationStatus.Installed;
}

public sealed record EligibleCertificate(
    StoreLocation StoreLocation,
    string StoreName,
    string Thumbprint,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool HasPrivateKey,
    IReadOnlyList<string> EnhancedKeyUsageOids);

public sealed record CertificateStoreDiagnostic(
    StoreLocation StoreLocation,
    string StoreName,
    CertificateStoreReadStatus Status,
    CertificateStoreFailureDetail FailureDetail = CertificateStoreFailureDetail.None);

public sealed record CertificateCatalog(
    CertificateAvailabilityStatus Status,
    IReadOnlyList<EligibleCertificate> Certificates,
    IReadOnlyList<CertificateStoreDiagnostic> Stores);

public sealed record TimestampConfiguration(TimestampConfigurationStatus Status, Uri? Uri);

public sealed record WindowsPowerShellBridgeReadiness(
    WindowsPowerShellBridgeStatus Status,
    string? ExecutablePath,
    string? Version,
    string DiagnosticCode);

public sealed record ReadinessSnapshot(
    WorkstationReadiness Workstation,
    NativeApiAvailability NativeApi,
    SimplySignInstallation SimplySign,
    CertificateCatalog CertificateCatalog,
    TimestampConfiguration Timestamp,
    ProviderAuthorizationStatus Authorization,
    WindowsPowerShellBridgeReadiness? PowerShellBridge = null);

internal sealed record WindowsInstallerProductRegistration(
    string ProductCode,
    string ProductName,
    string Publisher,
    string Version,
    WindowsInstallerInstallState InstallState = WindowsInstallerInstallState.Default)
{
    public int InstallStateCode => (int)InstallState;
}

internal sealed record CertificateCandidate(
    string Thumbprint,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool HasPrivateKey,
    IReadOnlyList<string> EnhancedKeyUsageOids);

internal sealed record CertificateStoreReadResult(
    StoreLocation StoreLocation,
    string StoreName,
    CertificateStoreReadStatus Status,
    IReadOnlyList<CertificateCandidate> Certificates,
    CertificateStoreFailureDetail FailureDetail = CertificateStoreFailureDetail.None);
