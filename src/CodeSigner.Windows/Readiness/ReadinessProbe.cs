using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Readiness;

public sealed class ReadinessProbe
{
    private readonly Func<WorkstationReadiness> workstationProbe;
    private readonly Func<NativeApiAvailability> nativeApiProbe;
    private readonly Func<SimplySignInstallation> simplySignProbe;
    private readonly Func<CertificateCatalog> certificateCatalogProbe;
    private readonly Func<WindowsPowerShellBridgeReadiness> powerShellBridgeProbe;

    public ReadinessProbe()
        : this(
            () => new WorkstationReadinessProbe().Probe(),
            Mssign32AvailabilityProbe.Probe,
            () => new SimplySignInstallationProbe().Probe(),
            () => new CertificateCatalogProbe().Probe(),
            () => new WindowsPowerShellBridgeReadinessProbe()
                .ProbeAsync(CancellationToken.None)
                .GetAwaiter()
                .GetResult())
    {
    }

    internal ReadinessProbe(
        Func<WorkstationReadiness> workstationProbe,
        Func<NativeApiAvailability> nativeApiProbe,
        Func<SimplySignInstallation> simplySignProbe,
        Func<CertificateCatalog> certificateCatalogProbe)
        : this(
            workstationProbe,
            nativeApiProbe,
            simplySignProbe,
            certificateCatalogProbe,
            static () => new WindowsPowerShellBridgeReadiness(
                WindowsPowerShellBridgeStatus.Unavailable,
                ExecutablePath: null,
                Version: null,
                "NotProbed"))
    {
    }

    internal ReadinessProbe(
        Func<WorkstationReadiness> workstationProbe,
        Func<NativeApiAvailability> nativeApiProbe,
        Func<SimplySignInstallation> simplySignProbe,
        Func<CertificateCatalog> certificateCatalogProbe,
        Func<WindowsPowerShellBridgeReadiness> powerShellBridgeProbe)
    {
        this.workstationProbe = workstationProbe ?? throw new ArgumentNullException(nameof(workstationProbe));
        this.nativeApiProbe = nativeApiProbe ?? throw new ArgumentNullException(nameof(nativeApiProbe));
        this.simplySignProbe = simplySignProbe ?? throw new ArgumentNullException(nameof(simplySignProbe));
        this.certificateCatalogProbe = certificateCatalogProbe ?? throw new ArgumentNullException(nameof(certificateCatalogProbe));
        this.powerShellBridgeProbe = powerShellBridgeProbe ?? throw new ArgumentNullException(nameof(powerShellBridgeProbe));
    }

    public ReadinessSnapshot Probe(Uri configuredTimestampUri)
    {
        ArgumentNullException.ThrowIfNull(configuredTimestampUri);
        bool usesHttp = configuredTimestampUri.IsAbsoluteUri
            && (string.Equals(configuredTimestampUri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                || string.Equals(configuredTimestampUri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal));
        TimestampConfiguration timestamp = configuredTimestampUri.IsAbsoluteUri && usesHttp
            ? new(TimestampConfigurationStatus.Configured, configuredTimestampUri)
            : new(TimestampConfigurationStatus.Invalid, null);
        return new(
            workstationProbe(),
            nativeApiProbe(),
            simplySignProbe(),
            certificateCatalogProbe(),
            timestamp,
            ProviderAuthorizationStatus.AuthorizationUnknown,
            powerShellBridgeProbe());
    }
}
