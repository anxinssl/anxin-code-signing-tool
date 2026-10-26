namespace CodeSigner.Windows.Readiness;

public enum SdkSignToolDiscoveryStatus
{
    Available,
    Unavailable,
    Rejected
}

public enum SdkSignToolRejectionReason
{
    None,
    NoCanonicalCandidate,
    OutsideCanonicalHierarchy,
    MalformedSdkVersion,
    ReparsePoint,
    NotX64PortableExecutable,
    WindowsTrustFailed,
    PublisherMismatch,
    CompanyMismatch,
    ProductMismatch,
    IdentityMismatch,
    InvalidVersionMetadata,
    CandidateChanged,
    ProbeFailed
}

public sealed record TrustedSdkSignToolCandidate(
    string Path,
    Version SdkVersion,
    Version ProductVersion,
    string Publisher,
    string CompanyName,
    string ProductName,
    string Sha256);

public sealed record SdkSignToolDiscoveryResult(
    SdkSignToolDiscoveryStatus Status,
    TrustedSdkSignToolCandidate? Candidate,
    SdkSignToolRejectionReason RejectionReason,
    string? RejectedPath)
{
    public bool IsAvailable =>
        Status == SdkSignToolDiscoveryStatus.Available && Candidate is not null;

    public static SdkSignToolDiscoveryResult Available(TrustedSdkSignToolCandidate candidate) =>
        new(
            SdkSignToolDiscoveryStatus.Available,
            candidate ?? throw new ArgumentNullException(nameof(candidate)),
            SdkSignToolRejectionReason.None,
            RejectedPath: null);

    public static SdkSignToolDiscoveryResult Unavailable() =>
        new(
            SdkSignToolDiscoveryStatus.Unavailable,
            Candidate: null,
            SdkSignToolRejectionReason.NoCanonicalCandidate,
            RejectedPath: null);

    public static SdkSignToolDiscoveryResult Rejected(
        SdkSignToolRejectionReason reason,
        string? rejectedPath = null)
    {
        if (reason is SdkSignToolRejectionReason.None or SdkSignToolRejectionReason.NoCanonicalCandidate)
        {
            throw new ArgumentOutOfRangeException(nameof(reason), reason, "A rejected result requires a rejection reason.");
        }

        return new SdkSignToolDiscoveryResult(
            SdkSignToolDiscoveryStatus.Rejected,
            Candidate: null,
            reason,
            rejectedPath);
    }
}

public interface ITrustedSdkSignToolLocator
{
    SdkSignToolDiscoveryResult Discover();

    SdkSignToolDiscoveryResult Revalidate(TrustedSdkSignToolCandidate candidate);
}

public interface ISdkSignToolReadinessState
{
    SdkSignToolDiscoveryResult Current { get; }

    SdkSignToolDiscoveryResult Refresh();
}

public sealed class SdkSignToolReadinessState(ITrustedSdkSignToolLocator locator)
    : ISdkSignToolReadinessState
{
    private readonly ITrustedSdkSignToolLocator locator =
        locator ?? throw new ArgumentNullException(nameof(locator));
    private readonly object sync = new();
    private SdkSignToolDiscoveryResult current = SdkSignToolDiscoveryResult.Unavailable();

    public SdkSignToolDiscoveryResult Current
    {
        get
        {
            lock (sync)
            {
                return current;
            }
        }
    }

    public SdkSignToolDiscoveryResult Refresh()
    {
        SdkSignToolDiscoveryResult refreshed = locator.Discover();
        lock (sync)
        {
            current = refreshed;
            return current;
        }
    }
}
