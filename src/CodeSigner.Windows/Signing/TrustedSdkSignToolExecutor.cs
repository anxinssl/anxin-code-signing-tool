using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;

namespace CodeSigner.Windows.Signing;

public enum SdkSignToolFallbackError
{
    None,
    InvalidInput,
    CandidateUnavailable,
    CandidateChanged,
    ProcessStartFailed,
    ProcessFailed,
    TimedOut,
    VerifierDisagreement,
    OriginalChanged,
    Cancelled
}

public enum SdkSignToolProcessOutcome
{
    Exited,
    StartFailed,
    TimedOut,
    Cancelled
}

public sealed record SdkSignToolInvocationReceipt(
    NativeDigestAlgorithm FileDigest,
    bool Append,
    SdkSignToolProcessOutcome Outcome,
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    bool StandardOutputTruncated,
    bool StandardErrorTruncated);

public sealed record SdkSignToolFallbackResult(
    bool Succeeded,
    SdkSignToolFallbackError Error,
    string OriginalSha256,
    string? StagedSha256,
    string? FreshStagedPath,
    IReadOnlyList<SdkSignToolInvocationReceipt> Invocations)
{
    public static SdkSignToolFallbackResult Failure(
        SdkSignToolFallbackError error,
        string originalSha256,
        IReadOnlyList<SdkSignToolInvocationReceipt>? invocations = null)
    {
        if (error == SdkSignToolFallbackError.None)
        {
            throw new ArgumentOutOfRangeException(nameof(error), error, "A failure requires a typed error.");
        }

        return new SdkSignToolFallbackResult(
            Succeeded: false,
            error,
            originalSha256,
            StagedSha256: null,
            FreshStagedPath: null,
            invocations ?? Array.Empty<SdkSignToolInvocationReceipt>());
    }
}

public sealed class SdkSignToolFallbackEligibility
{
    internal const int NoInterfaceHResult = unchecked((int)0x80004002);

    private SdkSignToolFallbackEligibility()
    {
    }

    public static bool TryCreate(
        NativeSigningResult directPeFailure,
        out SdkSignToolFallbackEligibility? eligibility)
    {
        ArgumentNullException.ThrowIfNull(directPeFailure);
        bool allowed = !directPeFailure.Succeeded &&
            directPeFailure.HResult == NoInterfaceHResult &&
            directPeFailure.ReasonCode is
                NativeSigningReasonCode.NativeSigningFailed or
                NativeSigningReasonCode.UnsupportedKeyAlgorithm;
        eligibility = allowed ? new SdkSignToolFallbackEligibility() : null;
        return allowed;
    }
}

public interface ITrustedSdkSignToolExecutor
{
    Task<SdkSignToolFallbackResult> ExecuteAsync(
        TrustedSdkSignToolCandidate selectedCandidate,
        SdkSignToolFallbackEligibility eligibility,
        string originalPath,
        string failedStagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        CancellationToken cancellationToken);
}

public sealed class TrustedSdkSignToolExecutor : ITrustedSdkSignToolExecutor
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);
    private readonly ITrustedSdkSignToolLocator locator;
    private readonly ITrustedSdkSignToolLaunchLeaseProvider? launchLeaseProvider;
    private readonly IProductionSignedFileVerifier verifier;
    private readonly ITrustedSdkSignToolProcessRunner processRunner;
    private readonly ISdkSignToolPristineStageFactory stageFactory;
    private readonly TimeSpan timeout;

    public TrustedSdkSignToolExecutor(
        ITrustedSdkSignToolLocator locator,
        IProductionSignedFileVerifier verifier)
        : this(
            locator,
            PeAuthenticodeStructuralVerifier.Wrap(
                new AuthenticodePeImageDigestProvider(),
                verifier),
            new TrustedSdkSignToolProcessRunner(),
            new SdkSignToolPristineStageFactory(),
            DefaultTimeout)
    {
    }

    internal TrustedSdkSignToolExecutor(
        ITrustedSdkSignToolLocator locator,
        IProductionSignedFileVerifier verifier,
        ITrustedSdkSignToolProcessRunner processRunner,
        ISdkSignToolPristineStageFactory stageFactory,
        TimeSpan timeout)
    {
        this.locator = locator ?? throw new ArgumentNullException(nameof(locator));
        launchLeaseProvider = locator as ITrustedSdkSignToolLaunchLeaseProvider;
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        this.stageFactory = stageFactory ?? throw new ArgumentNullException(nameof(stageFactory));
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        this.timeout = timeout;
    }

    public async Task<SdkSignToolFallbackResult> ExecuteAsync(
        TrustedSdkSignToolCandidate selectedCandidate,
        SdkSignToolFallbackEligibility eligibility,
        string originalPath,
        string failedStagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selectedCandidate);
        ArgumentNullException.ThrowIfNull(eligibility);
        ArgumentNullException.ThrowIfNull(plan);
        var invocations = new List<SdkSignToolInvocationReceipt>();
        string originalHash = string.Empty;
        string? freshStage = null;
        bool retainFreshStage = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryValidatePeInputs(originalPath, failedStagedPath, plan))
            {
                return SdkSignToolFallbackResult.Failure(
                    SdkSignToolFallbackError.InvalidInput,
                    originalHash,
                    invocations.AsReadOnly());
            }

            originalHash = await HashAsync(originalPath, cancellationToken).ConfigureAwait(false);
            freshStage = await stageFactory.CreatePristineAsync(
                originalPath,
                failedStagedPath,
                stagingOwnerPid,
                stagingOwnerStartUtc,
                cancellationToken).ConfigureAwait(false);
            if (Path.GetFullPath(freshStage).Equals(
                    Path.GetFullPath(failedStagedPath),
                    StringComparison.OrdinalIgnoreCase) ||
                !originalHash.Equals(
                    await HashAsync(freshStage, cancellationToken).ConfigureAwait(false),
                    StringComparison.Ordinal))
            {
                return SdkSignToolFallbackResult.Failure(
                    SdkSignToolFallbackError.InvalidInput,
                    originalHash,
                    invocations.AsReadOnly());
            }

            foreach (SignatureLeg leg in plan.Legs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                SdkSignToolDiscoveryResult revalidation = locator.Revalidate(selectedCandidate);
                if (!revalidation.IsAvailable)
                {
                    return SdkSignToolFallbackResult.Failure(
                        MapCandidateFailure(revalidation),
                        originalHash,
                        invocations.AsReadOnly());
                }

                TrustedSdkSignToolCandidate currentCandidate = revalidation.Candidate!;
                if (launchLeaseProvider is null)
                {
                    return SdkSignToolFallbackResult.Failure(
                        SdkSignToolFallbackError.CandidateUnavailable,
                        originalHash,
                        invocations.AsReadOnly());
                }

                SdkSignToolLaunchLeaseResult launch =
                    launchLeaseProvider.AcquireLaunchLease(currentCandidate);
                if (!launch.IsAvailable)
                {
                    return SdkSignToolFallbackResult.Failure(
                        MapCandidateFailure(launch.Revalidation),
                        originalHash,
                        invocations.AsReadOnly());
                }

                SdkSignToolProcessResult process;
                using (ITrustedSdkSignToolLaunchLease lease = launch.Lease!)
                {
                    currentCandidate = lease.Candidate;
                    ProcessStartInfo startInfo = CreateStartInfo(currentCandidate.Path, freshStage, leg);
                    process = await processRunner.RunAsync(
                        startInfo,
                        timeout,
                        cancellationToken).ConfigureAwait(false);
                }

                invocations.Add(CreateInvocationReceipt(
                    process,
                    leg,
                    currentCandidate.Path,
                    originalPath,
                    freshStage));
                if (process.Outcome != SdkSignToolProcessOutcome.Exited || process.ExitCode != 0)
                {
                    return SdkSignToolFallbackResult.Failure(
                        MapProcessFailure(process),
                        originalHash,
                        invocations.AsReadOnly());
                }
            }

            if (!await OriginalMatchesAsync(originalPath, originalHash, cancellationToken).ConfigureAwait(false))
            {
                return SdkSignToolFallbackResult.Failure(
                    SdkSignToolFallbackError.OriginalChanged,
                    originalHash,
                    invocations.AsReadOnly());
            }

            NativeSigningResult verification = await verifier.VerifyAsync(
                freshStage,
                plan,
                cancellationToken).ConfigureAwait(false);
            if (!verification.Succeeded ||
                verification.ReasonCode != NativeSigningReasonCode.None ||
                verification.HResult < 0)
            {
                return SdkSignToolFallbackResult.Failure(
                    SdkSignToolFallbackError.VerifierDisagreement,
                    originalHash,
                    invocations.AsReadOnly());
            }

            if (!await OriginalMatchesAsync(originalPath, originalHash, cancellationToken).ConfigureAwait(false))
            {
                return SdkSignToolFallbackResult.Failure(
                    SdkSignToolFallbackError.OriginalChanged,
                    originalHash,
                    invocations.AsReadOnly());
            }

            string stagedHash = await HashAsync(freshStage, cancellationToken).ConfigureAwait(false);
            retainFreshStage = true;
            return new SdkSignToolFallbackResult(
                Succeeded: true,
                SdkSignToolFallbackError.None,
                originalHash,
                stagedHash,
                freshStage,
                invocations.AsReadOnly());
        }
        catch (OperationCanceledException)
        {
            return SdkSignToolFallbackResult.Failure(
                SdkSignToolFallbackError.Cancelled,
                originalHash,
                invocations.AsReadOnly());
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            NotSupportedException or
            UnauthorizedAccessException or
            FilePipelineException or
            System.Security.SecurityException)
        {
            return SdkSignToolFallbackResult.Failure(
                SdkSignToolFallbackError.InvalidInput,
                originalHash,
                invocations.AsReadOnly());
        }
        finally
        {
            if (!retainFreshStage && freshStage is not null)
            {
                stageFactory.Delete(freshStage);
            }
        }
    }

    private static bool TryValidatePeInputs(
        string originalPath,
        string failedStagedPath,
        ProductionNativeSigningPlan plan)
    {
        if (string.IsNullOrWhiteSpace(originalPath) ||
            string.IsNullOrWhiteSpace(failedStagedPath) ||
            !File.Exists(originalPath) ||
            !File.Exists(failedStagedPath) ||
            Path.GetFullPath(originalPath).Equals(
                Path.GetFullPath(failedStagedPath),
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return plan.FormatFamily == CodeSigner.Core.Signing.SigningFormatFamily.PeImage &&
            plan.Capability == CodeSigner.Core.Signing.SigningCapability.PeImageDualCapable &&
            plan.Engine == CodeSigner.Core.Signing.SigningEngine.PeImage &&
            plan.Verification == CodeSigner.Core.Signing.SigningVerification.PeImage &&
            plan.Legs.Count is 1 or 2 &&
            Path.GetExtension(originalPath).Equals(plan.FileExtension, StringComparison.OrdinalIgnoreCase) &&
            Path.GetExtension(failedStagedPath).Equals(plan.FileExtension, StringComparison.OrdinalIgnoreCase);
    }

    private static ProcessStartInfo CreateStartInfo(
        string executablePath,
        string freshStage,
        SignatureLeg leg)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("sign");
        startInfo.ArgumentList.Add("/sha1");
        startInfo.ArgumentList.Add(leg.Certificate.Thumbprint);
        startInfo.ArgumentList.Add("/s");
        startInfo.ArgumentList.Add(leg.Certificate.StoreName);
        if (leg.Certificate.StoreLocation == System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine)
        {
            startInfo.ArgumentList.Add("/sm");
        }

        startInfo.ArgumentList.Add("/fd");
        startInfo.ArgumentList.Add(FormatDigest(leg.FileDigest));
        startInfo.ArgumentList.Add("/tr");
        startInfo.ArgumentList.Add(leg.TimestampUri.AbsoluteUri);
        startInfo.ArgumentList.Add("/td");
        startInfo.ArgumentList.Add(FormatDigest(leg.TimestampDigest));
        if (leg.Append)
        {
            startInfo.ArgumentList.Add("/as");
        }

        startInfo.ArgumentList.Add(freshStage);
        return startInfo;
    }

    private static string FormatDigest(NativeDigestAlgorithm digest) => digest switch
    {
        NativeDigestAlgorithm.Sha1 => "sha1",
        NativeDigestAlgorithm.Sha256 => "sha256",
        _ => throw new ArgumentOutOfRangeException(nameof(digest), digest, "Unsupported SignTool digest.")
    };

    private static SdkSignToolInvocationReceipt CreateInvocationReceipt(
        SdkSignToolProcessResult process,
        SignatureLeg leg,
        string executablePath,
        string originalPath,
        string freshStage)
    {
        string[] sensitiveValues =
        [
            executablePath,
            originalPath,
            freshStage,
            leg.Certificate.Thumbprint,
            leg.TimestampUri.AbsoluteUri
        ];
        SdkSignToolRedactedOutput stdout = SdkSignToolOutputRedactor.Redact(
            process.StandardOutput,
            sensitiveValues);
        SdkSignToolRedactedOutput stderr = SdkSignToolOutputRedactor.Redact(
            process.StandardError,
            sensitiveValues);
        return new SdkSignToolInvocationReceipt(
            leg.FileDigest,
            leg.Append,
            process.Outcome,
            process.ExitCode,
            stdout.Value,
            stderr.Value,
            process.StandardOutputTruncated || stdout.Truncated,
            process.StandardErrorTruncated || stderr.Truncated);
    }

    private static SdkSignToolFallbackError MapCandidateFailure(SdkSignToolDiscoveryResult result) =>
        result.RejectionReason == SdkSignToolRejectionReason.CandidateChanged
            ? SdkSignToolFallbackError.CandidateChanged
            : SdkSignToolFallbackError.CandidateUnavailable;

    private static SdkSignToolFallbackError MapProcessFailure(SdkSignToolProcessResult process) =>
        process.Outcome switch
        {
            SdkSignToolProcessOutcome.Cancelled => SdkSignToolFallbackError.Cancelled,
            SdkSignToolProcessOutcome.TimedOut => SdkSignToolFallbackError.TimedOut,
            SdkSignToolProcessOutcome.StartFailed => SdkSignToolFallbackError.ProcessStartFailed,
            _ => SdkSignToolFallbackError.ProcessFailed
        };

    private static async Task<bool> OriginalMatchesAsync(
        string originalPath,
        string expectedHash,
        CancellationToken cancellationToken) =>
        expectedHash.Equals(
            await HashAsync(originalPath, cancellationToken).ConfigureAwait(false),
            StringComparison.Ordinal);

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }
}

internal interface ISdkSignToolPristineStageFactory
{
    Task<string> CreatePristineAsync(
        string originalPath,
        string failedStagedPath,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        CancellationToken cancellationToken);

    void Delete(string path);
}

internal sealed class SdkSignToolPristineStageFactory : ISdkSignToolPristineStageFactory
{
    public async Task<string> CreatePristineAsync(
        string originalPath,
        string failedStagedPath,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        CancellationToken cancellationToken)
    {
        string canonicalFailedStage = TransactionalStaging.EnsureActiveOwnedStagedFile(
            failedStagedPath,
            stagingOwnerPid,
            stagingOwnerStartUtc);
        string directory = Path.GetDirectoryName(canonicalFailedStage)
            ?? throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The failed stage has no owning attempt directory.");
        string extension = Path.GetExtension(originalPath);
        string freshStage = Path.Combine(
            directory,
            $".codesigner-sdk-fallback-{Guid.NewGuid():N}{extension}");
        try
        {
            await using FileStream source = new(
                originalPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using FileStream destination = new(
                freshStage,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            _ = TransactionalStaging.EnsureActiveOwnedStagedFile(
                freshStage,
                stagingOwnerPid,
                stagingOwnerStartUtc);
            return freshStage;
        }
        catch
        {
            Delete(freshStage);
            throw;
        }
    }

    public void Delete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is
            IOException or
            UnauthorizedAccessException or
            System.Security.SecurityException)
        {
        }
    }
}

internal sealed record SdkSignToolProcessResult(
    SdkSignToolProcessOutcome Outcome,
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    bool StandardOutputTruncated,
    bool StandardErrorTruncated);

internal interface ITrustedSdkSignToolProcessRunner
{
    Task<SdkSignToolProcessResult> RunAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal sealed class TrustedSdkSignToolProcessRunner : ITrustedSdkSignToolProcessRunner
{
    private const int OutputLimit = 8192;

    public async Task<SdkSignToolProcessResult> RunAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            return new SdkSignToolProcessResult(
                SdkSignToolProcessOutcome.StartFailed,
                ExitCode: null,
                StandardOutput: string.Empty,
                StandardError: string.Empty,
                StandardOutputTruncated: false,
                StandardErrorTruncated: false);
        }

        if (process is null)
        {
            return new SdkSignToolProcessResult(
                SdkSignToolProcessOutcome.StartFailed,
                ExitCode: null,
                StandardOutput: string.Empty,
                StandardError: string.Empty,
                StandardOutputTruncated: false,
                StandardErrorTruncated: false);
        }

        using (process)
        {
            Task<BoundedText> stdout = ReadBoundedAsync(process.StandardOutput, OutputLimit);
            Task<BoundedText> stderr = ReadBoundedAsync(process.StandardError, OutputLimit);
            Task exit = process.WaitForExitAsync(CancellationToken.None);
            Task boundary = Task.Delay(timeout, cancellationToken);
            Task completed = await Task.WhenAny(exit, boundary).ConfigureAwait(false);
            if (completed != exit)
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }

                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }

            BoundedText standardOutput = await stdout.ConfigureAwait(false);
            BoundedText standardError = await stderr.ConfigureAwait(false);
            if (completed == exit)
            {
                await exit.ConfigureAwait(false);
                return new SdkSignToolProcessResult(
                    SdkSignToolProcessOutcome.Exited,
                    process.ExitCode,
                    standardOutput.Value,
                    standardError.Value,
                    standardOutput.Truncated,
                    standardError.Truncated);
            }

            return new SdkSignToolProcessResult(
                cancellationToken.IsCancellationRequested
                    ? SdkSignToolProcessOutcome.Cancelled
                    : SdkSignToolProcessOutcome.TimedOut,
                ExitCode: null,
                standardOutput.Value,
                standardError.Value,
                standardOutput.Truncated,
                standardError.Truncated);
        }
    }

    private static async Task<BoundedText> ReadBoundedAsync(StreamReader reader, int limit)
    {
        var builder = new StringBuilder(Math.Min(limit, 1024));
        char[] buffer = new char[1024];
        bool truncated = false;
        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            int remaining = limit - builder.Length;
            if (remaining > 0)
            {
                builder.Append(buffer, 0, Math.Min(read, remaining));
            }

            truncated |= read > remaining;
        }

        return new BoundedText(builder.ToString(), truncated);
    }

    private sealed record BoundedText(string Value, bool Truncated);
}

internal sealed record SdkSignToolRedactedOutput(string Value, bool Truncated);

internal static partial class SdkSignToolOutputRedactor
{
    private const int RedactedOutputLimit = 4096;

    public static SdkSignToolRedactedOutput Redact(string value, IEnumerable<string> sensitiveValues)
    {
        string redacted = value ?? string.Empty;
        foreach (string sensitive in sensitiveValues.Where(static item => !string.IsNullOrEmpty(item)))
        {
            redacted = redacted.Replace(sensitive, "[REDACTED_VALUE]", StringComparison.OrdinalIgnoreCase);
        }

        redacted = ThumbprintPattern().Replace(redacted, "[REDACTED_THUMBPRINT]");
        redacted = SecretAssignmentPattern().Replace(redacted, "$1[REDACTED_SECRET]");
        bool truncated = redacted.Length > RedactedOutputLimit;
        if (truncated)
        {
            redacted = redacted[..RedactedOutputLimit];
        }

        return new SdkSignToolRedactedOutput(redacted, truncated);
    }

    [GeneratedRegex("(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", RegexOptions.CultureInvariant)]
    private static partial Regex ThumbprintPattern();

    [GeneratedRegex("(?i)\\b(pin|password|token|secret)\\s*[:=]\\s*\\S+", RegexOptions.CultureInvariant)]
    private static partial Regex SecretAssignmentPattern();
}
