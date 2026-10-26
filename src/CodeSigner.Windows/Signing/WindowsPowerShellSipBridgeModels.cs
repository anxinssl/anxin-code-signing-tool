using System.Diagnostics;
using CodeSigner.Core.Signing;

namespace CodeSigner.Windows.Signing;

public enum WindowsSipSigningError
{
    None,
    InvalidInput,
    PowerShellUnavailable,
    ExecutionDenied,
    SipUnavailable,
    PackageIncompatible,
    CertificateMismatch,
    CertificateNotFound,
    CertificateHasNoPrivateKey,
    ExistingSignatureRejected,
    ProviderCancelled,
    TimestampUnavailable,
    VerificationFailed,
    MalformedResponse,
    ProcessFailed,
    OriginalChanged,
    Cancelled
}

public sealed record WindowsSipSigningResult(
    bool Succeeded,
    WindowsSipSigningError Error,
    int HResult,
    string OriginalSha256,
    string? StagedSha256,
    bool SkippedExistingSignature = false)
{
    public static WindowsSipSigningResult Success(
        string originalSha256,
        string stagedSha256,
        bool skippedExistingSignature = false) => new(
        true,
        WindowsSipSigningError.None,
        0,
        originalSha256,
        stagedSha256,
        skippedExistingSignature);

    public static WindowsSipSigningResult Failure(
        WindowsSipSigningError error,
        int hResult,
        string originalSha256 = "")
    {
        if (error == WindowsSipSigningError.None)
        {
            throw new ArgumentOutOfRangeException(nameof(error), error, "A failure requires a typed error.");
        }

        return new WindowsSipSigningResult(false, error, hResult, originalSha256, null);
    }
}

public enum WindowsSipSigningPhase
{
    Signing,
    Verifying
}

public interface IWindowsSipSigningBridge
{
    Task<WindowsSipSigningResult> ExecuteAsync(
        string originalPath,
        string stagedPath,
        SigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        Func<WindowsSipSigningPhase, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken);
}

internal enum WindowsPowerShellProcessStartFailure
{
    None,
    MissingExecutable,
    ExecutionDenied,
    Other
}

internal sealed record WindowsPowerShellProcessResult(
    int ExitCode,
    WindowsPowerShellProcessStartFailure StartFailure = WindowsPowerShellProcessStartFailure.None,
    byte[]? StandardOutput = null,
    bool StandardOutputLimitExceeded = false,
    int StandardErrorBytes = 0,
    bool StandardErrorLimitExceeded = false,
    string? StandardErrorDiagnostic = null);

internal interface IWindowsPowerShellProcessRunner
{
    Task<WindowsPowerShellProcessResult> RunAsync(
        ProcessStartInfo startInfo,
        CancellationToken cancellationToken) => RunAsync(startInfo, standardInput: null, cancellationToken);

    Task<WindowsPowerShellProcessResult> RunAsync(
        ProcessStartInfo startInfo,
        string? standardInput,
        CancellationToken cancellationToken);
}

internal interface IWindowsPowerShellEnvironment
{
    bool IsWindows { get; }

    string WindowsDirectory { get; }

    bool FileExists(string path);

    FileAttributes GetAttributes(string path);
}

internal interface IWindowsSipAtomicFileReplacer
{
    bool TryReplace(
        string sourcePath,
        WindowsSipFileIdentity expectedSourceIdentity,
        string expectedSourceSha256,
        string destinationPath,
        WindowsSipFileIdentity expectedDestinationIdentity,
        string expectedDestinationSha256);
}

internal readonly record struct WindowsSipFileIdentity(uint VolumeSerialNumber, ulong FileIndex);

internal enum WindowsSipVerificationError
{
    None,
    PackageIncompatible,
    CertificateMismatch,
    VerificationFailed
}

internal sealed record WindowsSipVerificationResult(
    bool Succeeded,
    WindowsSipVerificationError Error)
{
    internal static WindowsSipVerificationResult Success() => new(true, WindowsSipVerificationError.None);

    internal static WindowsSipVerificationResult Failure(WindowsSipVerificationError error) => new(false, error);
}

internal interface IWindowsSipSignatureVerifier
{
    WindowsSipVerificationResult VerifySigned(
        string originalPath,
        string stagedPath,
        SigningPlan plan);

    WindowsSipVerificationResult VerifyExisting(
        string originalPath,
        string stagedPath,
        SigningPlan plan);
}
