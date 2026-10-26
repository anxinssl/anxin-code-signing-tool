using System.Security.Cryptography;
using System.Runtime.ExceptionServices;

namespace CodeSigner.Windows.Signing;

public sealed class CompatibilityGateRunner(
    INativeSigningLegExecutor signer,
    INativeSignedFileVerifier verifier)
{
    public async Task<CompatibilityGateResult> RunAsync(
        string inputPath,
        string outputPath,
        CompatibilitySigningPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(plan);
        string input = Path.GetFullPath(inputPath);
        string output = Path.GetFullPath(outputPath);
        if (!File.Exists(input) || string.Equals(input, output, StringComparison.OrdinalIgnoreCase))
        {
            return new(false, NativeSigningReasonCode.InvalidInput, unchecked((int)0x80070057), string.Empty, null);
        }

        string originalHash = await HashAsync(input, cancellationToken).ConfigureAwait(false);
        if (File.Exists(output))
        {
            return new(false, NativeSigningReasonCode.DestinationExists, unchecked((int)0x80070050), originalHash, null);
        }

        string? outputDirectory = Path.GetDirectoryName(output);
        if (string.IsNullOrEmpty(outputDirectory) || !Directory.Exists(outputDirectory))
        {
            return new(false, NativeSigningReasonCode.InvalidInput, unchecked((int)0x80070003), originalHash, null);
        }

        string staging = Path.Combine(outputDirectory, Path.GetFileNameWithoutExtension(output) + ".partial-" + Guid.NewGuid().ToString("N") + Path.GetExtension(output));
        CompatibilityGateResult? primaryResult = null;
        ExceptionDispatchInfo? primaryException = null;
        try
        {
            primaryResult = await ExecuteStagedAsync(
                input,
                output,
                staging,
                originalHash,
                plan,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            primaryResult = new(false, NativeSigningReasonCode.Cancelled, unchecked((int)0x800704C7), originalHash, null);
        }
        catch (Exception exception)
        {
            primaryException = ExceptionDispatchInfo.Capture(exception);
        }

        try
        {
            if (File.Exists(staging))
            {
                File.Delete(staging);
            }
        }
        catch (Exception) when (primaryResult is not null || primaryException is not null)
        {
        }

        primaryException?.Throw();
        return primaryResult ?? throw new InvalidOperationException("The compatibility gate completed without a result.");
    }

    private async Task<CompatibilityGateResult> ExecuteStagedAsync(
        string input,
        string output,
        string staging,
        string originalHash,
        CompatibilitySigningPlan plan,
        CancellationToken cancellationToken)
    {
        File.Copy(input, staging, overwrite: false);
        for (int index = 0; index < plan.Legs.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            NativeSigningResult legResult = await signer.ExecuteAsync(staging, plan.Legs[index], cancellationToken).ConfigureAwait(false);
            if (!legResult.Succeeded)
            {
                NativeSigningReasonCode reason = index == 1 && legResult.ReasonCode == NativeSigningReasonCode.NativeSigningFailed
                    ? NativeSigningReasonCode.SecondLegFailed
                    : legResult.ReasonCode;
                return new(false, reason, legResult.HResult, originalHash, null, index);
            }
        }

        NativeSigningResult verification = await verifier.VerifyAsync(staging, plan, cancellationToken).ConfigureAwait(false);
        if (!verification.Succeeded)
        {
            return new(false, verification.ReasonCode, verification.HResult, originalHash, null);
        }

        string currentOriginalHash = await HashAsync(input, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(originalHash, currentOriginalHash, StringComparison.Ordinal))
        {
            return new(false, NativeSigningReasonCode.OriginalChanged, unchecked((int)0x80004005), originalHash, null);
        }

        string outputHash = await HashAsync(staging, cancellationToken).ConfigureAwait(false);
        File.Move(staging, output);
        return new(true, NativeSigningReasonCode.None, 0, originalHash, outputHash);
    }

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }
}
