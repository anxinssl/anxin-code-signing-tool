using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.CompatibilityProbe.Oracle;
using CodeSigner.Core.Evidence;
using CodeSigner.Windows.Signing;

namespace CodeSigner.CompatibilityProbe.Signing;

internal static class SelfSignedCompatibilityGate
{
    private static readonly TimeSpan ExternalVerifierTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan RootTrustTimeout = TimeSpan.FromMinutes(5);

    internal static async Task<int> RunAsync(string[] arguments, Stream output, CancellationToken cancellationToken)
    {
        if (arguments.Length != 5 ||
            !File.Exists(arguments[1]) ||
            !Directory.Exists(arguments[2]) ||
            !Uri.TryCreate(arguments[3], UriKind.Absolute, out Uri? timestampUri) ||
            timestampUri.Scheme is not ("http" or "https"))
        {
            return await WriteReceiptAsync(output, "failed", "InvalidArguments", null, null, cancellationToken).ConfigureAwait(false);
        }

        OracleResolution oracle = new ExternalSignToolResolver(new WindowsExternalExecutableProbe()).Resolve(arguments[4]);
        if (!oracle.IsApproved)
        {
            return await WriteReceiptAsync(output, "blocked", oracle.ReasonCode.ToString(), null, null, cancellationToken).ConfigureAwait(false);
        }

        string singleOutput = Path.Combine(arguments[2], "self-signed-single-" + Guid.NewGuid().ToString("N") + ".exe");
        string dualOutput = Path.Combine(arguments[2], "self-signed-dual-" + Guid.NewGuid().ToString("N") + ".exe");
        string? publicCertificatePath = null;
        string? thumbprint = null;
        try
        {
            try
            {
                using DisposableCodeSigningCertificate disposableCertificate = DisposableCodeSigningCertificate.Create();
                thumbprint = NormalizeThumbprint(disposableCertificate.Certificate.Thumbprint);
                disposableCertificate.AddToCurrentUserMy();
                publicCertificatePath = await disposableCertificate.WritePublicCertificateAsync(
                    arguments[2],
                    cancellationToken).ConfigureAwait(false);
                await WriteCertificateCreatedReceiptAsync(
                    output,
                    Path.GetFileName(publicCertificatePath),
                    thumbprint,
                    cancellationToken).ConfigureAwait(false);
                bool rootTrusted = await disposableCertificate.WaitForCurrentUserRootAsync(
                    RootTrustTimeout,
                    cancellationToken).ConfigureAwait(false);
                if (!rootTrusted)
                {
                    return await WriteReceiptAsync(
                        output,
                        "blocked",
                        "RootTrustTimedOut",
                        thumbprint,
                        null,
                        cancellationToken).ConfigureAwait(false);
                }

                return await RunSigningGateAsync(
                    arguments,
                    output,
                    timestampUri,
                    thumbprint,
                    singleOutput,
                    dualOutput,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                DeleteIfPresent(publicCertificatePath);
                DeleteIfPresent(singleOutput);
                DeleteIfPresent(dualOutput);
            }
        }
        catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
        {
            return await WriteReceiptAsync(
                output,
                "blocked",
                "SelfTestCancelled",
                thumbprint,
                exception.HResult,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return await WriteReceiptAsync(
                output,
                "blocked",
                "SelfTestFailed",
                thumbprint,
                exception.HResult,
                CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static async Task<int> RunSigningGateAsync(
        string[] arguments,
        Stream output,
        Uri timestampUri,
        string thumbprint,
        string singleOutput,
        string dualOutput,
        CancellationToken cancellationToken)
    {
        CertificateReference reference = CertificateReference.Create(StoreLocation.CurrentUser, "My", thumbprint);
        using Mssign32LegExecutor signer = Mssign32LegExecutor.Create();
        CompatibilityGateRunner runner = new(signer, new WinVerifyTrustSignatureVerifier());
        CompatibilityGateResult single = await runner.RunAsync(
            arguments[1],
            singleOutput,
            CompatibilitySigningPlan.CreateSingle(reference, timestampUri),
            cancellationToken).ConfigureAwait(false);
        if (!single.Succeeded)
        {
            return await WriteReceiptAsync(output, "blocked", "Single" + single.ReasonCode, thumbprint, single.HResult, cancellationToken).ConfigureAwait(false);
        }

        CompatibilityGateResult dual = await runner.RunAsync(
            arguments[1],
            dualOutput,
            CompatibilitySigningPlan.CreateDual(reference, reference, timestampUri),
            cancellationToken).ConfigureAwait(false);
        if (!dual.Succeeded)
        {
            return await WriteReceiptAsync(output, "blocked", "Dual" + dual.ReasonCode, thumbprint, dual.HResult, cancellationToken).ConfigureAwait(false);
        }

        BoundedProcessResult singleOracle = await VerifyWithSignToolAsync(arguments[4], singleOutput, cancellationToken).ConfigureAwait(false);
        if (singleOracle.TimedOut)
        {
            return await WriteReceiptAsync(output, "blocked", "SingleExternalVerifierTimedOut", thumbprint, null, cancellationToken).ConfigureAwait(false);
        }

        BoundedProcessResult dualOracle = await VerifyWithSignToolAsync(arguments[4], dualOutput, cancellationToken).ConfigureAwait(false);
        if (dualOracle.TimedOut)
        {
            return await WriteReceiptAsync(output, "blocked", "DualExternalVerifierTimedOut", thumbprint, null, cancellationToken).ConfigureAwait(false);
        }

        int singleExitCode = singleOracle.ExitCode ?? unchecked((int)0x80004005);
        int dualExitCode = dualOracle.ExitCode ?? unchecked((int)0x80004005);
        await WriteSignatureReceiptAsync(
            output,
            "self-signed-single",
            singleExitCode,
            thumbprint,
            single.OutputSha256,
            "Sha256",
            1,
            cancellationToken).ConfigureAwait(false);
        await WriteSignatureReceiptAsync(
            output,
            "self-signed-dual",
            dualExitCode,
            thumbprint,
            dual.OutputSha256,
            "Sha1,Sha256",
            2,
            cancellationToken).ConfigureAwait(false);
        if (singleExitCode != 0 || dualExitCode != 0)
        {
            return await WriteReceiptAsync(output, "blocked", "ExternalVerifierDisagreement", thumbprint, unchecked((int)0x800B0100), cancellationToken).ConfigureAwait(false);
        }

        return await WriteReceiptAsync(output, "passed", "SelfSignedSingleAndDualVerified", thumbprint, 0, cancellationToken).ConfigureAwait(false);
    }

    private static Task<BoundedProcessResult> VerifyWithSignToolAsync(
        string signToolPath,
        string filePath,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo startInfo = new(signToolPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("verify");
        startInfo.ArgumentList.Add("/pa");
        startInfo.ArgumentList.Add("/all");
        startInfo.ArgumentList.Add("/tw");
        startInfo.ArgumentList.Add("/v");
        startInfo.ArgumentList.Add(filePath);
        return BoundedProcessRunner.RunAsync(startInfo, ExternalVerifierTimeout, cancellationToken);
    }

    private static string NormalizeThumbprint(string thumbprint)
    {
        string normalized = thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
        if (normalized.Length != 40)
        {
            throw new InvalidOperationException("The generated certificate did not expose a full SHA-1 thumbprint.");
        }

        _ = Convert.FromHexString(normalized);
        return normalized;
    }

    private static async Task<int> WriteReceiptAsync(
        Stream output,
        string status,
        string reasonCode,
        string? thumbprint,
        int? hresult,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = "self-signed-compatibility-gate",
            ["status"] = status,
            ["reasonCode"] = reasonCode,
            ["publicCertificateThumbprint"] = thumbprint,
            ["hresult"] = hresult is null ? null : $"0x{unchecked((uint)hresult.Value):X8}",
            ["count"] = status == "passed" ? 2 : 0,
            ["digestAlgorithm"] = "Sha256;Sha1,Sha256",
            ["timestampDigestAlgorithm"] = "Sha256"
        };
        await AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken).ConfigureAwait(false);
        return status == "passed" ? 0 : status == "failed" ? 64 : 20;
    }

    private static Task WriteSignatureReceiptAsync(
        Stream output,
        string eventName,
        int oracleExitCode,
        string thumbprint,
        string? sha256,
        string digestAlgorithm,
        int signatureCount,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = eventName,
            ["status"] = oracleExitCode == 0 ? "passed" : "blocked",
            ["reasonCode"] = oracleExitCode == 0 ? "InternalAndExternalVerificationPassed" : "ExternalVerifierDisagreement",
            ["publicCertificateThumbprint"] = thumbprint,
            ["digestAlgorithm"] = digestAlgorithm,
            ["timestampDigestAlgorithm"] = "Sha256",
            ["hresult"] = $"0x{unchecked((uint)oracleExitCode):X8}",
            ["sha256"] = sha256,
            ["count"] = signatureCount,
            ["fixtureState"] = "private-key-export-disabled"
        };
        return AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken);
    }

    internal static Task WriteCertificateCreatedReceiptAsync(
        Stream output,
        string fileName,
        string thumbprint,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = "self-signed-certificate-created",
            ["status"] = "pending",
            ["reasonCode"] = "AwaitingCurrentUserRootTrust",
            ["publicCertificateThumbprint"] = thumbprint,
            ["fileName"] = fileName,
            ["durationMs"] = checked((long)RootTrustTimeout.TotalMilliseconds),
            ["fixtureState"] = "private-key-export-disabled"
        };
        return AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken);
    }

    private static void DeleteIfPresent(string? path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
