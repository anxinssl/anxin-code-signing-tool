namespace CodeSigner.Windows.Signing;

public sealed class WinVerifyTrustSignatureVerifier :
    INativeSignedFileVerifier,
    IProductionSignedFileVerifier
{
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private readonly IAuthenticodeSignatureInspector inspector;
    private readonly ICertificateStoreMembership storeMembership;

    public WinVerifyTrustSignatureVerifier()
        : this(new AuthenticodeSignatureInspector(), new WindowsCertificateStoreMembership())
    {
    }

    internal WinVerifyTrustSignatureVerifier(
        IAuthenticodeSignatureInspector inspector,
        ICertificateStoreMembership storeMembership)
    {
        this.inspector = inspector;
        this.storeMembership = storeMembership;
    }

    public Task<NativeSigningResult> VerifyAsync(
        string path,
        CompatibilitySigningPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return VerifyAsync(path, plan.Legs, cancellationToken);
    }

    public Task<NativeSigningResult> VerifyAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return VerifyAsync(stagedPath, plan.Legs, cancellationToken);
    }

    private Task<NativeSigningResult> VerifyAsync(
        string path,
        IReadOnlyList<SignatureLeg> expectedSignatures,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsPeImage(path))
        {
            return Task.FromResult(NativeSigningResult.Failure(
                NativeSigningReasonCode.UnsupportedFileType,
                unchecked((int)0x80070057)));
        }

        try
        {
            AuthenticodeSignatureCountInspection count = inspector.GetSignatureCount(path);
            if (count.TrustStatus != 0 || checked(count.SecondarySignatureCount + 1) != expectedSignatures.Count)
            {
                return Task.FromResult(Failure(count.TrustStatus));
            }

            for (uint index = 0; index <= count.SecondarySignatureCount; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                AuthenticodeSignatureInspection signature = inspector.InspectSignature(path, index);
                SignatureLeg expected = expectedSignatures[checked((int)index)];
                if (!MatchesPlan(index, signature, expected))
                {
                    return Task.FromResult(Failure(signature.TrustStatus));
                }
            }

            return Task.FromResult(NativeSigningResult.Success());
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException or
            ArgumentException or
            InvalidOperationException or
            System.ComponentModel.Win32Exception or
            System.Security.Cryptography.CryptographicException or
            OverflowException)
        {
            return Task.FromResult(Failure(exception.HResult));
        }
    }

    private bool MatchesPlan(uint index, AuthenticodeSignatureInspection actual, SignatureLeg expected)
    {
        if (actual.TrustStatus != 0 ||
            actual.VerifiedSignatureIndex != index ||
            !string.Equals(actual.FileDigestAlgorithmOid, GetDigestOid(expected.FileDigest), StringComparison.Ordinal) ||
            !string.Equals(actual.SignerThumbprint, expected.Certificate.Thumbprint, StringComparison.Ordinal) ||
            !storeMembership.ContainsExact(expected.Certificate, actual.SignerCertificateDer))
        {
            return false;
        }

        return expected.TimestampDigest == NativeDigestAlgorithm.Sha256 &&
            HasRequiredTimestamp(actual.Timestamp);
    }

    private static bool HasRequiredTimestamp(AuthenticodeTimestampInspection timestamp) =>
        timestamp.Kind == AuthenticodeTimestampKind.Rfc3161 &&
            string.Equals(timestamp.MessageImprintAlgorithmOid, AuthenticodeOids.Sha256, StringComparison.Ordinal) &&
            timestamp.CryptographicallyValid &&
            timestamp.ChainValid &&
            timestamp.TimeValid &&
            timestamp.TimestampingEkuValid;

    private static string GetDigestOid(NativeDigestAlgorithm digest) => digest switch
    {
        NativeDigestAlgorithm.Sha1 => AuthenticodeOids.Sha1,
        NativeDigestAlgorithm.Sha256 => AuthenticodeOids.Sha256,
        _ => throw new InvalidDataException("Unsupported planned digest algorithm.")
    };

    private static NativeSigningResult Failure(int hresult) => NativeSigningResult.Failure(
        NativeSigningReasonCode.VerifierDisagreement,
        hresult == 0 ? TrustESubjectFormUnknown : hresult);

    private static bool IsPeImage(string path)
    {
        if (!File.Exists(path))
        {
            return Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase);
        }

        try
        {
            _ = PeImageCertificateTable.Read(path);
            return true;
        }
        catch (Exception exception) when (exception is InvalidDataException or
            ArgumentException or
            IOException or
            UnauthorizedAccessException or
            OverflowException)
        {
            return false;
        }
    }
}
