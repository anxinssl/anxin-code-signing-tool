using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Signing;

public interface IPeAuthenticodeSigningEngine
{
    Task<NativeSigningResult> ExecuteAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        nint providerWindowHandle,
        CancellationToken cancellationToken);

    async Task<NativeSigningResult> ExecuteAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        nint providerWindowHandle,
        Func<int, CancellationToken, ValueTask> reportLeg,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reportLeg);
        for (int index = 0; index < plan.Legs.Count; index++)
        {
            await reportLeg(index, cancellationToken).ConfigureAwait(false);
        }

        return await ExecuteAsync(
            stagedPath,
            plan,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            providerWindowHandle,
            cancellationToken).ConfigureAwait(false);
    }
}

public sealed class PeAuthenticodeSigningEngine : IPeAuthenticodeSigningEngine
{
    private const int CancelledHResult = unchecked((int)0x800704C7);
    private const int FailureHResult = unchecked((int)0x80004005);
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);

    private readonly IPeImageDigestProvider digestProvider;
    private readonly IPeAuthenticodeCmsSigner cmsSigner;
    private readonly IProductionSignedFileVerifier verifier;

    internal PeAuthenticodeSigningEngine(
        IPeImageDigestProvider digestProvider,
        IPeAuthenticodeCmsSigner cmsSigner,
        IProductionSignedFileVerifier verifier)
    {
        this.digestProvider = digestProvider;
        this.cmsSigner = cmsSigner;
        this.verifier = PeAuthenticodeStructuralVerifier.Wrap(digestProvider, verifier);
    }

    public static PeAuthenticodeSigningEngine Create()
    {
        var digestProvider = new AuthenticodePeImageDigestProvider();
        var inspector = new AuthenticodeCmsRecordInspector();
        var cmsSigner = new WindowsPeAuthenticodeCmsSigner(
            new WindowsCertificatePrivateKeyAcquirer(),
            new CryptMsgAuthenticodeCmsEncoder(inspector),
            new Rfc3161TimestampClient(),
            inspector);
        IProductionSignedFileVerifier verifier = CreateVerifier(digestProvider, inspector);
        return new PeAuthenticodeSigningEngine(digestProvider, cmsSigner, verifier);
    }

    public static IProductionSignedFileVerifier CreateVerifier()
    {
        var digestProvider = new AuthenticodePeImageDigestProvider();
        var inspector = new AuthenticodeCmsRecordInspector();
        return CreateVerifier(digestProvider, inspector);
    }

    public async Task<NativeSigningResult> ExecuteAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        CancellationToken cancellationToken)
    {
        using Process current = Process.GetCurrentProcess();
        return await ExecuteAsync(
            stagedPath,
            plan,
            current.Id,
            current.StartTime.ToUniversalTime(),
            providerWindowHandle: nint.Zero,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<NativeSigningResult> ExecuteAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        nint providerWindowHandle,
        CancellationToken cancellationToken)
        => await ExecuteCoreAsync(
            stagedPath,
            plan,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            providerWindowHandle,
            reportLeg: null,
            cancellationToken).ConfigureAwait(false);

    public async Task<NativeSigningResult> ExecuteAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        nint providerWindowHandle,
        Func<int, CancellationToken, ValueTask> reportLeg,
        CancellationToken cancellationToken)
        => await ExecuteCoreAsync(
            stagedPath,
            plan,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            providerWindowHandle,
            reportLeg ?? throw new ArgumentNullException(nameof(reportLeg)),
            cancellationToken).ConfigureAwait(false);

    private async Task<NativeSigningResult> ExecuteCoreAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        nint providerWindowHandle,
        Func<int, CancellationToken, ValueTask>? reportLeg,
        CancellationToken cancellationToken)
    {
        string? workPath = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidatePlan(plan);
            string canonicalStage = TransactionalStaging.EnsureActiveOwnedStagedFile(
                stagedPath,
                stagingOwnerPid,
                stagingOwnerStartUtc);
            PeImageCertificateTable originalTable = PeImageCertificateTable.Read(canonicalStage);
            if (originalTable.Records.Count != 0)
            {
                return NativeSigningResult.Failure(
                    NativeSigningReasonCode.InvalidInput,
                    InvalidArgumentHResult);
            }

            workPath = CreateWorkPath(canonicalStage);
            File.Copy(canonicalStage, workPath, overwrite: false);
            _ = TransactionalStaging.EnsureActiveOwnedStagedFile(
                workPath,
                stagingOwnerPid,
                stagingOwnerStartUtc);
            PeImageCertificateTable.AlignUnsignedImageForAppend(workPath);

            byte[][] imageDigests = new byte[plan.Legs.Count][];
            byte[][] completedCms = new byte[plan.Legs.Count][];
            for (int legIndex = 0; legIndex < plan.Legs.Count; legIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reportLeg is not null)
                {
                    await reportLeg(legIndex, cancellationToken).ConfigureAwait(false);
                }

                SignatureLeg leg = plan.Legs[legIndex];
                byte[] imageDigest = digestProvider.ComputeDigest(workPath, leg.FileDigest);
                imageDigests[legIndex] = imageDigest;
                PeCmsCreationResult cms = await cmsSigner.CreateAsync(
                    leg,
                    imageDigest,
                    providerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
                if (!cms.Result.Succeeded ||
                    cms.Result.ReasonCode != NativeSigningReasonCode.None ||
                    cms.Result.HResult < 0 ||
                    cms.EncodedCms is null)
                {
                    return NormalizeFailure(cms.Result);
                }

                completedCms[legIndex] = PeAuthenticodeCmsEnvelope.ValidateSingle(
                    cms.EncodedCms,
                    leg.FileDigest,
                    imageDigest,
                    leg.Certificate.Thumbprint);
            }

            byte[] envelope = plan.Legs.Count == 1
                ? completedCms[0]
                : PeAuthenticodeCmsEnvelope.CreateDual(
                    completedCms[0],
                    imageDigests[0],
                    plan.Legs[0].Certificate.Thumbprint,
                    completedCms[1],
                    imageDigests[1],
                    plan.Legs[1].Certificate.Thumbprint);
            PeImageCertificateTable.Append(workPath, envelope);

            cancellationToken.ThrowIfCancellationRequested();
            NativeSigningResult verification = await verifier.VerifyAsync(
                workPath,
                plan,
                cancellationToken).ConfigureAwait(false);
            if (!verification.Succeeded ||
                verification.ReasonCode != NativeSigningReasonCode.None ||
                verification.HResult < 0)
            {
                return NativeSigningResult.Failure(
                    NativeSigningReasonCode.VerifierDisagreement,
                    verification.HResult < 0 ? verification.HResult : FailureHResult);
            }

            cancellationToken.ThrowIfCancellationRequested();
            _ = TransactionalStaging.EnsureActiveOwnedStagedFile(
                canonicalStage,
                stagingOwnerPid,
                stagingOwnerStartUtc);
            File.Replace(workPath, canonicalStage, destinationBackupFileName: null, ignoreMetadataErrors: true);
            workPath = null;
            return NativeSigningResult.Success();
        }
        catch (OperationCanceledException)
        {
            return NativeSigningResult.Failure(
                NativeSigningReasonCode.Cancelled,
                CancelledHResult);
        }
        catch (Exception exception) when (exception is InvalidDataException or
            System.Formats.Asn1.AsnContentException or
            ArgumentException or
            NotSupportedException or
            FilePipelineException or
            UnauthorizedAccessException or
            System.ComponentModel.Win32Exception or
            CryptographicException or
            IOException or
            OverflowException)
        {
            NativeSigningReasonCode reason = exception is InvalidDataException or
                ArgumentException or
                NotSupportedException or
                FilePipelineException
                ? NativeSigningReasonCode.InvalidInput
                : NativeSigningReasonCode.NativeSigningFailed;
            return NativeSigningResult.Failure(
                reason,
                exception.HResult < 0 ? exception.HResult : FailureHResult);
        }
        finally
        {
            if (workPath is not null)
            {
                TryDeleteWorkFile(workPath);
            }
        }
    }

    private static void ValidatePlan(ProductionNativeSigningPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.FormatFamily != SigningFormatFamily.PeImage ||
            plan.Capability != SigningCapability.PeImageDualCapable ||
            plan.Engine != SigningEngine.PeImage ||
            plan.Verification != SigningVerification.PeImage ||
            plan.Legs.Count is < 1 or > 2)
        {
            throw new ArgumentException("The public Authenticode engine requires a PE-image plan.", nameof(plan));
        }

        for (int index = 0; index < plan.Legs.Count; index++)
        {
            SignatureLeg leg = plan.Legs[index];
            NativeDigestAlgorithm expectedDigest = plan.Legs.Count == 1 || index == 1
                ? NativeDigestAlgorithm.Sha256
                : NativeDigestAlgorithm.Sha1;
            bool expectedAppend = plan.Legs.Count == 2 && index == 1;
            if (leg.FileDigest != expectedDigest ||
                leg.TimestampDigest != NativeDigestAlgorithm.Sha256 ||
                leg.Append != expectedAppend)
            {
                throw new ArgumentException("The PE signature-leg order is invalid.", nameof(plan));
            }
        }
    }

    private static NativeSigningResult NormalizeFailure(NativeSigningResult result) =>
        result.Succeeded || result.ReasonCode == NativeSigningReasonCode.None || result.HResult >= 0
            ? NativeSigningResult.Failure(NativeSigningReasonCode.NativeSigningFailed, FailureHResult)
            : result;

    private static PeAuthenticodeStructuralVerifier CreateVerifier(
        IPeImageDigestProvider digestProvider,
        IAuthenticodeCmsRecordInspector inspector) => new PeAuthenticodeStructuralVerifier(
            digestProvider,
            inspector,
            new WinVerifyTrustSignatureVerifier());

    private static string CreateWorkPath(string stagedPath)
    {
        string directory = Path.GetDirectoryName(stagedPath)
            ?? throw new InvalidDataException("The staged PE path has no parent directory.");
        string extension = Path.GetExtension(stagedPath);
        string name = Path.GetFileNameWithoutExtension(stagedPath);
        return Path.Combine(directory, $".{name}.pe-work-{Guid.NewGuid():N}{extension}");
    }

    private static void TryDeleteWorkFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

internal sealed class PeAuthenticodeStructuralVerifier(
    IPeImageDigestProvider digestProvider,
    IAuthenticodeCmsRecordInspector inspector,
    IProductionSignedFileVerifier windowsTrustVerifier) : IProductionSignedFileVerifier
{
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);

    internal static IProductionSignedFileVerifier Wrap(
        IPeImageDigestProvider digestProvider,
        IProductionSignedFileVerifier windowsTrustVerifier)
    {
        ArgumentNullException.ThrowIfNull(digestProvider);
        ArgumentNullException.ThrowIfNull(windowsTrustVerifier);
        return windowsTrustVerifier is PeAuthenticodeStructuralVerifier
            ? windowsTrustVerifier
            : new PeAuthenticodeStructuralVerifier(
                digestProvider,
                new AuthenticodeCmsRecordInspector(),
                windowsTrustVerifier);
    }

    public async Task<NativeSigningResult> VerifyAsync(
        string stagedPath,
        ProductionNativeSigningPlan plan,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(plan);
            PeImageCertificateTable table = PeImageCertificateTable.Read(stagedPath);
            if (table.Records.Count != 1)
            {
                return Failure();
            }

            PeAuthenticodeCmsInspection primary = inspector.Inspect(table.Records[0].Content);
            PeAuthenticodeCmsInspection[] logicalSignatures =
            [
                primary,
                .. primary.NestedSignatures
            ];
            if (logicalSignatures.Length != plan.Legs.Count)
            {
                return Failure();
            }

            for (int index = 0; index < plan.Legs.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                SignatureLeg leg = plan.Legs[index];
                PeAuthenticodeCmsInspection cms = logicalSignatures[index];
                byte[] expectedImageDigest = digestProvider.ComputeDigest(stagedPath, leg.FileDigest);
                if (!string.Equals(
                        cms.DigestAlgorithmOid,
                        AuthenticodeAsn1.DigestOid(leg.FileDigest),
                        StringComparison.Ordinal) ||
                    !CryptographicOperations.FixedTimeEquals(cms.ImageDigest, expectedImageDigest) ||
                    !string.Equals(
                        cms.SignerCertificateThumbprint,
                        leg.Certificate.Thumbprint,
                        StringComparison.Ordinal) ||
                    cms.Rfc3161TimestampCount != 1 ||
                    !string.Equals(
                        cms.TimestampDigestAlgorithmOid,
                        AuthenticodeOids.Sha256,
                        StringComparison.Ordinal) ||
                    !cms.TimestampMessageImprintMatchesSignature)
                {
                    return Failure();
                }
            }

            NativeSigningResult trust = await windowsTrustVerifier.VerifyAsync(
                stagedPath,
                plan,
                cancellationToken).ConfigureAwait(false);
            return trust.Succeeded &&
                trust.ReasonCode == NativeSigningReasonCode.None &&
                trust.HResult >= 0
                ? NativeSigningResult.Success()
                : Failure(trust.HResult);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException or
            System.Formats.Asn1.AsnContentException or
            ArgumentException or
            System.ComponentModel.Win32Exception or
            CryptographicException or
            IOException or
            OverflowException)
        {
            return Failure(exception.HResult);
        }
    }

    private static NativeSigningResult Failure(int hResult = TrustESubjectFormUnknown) =>
        NativeSigningResult.Failure(
            NativeSigningReasonCode.VerifierDisagreement,
            hResult < 0 ? hResult : TrustESubjectFormUnknown);
}
