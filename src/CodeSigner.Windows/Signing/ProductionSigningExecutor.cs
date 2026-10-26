using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CoreSigningPlan = CodeSigner.Core.Signing.SigningPlan;

namespace CodeSigner.Windows.Signing;

public sealed class ProductionSigningExecutor
{
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);
    private const int CancelledHResult = unchecked((int)0x800704C7);
    private const int FailureHResult = unchecked((int)0x80004005);

    private readonly INativeSigningLegExecutor? legExecutor;
    private readonly IPeAuthenticodeSigningEngine? peEngine;
    private readonly IProductionSignedFileVerifier verifier;
    private readonly ISecureFileCommitter fileCommitter;
    private readonly ITrustedSdkSignToolExecutor? sdkFallbackExecutor;
    private readonly TrustedSdkSignToolCandidate? sdkFallbackCandidate;
    private readonly IProductionSigningSubjectClassifier subjectClassifier;

    public SdkSignToolFallbackResult? SdkFallbackResult { get; private set; }

    public ProductionSigningExecutor(
        INativeSigningLegExecutor legExecutor,
        IProductionSignedFileVerifier verifier)
        : this(legExecutor, verifier, new ProductionSigningSubjectClassifier())
    {
    }

    internal ProductionSigningExecutor(
        INativeSigningLegExecutor legExecutor,
        IProductionSignedFileVerifier verifier,
        IProductionSigningSubjectClassifier subjectClassifier)
        : this(legExecutor, verifier, subjectClassifier, LocalStagingFileCommitter.Instance)
    {
    }

    internal ProductionSigningExecutor(
        INativeSigningLegExecutor legExecutor,
        IProductionSignedFileVerifier verifier,
        IProductionSigningSubjectClassifier subjectClassifier,
        ISecureFileCommitter fileCommitter)
    {
        this.legExecutor = legExecutor ?? throw new ArgumentNullException(nameof(legExecutor));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.subjectClassifier = subjectClassifier
            ?? throw new ArgumentNullException(nameof(subjectClassifier));
        this.fileCommitter = fileCommitter ?? throw new ArgumentNullException(nameof(fileCommitter));
    }

    public ProductionSigningExecutor(
        IPeAuthenticodeSigningEngine peEngine,
        IProductionSignedFileVerifier verifier,
        ITrustedSdkSignToolExecutor? sdkFallbackExecutor = null,
        TrustedSdkSignToolCandidate? sdkFallbackCandidate = null)
        : this(
            peEngine,
            verifier,
            sdkFallbackExecutor,
            sdkFallbackCandidate,
            new ProductionSigningSubjectClassifier())
    {
    }

    internal ProductionSigningExecutor(
        IPeAuthenticodeSigningEngine peEngine,
        IProductionSignedFileVerifier verifier,
        ITrustedSdkSignToolExecutor? sdkFallbackExecutor,
        TrustedSdkSignToolCandidate? sdkFallbackCandidate,
        IProductionSigningSubjectClassifier subjectClassifier)
        : this(
            peEngine,
            verifier,
            sdkFallbackExecutor,
            sdkFallbackCandidate,
            subjectClassifier,
            LocalStagingFileCommitter.Instance)
    {
    }

    internal ProductionSigningExecutor(
        IPeAuthenticodeSigningEngine peEngine,
        IProductionSignedFileVerifier verifier,
        ITrustedSdkSignToolExecutor? sdkFallbackExecutor,
        TrustedSdkSignToolCandidate? sdkFallbackCandidate,
        IProductionSigningSubjectClassifier subjectClassifier,
        ISecureFileCommitter fileCommitter)
    {
        if ((sdkFallbackExecutor is null) != (sdkFallbackCandidate is null))
        {
            throw new ArgumentException("SDK fallback requires both an executor and a current-session candidate.");
        }

        this.peEngine = peEngine ?? throw new ArgumentNullException(nameof(peEngine));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.sdkFallbackExecutor = sdkFallbackExecutor;
        this.sdkFallbackCandidate = sdkFallbackCandidate;
        this.subjectClassifier = subjectClassifier
            ?? throw new ArgumentNullException(nameof(subjectClassifier));
        this.fileCommitter = fileCommitter ?? throw new ArgumentNullException(nameof(fileCommitter));
    }

    public static ProductionSigningExecutor CreateForCurrentSession()
    {
        IProductionSignedFileVerifier verifier = PeAuthenticodeSigningEngine.CreateVerifier();
        return new ProductionSigningExecutor(
            PeAuthenticodeSigningEngine.Create(),
            verifier,
            sdkFallbackExecutor: null,
            sdkFallbackCandidate: null,
            new ProductionSigningSubjectClassifier(),
            LocalStagingFileCommitter.Instance);
    }

    public async Task<ProductionSigningReceipt> ExecuteAsync(
        string originalPath,
        string stagedPath,
        CoreSigningPlan plan,
        CancellationToken cancellationToken)
    {
        using Process current = Process.GetCurrentProcess();
        return await ExecuteAsync(
            originalPath,
            stagedPath,
            plan,
            current.Id,
            current.StartTime.ToUniversalTime(),
            cancellationToken).ConfigureAwait(false);
    }

    public Task<ProductionSigningReceipt> ExecuteAsync(
        string originalPath,
        string stagedPath,
        CoreSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        CancellationToken cancellationToken) => ExecuteAsync(
            originalPath,
            stagedPath,
            plan,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            reportProgress: null,
            cancellationToken);

    public async Task<ProductionSigningReceipt> ExecuteAsync(
        string originalPath,
        string stagedPath,
        CoreSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        Func<ProductionSigningPhase, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken)
    {
        SdkFallbackResult = null;
        if (cancellationToken.IsCancellationRequested)
        {
            return Failure(ProductionSigningError.Cancelled, CancelledHResult, string.Empty);
        }

        if (!TryValidateInputs(
            originalPath,
            stagedPath,
            plan,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            subjectClassifier,
            out ValidatedInput input,
            out ProductionSigningError validationError))
        {
            return Failure(validationError, InvalidArgumentHResult, string.Empty);
        }

        string originalHash;
        string stagedHash;
        try
        {
            originalHash = await HashAsync(input.OriginalPath, cancellationToken).ConfigureAwait(false);
            stagedHash = await HashAsync(input.StagedPath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Failure(ProductionSigningError.Cancelled, CancelledHResult, string.Empty);
        }
        catch (Exception exception) when (IsFileAccessFailure(exception))
        {
            return Failure(ProductionSigningError.InvalidInput, InvalidArgumentHResult, string.Empty);
        }

        if (!originalHash.Equals(stagedHash, StringComparison.Ordinal))
        {
            return Failure(ProductionSigningError.OriginalChanged, FailureHResult, originalHash);
        }

        if (peEngine is not null)
        {
            return await ExecuteProductPeAsync(
                input,
                originalHash,
                reportProgress,
                cancellationToken).ConfigureAwait(false);
        }

        string publisherStage = input.StagedPath;
        string? strategyStage = null;
        bool legacyFallbackAttempted = false;
        try
        {
            strategyStage = await CreatePristineStageAsync(
                input.OriginalPath,
                publisherStage,
                input.NativePlan.FileExtension,
                input.StagingOwnerPid,
                input.StagingOwnerStartUtc,
                originalHash,
                "mssign32",
                cancellationToken).ConfigureAwait(false);
            input = input with { StagedPath = strategyStage };

            for (int index = 0; index < input.NativePlan.Legs.Count; index++)
            {
                SignatureLeg leg = input.NativePlan.Legs[index];
                ProductionSigningPhase phase = index == 0
                    ? ProductionSigningPhase.SigningPrimary
                    : ProductionSigningPhase.SigningSecondary;
                NativeSigningResult legResult;
                long legStartTimestamp = 0;
                bool legExecutionStarted = false;
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (reportProgress is not null)
                    {
                        await reportProgress(phase, cancellationToken).ConfigureAwait(false);
                    }

                    legStartTimestamp = Stopwatch.GetTimestamp();
                    legExecutionStarted = true;
                    legacyFallbackAttempted = true;
                    legResult = await legExecutor!.ExecuteAsync(
                        input.StagedPath,
                        leg,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return Failure(
                        ProductionSigningError.Cancelled,
                        CancelledHResult,
                        originalHash,
                        index,
                        CreateLegFailureContext(
                            phase,
                            leg,
                            nativeResult: null,
                            ProductionHResultOrigin.Managed,
                            GetLegElapsedMilliseconds(legExecutionStarted, legStartTimestamp)),
                        legacyFallbackAttempted: legacyFallbackAttempted);
                }
                catch (Exception)
                {
                    return Failure(
                        ProductionSigningError.NativeSigningFailed,
                        FailureHResult,
                        originalHash,
                        index,
                        CreateLegFailureContext(
                            phase,
                            leg,
                            nativeResult: null,
                            ProductionHResultOrigin.Managed,
                            GetLegElapsedMilliseconds(legExecutionStarted, legStartTimestamp)),
                        legacyFallbackAttempted: legacyFallbackAttempted);
                }

                if (!IsConsistentSuccess(legResult))
                {
                    return Failure(
                        MapLegFailure(legResult),
                        NormalizeFailureHResult(legResult),
                        originalHash,
                        index,
                        CreateLegFailureContext(
                            phase,
                            leg,
                            legResult,
                            ProductionHResultOrigin.Native,
                            GetLegElapsedMilliseconds(legExecutionStarted, legStartTimestamp)),
                        legacyFallbackAttempted: legacyFallbackAttempted);
                }
            }

            ProductionSigningReceipt? originalFailure = await CheckOriginalAsync(
                input.OriginalPath,
                input.OriginalIdentity,
                originalHash,
                cancellationToken).ConfigureAwait(false);
            if (originalFailure is not null)
            {
                return originalFailure with { LegacyFallbackAttempted = legacyFallbackAttempted };
            }

            NativeSigningResult verification;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reportProgress is not null)
                {
                    await reportProgress(ProductionSigningPhase.Verifying, cancellationToken).ConfigureAwait(false);
                }

                verification = await verifier.VerifyAsync(
                    input.StagedPath,
                    input.NativePlan,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return Failure(
                    ProductionSigningError.Cancelled,
                    CancelledHResult,
                    originalHash,
                    diagnostic: CreateVerificationFailureContext(
                        nativeResult: null,
                        ProductionHResultOrigin.Managed),
                    legacyFallbackAttempted: legacyFallbackAttempted);
            }
            catch (Exception)
            {
                return Failure(
                    ProductionSigningError.VerifierDisagreement,
                    FailureHResult,
                    originalHash,
                    diagnostic: CreateVerificationFailureContext(
                        nativeResult: null,
                        ProductionHResultOrigin.Managed),
                    legacyFallbackAttempted: legacyFallbackAttempted);
            }

            if (!IsConsistentSuccess(verification))
            {
                return Failure(
                    ProductionSigningError.VerifierDisagreement,
                    NormalizeFailureHResult(verification),
                    originalHash,
                    diagnostic: CreateVerificationFailureContext(
                        verification,
                        ProductionHResultOrigin.Native),
                    legacyFallbackAttempted: legacyFallbackAttempted);
            }

            StableFileIdentity verifiedStageIdentity = ReadIdentity(input.StagedPath);

            originalFailure = await CheckOriginalAsync(
                input.OriginalPath,
                input.OriginalIdentity,
                originalHash,
                cancellationToken).ConfigureAwait(false);
            if (originalFailure is not null)
            {
                return originalFailure with { LegacyFallbackAttempted = legacyFallbackAttempted };
            }

            try
            {
                if (!MatchesSubject(subjectClassifier.Classify(input.StagedPath), input.NativePlan))
                {
                    return Failure(
                        ProductionSigningError.VerifierDisagreement,
                        FailureHResult,
                        originalHash,
                        legacyFallbackAttempted: legacyFallbackAttempted);
                }

                SecureFileCommitReceipt publication = await CommitVerifiedStageAsync(
                    input,
                    input.StagedPath,
                    verifiedStageIdentity,
                    originalHash,
                    publisherStage,
                    cancellationToken).ConfigureAwait(false);
                stagedHash = publication.PublishedSha256.ToUpperInvariant();
                return new ProductionSigningReceipt(
                    true,
                    ProductionSigningError.None,
                    0,
                    originalHash,
                    stagedHash,
                    LegacyFallbackAttempted: legacyFallbackAttempted);
            }
            catch (OperationCanceledException)
            {
                return Failure(
                    ProductionSigningError.Cancelled,
                    CancelledHResult,
                    originalHash,
                    legacyFallbackAttempted: legacyFallbackAttempted);
            }
            catch (Exception exception) when (IsFileAccessFailure(exception))
            {
                return Failure(
                    ProductionSigningError.VerifierDisagreement,
                    FailureHResult,
                    originalHash,
                    legacyFallbackAttempted: legacyFallbackAttempted);
            }
        }
        catch (OperationCanceledException)
        {
            return Failure(
                ProductionSigningError.Cancelled,
                CancelledHResult,
                originalHash,
                legacyFallbackAttempted: legacyFallbackAttempted);
        }
        catch (FilePipelineException exception) when (exception.Error == FilePipelineError.OriginalChanged)
        {
            return Failure(
                ProductionSigningError.OriginalChanged,
                FailureHResult,
                originalHash,
                legacyFallbackAttempted: legacyFallbackAttempted);
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            NotSupportedException or
            UnauthorizedAccessException or
            FilePipelineException or
            System.Security.SecurityException)
        {
            return Failure(
                ProductionSigningError.InvalidInput,
                InvalidArgumentHResult,
                originalHash,
                legacyFallbackAttempted: legacyFallbackAttempted);
        }
        finally
        {
            TryDeleteStage(strategyStage);
        }
    }

    private static bool TryValidateInputs(
        string originalPath,
        string stagedPath,
        CoreSigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        IProductionSigningSubjectClassifier subjectClassifier,
        out ValidatedInput input,
        out ProductionSigningError error)
    {
        input = null!;
        error = ProductionSigningError.InvalidInput;
        try
        {
            if (string.IsNullOrWhiteSpace(originalPath) || string.IsNullOrWhiteSpace(stagedPath) || plan is null)
            {
                return false;
            }

            string original = Path.GetFullPath(originalPath);
            string staged = TransactionalStaging.EnsureActiveOwnedStagedFile(
                stagedPath,
                stagingOwnerPid,
                stagingOwnerStartUtc);
            ProductionNativeSigningPlan nativePlan = ProductionNativeSigningPlan.FromCore(plan);
            if (!File.Exists(original) ||
                original.Equals(staged, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetExtension(original).Equals(nativePlan.FileExtension, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetExtension(staged).Equals(nativePlan.FileExtension, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            SigningSubject originalSubject = subjectClassifier.Classify(original);
            SigningSubject stagedSubject = subjectClassifier.Classify(staged);
            if (!MatchesSubject(originalSubject, nativePlan) ||
                !MatchesSubject(stagedSubject, nativePlan))
            {
                error = ProductionSigningError.UnsupportedFileType;
                return false;
            }

            input = new ValidatedInput(
                original,
                staged,
                nativePlan,
                ReadIdentity(original),
                stagingOwnerPid,
                stagingOwnerStartUtc);
            return true;
        }
        catch (SignableSubjectProbeException)
        {
            error = ProductionSigningError.UnsupportedFileType;
            return false;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or IOException or UnauthorizedAccessException or FilePipelineException or IntakeValidationException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool MatchesSubject(SigningSubject subject, ProductionNativeSigningPlan plan) =>
        subject.FormatFamily == plan.FormatFamily &&
        subject.Capability == plan.Capability &&
        string.Equals(subject.Extension, plan.FileExtension, StringComparison.Ordinal);

    private async Task<ProductionSigningReceipt> ExecuteProductPeAsync(
        ValidatedInput input,
        string originalHash,
        Func<ProductionSigningPhase, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken)
    {
        string? peStage = null;
        string? sdkStage = null;
        int? activeLegIndex = null;
        try
        {
            peStage = await CreatePristineStageAsync(
                input.OriginalPath,
                input.StagedPath,
                input.NativePlan.FileExtension,
                input.StagingOwnerPid,
                input.StagingOwnerStartUtc,
                originalHash,
                "pe",
                cancellationToken).ConfigureAwait(false);

            async ValueTask ReportLegAsync(int index, CancellationToken token)
            {
                activeLegIndex = index;
                if (reportProgress is not null)
                {
                    await reportProgress(
                        index == 0
                            ? ProductionSigningPhase.SigningPrimary
                            : ProductionSigningPhase.SigningSecondary,
                        token).ConfigureAwait(false);
                }
            }

            NativeSigningResult peResult = await peEngine!.ExecuteAsync(
                peStage,
                input.NativePlan,
                input.StagingOwnerPid,
                input.StagingOwnerStartUtc,
                providerWindowHandle: nint.Zero,
                ReportLegAsync,
                cancellationToken).ConfigureAwait(false);
            if (IsConsistentSuccess(peResult))
            {
                return await VerifyAndPublishAsync(
                    input,
                    peStage,
                    originalHash,
                    reportProgress,
                    cancellationToken).ConfigureAwait(false);
            }

            if (sdkFallbackExecutor is not null &&
                sdkFallbackCandidate is not null &&
                SdkSignToolFallbackEligibility.TryCreate(peResult, out SdkSignToolFallbackEligibility? eligibility))
            {
                SdkSignToolFallbackResult fallback = await sdkFallbackExecutor.ExecuteAsync(
                    sdkFallbackCandidate,
                    eligibility!,
                    input.OriginalPath,
                    peStage,
                    input.NativePlan,
                    input.StagingOwnerPid,
                    input.StagingOwnerStartUtc,
                    cancellationToken).ConfigureAwait(false);
                SdkFallbackResult = fallback;
                if (!fallback.Succeeded ||
                    fallback.Error != SdkSignToolFallbackError.None ||
                    string.IsNullOrWhiteSpace(fallback.FreshStagedPath))
                {
                    return FromSdkFailure(fallback, originalHash, activeLegIndex, input.NativePlan);
                }

                sdkStage = TransactionalStaging.EnsureActiveOwnedStagedFile(
                    fallback.FreshStagedPath,
                    input.StagingOwnerPid,
                    input.StagingOwnerStartUtc);
                if (string.Equals(sdkStage, peStage, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(sdkStage, input.StagedPath, StringComparison.OrdinalIgnoreCase))
                {
                    return Failure(ProductionSigningError.InvalidInput, InvalidArgumentHResult, originalHash);
                }

                return await VerifyAndPublishAsync(
                    input,
                    sdkStage,
                    originalHash,
                    reportProgress,
                    cancellationToken).ConfigureAwait(false);
            }

            int failedIndex = Math.Clamp(activeLegIndex ?? 0, 0, input.NativePlan.Legs.Count - 1);
            SignatureLeg failedLeg = input.NativePlan.Legs[failedIndex];
            ProductionSigningPhase failedPhase = failedIndex == 0
                ? ProductionSigningPhase.SigningPrimary
                : ProductionSigningPhase.SigningSecondary;
            return Failure(
                MapLegFailure(peResult),
                NormalizeFailureHResult(peResult),
                originalHash,
                failedIndex,
                CreateLegFailureContext(
                    failedPhase,
                    failedLeg,
                    peResult,
                    ProductionHResultOrigin.Native,
                    legElapsedMilliseconds: null,
                    signerSignEx3: false));
        }
        catch (OperationCanceledException)
        {
            return Failure(ProductionSigningError.Cancelled, CancelledHResult, originalHash);
        }
        catch (FilePipelineException exception) when (exception.Error == FilePipelineError.OriginalChanged)
        {
            return Failure(ProductionSigningError.OriginalChanged, FailureHResult, originalHash);
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            NotSupportedException or
            UnauthorizedAccessException or
            FilePipelineException or
            System.Security.SecurityException)
        {
            return Failure(ProductionSigningError.InvalidInput, InvalidArgumentHResult, originalHash);
        }
        finally
        {
            TryDeleteStage(sdkStage);
            TryDeleteStage(peStage);
        }
    }

    private async Task<ProductionSigningReceipt> VerifyAndPublishAsync(
        ValidatedInput input,
        string verifiedStage,
        string originalHash,
        Func<ProductionSigningPhase, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reportProgress is not null)
            {
                await reportProgress(ProductionSigningPhase.Verifying, cancellationToken).ConfigureAwait(false);
            }

            NativeSigningResult verification = await verifier.VerifyAsync(
                verifiedStage,
                input.NativePlan,
                cancellationToken).ConfigureAwait(false);
            if (!IsConsistentSuccess(verification))
            {
                return Failure(
                    ProductionSigningError.VerifierDisagreement,
                    NormalizeFailureHResult(verification),
                    originalHash,
                    diagnostic: CreateVerificationFailureContext(
                        verification,
                        ProductionHResultOrigin.Native));
            }

            StableFileIdentity verifiedStageIdentity = ReadIdentity(verifiedStage);
            SigningSubject verifiedSubject = subjectClassifier.Classify(verifiedStage);
            bool subjectMatches = MatchesSubject(verifiedSubject, input.NativePlan);
            if (!subjectMatches)
            {
                return Failure(
                    ProductionSigningError.VerifierDisagreement,
                    FailureHResult,
                    originalHash,
                    diagnostic: CreateVerificationFailureContext(
                        nativeResult: null,
                        ProductionHResultOrigin.Managed));
            }

            ProductionSigningReceipt? originalFailure = await CheckOriginalAsync(
                input.OriginalPath,
                input.OriginalIdentity,
                originalHash,
                cancellationToken).ConfigureAwait(false);
            if (originalFailure is not null)
            {
                return originalFailure;
            }

            SecureFileCommitReceipt publication = await CommitVerifiedStageAsync(
                input,
                verifiedStage,
                verifiedStageIdentity,
                originalHash,
                input.StagedPath,
                cancellationToken).ConfigureAwait(false);
            string stagedHash = publication.PublishedSha256.ToUpperInvariant();
            return new ProductionSigningReceipt(
                true,
                ProductionSigningError.None,
                0,
                originalHash,
                stagedHash);
        }
        catch (OperationCanceledException)
        {
            return Failure(
                ProductionSigningError.Cancelled,
                CancelledHResult,
                originalHash,
                diagnostic: CreateVerificationFailureContext(
                    nativeResult: null,
                    ProductionHResultOrigin.Managed));
        }
        catch (FilePipelineException error) when (error.Error == FilePipelineError.OriginalChanged)
        {
            return Failure(
                ProductionSigningError.OriginalChanged,
                FailureHResult,
                originalHash);
        }
        catch (Exception exception) when (exception is
            SignableSubjectProbeException or
            ArgumentException or
            IOException or
            NotSupportedException or
            UnauthorizedAccessException or
            FilePipelineException or
            System.Security.SecurityException)
        {
            return Failure(
                ProductionSigningError.VerifierDisagreement,
                FailureHResult,
                originalHash,
                diagnostic: CreateVerificationFailureContext(
                    nativeResult: null,
                    ProductionHResultOrigin.Managed));
        }
    }

    private static ProductionSigningReceipt FromSdkFailure(
        SdkSignToolFallbackResult fallback,
        string originalHash,
        int? activeLegIndex,
        ProductionNativeSigningPlan plan)
    {
        ProductionSigningError error = fallback.Error switch
        {
            SdkSignToolFallbackError.Cancelled => ProductionSigningError.Cancelled,
            SdkSignToolFallbackError.OriginalChanged => ProductionSigningError.OriginalChanged,
            SdkSignToolFallbackError.VerifierDisagreement => ProductionSigningError.VerifierDisagreement,
            SdkSignToolFallbackError.InvalidInput => ProductionSigningError.InvalidInput,
            _ => ProductionSigningError.NativeSigningFailed
        };
        int hResult = error == ProductionSigningError.Cancelled ? CancelledHResult : FailureHResult;
        if (error is ProductionSigningError.OriginalChanged or ProductionSigningError.InvalidInput)
        {
            return Failure(error, hResult, originalHash);
        }

        if (error == ProductionSigningError.VerifierDisagreement)
        {
            return Failure(
                error,
                hResult,
                originalHash,
                diagnostic: CreateVerificationFailureContext(
                    NativeSigningResult.Failure(NativeSigningReasonCode.VerifierDisagreement, hResult),
                    ProductionHResultOrigin.Native));
        }

        int failedIndex = Math.Clamp(activeLegIndex ?? 0, 0, plan.Legs.Count - 1);
        SignatureLeg leg = plan.Legs[failedIndex];
        return Failure(
            error,
            hResult,
            originalHash,
            failedIndex,
            CreateLegFailureContext(
                failedIndex == 0
                    ? ProductionSigningPhase.SigningPrimary
                    : ProductionSigningPhase.SigningSecondary,
                leg,
                NativeSigningResult.Failure(NativeSigningReasonCode.NativeSigningFailed, hResult),
                ProductionHResultOrigin.Native,
                legElapsedMilliseconds: null,
                signerSignEx3: false));
    }

    private static async Task<string> CreatePristineStageAsync(
        string originalPath,
        string publisherStage,
        string extension,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        string expectedOriginalHash,
        string strategy,
        CancellationToken cancellationToken)
    {
        string canonicalPublisherStage = TransactionalStaging.EnsureActiveOwnedStagedFile(
            publisherStage,
            stagingOwnerPid,
            stagingOwnerStartUtc);
        string directory = Path.GetDirectoryName(canonicalPublisherStage)
            ?? throw new FilePipelineException(FilePipelineError.InvalidPlan, "The owned stage has no parent directory.");
        string stage = Path.Combine(
            directory,
            $".codesigner-{strategy}-{Guid.NewGuid():N}{extension}");
        try
        {
            await using (FileStream source = new(
                originalPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (FileStream destination = new(
                stage,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            _ = TransactionalStaging.EnsureActiveOwnedStagedFile(
                stage,
                stagingOwnerPid,
                stagingOwnerStartUtc);
            string stageHash = await HashAsync(stage, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(stageHash, expectedOriginalHash, StringComparison.Ordinal))
            {
                throw new FilePipelineException(
                    FilePipelineError.OriginalChanged,
                    "The pristine strategy stage does not match the original bytes.");
            }

            return stage;
        }
        catch
        {
            TryDeleteStage(stage);
            throw;
        }
    }

    private async Task<SecureFileCommitReceipt> CommitVerifiedStageAsync(
        ValidatedInput input,
        string verifiedStage,
        StableFileIdentity verifiedStageIdentity,
        string originalHash,
        string stagingPath,
        CancellationToken cancellationToken)
    {
        string source = TransactionalStaging.EnsureActiveOwnedStagedFile(
            verifiedStage,
            input.StagingOwnerPid,
            input.StagingOwnerStartUtc);
        string destination = TransactionalStaging.EnsureActiveOwnedStagedFile(
            stagingPath,
            input.StagingOwnerPid,
            input.StagingOwnerStartUtc);
        await using FileStream candidate = new(
            source,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        StableFileIdentity identity = WindowsFileIdentity.FromHandle(candidate.SafeFileHandle);
        if (identity != verifiedStageIdentity)
        {
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The verified candidate identity changed before the staging commit.");
        }
        string candidateHash = await HashAsync(candidate, cancellationToken).ConfigureAwait(false);

        ProductionSigningReceipt? originalFailure = await CheckOriginalAsync(
            input.OriginalPath,
            input.OriginalIdentity,
            originalHash,
            cancellationToken).ConfigureAwait(false);
        if (originalFailure is not null)
        {
            throw new FilePipelineException(
                FilePipelineError.OriginalChanged,
                "The original file changed before the verified candidate commit.");
        }

        SecureFileCommitReceipt publication = await fileCommitter.CommitAsync(
            new SecureFileCommitRequest(
                source,
                destination,
                input.NativePlan.FileExtension,
                candidateHash,
                candidate.Length),
            cancellationToken).ConfigureAwait(false);
        if (publication is null ||
            !string.Equals(publication.PublishedPath, destination, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(publication.PublishedSha256, candidateHash, StringComparison.OrdinalIgnoreCase) ||
            publication.PublishedLength != candidate.Length)
        {
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The local staging commit does not match the verified candidate.");
        }

        if (WindowsFileIdentity.FromHandle(candidate.SafeFileHandle) != identity)
        {
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The verified candidate identity changed during the staging commit.");
        }
        string afterHash = await HashAsync(candidate, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(candidateHash, afterHash, StringComparison.Ordinal))
        {
            throw new FilePipelineException(
                FilePipelineError.InvalidPlan,
                "The verified candidate bytes changed during the staging commit.");
        }

        return publication;
    }

    private static void TryDeleteStage(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

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

    private static async Task<ProductionSigningReceipt?> CheckOriginalAsync(
        string originalPath,
        StableFileIdentity expectedIdentity,
        string expectedHash,
        CancellationToken cancellationToken)
    {
        try
        {
            if (ReadIdentity(originalPath) != expectedIdentity)
            {
                return Failure(ProductionSigningError.OriginalChanged, FailureHResult, expectedHash);
            }
            string currentHash = await HashAsync(originalPath, cancellationToken).ConfigureAwait(false);
            return expectedHash.Equals(currentHash, StringComparison.Ordinal)
                ? null
                : Failure(ProductionSigningError.OriginalChanged, FailureHResult, expectedHash);
        }
        catch (OperationCanceledException)
        {
            return Failure(ProductionSigningError.Cancelled, CancelledHResult, expectedHash);
        }
        catch (Exception exception) when (IsFileAccessFailure(exception))
        {
            return Failure(ProductionSigningError.OriginalChanged, FailureHResult, expectedHash);
        }
    }

    private static bool IsConsistentSuccess(NativeSigningResult result) =>
        result.Succeeded && result.ReasonCode == NativeSigningReasonCode.None && result.HResult >= 0;

    private static ProductionSigningError MapLegFailure(NativeSigningResult result) => result.ReasonCode switch
    {
        NativeSigningReasonCode.CertificateNotFound => ProductionSigningError.CertificateNotFound,
        NativeSigningReasonCode.CertificateHasNoPrivateKey => ProductionSigningError.CertificateHasNoPrivateKey,
        NativeSigningReasonCode.OperatorCancelled => ProductionSigningError.ProviderCancelled,
        NativeSigningReasonCode.TimestampUnavailable => ProductionSigningError.TimestampUnavailable,
        NativeSigningReasonCode.Cancelled => ProductionSigningError.Cancelled,
        NativeSigningReasonCode.UnsupportedFileType => ProductionSigningError.UnsupportedFileType,
        NativeSigningReasonCode.InvalidInput => ProductionSigningError.InvalidInput,
        _ => ProductionSigningError.NativeSigningFailed
    };

    private static int NormalizeFailureHResult(NativeSigningResult result) =>
        result.HResult < 0 ? result.HResult : FailureHResult;

    private static ProductionSigningFailureContext CreateLegFailureContext(
        ProductionSigningPhase phase,
        SignatureLeg leg,
        NativeSigningResult? nativeResult,
        ProductionHResultOrigin hResultOrigin,
        long? legElapsedMilliseconds,
        bool signerSignEx3 = true)
    {
        bool signerSignEx3Called = signerSignEx3 &&
            nativeResult is not null &&
            IsSignerSignEx3Result(nativeResult);
        return new ProductionSigningFailureContext(
            phase,
            leg.FileDigest,
            leg.Append,
            signerSignEx3Called ? ProductionSigningNativeCall.SignerSignEx3 : null,
            signerSignEx3Called ? GetSignerSignEx3Flags(leg) : null,
            nativeResult?.ReasonCode,
            hResultOrigin,
            legElapsedMilliseconds);
    }

    private static ProductionSigningFailureContext CreateVerificationFailureContext(
        NativeSigningResult? nativeResult,
        ProductionHResultOrigin hResultOrigin) => new(
            ProductionSigningPhase.Verifying,
            DigestAlgorithm: null,
            AppendSignature: null,
            NativeCall: null,
            SignerSignEx3Flags: null,
            nativeResult?.ReasonCode,
            hResultOrigin,
            LegElapsedMilliseconds: null);

    private static bool IsSignerSignEx3Result(NativeSigningResult result) => result.ReasonCode is
        NativeSigningReasonCode.OperatorCancelled or
        NativeSigningReasonCode.TimestampUnavailable or
        NativeSigningReasonCode.NativeSigningFailed ||
        result.ReasonCode == NativeSigningReasonCode.None && result.HResult < 0;

    private static int GetSignerSignEx3Flags(SignatureLeg leg) =>
        checked((int)(leg.Append ? Mssign32Constants.SignatureAppend : 0U));

    private static long? GetLegElapsedMilliseconds(bool started, long startTimestamp) =>
        started ? Math.Max(0L, (long)Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds) : null;

    private static ProductionSigningReceipt Failure(
        ProductionSigningError error,
        int hResult,
        string originalHash,
        int? failedLegIndex = null,
        ProductionSigningFailureContext? diagnostic = null,
        bool legacyFallbackAttempted = false) =>
        new(
            false,
            error,
            hResult,
            originalHash,
            null,
            failedLegIndex,
            diagnostic,
            legacyFallbackAttempted);

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

    private static async Task<string> HashAsync(FileStream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }

    private static StableFileIdentity ReadIdentity(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
    }

    private static bool IsFileAccessFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or System.Security.SecurityException;

    private sealed record ValidatedInput(
        string OriginalPath,
        string StagedPath,
        ProductionNativeSigningPlan NativePlan,
        StableFileIdentity OriginalIdentity,
        int StagingOwnerPid,
        DateTimeOffset StagingOwnerStartUtc);
}
