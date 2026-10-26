using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Worker;

public sealed class ProductionSigningWorkerCommandHandler : IStreamingWorkerCommandHandler
{
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);
    private const int FailureHResult = unchecked((int)0x80004005);
    private const int CancelledHResult = unchecked((int)0x800704C7);

    private readonly Func<INativeSigningLegExecutor> legExecutorFactory;
    private readonly Func<IProductionSignedFileVerifier> verifierFactory;
    private readonly Func<IPeAuthenticodeSigningEngine>? peEngineFactory;
    private readonly Func<ITrustedSdkSignToolLocator>? sdkLocatorFactory;
    private readonly Func<
        ITrustedSdkSignToolLocator,
        IProductionSignedFileVerifier,
        ITrustedSdkSignToolExecutor>? sdkExecutorFactory;
    private readonly Func<IWindowsSipSigningBridge> sipBridgeFactory;
    private readonly Func<IExistingSignatureInspector> existingSignatureInspectorFactory;
    private readonly ProductionSigningSubjectClassifier subjectClassifier;
    private readonly ISecureFileCommitter fileCommitter;
    private readonly Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy;

    public ProductionSigningWorkerCommandHandler()
        : this(
            Mssign32LegExecutor.Create,
            static () => new WinVerifyTrustSignatureVerifier(),
            static () => new WindowsPowerShellSipBridge(),
            WorkerProcessLaunchPolicy.Validate,
            LocalStagingFileCommitter.Instance)
    {
        peEngineFactory = PeAuthenticodeSigningEngine.Create;
        sdkLocatorFactory = static () => new TrustedSdkSignToolLocator();
        sdkExecutorFactory = static (locator, verifier) =>
            new TrustedSdkSignToolExecutor(locator, verifier);
    }

    public ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory)
        : this(
            legExecutorFactory,
            verifierFactory,
            static () => new WindowsPowerShellSipBridge(),
            WorkerProcessLaunchPolicy.Validate)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
        : this(
            legExecutorFactory,
            verifierFactory,
            static () => new WindowsPowerShellSipBridge(),
            validateLaunchPolicy)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy,
        ISecureFileCommitter fileCommitter)
        : this(
            legExecutorFactory,
            verifierFactory,
            static () => new WindowsPowerShellSipBridge(),
            static () => new WindowsExistingSignatureInspector(),
            validateLaunchPolicy,
            fileCommitter)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
        : this(
            legExecutorFactory,
            verifierFactory,
            sipBridgeFactory,
            static () => new WindowsExistingSignatureInspector(),
            validateLaunchPolicy)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy,
        ISecureFileCommitter fileCommitter)
        : this(
            legExecutorFactory,
            verifierFactory,
            sipBridgeFactory,
            static () => new WindowsExistingSignatureInspector(),
            validateLaunchPolicy,
            fileCommitter)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Func<IExistingSignatureInspector> existingSignatureInspectorFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
        : this(
            legExecutorFactory,
            verifierFactory,
            sipBridgeFactory,
            existingSignatureInspectorFactory,
            validateLaunchPolicy,
            LocalStagingFileCommitter.Instance)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<INativeSigningLegExecutor> legExecutorFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Func<IExistingSignatureInspector> existingSignatureInspectorFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy,
        ISecureFileCommitter fileCommitter)
    {
        this.legExecutorFactory = legExecutorFactory
            ?? throw new ArgumentNullException(nameof(legExecutorFactory));
        this.verifierFactory = verifierFactory
            ?? throw new ArgumentNullException(nameof(verifierFactory));
        this.sipBridgeFactory = sipBridgeFactory
            ?? throw new ArgumentNullException(nameof(sipBridgeFactory));
        this.existingSignatureInspectorFactory = existingSignatureInspectorFactory
            ?? throw new ArgumentNullException(nameof(existingSignatureInspectorFactory));
        subjectClassifier = new ProductionSigningSubjectClassifier();
        this.fileCommitter = fileCommitter ?? throw new ArgumentNullException(nameof(fileCommitter));
        this.validateLaunchPolicy = validateLaunchPolicy
            ?? throw new ArgumentNullException(nameof(validateLaunchPolicy));
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<IPeAuthenticodeSigningEngine> peEngineFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<ITrustedSdkSignToolLocator> sdkLocatorFactory,
        Func<
            ITrustedSdkSignToolLocator,
            IProductionSignedFileVerifier,
            ITrustedSdkSignToolExecutor> sdkExecutorFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
        : this(
            peEngineFactory,
            verifierFactory,
            sdkLocatorFactory,
            sdkExecutorFactory,
            sipBridgeFactory,
            static () => new WindowsExistingSignatureInspector(),
            validateLaunchPolicy)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<IPeAuthenticodeSigningEngine> peEngineFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<ITrustedSdkSignToolLocator> sdkLocatorFactory,
        Func<
            ITrustedSdkSignToolLocator,
            IProductionSignedFileVerifier,
            ITrustedSdkSignToolExecutor> sdkExecutorFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy,
        ISecureFileCommitter fileCommitter)
        : this(
            peEngineFactory,
            verifierFactory,
            sdkLocatorFactory,
            sdkExecutorFactory,
            sipBridgeFactory,
            static () => new WindowsExistingSignatureInspector(),
            validateLaunchPolicy,
            fileCommitter)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<IPeAuthenticodeSigningEngine> peEngineFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<ITrustedSdkSignToolLocator> sdkLocatorFactory,
        Func<
            ITrustedSdkSignToolLocator,
            IProductionSignedFileVerifier,
            ITrustedSdkSignToolExecutor> sdkExecutorFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Func<IExistingSignatureInspector> existingSignatureInspectorFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy)
        : this(
            peEngineFactory,
            verifierFactory,
            sdkLocatorFactory,
            sdkExecutorFactory,
            sipBridgeFactory,
            existingSignatureInspectorFactory,
            validateLaunchPolicy,
            LocalStagingFileCommitter.Instance)
    {
    }

    internal ProductionSigningWorkerCommandHandler(
        Func<IPeAuthenticodeSigningEngine> peEngineFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<ITrustedSdkSignToolLocator> sdkLocatorFactory,
        Func<
            ITrustedSdkSignToolLocator,
            IProductionSignedFileVerifier,
            ITrustedSdkSignToolExecutor> sdkExecutorFactory,
        Func<IWindowsSipSigningBridge> sipBridgeFactory,
        Func<IExistingSignatureInspector> existingSignatureInspectorFactory,
        Action<WorkerProcessIdentity, WorkerProcessIdentity> validateLaunchPolicy,
        ISecureFileCommitter fileCommitter)
        : this(
            static () => throw new InvalidOperationException("The legacy PE executor is unavailable."),
            verifierFactory,
            sipBridgeFactory,
            existingSignatureInspectorFactory,
            validateLaunchPolicy,
            fileCommitter)
    {
        this.peEngineFactory = peEngineFactory ?? throw new ArgumentNullException(nameof(peEngineFactory));
        this.sdkLocatorFactory = sdkLocatorFactory ?? throw new ArgumentNullException(nameof(sdkLocatorFactory));
        this.sdkExecutorFactory = sdkExecutorFactory ?? throw new ArgumentNullException(nameof(sdkExecutorFactory));
    }

    public ValueTask<WorkerResponse> HandleAsync(
        WorkerRequest request,
        CancellationToken cancellationToken) => HandleCoreAsync(request, null, cancellationToken);

    public ValueTask<WorkerResponse> HandleAsync(
        WorkerRequest request,
        Func<WorkerProgress, CancellationToken, ValueTask> reportProgress,
        CancellationToken cancellationToken) => HandleCoreAsync(
            request,
            reportProgress ?? throw new ArgumentNullException(nameof(reportProgress)),
            cancellationToken);

    private async ValueTask<WorkerResponse> HandleCoreAsync(
        WorkerRequest request,
        Func<WorkerProgress, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.Equals(request.Command, WorkerCommands.Probe, StringComparison.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Response(true, WorkerResponseCodes.Ready);
        }

        bool isBatchSign = string.Equals(request.Command, WorkerCommands.SignBatch, StringComparison.Ordinal);
        if (!string.Equals(request.Command, WorkerCommands.Sign, StringComparison.Ordinal) && !isBatchSign)
        {
            return Response(false, WorkerResponseCodes.UnsupportedCommand);
        }

        PolicyResult<SigningPlan> parsedPlan = SigningPlanJson.Parse(request.SigningPlanJson);
        if (!parsedPlan.IsSuccess)
        {
            return Response(false, WorkerResponseCodes.InvalidSigningPlan, InvalidArgumentHResult);
        }

        SigningPlan plan = parsedPlan.Value!;
        WorkerSigningContract contract = WorkerSigningContract.FromSigningPlan(plan);
        WorkerExecutionRoute route = plan.Subject.Capability == SigningCapability.PeImageDualCapable
            ? WorkerExecutionRoute.ProductPe
            : WorkerExecutionRoute.WindowsSip;
        if (!contract.Matches(request))
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.SubjectCapabilityMismatch,
                InvalidArgumentHResult,
                null,
                null);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.Cancelled,
                CancelledHResult,
                null,
                null);
        }

        if (!TryCreateSdkCandidate(request.SdkFallback, out TrustedSdkSignToolCandidate? sdkCandidate))
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.InvalidInput,
                InvalidArgumentHResult,
                null,
                null);
        }

        if (!ValidateStagingOwner(request))
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.InvalidStagingOwner,
                InvalidArgumentHResult,
                null,
                null);
        }

        if (!TryClassifySubject(request.OriginalPath, out SigningSubject? originalSubject) ||
            !TryClassifySubject(request.StagedPath, out SigningSubject? stagedSubject))
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.UnsupportedFileType,
                InvalidArgumentHResult,
                null,
                null);
        }

        if (!MatchesPlanSubject(originalSubject!, plan.Subject) ||
            !MatchesPlanSubject(stagedSubject!, plan.Subject))
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.SubjectCapabilityMismatch,
                InvalidArgumentHResult,
                null,
                null);
        }

        (WorkerResponse? existingSignatureResponse, string originalHash, string stagedHash) =
            await InspectExistingSignatureAsync(
                request,
                plan,
                contract,
                cancellationToken).ConfigureAwait(false);
        if (existingSignatureResponse is not null)
        {
            return existingSignatureResponse;
        }

        if (plan.Subject.Capability == SigningCapability.WindowsSipSingleOnly)
        {
            return await ExecuteSipAsync(
                request,
                plan,
                contract,
                isBatchSign,
                reportProgress,
                cancellationToken).ConfigureAwait(false);
        }

        INativeSigningLegExecutor? legExecutor = null;
        IProductionSignedFileVerifier? verifier = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProductionSigningExecutor executor;
            if (peEngineFactory is not null)
            {
                verifier = verifierFactory();
                executor = new ProductionSigningExecutor(
                    peEngineFactory(),
                    verifier,
                    sdkFallbackExecutor: null,
                    sdkFallbackCandidate: null,
                    subjectClassifier,
                    fileCommitter);
            }
            else
            {
                if (sdkCandidate is not null)
                {
                    return RoutedFailure(
                        request.OperationId,
                        contract,
                        WorkerExecutionRoute.SdkSignTool,
                        WorkerFailureCode.SdkStartFailed,
                        FailureHResult,
                        null,
                        null);
                }

                legExecutor = legExecutorFactory();
                verifier = verifierFactory();
                executor = new ProductionSigningExecutor(
                    legExecutor,
                    verifier,
                    subjectClassifier,
                    fileCommitter);
            }

            ProductionSigningReceipt receipt = await executor
                .ExecuteAsync(
                    request.OriginalPath,
                    request.StagedPath,
                    plan,
                    request.StagingOwnerPid,
                    request.StagingOwnerStartUtc,
                    isBatchSign && reportProgress is not null
                        ? (phase, token) => reportProgress(ToProgress(phase, contract), token)
                        : null,
                    cancellationToken)
                .ConfigureAwait(false);
            return FromReceiptWithSdkResult(
                receipt,
                request.OperationId,
                contract,
                executor.SdkFallbackResult);
        }
        catch (OperationCanceledException)
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.Cancelled,
                CancelledHResult,
                null,
                null);
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException or Win32Exception or System.Security.SecurityException)
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                route,
                WorkerFailureCode.NativeSigningFailed,
                FailureHResult,
                null,
                null);
        }
        finally
        {
            if (verifier is IDisposable verifierDisposable)
            {
                verifierDisposable.Dispose();
            }

            if (legExecutor is IDisposable legExecutorDisposable && !ReferenceEquals(legExecutor, verifier))
            {
                legExecutorDisposable.Dispose();
            }
        }
    }

    private async Task<WorkerResponse> ExecuteSipAsync(
        WorkerRequest request,
        SigningPlan plan,
        WorkerSigningContract contract,
        bool isBatchSign,
        Func<WorkerProgress, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken)
    {
        IWindowsSipSigningBridge? bridge = null;
        try
        {
            bridge = sipBridgeFactory();
            WindowsSipSigningResult result = await bridge.ExecuteAsync(
                request.OriginalPath,
                request.StagedPath,
                plan,
                request.StagingOwnerPid,
                request.StagingOwnerStartUtc,
                isBatchSign && reportProgress is not null
                    ? (phase, token) => reportProgress(ToProgress(phase, contract), token)
                    : null,
                cancellationToken).ConfigureAwait(false);
            return FromSipResult(result, request.OperationId, contract);
        }
        catch (OperationCanceledException)
        {
            return RoutedFailure(
                request.OperationId,
                contract,
                WorkerExecutionRoute.WindowsSip,
                WorkerFailureCode.Cancelled,
                CancelledHResult,
                null,
                null);
        }
        catch (Exception exception)
        {
            ReportUnexpectedSipException(exception);
            return RoutedFailure(
                request.OperationId,
                contract,
                WorkerExecutionRoute.WindowsSip,
                WorkerFailureCode.NativeSigningFailed,
                NormalizeFailureHResult(exception.HResult),
                null,
                null);
        }
        finally
        {
            if (bridge is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    private static int NormalizeFailureHResult(int hResult) => hResult < 0 ? hResult : FailureHResult;

    private static void ReportUnexpectedSipException(Exception exception) => Console.Error.WriteLine(
        $"sip_unhandled={exception.GetType().Name};hresult=0x{unchecked((uint)exception.HResult):X8}");

    private async ValueTask<(WorkerResponse? Response, string OriginalHash, string StagedHash)>
        InspectExistingSignatureAsync(
            WorkerRequest request,
            SigningPlan plan,
            WorkerSigningContract contract,
            CancellationToken cancellationToken)
    {
        WorkerExecutionRoute route = plan.Subject.Capability == SigningCapability.PeImageDualCapable
            ? WorkerExecutionRoute.ProductPe
            : WorkerExecutionRoute.WindowsSip;
        string originalHash = string.Empty;
        string stagedHash = string.Empty;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalHash = await HashAsync(request.OriginalPath, cancellationToken).ConfigureAwait(false);
            stagedHash = await HashAsync(request.StagedPath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(originalHash, stagedHash, StringComparison.Ordinal))
            {
                return (
                    RoutedFailure(
                        request.OperationId,
                        contract,
                        route,
                        WorkerFailureCode.OriginalChanged,
                        FailureHResult,
                        originalHash,
                        stagedHash),
                    originalHash,
                    stagedHash);
            }

            IExistingSignatureInspector inspector = existingSignatureInspectorFactory();
            ExistingSignatureInspectionResult inspection = inspector.Inspect(
                request.OriginalPath,
                request.StagedPath,
                plan,
                cancellationToken);
            string postOriginalHash = await HashAsync(request.OriginalPath, cancellationToken).ConfigureAwait(false);
            string postStagedHash = await HashAsync(request.StagedPath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(originalHash, postOriginalHash, StringComparison.Ordinal) ||
                !string.Equals(stagedHash, postStagedHash, StringComparison.Ordinal))
            {
                return (
                    RoutedFailure(
                        request.OperationId,
                        contract,
                        route,
                        WorkerFailureCode.OriginalChanged,
                        FailureHResult,
                        originalHash,
                        stagedHash),
                    originalHash,
                    stagedHash);
            }

            if (inspection.Status == ExistingSignatureInspectionStatus.Unsigned)
            {
                return (null, originalHash, stagedHash);
            }

            ExistingSignatureStatus policyStatus = ToPolicyStatus(inspection.Status);
            bool skip = inspection.Status == ExistingSignatureInspectionStatus.Valid &&
                inspection.HResult >= 0 &&
                plan.ExistingSignatures.For(policyStatus) == ExistingSignatureDisposition.Skip;
            if (skip)
            {
                return (
                    ExistingSignatureSkip(
                        request.OperationId,
                        contract,
                        originalHash,
                        stagedHash),
                    originalHash,
                    stagedHash);
            }

            return (
                RoutedFailure(
                    request.OperationId,
                    contract,
                    route,
                    WorkerFailureCode.ExistingSignatureRejected,
                    inspection.HResult < 0 ? inspection.HResult : FailureHResult,
                    originalHash,
                    stagedHash),
                originalHash,
                stagedHash);
        }
        catch (OperationCanceledException)
        {
            return (
                RoutedFailure(
                    request.OperationId,
                    contract,
                    route,
                    WorkerFailureCode.Cancelled,
                    CancelledHResult,
                    originalHash,
                    stagedHash),
                originalHash,
                stagedHash);
        }
        catch (Exception exception) when (exception is
            IOException or
            UnauthorizedAccessException or
            PlatformNotSupportedException or
            Win32Exception or
            System.Security.SecurityException or
            InvalidOperationException or
            ArgumentException or
            CryptographicException)
        {
            return (
                RoutedFailure(
                    request.OperationId,
                    contract,
                    route,
                    WorkerFailureCode.ExistingSignatureRejected,
                    FailureHResult,
                    originalHash,
                    stagedHash),
                originalHash,
                stagedHash);
        }
    }

    private static bool TryCreateSdkCandidate(
        WorkerSdkFallback? fallback,
        out TrustedSdkSignToolCandidate? candidate)
    {
        candidate = null;
        if (fallback is null || fallback.Enabled != (fallback.Candidate is not null))
        {
            return false;
        }

        WorkerSdkCandidateIdentity? identity = fallback.Candidate;
        if (identity is null)
        {
            return true;
        }

        if (!TryParseExactVersion(identity.SdkVersion, out Version? sdkVersion) ||
            !TryParseExactVersion(identity.ProductVersion, out Version? productVersion) ||
            !IsCanonicalAbsolutePath(identity.Path) ||
            !IsBoundedText(identity.Publisher) ||
            !IsBoundedText(identity.CompanyName) ||
            !IsBoundedText(identity.ProductName) ||
            !IsLowerSha256(identity.Sha256))
        {
            return false;
        }

        candidate = new TrustedSdkSignToolCandidate(
            identity.Path,
            sdkVersion!,
            productVersion!,
            identity.Publisher,
            identity.CompanyName,
            identity.ProductName,
            identity.Sha256);
        return true;
    }

    private static bool TryParseExactVersion(string value, out Version? version) =>
        Version.TryParse(value, out version) &&
        version.Major >= 0 && version.Minor >= 0 && version.Build >= 0 && version.Revision >= 0 &&
        string.Equals(value, version.ToString(4), StringComparison.Ordinal);

    private static bool IsCanonicalAbsolutePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        try
        {
            string canonical = Path.GetFullPath(path);
            return canonical.Equals(path, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(Path.GetFileName(canonical));
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            NotSupportedException or
            PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsBoundedText(string value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 256;

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private sealed class DeferredSdkSignToolExecutor(
        Func<ITrustedSdkSignToolLocator> locatorFactory,
        IProductionSignedFileVerifier verifier,
        Func<
            ITrustedSdkSignToolLocator,
            IProductionSignedFileVerifier,
            ITrustedSdkSignToolExecutor> executorFactory) : ITrustedSdkSignToolExecutor
    {
        public Task<SdkSignToolFallbackResult> ExecuteAsync(
            TrustedSdkSignToolCandidate selectedCandidate,
            SdkSignToolFallbackEligibility eligibility,
            string originalPath,
            string failedStagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            CancellationToken cancellationToken)
        {
            ITrustedSdkSignToolLocator locator = locatorFactory();
            ITrustedSdkSignToolExecutor executor = executorFactory(locator, verifier);
            return executor.ExecuteAsync(
                selectedCandidate,
                eligibility,
                originalPath,
                failedStagedPath,
                plan,
                stagingOwnerPid,
                stagingOwnerStartUtc,
                cancellationToken);
        }
    }

    private bool ValidateStagingOwner(WorkerRequest request)
    {
        try
        {
            TransactionalStaging.EnsureActiveOwnedStagedFile(
                request.StagedPath,
                request.StagingOwnerPid,
                request.StagingOwnerStartUtc);
            using Process owner = Process.GetProcessById(request.StagingOwnerPid);
            DateTimeOffset actualStartUtc = owner.StartTime.ToUniversalTime();
            if (Math.Abs((actualStartUtc - request.StagingOwnerStartUtc.ToUniversalTime()).TotalSeconds) >= 1)
            {
                return false;
            }

            using Process worker = Process.GetCurrentProcess();
            validateLaunchPolicy(
                WorkerProcessIdentity.Capture(owner),
                WorkerProcessIdentity.Capture(worker));
            return true;
        }
        catch (Exception exception) when (exception is FilePipelineException or ArgumentException or InvalidOperationException or Win32Exception or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static WorkerResponse FromReceipt(
        ProductionSigningReceipt receipt,
        string? operationId,
        WorkerSigningContract contract) => FromReceiptWithSdkResult(
            receipt,
            operationId,
            contract,
            sdkFallbackResult: null);

    private static WorkerResponse FromReceiptWithSdkResult(
        ProductionSigningReceipt receipt,
        string? operationId,
        WorkerSigningContract contract,
        SdkSignToolFallbackResult? sdkFallbackResult)
    {
        if (sdkFallbackResult is not null)
        {
            return FromSdkReceipt(receipt, sdkFallbackResult, operationId, contract);
        }

        bool succeeded = receipt.Succeeded &&
            receipt.Error == ProductionSigningError.None;
        WorkerFailureCode? failure = succeeded
            ? null
            : receipt.Error switch
            {
                ProductionSigningError.InvalidInput => WorkerFailureCode.InvalidInput,
                ProductionSigningError.UnsupportedFileType => WorkerFailureCode.UnsupportedFileType,
                ProductionSigningError.CertificateNotFound => WorkerFailureCode.CertificateNotFound,
                ProductionSigningError.CertificateHasNoPrivateKey => WorkerFailureCode.CertificateHasNoPrivateKey,
                ProductionSigningError.ProviderCancelled => WorkerFailureCode.ProviderCancelled,
                ProductionSigningError.TimestampUnavailable => WorkerFailureCode.TimestampUnavailable,
                ProductionSigningError.NativeSigningFailed => WorkerFailureCode.NativeSigningFailed,
                ProductionSigningError.VerifierDisagreement => WorkerFailureCode.VerifierDisagreement,
                ProductionSigningError.OriginalChanged => WorkerFailureCode.OriginalChanged,
                ProductionSigningError.Cancelled => WorkerFailureCode.Cancelled,
                ProductionSigningError.None => WorkerFailureCode.HandlerFailure,
                _ => WorkerFailureCode.HandlerFailure
            };
        string code = failure is null
            ? WorkerResponseCodes.SigningCompleted
            : WorkerProtocol.FailureCodeFor(failure.Value);
        if (succeeded)
        {
            return new WorkerResponse(
                WorkerProtocol.Version,
                true,
                code,
                receipt.HResult,
                OriginalSha256: NormalizeHash(receipt.OriginalSha256),
                StagedSha256: NormalizeHash(receipt.StagedSha256),
                OperationId: operationId,
                Subject: contract.Subject,
                Capability: contract.Capability,
                Engine: contract.Engine,
                Verification: contract.Verification,
                LegacyFallbackAttempted: receipt.LegacyFallbackAttempted,
                Outcome: WorkerSigningOutcome.Signed,
                Route: WorkerExecutionRoute.ProductPe);
        }

        ProductionSigningFailureContext? diagnostic = receipt.Diagnostic;
        if (diagnostic is null || !CanMapSigningLeg(receipt, diagnostic))
        {
            return RoutedFailure(
                operationId,
                contract,
                WorkerExecutionRoute.ProductPe,
                failure!.Value,
                receipt.HResult,
                NormalizeHash(receipt.OriginalSha256),
                NormalizeHash(receipt.StagedSha256)) with
            {
                LegacyFallbackAttempted = receipt.LegacyFallbackAttempted
            };
        }

        return new WorkerResponse(
            WorkerProtocol.Version,
            false,
            code,
            receipt.HResult,
            receipt.FailedLegIndex,
            NormalizeHash(receipt.OriginalSha256),
            NormalizeHash(receipt.StagedSha256),
            operationId,
            NewDiagnosticId(),
            ToDiagnosticPhase(diagnostic.Phase),
            ToDiagnosticLeg(diagnostic.Phase),
            ToDigestAlgorithm(diagnostic.DigestAlgorithm),
            diagnostic.AppendSignature,
            diagnostic.NativeCall == ProductionSigningNativeCall.SignerSignEx3
                ? WorkerNativeCalls.SignerSignEx3
                : null,
            diagnostic.SignerSignEx3Flags,
            diagnostic.NativeReasonCode?.ToString(),
            GetHResultSymbol(receipt.HResult),
            ToHResultOrigin(diagnostic.HResultOrigin),
            diagnostic.LegElapsedMilliseconds,
            contract.Subject,
            contract.Capability,
            contract.Engine,
            contract.Verification,
            LegacyFallbackAttempted: receipt.LegacyFallbackAttempted,
            Outcome: WorkerSigningOutcome.Failure,
            Route: WorkerExecutionRoute.ProductPe,
            Failure: failure);
    }

    private static WorkerResponse FromSdkReceipt(
        ProductionSigningReceipt receipt,
        SdkSignToolFallbackResult fallback,
        string? operationId,
        WorkerSigningContract contract)
    {
        bool succeeded = receipt.Succeeded &&
            receipt.Error == ProductionSigningError.None &&
            fallback.Succeeded &&
            fallback.Error == SdkSignToolFallbackError.None;
        WorkerFailureCode? failure = succeeded
            ? null
            : MapSdkFailure(receipt, fallback);
        string code = failure is null
            ? WorkerResponseCodes.SigningCompleted
            : WorkerProtocol.FailureCodeFor(failure.Value);
        return new WorkerResponse(
            WorkerProtocol.Version,
            succeeded,
            code,
            receipt.HResult,
            OriginalSha256: NormalizeHash(receipt.OriginalSha256),
            StagedSha256: NormalizeHash(receipt.StagedSha256),
            OperationId: operationId,
            Subject: contract.Subject,
            Capability: contract.Capability,
            Engine: contract.Engine,
            Verification: contract.Verification,
            LegacyFallbackAttempted: false,
            Outcome: succeeded ? WorkerSigningOutcome.Signed : WorkerSigningOutcome.Failure,
            Route: WorkerExecutionRoute.SdkSignTool,
            Failure: failure);
    }

    private static WorkerFailureCode MapSdkFailure(
        ProductionSigningReceipt receipt,
        SdkSignToolFallbackResult fallback) => fallback.Error switch
        {
            SdkSignToolFallbackError.InvalidInput => WorkerFailureCode.InvalidInput,
            SdkSignToolFallbackError.CandidateUnavailable or
            SdkSignToolFallbackError.CandidateChanged => WorkerFailureCode.SdkCandidateChanged,
            SdkSignToolFallbackError.ProcessStartFailed => WorkerFailureCode.SdkStartFailed,
            SdkSignToolFallbackError.ProcessFailed => WorkerFailureCode.SdkExitFailed,
            SdkSignToolFallbackError.TimedOut => WorkerFailureCode.SdkTimedOut,
            SdkSignToolFallbackError.VerifierDisagreement => WorkerFailureCode.SdkVerificationFailed,
            SdkSignToolFallbackError.OriginalChanged => WorkerFailureCode.OriginalChanged,
            SdkSignToolFallbackError.Cancelled => WorkerFailureCode.Cancelled,
            SdkSignToolFallbackError.None when receipt.Error == ProductionSigningError.OriginalChanged =>
                WorkerFailureCode.OriginalChanged,
            SdkSignToolFallbackError.None when receipt.Error == ProductionSigningError.Cancelled =>
                WorkerFailureCode.Cancelled,
            _ => WorkerFailureCode.SdkVerificationFailed
        };

    private static WorkerResponse FromSipResult(
        WindowsSipSigningResult result,
        string? operationId,
        WorkerSigningContract contract)
    {
        ArgumentNullException.ThrowIfNull(result);
        bool consistentSuccess = result.Succeeded &&
            result.Error == WindowsSipSigningError.None &&
            result.HResult >= 0 &&
            IsSha256(result.OriginalSha256) &&
            IsSha256(result.StagedSha256);
        if (consistentSuccess)
        {
            return new WorkerResponse(
                WorkerProtocol.Version,
                true,
                WorkerResponseCodes.SigningCompleted,
                result.HResult,
                OriginalSha256: NormalizeHash(result.OriginalSha256),
                StagedSha256: NormalizeHash(result.StagedSha256),
                OperationId: operationId,
                Subject: contract.Subject,
                Capability: contract.Capability,
                Engine: contract.Engine,
                Verification: contract.Verification,
                LegacyFallbackAttempted: false,
                Outcome: WorkerSigningOutcome.Signed,
                Route: WorkerExecutionRoute.WindowsSip);
        }

        WindowsSipSigningError error = result.Succeeded || result.Error == WindowsSipSigningError.None
            ? WindowsSipSigningError.MalformedResponse
            : result.Error;
        WorkerFailureCode failure = error switch
        {
            WindowsSipSigningError.InvalidInput => WorkerFailureCode.InvalidInput,
            WindowsSipSigningError.PowerShellUnavailable => WorkerFailureCode.WindowsPowerShellUnavailable,
            WindowsSipSigningError.ExecutionDenied => WorkerFailureCode.WindowsPowerShellExecutionDenied,
            WindowsSipSigningError.SipUnavailable => WorkerFailureCode.WindowsSipUnavailable,
            WindowsSipSigningError.PackageIncompatible => WorkerFailureCode.PackageIncompatible,
            WindowsSipSigningError.CertificateMismatch => WorkerFailureCode.CertificateMismatch,
            WindowsSipSigningError.CertificateNotFound => WorkerFailureCode.CertificateNotFound,
            WindowsSipSigningError.CertificateHasNoPrivateKey => WorkerFailureCode.CertificateHasNoPrivateKey,
            WindowsSipSigningError.ExistingSignatureRejected => WorkerFailureCode.ExistingSignatureRejected,
            WindowsSipSigningError.ProviderCancelled => WorkerFailureCode.ProviderCancelled,
            WindowsSipSigningError.TimestampUnavailable => WorkerFailureCode.TimestampUnavailable,
            WindowsSipSigningError.VerificationFailed => WorkerFailureCode.VerifierDisagreement,
            WindowsSipSigningError.MalformedResponse => WorkerFailureCode.InvalidBridgeResponse,
            WindowsSipSigningError.ProcessFailed => WorkerFailureCode.NativeSigningFailed,
            WindowsSipSigningError.OriginalChanged => WorkerFailureCode.OriginalChanged,
            WindowsSipSigningError.Cancelled => WorkerFailureCode.Cancelled,
            _ => WorkerFailureCode.HandlerFailure
        };
        int hResult = result.HResult < 0 ? result.HResult : FailureHResult;
        return RoutedFailure(
            operationId,
            contract,
            WorkerExecutionRoute.WindowsSip,
            failure,
            hResult,
            NormalizeHash(result.OriginalSha256),
            NormalizeHash(result.StagedSha256));
    }

    private static WorkerResponse Response(bool success, string code, int? hResult = null) =>
        new(
            WorkerProtocol.Version,
            success,
            code,
            hResult);

    private static WorkerResponse BridgeFailure(
        string? operationId,
        string code,
        int hResult,
        string? originalSha256 = null,
        string? stagedSha256 = null,
        WorkerSigningContract? contract = null,
        bool legacyFallbackAttempted = false) => new(
            WorkerProtocol.Version,
            false,
            code,
            hResult,
            OriginalSha256: originalSha256,
            StagedSha256: stagedSha256,
            OperationId: operationId,
            DiagnosticId: NewDiagnosticId(),
            DiagnosticPhase: WorkerDiagnosticPhases.WorkerBridge,
            HResultSymbol: GetHResultSymbol(hResult),
            HResultOrigin: WorkerHResultOrigins.WorkerBridge,
        Subject: contract?.Subject,
        Capability: contract?.Capability,
        Engine: contract?.Engine,
        Verification: contract?.Verification,
        LegacyFallbackAttempted: legacyFallbackAttempted);

    private static WorkerResponse ExistingSignatureSkip(
        string? operationId,
        WorkerSigningContract contract,
        string originalSha256,
        string stagedSha256) => new(
            WorkerProtocol.Version,
            true,
            WorkerResponseCodes.SkippedExistingSignature,
            0,
            OriginalSha256: NormalizeHash(originalSha256),
            StagedSha256: NormalizeHash(stagedSha256),
            OperationId: operationId,
            Subject: contract.Subject,
            Capability: contract.Capability,
            Engine: contract.Engine,
            Verification: contract.Verification,
            LegacyFallbackAttempted: false,
            Outcome: WorkerSigningOutcome.SkippedExistingSignature,
            Route: WorkerExecutionRoute.Skip);

    private static WorkerResponse RoutedFailure(
        string? operationId,
        WorkerSigningContract contract,
        WorkerExecutionRoute route,
        WorkerFailureCode failure,
        int hResult,
        string? originalSha256,
        string? stagedSha256) => BridgeFailure(
            operationId,
            WorkerProtocol.FailureCodeFor(failure),
            hResult,
            NormalizeHash(originalSha256),
            NormalizeHash(stagedSha256),
            contract) with
        {
            Outcome = WorkerSigningOutcome.Failure,
            Route = route,
            Failure = failure
        };

    private static WorkerProgress ToProgress(
        ProductionSigningPhase phase,
        WorkerSigningContract contract) => new(
        WorkerProtocol.Version,
        phase switch
        {
            ProductionSigningPhase.SigningPrimary => WorkerProgressPhases.SigningPrimary,
            ProductionSigningPhase.SigningSecondary => WorkerProgressPhases.SigningSecondary,
            ProductionSigningPhase.Verifying => WorkerProgressPhases.Verifying,
            _ => throw new ArgumentOutOfRangeException(nameof(phase), phase, "Unknown signing phase.")
        },
        contract.Subject,
        contract.Capability,
        contract.Engine,
        contract.Verification);

    private static WorkerProgress ToProgress(
        WindowsSipSigningPhase phase,
        WorkerSigningContract contract) => new(
        WorkerProtocol.Version,
        phase switch
        {
            WindowsSipSigningPhase.Signing => WorkerProgressPhases.SigningPrimary,
            WindowsSipSigningPhase.Verifying => WorkerProgressPhases.Verifying,
            _ => throw new ArgumentOutOfRangeException(nameof(phase), phase, "Unknown SIP signing phase.")
        },
        contract.Subject,
        contract.Capability,
        contract.Engine,
        contract.Verification);

    private static bool CanMapSigningLeg(
        ProductionSigningReceipt receipt,
        ProductionSigningFailureContext diagnostic) => diagnostic.Phase switch
        {
            ProductionSigningPhase.SigningPrimary =>
                receipt.FailedLegIndex == 0 &&
                diagnostic.DigestAlgorithm is NativeDigestAlgorithm.Sha1 or NativeDigestAlgorithm.Sha256 &&
                diagnostic.AppendSignature == false,
            ProductionSigningPhase.SigningSecondary =>
                receipt.FailedLegIndex == 1 &&
                diagnostic.DigestAlgorithm == NativeDigestAlgorithm.Sha256 &&
                diagnostic.AppendSignature == true,
            ProductionSigningPhase.Verifying => receipt.FailedLegIndex is null,
            _ => false
        };

    private static string ToDiagnosticPhase(ProductionSigningPhase phase) => phase switch
    {
        ProductionSigningPhase.SigningPrimary => WorkerDiagnosticPhases.SigningPrimary,
        ProductionSigningPhase.SigningSecondary => WorkerDiagnosticPhases.SigningSecondary,
        ProductionSigningPhase.Verifying => WorkerDiagnosticPhases.Verifying,
        _ => throw new ArgumentOutOfRangeException(nameof(phase), phase, "Unknown diagnostic phase.")
    };

    private static string? ToDiagnosticLeg(ProductionSigningPhase phase) => phase switch
    {
        ProductionSigningPhase.SigningPrimary => WorkerDiagnosticLegs.Primary,
        ProductionSigningPhase.SigningSecondary => WorkerDiagnosticLegs.Secondary,
        ProductionSigningPhase.Verifying => null,
        _ => throw new ArgumentOutOfRangeException(nameof(phase), phase, "Unknown diagnostic phase.")
    };

    private static string? ToDigestAlgorithm(NativeDigestAlgorithm? digestAlgorithm) => digestAlgorithm switch
    {
        NativeDigestAlgorithm.Sha1 => WorkerDigestAlgorithms.Sha1,
        NativeDigestAlgorithm.Sha256 => WorkerDigestAlgorithms.Sha256,
        null => null,
        _ => throw new ArgumentOutOfRangeException(nameof(digestAlgorithm), digestAlgorithm, "Unknown digest algorithm.")
    };

    private static string ToHResultOrigin(ProductionHResultOrigin hResultOrigin) => hResultOrigin switch
    {
        ProductionHResultOrigin.Native => WorkerHResultOrigins.Native,
        ProductionHResultOrigin.Managed => WorkerHResultOrigins.Managed,
        _ => throw new ArgumentOutOfRangeException(nameof(hResultOrigin), hResultOrigin, "Unknown HRESULT origin.")
    };

    private static ExistingSignatureStatus ToPolicyStatus(
        ExistingSignatureInspectionStatus status) => status switch
    {
        ExistingSignatureInspectionStatus.Valid => ExistingSignatureStatus.Valid,
        ExistingSignatureInspectionStatus.Invalid => ExistingSignatureStatus.Invalid,
        ExistingSignatureInspectionStatus.Untrusted => ExistingSignatureStatus.Untrusted,
        ExistingSignatureInspectionStatus.Expired => ExistingSignatureStatus.Expired,
        ExistingSignatureInspectionStatus.Partial => ExistingSignatureStatus.Partial,
        ExistingSignatureInspectionStatus.Malformed or ExistingSignatureInspectionStatus.FamilyIncompatible =>
            ExistingSignatureStatus.Malformed,
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown existing-signature status.")
    };

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }

    private static string? NormalizeHash(string? value) =>
        string.IsNullOrEmpty(value) ? null : value.ToLowerInvariant();

    private static bool IsSha256(string? value) => value is { Length: 64 } && value.All(static character =>
        character is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f');

    private static string NewDiagnosticId() => Guid.NewGuid().ToString("N");

    private static string? GetHResultSymbol(int hResult) => unchecked((uint)hResult) switch
    {
        0x80004002 => "E_NOINTERFACE",
        _ => null
    };

    private bool TryClassifySubject(string path, out SigningSubject? subject)
    {
        subject = null;
        try
        {
            subject = subjectClassifier.Classify(path);
            return true;
        }
        catch (Exception exception) when (exception is
            SignableSubjectProbeException or
            IOException or
            UnauthorizedAccessException or
            ArgumentException or
            NotSupportedException or
            System.Security.SecurityException or
            OverflowException)
        {
            return false;
        }
    }

    private static bool MatchesPlanSubject(SigningSubject classified, SigningSubject planned) =>
        classified.FormatFamily == planned.FormatFamily &&
        classified.Capability == planned.Capability &&
        string.Equals(classified.Extension, planned.Extension, StringComparison.Ordinal);
}
