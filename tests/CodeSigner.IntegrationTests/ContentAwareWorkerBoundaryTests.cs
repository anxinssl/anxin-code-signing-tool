using System.Diagnostics;
using System.Reflection;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class ContentAwareWorkerBoundaryTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const int FailureHResult = unchecked((int)0x80004005);

    [Theory]
    [InlineData("valid-unsigned.dll", "payload.dll", WorkerEngines.PeImage, WorkerResponseCodes.NativeSigningFailed)]
    [InlineData("valid-unsigned.msi", "payload.msi", WorkerEngines.WindowsSip, WorkerResponseCodes.WindowsSipUnavailable)]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidSupportedContentRoutesToItsTypedSigningEngine(
        string fixtureName,
        string fileName,
        string expectedEngine,
        string expectedCode)
    {
        var leg = new RecordingLegExecutor();
        var sipBridge = new RecordingSipBridge();
        int legFactoryCalls = 0;
        int verifierFactoryCalls = 0;
        int sipFactoryCalls = 0;
        IWorkerCommandHandler handler = CreateHandler(
            () =>
            {
                legFactoryCalls++;
                return leg;
            },
            () =>
            {
                verifierFactoryCalls++;
                return new NeverVerifier();
            },
            () =>
            {
                sipFactoryCalls++;
                return sipBridge;
            });
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-ContentRoute-" + Guid.NewGuid().ToString("N"));
        string original = CopyFixture(root, Path.Combine("original", fileName), fixtureName);
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string staged = Path.Combine(attemptDirectory, fileName);
        File.Copy(original, staged);

        try
        {
            using Process owner = Process.GetCurrentProcess();
            WorkerResponse response = await handler.HandleAsync(
                new WorkerRequest(
                    WorkerProtocol.Version,
                    WorkerCommands.Sign,
                    original,
                    staged,
                    SigningPlanJson.Serialize(PlanFor(Path.GetExtension(fileName))),
                    owner.Id,
                    new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero)),
                CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(expectedCode, response.Code);
            Assert.Equal(expectedEngine, response.Engine);
            if (expectedEngine == WorkerEngines.PeImage)
            {
                Assert.Equal(1, legFactoryCalls);
                Assert.Equal(1, verifierFactoryCalls);
                Assert.Equal(1, leg.CallCount);
                Assert.Equal(0, sipFactoryCalls);
                Assert.Equal(0, sipBridge.CallCount);
            }
            else
            {
                Assert.Equal(0, legFactoryCalls);
                Assert.Equal(0, verifierFactoryCalls);
                Assert.Equal(0, leg.CallCount);
                Assert.Equal(1, sipFactoryCalls);
                Assert.Equal(1, sipBridge.CallCount);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("payload.dll")]
    [InlineData("payload.msi")]
    [InlineData("payload.cab")]
    [InlineData("payload.ocx")]
    [Trait("Category", "SigningIntegration")]
    public async Task MalformedSupportedExtensionIsTypedRejectedBeforeSigningRoutes(string fileName)
    {
        int factoryCalls = 0;
        IWorkerCommandHandler handler = CreateHandler(
            () =>
            {
                factoryCalls++;
                return new NeverLegExecutor();
            },
            () =>
            {
                factoryCalls++;
                return new NeverVerifier();
            });
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-Malformed-" + Guid.NewGuid().ToString("N"));
        string original = Path.Combine(root, "original", fileName);
        Directory.CreateDirectory(Path.GetDirectoryName(original)!);
        await File.WriteAllBytesAsync(original, [0x00]);
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string staged = Path.Combine(attemptDirectory, fileName);
        File.Copy(original, staged);

        try
        {
            using Process owner = Process.GetCurrentProcess();
            WorkerResponse response = await handler.HandleAsync(
                new WorkerRequest(
                    WorkerProtocol.Version,
                    WorkerCommands.Sign,
                    original,
                    staged,
                    SigningPlanJson.Serialize(PlanFor(".exe")),
                    owner.Id,
                    new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero)),
                CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(WorkerResponseCodes.UnsupportedFileType, response.Code);
            Assert.Equal(0, factoryCalls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("msi-disguised-as-exe.exe", ".exe", WorkerResponseCodes.UnsupportedFileType)]
    [InlineData("pe-disguised-as-msi.msi", ".msi", WorkerResponseCodes.UnsupportedFileType)]
    [Trait("Category", "SigningIntegration")]
    public async Task SpoofedSupportedExtensionIsTypedRejectedBeforeSigningRoutes(
        string fixtureName,
        string plannedExtension,
        string expectedCode)
    {
        int factoryCalls = 0;
        var sipBridge = new RecordingSipBridge();
        IWorkerCommandHandler handler = CreateHandler(
            () =>
            {
                factoryCalls++;
                return new NeverLegExecutor();
            },
            () =>
            {
                factoryCalls++;
                return new NeverVerifier();
            },
            () =>
            {
                factoryCalls++;
                return sipBridge;
            });
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-Spoofed-" + Guid.NewGuid().ToString("N"));
        string original = CopyFixture(root, Path.Combine("original", fixtureName), fixtureName);
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string staged = Path.Combine(attemptDirectory, fixtureName);
        File.Copy(original, staged);

        try
        {
            using Process owner = Process.GetCurrentProcess();
            WorkerResponse response = await handler.HandleAsync(
                new WorkerRequest(
                    WorkerProtocol.Version,
                    WorkerCommands.Sign,
                    original,
                    staged,
                    SigningPlanJson.Serialize(PlanFor(plannedExtension)),
                    owner.Id,
                    new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero)),
                CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(expectedCode, response.Code);
            Assert.Equal(0, factoryCalls);
            Assert.Equal(0, sipBridge.CallCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task WorkerRejectsUnclassifiableContentBeforeComparingCallerCapability()
    {
        int factoryCalls = 0;
        IWorkerCommandHandler handler = CreateHandler(
            () =>
            {
                factoryCalls++;
                return new NeverLegExecutor();
            },
            () =>
            {
                factoryCalls++;
                return new NeverVerifier();
            });
        string root = Path.Combine(Path.GetTempPath(), "CodeSigner-CapabilityMismatch-" + Guid.NewGuid().ToString("N"));
        string original = Path.Combine(root, "original", "payload.msi");
        Directory.CreateDirectory(Path.GetDirectoryName(original)!);
        await File.WriteAllBytesAsync(original, [0x00]);
        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string staged = Path.Combine(attemptDirectory, "payload.msi");
        File.Copy(original, staged);
        string forgedPePlan = SigningPlanJson.Serialize(PlanFor(".exe")).Replace(
            "\"extension\":\".exe\"",
            "\"extension\":\".msi\"",
            StringComparison.Ordinal);

        try
        {
            using Process owner = Process.GetCurrentProcess();
            WorkerResponse response = await handler.HandleAsync(
                new WorkerRequest(
                    WorkerProtocol.Version,
                    WorkerCommands.Sign,
                    original,
                    staged,
                    forgedPePlan,
                    owner.Id,
                    new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero)),
                CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(WorkerResponseCodes.UnsupportedFileType, response.Code);
            Assert.Equal(0, factoryCalls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static SigningPlan PlanFor(string extension)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, extension).Value);
    }

    private static IWorkerCommandHandler CreateHandler(
        Func<INativeSigningLegExecutor> signerFactory,
        Func<IProductionSignedFileVerifier> verifierFactory,
        Func<IWindowsSipSigningBridge>? sipBridgeFactory = null)
    {
        Type handlerType = Assembly.LoadFrom(WorkerAssemblyPath()).GetType(
            "CodeSigner.Worker.ProductionSigningWorkerCommandHandler",
            throwOnError: true)!;
        return Assert.IsAssignableFrom<IWorkerCommandHandler>(
            Activator.CreateInstance(
                handlerType,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args:
                [
                    signerFactory,
                    verifierFactory,
                    sipBridgeFactory ?? (() => new NeverSipBridge()),
                    (Func<IExistingSignatureInspector>)(() => new UnsignedInspector()),
                    (Action<WorkerProcessIdentity, WorkerProcessIdentity>)((_, _) => { }),
                    IntegrationTestSecureFileCommitter.Instance
                ],
                culture: null));
    }

    private static string WorkerAssemblyPath() => Path.Combine(
        RepositoryRoot(),
        "src",
        "CodeSigner.Worker",
        "bin",
#if DEBUG
        "Debug",
#else
        "Release",
#endif
        "net10.0-windows",
        "win-x64",
        "CodeSigner.Worker.dll");

    private static string CopyFixture(string root, string relativePath, string fixtureName)
    {
        string destination = Path.Combine(root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fixtureName), destination);
        return destination;
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
    }

    private sealed class NeverLegExecutor : INativeSigningLegExecutor
    {
        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            CodeSigner.Windows.Signing.SignatureLeg leg,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Rejected content reached native signing.");
    }

    private sealed class RecordingLegExecutor : INativeSigningLegExecutor
    {
        public int CallCount { get; private set; }

        public Task<NativeSigningResult> ExecuteAsync(
            string path,
            CodeSigner.Windows.Signing.SignatureLeg leg,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(NativeSigningResult.Failure(
                NativeSigningReasonCode.NativeSigningFailed,
                FailureHResult));
        }
    }

    private sealed class NeverVerifier : IProductionSignedFileVerifier
    {
        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The route unexpectedly reached verification.");
    }

    private sealed class UnsignedInspector : IExistingSignatureInspector
    {
        public ExistingSignatureInspectionResult Inspect(
            string originalPath, string stagedPath, SigningPlan plan, CancellationToken cancellationToken) =>
            new(ExistingSignatureInspectionStatus.Unsigned, unchecked((int)0x800B0100));
    }

    private sealed class RecordingSipBridge : IWindowsSipSigningBridge
    {
        public int CallCount { get; private set; }

        public Task<WindowsSipSigningResult> ExecuteAsync(
            string originalPath,
            string stagedPath,
            SigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            Func<WindowsSipSigningPhase, CancellationToken, ValueTask>? reportProgress,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(WindowsSipSigningResult.Failure(
                WindowsSipSigningError.SipUnavailable,
                FailureHResult));
        }
    }

    private sealed class NeverSipBridge : IWindowsSipSigningBridge
    {
        public Task<WindowsSipSigningResult> ExecuteAsync(
            string originalPath,
            string stagedPath,
            SigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            Func<WindowsSipSigningPhase, CancellationToken, ValueTask>? reportProgress,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Rejected content reached the SIP signing bridge.");
    }
}
