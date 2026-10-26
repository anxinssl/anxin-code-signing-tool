using System.Buffers.Binary;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class ExistingSignatureWorkerTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string OperationId = "0123456789abcdef0123456789abcdef";
    private const int FailureHResult = unchecked((int)0x80004005);

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public async Task ValidPeWithCertificateTableReturnsExplicitSkipWithoutDownstreamCalls()
    {
        Attempt attempt = CreateAttempt("valid-pe", "valid-unsigned.dll", "payload.dll", addPeCertificateTable: true);
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler("Valid", 0, dependencies)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            AssertSkip(response, attempt, WorkerSubjects.PeImage);
            dependencies.AssertNoDownstreamCalls();
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    [Theory]
    [InlineData("valid-unsigned.msi", "payload.msi", WorkerSubjects.WindowsInstaller)]
    [InlineData("valid-unsigned.cab", "payload.cab", WorkerSubjects.Cabinet)]
    [InlineData("generated-catalog", "payload.cat", WorkerSubjects.Catalog)]
    [InlineData("generated-app-package", "payload.appx", WorkerSubjects.AppPackage)]
    [InlineData("generated-powershell", "payload.ps1", WorkerSubjects.PowerShellScript)]
    [InlineData("generated-windows-script", "payload.vbs", WorkerSubjects.WindowsScript)]
    [Trait("Category", "ExistingSignature")]
    public async Task ValidSipReturnsExplicitSkipWithoutDownstreamCalls(
        string fixtureName,
        string fileName,
        string expectedSubject)
    {
        Attempt attempt = CreateAttempt("valid-sip", fixtureName, fileName);
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler("Valid", 0, dependencies)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            AssertSkip(response, attempt, expectedSubject);
            dependencies.AssertNoDownstreamCalls();
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    [Theory]
    [InlineData("Invalid", unchecked((int)0x80096010))]
    [InlineData("Untrusted", unchecked((int)0x800B0109))]
    [InlineData("Expired", unchecked((int)0x800B0101))]
    [InlineData("Partial", unchecked((int)0x800B0100))]
    [InlineData("Malformed", unchecked((int)0x800B0003))]
    [InlineData("FamilyIncompatible", unchecked((int)0x80070057))]
    [Trait("Category", "ExistingSignature")]
    public async Task RejectedExistingPeDispositionFailsClosedWithoutDownstreamCalls(
        string status,
        int hResult)
    {
        Attempt attempt = CreateAttempt("rejected-pe", "valid-unsigned.dll", "payload.dll", addPeCertificateTable: true);
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler(status, hResult, dependencies)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            AssertExistingSignatureFailure(response, attempt, WorkerExecutionRoute.ProductPe, hResult);
            dependencies.AssertNoDownstreamCalls();
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public async Task FamilyIncompatibleSipSignatureFailsBeforeInspectionOrSipExecution()
    {
        Attempt attempt = CreateAttempt("family-incompatible-sip", "valid-unsigned.msi", "payload.msi");
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler(
                    "FamilyIncompatible",
                    unchecked((int)0x80070057),
                    dependencies)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            AssertExistingSignatureFailure(
                response,
                attempt,
                WorkerExecutionRoute.WindowsSip,
                unchecked((int)0x80070057));
            dependencies.AssertNoDownstreamCalls();
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public async Task UnsignedPePreservesProductPeRouting()
    {
        Attempt attempt = CreateAttempt("unsigned-pe", "valid-unsigned.dll", "payload.dll");
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler(
                    "Unsigned",
                    unchecked((int)0x800B0100),
                    dependencies)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
            Assert.Equal(1, dependencies.PeEngineFactoryCalls);
            Assert.Equal(1, dependencies.PeEngineCalls);
            Assert.Equal(1, dependencies.PostSignVerifierFactoryCalls);
            Assert.Equal(0, dependencies.PostSignVerifierCalls);
            Assert.Equal(0, dependencies.SipBridgeFactoryCalls);
            Assert.Equal(0, dependencies.SdkLocatorFactoryCalls);
            Assert.Equal(0, dependencies.SdkExecutorFactoryCalls);
            AssertUnchanged(attempt);
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public async Task UnsignedSipFactoryFailureStaysOnSipRouteWithoutInvokingPeEngine()
    {
        Attempt attempt = CreateAttempt("unsigned-sip", "valid-unsigned.msi", "payload.msi");
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler(
                    "Unsigned",
                    unchecked((int)0x800B0100),
                    dependencies)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(WorkerResponseCodes.NativeSigningFailed, response.Code);
            Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
            Assert.Equal(WorkerExecutionRoute.WindowsSip, response.Route);
            Assert.Equal(WorkerFailureCode.NativeSigningFailed, response.Failure);
            Assert.Equal(1, dependencies.InspectionFactoryCalls);
            Assert.Equal(1, dependencies.InspectionCalls);
            Assert.Equal(0, dependencies.PeEngineFactoryCalls);
            Assert.Equal(0, dependencies.PeEngineCalls);
            Assert.Equal(0, dependencies.PostSignVerifierFactoryCalls);
            Assert.Equal(0, dependencies.PostSignVerifierCalls);
            Assert.Equal(1, dependencies.SipBridgeFactoryCalls);
            AssertUnchanged(attempt);
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public async Task CancellationDuringInspectionCannotReachAnySigningDependency()
    {
        Attempt attempt = CreateAttempt("cancel-inspection", "valid-unsigned.dll", "payload.dll", addPeCertificateTable: true);
        var dependencies = new RecordingDependencies();

        try
        {
            WorkerResponse response = await CreateInspectionHandler(
                    "Valid",
                    0,
                    dependencies,
                    cancelInspection: true)
                .HandleAsync(CreateRequest(attempt), CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal(WorkerResponseCodes.Cancelled, response.Code);
            Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
            Assert.Equal(WorkerExecutionRoute.ProductPe, response.Route);
            Assert.Equal(WorkerFailureCode.Cancelled, response.Failure);
            dependencies.AssertNoDownstreamCalls();
            AssertUnchanged(attempt);
        }
        finally
        {
            Directory.Delete(attempt.Root, recursive: true);
        }
    }

    private static IWorkerCommandHandler CreateInspectionHandler(
        string status,
        int hResult,
        RecordingDependencies dependencies,
        bool cancelInspection = false)
    {
        Assembly windowsAssembly = typeof(TransactionalStaging).Assembly;
        Type? inspectorType = windowsAssembly.GetType(
            "CodeSigner.Windows.Signing.IExistingSignatureInspector",
            throwOnError: false);
        Assert.NotNull(inspectorType);
        object proxy = DispatchProxy.Create(inspectorType, typeof(RuntimeInspectorProxy));
        var configuredProxy = Assert.IsAssignableFrom<RuntimeInspectorProxy>(proxy);
        configuredProxy.Status = status;
        configuredProxy.HResult = hResult;
        configuredProxy.CancelInspection = cancelInspection;
        configuredProxy.OnInspect = () => dependencies.InspectionCalls++;
        var holder = new RuntimeInspectorFactoryHolder(proxy, dependencies);
        Type factoryType = typeof(Func<>).MakeGenericType(inspectorType);
        MethodInfo createMethod = typeof(RuntimeInspectorFactoryHolder).GetMethod(
            nameof(RuntimeInspectorFactoryHolder.Create),
            BindingFlags.Instance | BindingFlags.Public)!;
        Delegate inspectorFactory = Expression.Lambda(
                factoryType,
                Expression.Convert(
                    Expression.Call(Expression.Constant(holder), createMethod),
                    inspectorType))
            .Compile();

        return Assert.IsAssignableFrom<IWorkerCommandHandler>(
            Activator.CreateInstance(
                LoadHandlerType(),
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args:
                [
                    (Func<IPeAuthenticodeSigningEngine>)(() => dependencies.CreatePeEngine()),
                    (Func<IProductionSignedFileVerifier>)(() => dependencies.CreatePostSignVerifier()),
                    (Func<ITrustedSdkSignToolLocator>)dependencies.CreateSdkLocator,
                    (Func<ITrustedSdkSignToolLocator, IProductionSignedFileVerifier, ITrustedSdkSignToolExecutor>)
                        dependencies.CreateSdkExecutor,
                    (Func<IWindowsSipSigningBridge>)dependencies.CreateSipBridge,
                    inspectorFactory,
                    (Action<WorkerProcessIdentity, WorkerProcessIdentity>)((_, _) => { }),
                    IntegrationTestSecureFileCommitter.Instance
                ],
                culture: null));
    }

    private static WorkerRequest CreateRequest(Attempt attempt)
    {
        using Process owner = Process.GetCurrentProcess();
        return new WorkerRequest(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            attempt.OriginalPath,
            attempt.StagedPath,
            SigningPlanJson.Serialize(PlanFor(Path.GetExtension(attempt.OriginalPath))),
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
            OperationId);
    }

    private static Attempt CreateAttempt(
        string name,
        string fixtureName,
        string fileName,
        bool addPeCertificateTable = false)
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            $"CodeSigner-ExistingSignature-{name}-{Guid.NewGuid():N}");
        string relativePath = Path.Combine("original", fileName);
        string original = fixtureName switch
        {
            "generated-catalog" => ExistingSignatureFixtureFactory.CreateCatalog(root, relativePath),
            "generated-app-package" => ExistingSignatureFixtureFactory.CreateAppPackage(root, relativePath),
            "generated-powershell" => ExistingSignatureFixtureFactory.CreatePowerShellScript(root, relativePath),
            "generated-windows-script" => ExistingSignatureFixtureFactory.CreateWindowsScript(root, relativePath),
            _ => CopyFixture(root, relativePath, fixtureName)
        };
        if (addPeCertificateTable)
        {
            AddPeCertificateTable(original);
        }

        string attemptDirectory = TransactionalStaging.CreateAttemptDirectory(root);
        string staged = Path.Combine(attemptDirectory, fileName);
        File.Copy(original, staged);
        return new Attempt(
            root,
            original,
            staged,
            Hash(original),
            Hash(staged),
            ReadIdentity(original),
            ReadIdentity(staged),
            Path.Combine(root, "published" + Path.GetExtension(fileName)));
    }

    private static void AssertSkip(WorkerResponse response, Attempt attempt, string expectedSubject)
    {
        Assert.True(response.Success);
        Assert.Equal(WorkerResponseCodes.SkippedExistingSignature, response.Code);
        Assert.Equal(WorkerSigningOutcome.SkippedExistingSignature, response.Outcome);
        Assert.Equal(WorkerExecutionRoute.Skip, response.Route);
        Assert.Null(response.Failure);
        Assert.Equal(expectedSubject, response.Subject);
        Assert.Equal(attempt.OriginalHash.ToLowerInvariant(), response.OriginalSha256);
        Assert.Equal(attempt.StagedHash.ToLowerInvariant(), response.StagedSha256);
        AssertUnchanged(attempt);
    }

    private static void AssertExistingSignatureFailure(
        WorkerResponse response,
        Attempt attempt,
        WorkerExecutionRoute route,
        int expectedHResult)
    {
        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.ExistingSignatureRejected, response.Code);
        Assert.Equal(WorkerSigningOutcome.Failure, response.Outcome);
        Assert.Equal(route, response.Route);
        Assert.Equal(WorkerFailureCode.ExistingSignatureRejected, response.Failure);
        Assert.Equal(expectedHResult, response.HResult);
        Assert.Equal(attempt.OriginalHash.ToLowerInvariant(), response.OriginalSha256);
        Assert.Equal(attempt.StagedHash.ToLowerInvariant(), response.StagedSha256);
        AssertUnchanged(attempt);
    }

    private static void AssertUnchanged(Attempt attempt)
    {
        Assert.Equal(attempt.OriginalHash, Hash(attempt.OriginalPath));
        Assert.Equal(attempt.StagedHash, Hash(attempt.StagedPath));
        Assert.Equal(attempt.OriginalIdentity, ReadIdentity(attempt.OriginalPath));
        Assert.Equal(attempt.StagedIdentity, ReadIdentity(attempt.StagedPath));
        Assert.False(File.Exists(attempt.TargetPath));
    }

    private static StableFileIdentity ReadIdentity(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return WindowsFileIdentity.FromHandle(stream.SafeFileHandle);
    }

    private static void AddPeCertificateTable(string path)
    {
        byte[] image = File.ReadAllBytes(path);
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3c, sizeof(int)));
        int optionalHeaderOffset = checked(peOffset + 4 + 20);
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optionalHeaderOffset, sizeof(ushort)));
        int directoriesOffset = magic switch
        {
            0x10b => 96,
            0x20b => 112,
            _ => throw new InvalidDataException("The fixture does not contain a supported PE optional header.")
        };
        int certificateDirectoryOffset = checked(optionalHeaderOffset + directoriesOffset + (4 * 8));
        int tableOffset = checked((image.Length + 7) & ~7);
        const int recordLength = 16;
        byte[] signedImage = new byte[checked(tableOffset + recordLength)];
        image.CopyTo(signedImage, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedImage.AsSpan(certificateDirectoryOffset, sizeof(uint)),
            checked((uint)tableOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedImage.AsSpan(certificateDirectoryOffset + sizeof(uint), sizeof(uint)),
            recordLength);
        BinaryPrimitives.WriteUInt32LittleEndian(signedImage.AsSpan(tableOffset, sizeof(uint)), recordLength);
        BinaryPrimitives.WriteUInt16LittleEndian(signedImage.AsSpan(tableOffset + 4, sizeof(ushort)), 0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(signedImage.AsSpan(tableOffset + 6, sizeof(ushort)), 0x0002);
        signedImage.AsSpan(tableOffset + 8, 8).Fill(0x5a);
        File.WriteAllBytes(path, signedImage);
    }

    private static Type LoadHandlerType() => Assembly.LoadFrom(WorkerAssemblyPath()).GetType(
        "CodeSigner.Worker.ProductionSigningWorkerCommandHandler",
        throwOnError: true)!;

    private static SigningPlan PlanFor(string extension)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, extension).Value);
    }

    private static string CopyFixture(string root, string relativePath, string fixtureName)
    {
        string destination = Path.Combine(root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fixtureName), destination);
        return destination;
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

    private static string Hash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private sealed record Attempt(
        string Root,
        string OriginalPath,
        string StagedPath,
        string OriginalHash,
        string StagedHash,
        StableFileIdentity OriginalIdentity,
        StableFileIdentity StagedIdentity,
        string TargetPath);

    private sealed class RuntimeInspectorFactoryHolder(
        object inspector,
        RecordingDependencies dependencies)
    {
        public object Create()
        {
            dependencies.InspectionFactoryCalls++;
            return inspector;
        }
    }

    public class RuntimeInspectorProxy : DispatchProxy
    {
        public string Status { get; set; } = string.Empty;

        public int HResult { get; set; }

        public bool CancelInspection { get; set; }

        public Action? OnInspect { get; set; }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            Assert.NotNull(targetMethod);
            Assert.NotNull(args);
            Assert.Equal("Inspect", targetMethod.Name);
            OnInspect?.Invoke();
            CancellationToken cancellationToken = Assert.IsType<CancellationToken>(args[3]);
            if (CancelInspection)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
            Assembly assembly = targetMethod.ReturnType.Assembly;
            Type? statusType = assembly.GetType(
                "CodeSigner.Windows.Signing.ExistingSignatureInspectionStatus",
                throwOnError: false);
            Assert.NotNull(statusType);
            object parsedStatus = Enum.Parse(statusType, Status, ignoreCase: false);
            return Activator.CreateInstance(targetMethod.ReturnType, parsedStatus, HResult);
        }
    }

    private sealed class RecordingDependencies
    {
        public int InspectionFactoryCalls { get; set; }

        public int InspectionCalls { get; set; }

        public int PeEngineFactoryCalls { get; private set; }

        public int PeEngineCalls { get; set; }

        public int PostSignVerifierFactoryCalls { get; private set; }

        public int PostSignVerifierCalls { get; set; }

        public int SdkLocatorFactoryCalls { get; private set; }

        public int SdkExecutorFactoryCalls { get; private set; }

        public int SipBridgeFactoryCalls { get; private set; }

        public RecordingPeEngine CreatePeEngine()
        {
            PeEngineFactoryCalls++;
            return new RecordingPeEngine(this);
        }

        public RecordingPostSignVerifier CreatePostSignVerifier()
        {
            PostSignVerifierFactoryCalls++;
            return new RecordingPostSignVerifier(this);
        }

        public ITrustedSdkSignToolLocator CreateSdkLocator()
        {
            SdkLocatorFactoryCalls++;
            throw new InvalidOperationException("Existing-signature handling reached the SDK locator factory.");
        }

        public ITrustedSdkSignToolExecutor CreateSdkExecutor(
            ITrustedSdkSignToolLocator locator,
            IProductionSignedFileVerifier verifier)
        {
            SdkExecutorFactoryCalls++;
            throw new InvalidOperationException("Existing-signature handling reached the SDK executor factory.");
        }

        public IWindowsSipSigningBridge CreateSipBridge()
        {
            SipBridgeFactoryCalls++;
            throw new InvalidOperationException("Existing-signature handling reached the SIP bridge factory.");
        }

        public void AssertNoDownstreamCalls()
        {
            Assert.Equal(1, InspectionFactoryCalls);
            Assert.Equal(1, InspectionCalls);
            Assert.Equal(0, PeEngineFactoryCalls);
            Assert.Equal(0, PeEngineCalls);
            Assert.Equal(0, PostSignVerifierFactoryCalls);
            Assert.Equal(0, PostSignVerifierCalls);
            Assert.Equal(0, SdkLocatorFactoryCalls);
            Assert.Equal(0, SdkExecutorFactoryCalls);
            Assert.Equal(0, SipBridgeFactoryCalls);
        }

        public void AssertNoCalls()
        {
            Assert.Equal(0, InspectionFactoryCalls);
            Assert.Equal(0, InspectionCalls);
            Assert.Equal(0, PeEngineFactoryCalls);
            Assert.Equal(0, PeEngineCalls);
            Assert.Equal(0, PostSignVerifierFactoryCalls);
            Assert.Equal(0, PostSignVerifierCalls);
            Assert.Equal(0, SdkLocatorFactoryCalls);
            Assert.Equal(0, SdkExecutorFactoryCalls);
            Assert.Equal(0, SipBridgeFactoryCalls);
        }
    }

    private sealed class RecordingPeEngine(RecordingDependencies dependencies) : IPeAuthenticodeSigningEngine
    {
        public Task<NativeSigningResult> ExecuteAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            nint providerWindowHandle,
            CancellationToken cancellationToken) => ExecuteAsync(
            stagedPath,
            plan,
            stagingOwnerPid,
            stagingOwnerStartUtc,
            providerWindowHandle,
            static (_, _) => ValueTask.CompletedTask,
            cancellationToken);

        public Task<NativeSigningResult> ExecuteAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            int stagingOwnerPid,
            DateTimeOffset stagingOwnerStartUtc,
            nint providerWindowHandle,
            Func<int, CancellationToken, ValueTask> reportLeg,
            CancellationToken cancellationToken)
        {
            dependencies.PeEngineCalls++;
            return Task.FromResult(NativeSigningResult.Failure(
                NativeSigningReasonCode.NativeSigningFailed,
                FailureHResult));
        }
    }

    private sealed class RecordingPostSignVerifier(RecordingDependencies dependencies)
        : IProductionSignedFileVerifier
    {
        public Task<NativeSigningResult> VerifyAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            dependencies.PostSignVerifierCalls++;
            throw new InvalidOperationException("The failed PE route reached post-sign verification.");
        }
    }
}
