using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class SdkSignToolSettingsTests
{
    [Fact]
    public async Task SettingsDetectionDisplaysExactAvailabilityAndStartsNoSigningOperation()
    {
        TrustedSdkSignToolCandidate candidate = Candidate();
        var sdkReadiness = new SequenceSdkReadiness(
            SdkSignToolDiscoveryResult.Unavailable(),
            SdkSignToolDiscoveryResult.Available(candidate));
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(sdkReadiness, batch);
        await viewModel.InitializeAsync();

        Assert.False(viewModel.SdkSignToolAvailable);
        Assert.Equal("未检测到 Windows SDK 签名工具", viewModel.SdkSignToolStatusText);

        await viewModel.RefreshSdkSignToolCommand.ExecuteAsync(null);

        Assert.True(viewModel.SdkSignToolAvailable);
        Assert.Equal(candidate, viewModel.SdkSignToolCandidate);
        Assert.Equal(
            $"SDK 兼容备用可用；SDK 兼容备用已启用；SDK 10.0.26100.0；路径已验证：{candidate.Path}",
            viewModel.SdkSignToolStatusText);
        Assert.Equal(2, sdkReadiness.RefreshCount);
        Assert.Equal(0, batch.SigningInvocationCount);
    }

    [Fact]
    public async Task SettingsDetectionDisplaysExactRejectionAndDoesNotEnableFallback()
    {
        var sdkReadiness = new SequenceSdkReadiness(
            SdkSignToolDiscoveryResult.Unavailable(),
            SdkSignToolDiscoveryResult.Rejected(SdkSignToolRejectionReason.ProductMismatch));
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(sdkReadiness, batch);
        await viewModel.InitializeAsync();

        await viewModel.RefreshSdkSignToolCommand.ExecuteAsync(null);

        Assert.False(viewModel.SdkSignToolAvailable);
        Assert.Null(viewModel.SdkSignToolCandidate);
        Assert.Equal(
            "Windows SDK 签名工具不可用：Microsoft 产品元数据不匹配",
            viewModel.SdkSignToolStatusText);
        Assert.Equal(0, batch.SigningInvocationCount);
    }

    [Fact]
    public async Task NormalStartupRunsNonSigningSdkDetection()
    {
        TrustedSdkSignToolCandidate candidate = Candidate();
        var sdkReadiness = new SequenceSdkReadiness(SdkSignToolDiscoveryResult.Available(candidate));
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(sdkReadiness, batch);

        await viewModel.InitializeAsync();

        Assert.Equal(1, sdkReadiness.RefreshCount);
        Assert.True(viewModel.SdkSignToolAvailable);
        Assert.Equal(0, batch.SigningInvocationCount);
    }

    [Fact]
    public void SettingsXamlUsesExactDetectionButtonAndStatusBinding()
    {
        string root = FindRepositoryRoot();
        XDocument document = XDocument.Load(Path.Combine(root, "src", "CodeSigner.App", "SettingsWindow.xaml"));
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XElement button = Assert.Single(
            document.Descendants(presentation + "Button"),
            element => string.Equals(
                (string?)element.Attribute("Content"),
                "检测 Windows SDK 签名工具",
                StringComparison.Ordinal));

        Assert.Equal("{Binding RefreshSdkSignToolCommand}", (string?)button.Attribute("Command"));
        Assert.Equal(
            "SettingsDetectSdkSignToolButton",
            (string?)button.Attribute("AutomationProperties.AutomationId"));
        XElement status = Assert.Single(
            document.Descendants(presentation + "TextBlock"),
            element => string.Equals(
                (string?)element.Attribute("Text"),
                "{Binding SdkSignToolStatusText}",
                StringComparison.Ordinal));
        Assert.Equal("Wrap", (string?)status.Attribute("TextWrapping"));
    }

    [Fact]
    public async Task SuccessfulRefreshSnapshotsEnabledExactCandidateIntoNextSigningRequest()
    {
        string root = Directory.CreateTempSubdirectory("codesigner-sdk-settings-").FullName;
        try
        {
            TrustedSdkSignToolCandidate candidate = Candidate();
            var sdkReadiness = new SequenceSdkReadiness(
                SdkSignToolDiscoveryResult.Unavailable(),
                SdkSignToolDiscoveryResult.Available(candidate));
            var batch = new RecordingBatchAdapter();
            EligibleCertificate certificate = Certificate();
            string originalPath = Path.Combine(root, "input.exe");
            string destinationPath = Path.Combine(root, "output", "input.exe");
            File.WriteAllText(originalPath, "fixture");
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            var intake = new FixedIntakeAdapter(new IntakePlan(
                Path.GetDirectoryName(destinationPath)!,
                [new IntakeFile(
                    originalPath,
                    Path.GetFileName(originalPath),
                    destinationPath,
                    Path.GetDirectoryName(destinationPath)!,
                    new StableFileIdentity(1, "SDK-SETTINGS-1"),
                    new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()))]));
            await using SigningWorkbenchViewModel viewModel = CreateSigningViewModel(
                sdkReadiness,
                batch,
                intake,
                certificate);
            await viewModel.InitializeAsync();
            await viewModel.RefreshReadinessAsync();
            await viewModel.RefreshSdkSignToolCommand.ExecuteAsync(null);
            await viewModel.ReplanOutputRootAsync(Path.GetDirectoryName(destinationPath)!);
            await viewModel.QueueFilesAndWaitAsync([originalPath]);

            Assert.True(viewModel.CanSign, viewModel.SignDisabledReason);
            await viewModel.SignAsync();

            BatchItemRequest request = Assert.Single(batch.LastRequests);
            Assert.True(viewModel.SdkSignToolFallbackEnabledForSession);
            Assert.Equal(
                new WorkerSdkFallback(
                    true,
                    new WorkerSdkCandidateIdentity(
                        candidate.Path,
                        "10.0.26100.0",
                        "10.0.26100.7463",
                        candidate.Publisher,
                        candidate.CompanyName,
                        candidate.ProductName,
                        new string('a', 64))),
                request.SdkFallback);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UnavailableRefreshSnapshotsExplicitDisabledStateIntoNextSigningRequest()
    {
        string root = Directory.CreateTempSubdirectory("codesigner-sdk-disabled-").FullName;
        try
        {
            var batch = new RecordingBatchAdapter();
            EligibleCertificate certificate = Certificate();
            string originalPath = Path.Combine(root, "input.exe");
            string destinationPath = Path.Combine(root, "output", "input.exe");
            File.WriteAllText(originalPath, "fixture");
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            var intake = new FixedIntakeAdapter(new IntakePlan(
                Path.GetDirectoryName(destinationPath)!,
                [new IntakeFile(
                    originalPath,
                    Path.GetFileName(originalPath),
                    destinationPath,
                    Path.GetDirectoryName(destinationPath)!,
                    new StableFileIdentity(2, "SDK-SETTINGS-2"),
                    new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()))]));
            await using SigningWorkbenchViewModel viewModel = CreateSigningViewModel(
                new SequenceSdkReadiness(SdkSignToolDiscoveryResult.Unavailable()),
                batch,
                intake,
                certificate);
            await viewModel.InitializeAsync();
            await viewModel.RefreshReadinessAsync();
            await viewModel.ReplanOutputRootAsync(Path.GetDirectoryName(destinationPath)!);
            await viewModel.QueueFilesAndWaitAsync([originalPath]);

            Assert.True(viewModel.CanSign, viewModel.SignDisabledReason);
            await viewModel.SignAsync();

            Assert.False(viewModel.SdkSignToolFallbackEnabledForSession);
            Assert.Equal(WorkerSdkFallback.Disabled, Assert.Single(batch.LastRequests).SdkFallback);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static SigningWorkbenchViewModel CreateViewModel(
        ISdkSignToolReadinessState sdkReadiness,
        RecordingBatchAdapter batch) => new(
            new FixedReadinessAdapter(),
            new NoopIntakeAdapter(),
            batch,
            new NoopOperatorShell(),
            new HealthyWorkerService(),
            new NoopRepairService(),
            static _ => ValueTask.FromResult(true),
            sdkReadiness);

    private static SigningWorkbenchViewModel CreateSigningViewModel(
        ISdkSignToolReadinessState sdkReadiness,
        RecordingBatchAdapter batch,
        IIntakeAdapter intake,
        EligibleCertificate certificate) => new(
            new ReadyReadinessAdapter(certificate),
            intake,
            batch,
            new NoopOperatorShell(),
            new HealthyWorkerService(),
            new NoopRepairService(),
            static _ => ValueTask.FromResult(true),
            sdkReadiness);

    private static EligibleCertificate Certificate() => new(
        StoreLocation.CurrentUser,
        "My",
        new string('C', 40),
        "CN=SDK Session Test",
        "CN=Test Issuer",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddDays(30),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private static TrustedSdkSignToolCandidate Candidate()
    {
        string path = Path.GetFullPath(
            "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe");
        return new TrustedSdkSignToolCandidate(
            path,
            new Version(10, 0, 26100, 0),
            new Version(10, 0, 26100, 7463),
            "Microsoft Corporation",
            "Microsoft Corporation",
            "Microsoft® Windows® Operating System",
            new string('A', 64));
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "CodeSigner.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("The CodeSigner repository root was not found.");
    }

    private sealed class SequenceSdkReadiness(params SdkSignToolDiscoveryResult[] results)
        : ISdkSignToolReadinessState
    {
        private readonly object sync = new();
        private readonly Queue<SdkSignToolDiscoveryResult> results = new(results);
        private SdkSignToolDiscoveryResult current = SdkSignToolDiscoveryResult.Unavailable();

        public int RefreshCount { get; private set; }

        public SdkSignToolDiscoveryResult Current
        {
            get
            {
                lock (sync)
                {
                    return current;
                }
            }
        }

        public SdkSignToolDiscoveryResult Refresh()
        {
            lock (sync)
            {
                RefreshCount++;
                if (results.Count > 0)
                {
                    current = results.Dequeue();
                }

                return current;
            }
        }
    }

    private sealed class FixedReadinessAdapter : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => new(
            new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
            NativeApiAvailability.Available,
            new SimplySignInstallation(
                SimplySignInstallationStatus.Installed,
                "{A}",
                "{B}",
                "SimplySign Desktop",
                "Certum",
                "9.2.14.61"),
            new CertificateCatalog(
                CertificateAvailabilityStatus.Unavailable,
                Array.Empty<EligibleCertificate>(),
                [new CertificateStoreDiagnostic(
                    StoreLocation.CurrentUser,
                    "My",
                    CertificateStoreReadStatus.Success)]),
            new TimestampConfiguration(TimestampConfigurationStatus.Configured, timestampUri),
            ProviderAuthorizationStatus.AuthorizationUnknown);
    }

    private sealed class ReadyReadinessAdapter(EligibleCertificate certificate) : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => new(
            new WorkstationReadiness(WorkstationSupportStatus.Supported, "None"),
            NativeApiAvailability.Available,
            new SimplySignInstallation(
                SimplySignInstallationStatus.Installed,
                "{A}",
                "{B}",
                "SimplySign Desktop",
                "Certum",
                "9.2.14.61"),
            new CertificateCatalog(
                CertificateAvailabilityStatus.CertificateAvailable,
                [certificate],
                [new CertificateStoreDiagnostic(
                    StoreLocation.CurrentUser,
                    "My",
                    CertificateStoreReadStatus.Success)]),
            new TimestampConfiguration(TimestampConfigurationStatus.Configured, timestampUri),
            ProviderAuthorizationStatus.AuthorizationUnknown);
    }

    private sealed class NoopIntakeAdapter : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("SDK Settings tests do not perform intake.");
    }

    private sealed class FixedIntakeAdapter(IntakePlan plan) : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(plan);
        }
    }

    private sealed class RecordingBatchAdapter : IBatchAdapter
    {
        public int SigningInvocationCount { get; private set; }

        public IReadOnlyList<BatchItemRequest> LastRequests { get; private set; } = [];

        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            SigningInvocationCount++;
            LastRequests = [request];
            return Task.FromResult(new BatchProgressUpdate(
                request.ItemId,
                BatchItemState.Failed,
                new BatchItemReceipt(
                    request.ItemId,
                    BatchItemState.Failed,
                    BatchResultCode.WorkerFailure,
                    request.File.OriginalPath,
                    request.File.DestinationPath,
                    OriginalSha256: null,
                    PublishedSha256: null,
                    AttemptId: null,
                    WorkerProcessId: null,
                    HResult: unchecked((int)0x80004005))));
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            SigningInvocationCount++;
            throw new InvalidOperationException("SDK detection must never resume a signing batch.");
        }

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoopOperatorShell : IOperatorShell
    {
        public void OpenFolder(string path)
        {
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken) =>
            Task.FromResult(Path.Combine(Path.GetTempPath(), "codesigner-sdk-settings.json"));
    }

    private sealed class HealthyWorkerService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
    }

    private sealed class NoopRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("SDK Settings tests do not repair Worker.");

        public void Dispose()
        {
        }
    }
}
