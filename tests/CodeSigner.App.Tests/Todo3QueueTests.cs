using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class Todo3QueueTests
{
    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task DualModeResolvesMixedQueuePoliciesPerDetectedFormat()
    {
        using TempFixture fixture = new();
        string pePath = fixture.Write("library.dll", [0x4D, 0x5A, 0x01]);
        string msiPath = fixture.Write("installer.msi", [0xD0, 0xCF, 0x11, 0xE0]);
        string scriptPath = fixture.Write("deploy.ps1", [0x23, 0x20, 0x73, 0x63]);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [
                FileFor(pePath, outputRoot, ".dll"),
                FileFor(msiPath, outputRoot, ".msi"),
                FileFor(scriptPath, outputRoot, ".ps1")
            ]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, Certificate('A'), Certificate('B'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();

        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([pePath, msiPath, scriptPath]);
        viewModel.SelectedMode = SigningMode.Dual;

        Assert.Collection(
            viewModel.Rows,
            row =>
            {
                Assert.Equal(SigningFormatFamily.PeImage, row.FormatFamily);
                Assert.Equal(SigningEngine.PeImage, row.Engine);
                Assert.Equal(SigningMode.Dual, row.EffectiveMode);
                Assert.Equal("SHA-1 + SHA-256", row.EffectivePolicyText);
            },
            row =>
            {
                Assert.Equal(SigningFormatFamily.WindowsInstaller, row.FormatFamily);
                Assert.Equal(SigningEngine.WindowsSip, row.Engine);
                Assert.Equal(SigningMode.Single, row.EffectiveMode);
                Assert.Equal("SHA-256", row.EffectivePolicyText);
            },
            row =>
            {
                Assert.Equal(SigningFormatFamily.PowerShellScript, row.FormatFamily);
                Assert.Equal(SigningEngine.WindowsSip, row.Engine);
                Assert.Equal(SigningMode.Single, row.EffectiveMode);
                Assert.Equal("SHA-256", row.EffectivePolicyText);
            });

        Assert.False(viewModel.CanSign);
        Assert.Equal("选择 SHA-256 辅助签名证书", viewModel.SignDisabledReason);

        SigningPlan sipPlan = viewModel.BuildSigningPlan(FileFor(msiPath, outputRoot, ".msi"));
        Assert.Equal(SigningMode.Dual, sipPlan.RequestedMode);
        Assert.Equal(SigningMode.Single, sipPlan.EffectiveMode);
        Assert.Single(sipPlan.Legs);
        Assert.Equal(FileDigestAlgorithm.Sha256, sipPlan.Legs[0].FileDigest);

        viewModel.SecondaryCertificate = viewModel.Certificates[1];
        Assert.True(viewModel.CanSign);

        SigningPlan pePlan = viewModel.BuildSigningPlan(FileFor(pePath, outputRoot, ".dll"));
        Assert.Equal(SigningMode.Dual, pePlan.EffectiveMode);
        Assert.Collection(
            pePlan.Legs,
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha1, leg.FileDigest);
                Assert.False(leg.Append);
            },
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
                Assert.True(leg.Append);
            });
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task DualModeWithoutPeRowsDoesNotRequireSecondaryCertificate()
    {
        using TempFixture fixture = new();
        string msiPath = fixture.Write("installer.msi", [0xD0, 0xCF, 0x11, 0xE0]);
        string scriptPath = fixture.Write("deploy.ps1", [0x23, 0x20, 0x73, 0x63]);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [
                FileFor(msiPath, outputRoot, ".msi"),
                FileFor(scriptPath, outputRoot, ".ps1")
            ]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = viewModel.Certificates[0];

        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([msiPath, scriptPath]);
        viewModel.SelectedMode = SigningMode.Dual;

        Assert.DoesNotContain(viewModel.Rows, row => row.Capability == SigningCapability.PeImageDualCapable);
        Assert.True(viewModel.CanSign);
        Assert.NotEqual("选择 SHA-256 辅助签名证书", viewModel.SignDisabledReason);
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task RemovingPendingRowLeavesSourceBytesIdentical()
    {
        using TempFixture fixture = new();
        byte[] originalBytes = [0, 1, 2, 3, 0xFE, 0xFF, 42];
        string sourcePath = fixture.Write("installer.msi", originalBytes);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [FileFor(sourcePath, outputRoot, ".msi")]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();

        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([sourcePath]);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        row.IsSelected = true;
        viewModel.RemoveSelected();

        Assert.Empty(viewModel.Rows);
        Assert.True(File.Exists(sourcePath));
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(originalBytes)),
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourcePath))));
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task RemovalCommandsAreEnabledAndEffectiveOnlyForIdleRemovableStates()
    {
        using TempFixture fixture = new();
        string outputRoot = Path.Combine(fixture.Root, "out");
        BatchItemState[] states = Enum.GetValues<BatchItemState>();
        IntakeFile[] files = states
            .Select((state, index) => FileFor(
                fixture.Write($"state-{index}.exe", [0x4D, 0x5A, (byte)index]),
                outputRoot,
                ".exe"))
            .ToArray();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            files));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();

        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync(files.Select(static file => file.OriginalPath).ToArray());
        Assert.Equal(states.Length, viewModel.Rows.Count);
        BatchItemState[] removableStates =
        [
            BatchItemState.Pending,
            BatchItemState.Failed,
            BatchItemState.PausedProvider,
            BatchItemState.PausedTimestamp,
            BatchItemState.Cancelled,
            BatchItemState.Published,
            BatchItemState.SkippedAlreadySigned
        ];
        for (int index = 0; index < states.Length; index++)
        {
            QueueItemViewModel row = viewModel.Rows[index];
            row.Apply(states[index], receipt: null);
            row.IsSelected = true;
            Assert.Equal(
                removableStates.Contains(states[index]),
                viewModel.RemoveQueueItemCommand.CanExecute(row));
        }

        var foreignRow = new QueueItemViewModel("foreign", files[0]);
        Assert.False(viewModel.RemoveQueueItemCommand.CanExecute(foreignRow));

        Assert.True(viewModel.RemoveCommand.CanExecute(null));
        viewModel.RemoveSelected();

        Assert.DoesNotContain(viewModel.Rows, row => removableStates.Contains(row.State));
        Assert.Equal(states.Length - removableStates.Length, viewModel.Rows.Count);
        foreach ((IntakeFile file, int index) in files.Select((file, index) => (file, index)))
        {
            byte[] expected = [0x4D, 0x5A, (byte)index];
            Assert.True(File.Exists(file.OriginalPath));
            Assert.Equal(Hash(expected), Hash(File.ReadAllBytes(file.OriginalPath)));
        }

        Assert.False(viewModel.RemoveCommand.CanExecute(null));
        viewModel.RemoveSelected();
        Assert.Equal(states.Length - removableStates.Length, viewModel.Rows.Count);
        Assert.All(viewModel.Rows, row => Assert.False(viewModel.RemoveQueueItemCommand.CanExecute(row)));
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task RemovalCommandsAreBlockedWhileSigningIsBusy()
    {
        using TempFixture fixture = new();
        string sourcePath = fixture.Write("busy.exe", [0x4D, 0x5A, 0x22]);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var batch = new BlockingBatchAdapter();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [FileFor(sourcePath, outputRoot, ".exe")]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, batch, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([sourcePath]);
        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        row.IsSelected = true;

        Task signing = viewModel.SignAsync();
        await batch.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(viewModel.IsBusy);
        Assert.False(viewModel.RemoveCommand.CanExecute(null));
        Assert.False(viewModel.RemoveQueueItemCommand.CanExecute(row));
        viewModel.RemoveSelected();
        Assert.Same(row, Assert.Single(viewModel.Rows));

        batch.Complete(row.ItemId);
        await signing;
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task PendingRemovalExcludesSubsequentRequestAndPreservesBothSources()
    {
        using TempFixture fixture = new();
        byte[] removedBytes = [0x4D, 0x5A, 0x10, 0x11];
        byte[] retainedBytes = [0x4D, 0x5A, 0x20, 0x21];
        string removedPath = fixture.Write("removed.exe", removedBytes);
        string retainedPath = fixture.Write("retained.exe", retainedBytes);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var batch = new RecordingBatchAdapter();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [
                FileFor(removedPath, outputRoot, ".exe"),
                FileFor(retainedPath, outputRoot, ".exe")
            ]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, batch, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([removedPath, retainedPath]);

        viewModel.Rows[0].IsSelected = true;
        viewModel.RemoveSelected();
        await viewModel.SignAsync();

        BatchItemRequest request = Assert.Single(batch.RunRequests);
        Assert.Equal(retainedPath, request.File.OriginalPath);
        Assert.Equal(Hash(removedBytes), Hash(File.ReadAllBytes(removedPath)));
        Assert.Equal(Hash(retainedBytes), Hash(File.ReadAllBytes(retainedPath)));
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task RemovingFailedCurrentRowPrunesOnlyItsContextAndSignsNextCurrentRow()
    {
        using TempFixture fixture = new();
        byte[] failedBytes = [0x4D, 0x5A, 0x30, 0x31];
        byte[] retainedBytes = [0x4D, 0x5A, 0x40, 0x41];
        string failedPath = fixture.Write("failed.exe", failedBytes);
        string retainedPath = fixture.Write("retained.exe", retainedBytes);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var batch = new RetryRecordingBatchAdapter();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [
                FileFor(failedPath, outputRoot, ".exe"),
                FileFor(retainedPath, outputRoot, ".exe")
            ]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, batch, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([failedPath, retainedPath]);
        string failedItemId = viewModel.Rows[0].ItemId;
        string retainedItemId = viewModel.Rows[1].ItemId;
        Assert.Equal("1", failedItemId);
        Assert.Equal("2", retainedItemId);

        await viewModel.SignAsync();
        QueueItemViewModel failedRow = Assert.Single(viewModel.Rows, row => row.ItemId == failedItemId);
        failedRow.IsSelected = true;
        Assert.True(viewModel.RemoveCommand.CanExecute(null));
        Assert.True(viewModel.RemoveQueueItemCommand.CanExecute(failedRow));
        viewModel.RemoveSelected();
        Assert.False(viewModel.RetryCommand.CanExecute(null));
        Assert.True(viewModel.SignCommand.CanExecute(null));
        await viewModel.SignAsync();

        Assert.Equal([failedItemId], batch.PrunedItemIds);
        Assert.Equal([failedItemId, retainedItemId], batch.WorkerItemIds);
        Assert.Equal([retainedItemId], batch.PublicationItemIds);
        QueueItemViewModel retainedRow = Assert.Single(viewModel.Rows);
        Assert.Equal(retainedItemId, retainedRow.ItemId);
        Assert.Equal(BatchItemState.Published, retainedRow.State);
        Assert.Equal(100, viewModel.AggregateProgressPercent);
        Assert.False(viewModel.RetryCommand.CanExecute(null));
        Assert.False(viewModel.SignCommand.CanExecute(null));
        Assert.Equal(Hash(failedBytes), Hash(File.ReadAllBytes(failedPath)));
        Assert.Equal(Hash(retainedBytes), Hash(File.ReadAllBytes(retainedPath)));
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task PruneFailureLeavesFailedRowSourceAndVisibleFailureStateUntouched()
    {
        using TempFixture fixture = new();
        byte[] firstBytes = [0x4D, 0x5A, 0x61, 0x62];
        byte[] secondBytes = [0x4D, 0x5A, 0x63, 0x64];
        string firstPath = fixture.Write("prune-failure-1.exe", firstBytes);
        string secondPath = fixture.Write("prune-failure-2.exe", secondBytes);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var batch = new FailingPruneBatchAdapter();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [FileFor(firstPath, outputRoot, ".exe"), FileFor(secondPath, outputRoot, ".exe")]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, batch, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([firstPath, secondPath]);
        await viewModel.SignAsync();
        await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);
        await viewModel.SignAsync();
        Assert.All(viewModel.Rows, row => Assert.Equal(BatchItemState.Failed, row.State));
        foreach (QueueItemViewModel row in viewModel.Rows)
        {
            row.IsSelected = true;
        }

        viewModel.RemoveSelected();

        Assert.Equal(2, viewModel.Rows.Count);
        Assert.All(viewModel.Rows, row => Assert.Equal(BatchItemState.Failed, row.State));
        Assert.Contains("移除", viewModel.StatusMessage, StringComparison.Ordinal);
        Assert.False(viewModel.CanSign);
        Assert.Equal(Hash(firstBytes), Hash(File.ReadAllBytes(firstPath)));
        Assert.Equal(Hash(secondBytes), Hash(File.ReadAllBytes(secondPath)));
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task RemovingFailedRowThenAddingPendingRowImmediatelyEnablesSign()
    {
        using TempFixture fixture = new();
        byte[] sourceBytes = [0x4D, 0x5A, 0x71, 0x72];
        string sourcePath = fixture.Write("recovered.exe", sourceBytes);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var batch = new RecordingBatchAdapter();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [FileFor(sourcePath, outputRoot, ".exe")]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, batch, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        viewModel.PrimaryCertificate = viewModel.Certificates[0];
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([sourcePath]);
        QueueItemViewModel failedRow = Assert.Single(viewModel.Rows);
        Assert.Equal("1", failedRow.ItemId);
        failedRow.Apply(BatchItemState.Failed, receipt: null);
        failedRow.IsSelected = true;

        viewModel.RemoveSelected();
        await viewModel.QueueFilesAndWaitAsync([sourcePath]);

        QueueItemViewModel pendingRow = Assert.Single(viewModel.Rows);
        Assert.Equal("2", pendingRow.ItemId);
        Assert.Equal(BatchItemState.Pending, pendingRow.State);
        Assert.Equal(0, viewModel.AggregateProgressPercent);
        Assert.True(viewModel.CanSign);
        Assert.True(viewModel.SignCommand.CanExecute(null));
        Assert.Empty(batch.PrunedItemIds);
        Assert.Equal(Hash(sourceBytes), Hash(File.ReadAllBytes(sourcePath)));
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task ProgressWithoutAnActiveItemObservationIsIgnored()
    {
        using TempFixture fixture = new();
        string sourcePath = fixture.Write("known.exe", [0x4D, 0x5A, 0x50]);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var batch = new RecordingBatchAdapter();
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [FileFor(sourcePath, outputRoot, ".exe")]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, batch, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([sourcePath]);

        batch.Emit(new BatchProgressUpdate("removed-item", BatchItemState.Published, null));
        Assert.Equal(BatchItemState.Pending, Assert.Single(viewModel.Rows).State);
    }

    [Fact]
    [Trait("Category", "Todo3Queue")]
    public async Task RowRemovalCommandRemovesOnlyItsOwnRowWithoutDeletingTheSource()
    {
        using TempFixture fixture = new();
        byte[] firstBytes = [0x4D, 0x5A, 0x01, 0x02];
        byte[] secondBytes = [0x4D, 0x5A, 0x03, 0x04];
        string firstPath = fixture.Write("first.exe", firstBytes);
        string secondPath = fixture.Write("second.exe", secondBytes);
        string outputRoot = Path.Combine(fixture.Root, "out");
        var intake = new FixedIntakeAdapter(new IntakePlan(
            outputRoot,
            [
                FileFor(firstPath, outputRoot, ".exe"),
                FileFor(secondPath, outputRoot, ".exe")
            ]));
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(intake, Certificate('A'));
        await viewModel.InitializeAsync();
        await viewModel.RefreshReadinessAsync();
        await viewModel.ReplanOutputRootAsync(outputRoot);
        await viewModel.QueueFilesAndWaitAsync([firstPath, secondPath]);

        QueueItemViewModel firstRow = viewModel.Rows[0];
        QueueItemViewModel secondRow = viewModel.Rows[1];
        Assert.True(viewModel.RemoveQueueItemCommand.CanExecute(secondRow));

        viewModel.RemoveQueueItemCommand.Execute(secondRow);

        Assert.Collection(viewModel.Rows, row => Assert.Same(firstRow, row));
        Assert.True(File.Exists(secondPath));
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(secondBytes)),
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(secondPath))));
    }

    private static SigningWorkbenchViewModel CreateViewModel(
        FixedIntakeAdapter intake,
        params EligibleCertificate[] certificates) =>
        CreateViewModel(intake, new NoopBatchAdapter(), certificates);

    private static SigningWorkbenchViewModel CreateViewModel(
        FixedIntakeAdapter intake,
        IBatchAdapter batchAdapter,
        params EligibleCertificate[] certificates) =>
        new(
            new FixedReadinessAdapter(ReadySnapshot(certificates)),
            intake,
            batchAdapter,
            new NoopOperatorShell(),
            new HealthyWorkerService(),
            new NoopRepairService(),
            static _ => ValueTask.FromResult(true));

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private static IntakeFile FileFor(string sourcePath, string outputRoot, string extension)
    {
        PolicyResult<SigningSubject> subject = SigningSubject.TryCreateForExtension(extension);
        Assert.True(subject.IsSuccess);
        return new IntakeFile(
            sourcePath,
            Path.GetFileName(sourcePath),
            Path.Combine(outputRoot, Path.GetFileName(sourcePath)),
            outputRoot,
            new StableFileIdentity(1, sourcePath),
            new SignableSubject(subject.Value!, Guid.NewGuid(), null));
    }

    private static EligibleCertificate Certificate(char thumbprintCharacter) => new(
        StoreLocation.CurrentUser,
        "My",
        new string(thumbprintCharacter, 40),
        $"CN=Release {thumbprintCharacter}",
        "CN=Issuing CA",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddYears(1),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private static ReadinessSnapshot ReadySnapshot(IReadOnlyList<EligibleCertificate> certificates) => new(
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
            certificates,
            [new CertificateStoreDiagnostic(
                StoreLocation.CurrentUser,
                "My",
                CertificateStoreReadStatus.Success)]),
        new TimestampConfiguration(
            TimestampConfigurationStatus.Configured,
            new Uri(TimestampPolicy.DefaultUri)),
        ProviderAuthorizationStatus.AuthorizationUnknown,
        new WindowsPowerShellBridgeReadiness(
            WindowsPowerShellBridgeStatus.Available,
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "5.1",
            "None"));

    private sealed class TempFixture : IDisposable
    {
        public TempFixture() => Root = Directory.CreateTempSubdirectory("codesigner-todo3-").FullName;

        public string Root { get; }

        public string Write(string fileName, byte[] bytes)
        {
            string path = Path.Combine(Root, fileName);
            File.WriteAllBytes(path, bytes);
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class FixedReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => snapshot;
    }

    private sealed class FixedIntakeAdapter(IntakePlan plan) : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken) => Task.FromResult(plan);
    }

    private sealed class NoopBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Signing is intentionally not invoked by Todo 3 tests.");

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Signing is intentionally not invoked by Todo 3 tests.");

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private class RecordingBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

        public IReadOnlyList<BatchItemRequest> RunRequests { get; private set; } = [];

        public List<string> PrunedItemIds { get; } = [];

        public virtual Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RunRequests = [.. RunRequests, request];
            return Task.FromResult(new BatchProgressUpdate(request.ItemId, BatchItemState.Published, null));
        }

        public virtual Task<BatchProgressUpdate> ResumeAsync(
            string itemId,
            bool retryFailed,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Retry is not configured for this test adapter.");

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public virtual void PruneItems(IReadOnlyCollection<string> itemIds)
        {
            PrunedItemIds.AddRange(itemIds);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public void Emit(BatchProgressUpdate update) =>
            ProgressChanged?.Invoke(this, new BatchProgressChangedEventArgs(update));
    }

    private sealed class RetryRecordingBatchAdapter : RecordingBatchAdapter
    {
        private readonly List<string> retainedItemIds = [];

        public List<string> WorkerItemIds { get; } = [];

        public List<string> PublicationItemIds { get; } = [];

        public override Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool firstRequest = WorkerItemIds.Count == 0;
            retainedItemIds.Add(request.ItemId);
            WorkerItemIds.Add(request.ItemId);
            BatchItemState state = firstRequest ? BatchItemState.Failed : BatchItemState.Published;
            if (!firstRequest)
            {
                PublicationItemIds.Add(request.ItemId);
            }
            var update = new BatchProgressUpdate(request.ItemId, state, null);
            Emit(update);
            return Task.FromResult(update);
        }

        public override Task<BatchProgressUpdate> ResumeAsync(
            string itemId,
            bool retryFailed,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.True(retryFailed);
            Assert.Contains(itemId, retainedItemIds);
            WorkerItemIds.Add(itemId);
            PublicationItemIds.Add(itemId);
            var update = new BatchProgressUpdate(itemId, BatchItemState.Published, null);
            Emit(update);
            return Task.FromResult(update);
        }

        public override void PruneItems(IReadOnlyCollection<string> itemIds)
        {
            base.PruneItems(itemIds);
            retainedItemIds.RemoveAll(itemIds.Contains);
        }
    }

    private sealed class FailingPruneBatchAdapter : RecordingBatchAdapter
    {
        public override Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var update = new BatchProgressUpdate(request.ItemId, BatchItemState.Failed, null);
            Emit(update);
            return Task.FromResult(update);
        }

        public override void PruneItems(IReadOnlyCollection<string> itemIds) =>
            throw new InvalidOperationException("Injected prune failure.");
    }

    private sealed class BlockingBatchAdapter : RecordingBatchAdapter
    {
        private readonly TaskCompletionSource<BatchProgressUpdate> completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            return completion.Task.WaitAsync(cancellationToken);
        }

        public void Complete(string itemId) =>
            completion.TrySetResult(new BatchProgressUpdate(itemId, BatchItemState.Pending, null));
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
            Task.FromResult(Path.Combine(Path.GetTempPath(), "codesigner-todo3-diagnostics.json"));
    }

    private sealed class HealthyWorkerService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
    }

    private sealed class NoopRepairService : IWorkerRepairService
    {
        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Worker repair is intentionally not invoked by Todo 3 tests.");

        public void Dispose()
        {
        }
    }
}
