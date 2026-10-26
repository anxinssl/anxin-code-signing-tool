using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.Tests;

public sealed class SignButtonPendingOnlyTests
{
    [Fact]
    public async Task SignAsyncUsesCurrentPendingRowAndPreservesHistoricalResults()
    {
        const string initialOutput = @"C:\pending-only\initial";
        IntakeFile publishedFile = FileFor(@"C:\pending-only\published.exe", initialOutput, SignableFileType.PortableExecutable);
        IntakeFile skippedFile = FileFor(@"C:\pending-only\skipped.exe", initialOutput, SignableFileType.PortableExecutable);
        IntakeFile pendingFile = FileFor(@"C:\pending-only\pending.msi", initialOutput, SignableFileType.WindowsInstaller);
        var intake = new ReplanningIntakeAdapter([publishedFile, skippedFile, pendingFile]);
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            intake,
            batch,
            NativeApiAvailability.LibraryUnavailable,
            WindowsPowerShellBridgeStatus.Available);

        await viewModel.ReplanOutputRootAsync(initialOutput);
        await viewModel.QueueFilesAndWaitAsync([publishedFile.OriginalPath, skippedFile.OriginalPath, pendingFile.OriginalPath]);
        QueueItemViewModel published = viewModel.Rows[0];
        QueueItemViewModel skipped = viewModel.Rows[1];
        QueueItemViewModel pending = viewModel.Rows[2];
        published.Apply(BatchItemState.Published, ReceiptFor(published, BatchItemState.Published, BatchResultCode.Published));
        skipped.Apply(BatchItemState.SkippedAlreadySigned, ReceiptFor(skipped, BatchItemState.SkippedAlreadySigned, BatchResultCode.AlreadySigned));
        await viewModel.SetCurrentItemAsync(pending.ItemId);
        byte[] publishedEvidence = EvidenceBytes(published);
        byte[] skippedEvidence = EvidenceBytes(skipped);

        viewModel.SelectedMode = SigningMode.Dual;

        Assert.True(viewModel.CanSign, viewModel.SignDisabledReason);
        Assert.True(viewModel.SignCommand.CanExecute(null));
        Assert.Null(viewModel.SecondaryCertificate);

        Assert.Equal(publishedEvidence, EvidenceBytes(published));
        Assert.Equal(skippedEvidence, EvidenceBytes(skipped));
        Assert.Equal(Path.Combine(initialOutput, "pending.msi"), pending.DestinationPath);

        await viewModel.SignAsync();

        Assert.Equal(1, batch.RunCount);
        BatchItemRequest request = Assert.Single(batch.Requests);
        Assert.Equal(pending.ItemId, request.ItemId);
        Assert.Equal(Path.Combine(initialOutput, "pending.msi"), request.File.DestinationPath);
        Assert.Equal(BatchItemState.Published, pending.State);
        Assert.Equal(publishedEvidence, EvidenceBytes(published));
        Assert.Equal(skippedEvidence, EvidenceBytes(skipped));
    }

    [Fact]
    public async Task SignAsyncSubmitsOnlyCurrentRowWhenEveryRowIsPending()
    {
        const string output = @"C:\pending-only\all-pending";
        IntakeFile first = FileFor(@"C:\pending-only\first.exe", output, SignableFileType.PortableExecutable);
        IntakeFile second = FileFor(@"C:\pending-only\second.msi", output, SignableFileType.WindowsInstaller);
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            new ReplanningIntakeAdapter([first, second]),
            batch,
            NativeApiAvailability.Available,
            WindowsPowerShellBridgeStatus.Available);

        await viewModel.ReplanOutputRootAsync(output);
        await viewModel.QueueFilesAndWaitAsync([first.OriginalPath, second.OriginalPath]);
        await viewModel.SignAsync();
        await viewModel.SetCurrentItemAsync(viewModel.Rows[1].ItemId);
        await viewModel.SignAsync();

        Assert.Equal([viewModel.Rows[0].ItemId, viewModel.Rows[1].ItemId], batch.Requests.Select(request => request.ItemId));
        Assert.Equal(2, batch.RunCount);
    }

    [Fact]
    public async Task SignAsyncDoesNotCallBatchAdapterWhenNoPendingRowsRemain()
    {
        const string output = @"C:\pending-only\completed";
        IntakeFile completedFile = FileFor(@"C:\pending-only\completed.exe", output, SignableFileType.PortableExecutable);
        var batch = new RecordingBatchAdapter();
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            new ReplanningIntakeAdapter([completedFile]),
            batch,
            NativeApiAvailability.Available,
            WindowsPowerShellBridgeStatus.Available);

        await viewModel.ReplanOutputRootAsync(output);
        await viewModel.QueueFilesAndWaitAsync([completedFile.OriginalPath]);
        QueueItemViewModel completed = Assert.Single(viewModel.Rows);
        completed.Apply(BatchItemState.Published, ReceiptFor(completed, BatchItemState.Published, BatchResultCode.Published));

        await viewModel.SignAsync();

        Assert.Equal(0, batch.RunCount);
        Assert.Empty(batch.Requests);
    }

    private static SigningWorkbenchViewModel CreateViewModel(
        IIntakeAdapter intake,
        IBatchAdapter batch,
        NativeApiAvailability nativeApi,
        WindowsPowerShellBridgeStatus powerShellBridge)
    {
        var viewModel = new SigningWorkbenchViewModel(
            new FixedReadinessAdapter(ReadySnapshot(nativeApi, powerShellBridge)),
            intake,
            batch,
            new NoopOperatorShell(),
            new HealthyWorkerService(),
            new NoopRepairService(),
            static _ => ValueTask.FromResult(true));
        Assert.True(viewModel.ApplySettings(TimestampPolicy.DefaultUri, 30));
        return viewModel;
    }

    private static ReadinessSnapshot ReadySnapshot(
        NativeApiAvailability nativeApi,
        WindowsPowerShellBridgeStatus powerShellBridge) => new(
        new WorkstationReadiness(WorkstationSupportStatus.Supported, "test"),
        nativeApi,
        new SimplySignInstallation(SimplySignInstallationStatus.Installed, "{A}", "{B}", "SimplySign", "Certum", "1.0"),
        new CertificateCatalog(
            CertificateAvailabilityStatus.CertificateAvailable,
            [Certificate('A')],
            [new CertificateStoreDiagnostic(StoreLocation.CurrentUser, "My", CertificateStoreReadStatus.Success)]),
        new TimestampConfiguration(TimestampConfigurationStatus.Configured, new Uri(TimestampPolicy.DefaultUri)),
        ProviderAuthorizationStatus.AuthorizationUnknown,
        new WindowsPowerShellBridgeReadiness(powerShellBridge, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "5.1", "test"));

    private static EligibleCertificate Certificate(char thumbprint) => new(
        StoreLocation.CurrentUser,
        "My",
        new string(thumbprint, 40),
        "CN=Pending Only",
        "CN=Issuer",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddDays(1),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private static IntakeFile FileFor(string originalPath, string outputRoot, SignableFileType type) => new(
        originalPath,
        Path.GetFileName(originalPath),
        Path.Combine(outputRoot, Path.GetFileName(originalPath)),
        outputRoot,
        new StableFileIdentity(1, originalPath),
        new SignableSubject(type, Guid.NewGuid()));

    private static BatchItemReceipt ReceiptFor(
        QueueItemViewModel row,
        BatchItemState state,
        BatchResultCode code) => new(
        row.ItemId,
        state,
        code,
        row.FullPath,
        row.DestinationPath,
        new string('A', 64),
        new string('B', 64),
        $"attempt-{row.ItemId}",
        1,
        0);

    private static byte[] EvidenceBytes(QueueItemViewModel row) => Encoding.UTF8.GetBytes(string.Join("|",
        row.ItemId,
        row.State,
        row.ProgressPercent,
        row.FullPath,
        row.DestinationPath,
        row.ResultText,
        row.DetailText,
        row.Receipt?.ToString()));

    private sealed class ReplanningIntakeAdapter(IReadOnlyList<IntakeFile> initialFiles) : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            string root = outputRoot ?? initialFiles[0].OutputRoot;
            IntakeFile[] files = initialFiles
                .Where(file => inputs.Contains(file.OriginalPath, StringComparer.OrdinalIgnoreCase))
                .Select(file => file with
                {
                    DestinationPath = Path.Combine(root, file.RelativePath),
                    OutputRoot = root
                })
                .ToArray();
            return Task.FromResult(new IntakePlan(root, files));
        }
    }

    private sealed class RecordingBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged
        {
            add { }
            remove { }
        }

        public int RunCount { get; private set; }

        public IReadOnlyList<BatchItemRequest> Requests { get; private set; } = [];

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            RunCount++;
            Requests = [.. Requests, request];
            return Task.FromResult(new BatchProgressUpdate(
                request.ItemId,
                BatchItemState.Published,
                new BatchItemReceipt(
                    request.ItemId,
                    BatchItemState.Published,
                    BatchResultCode.Published,
                    request.File.OriginalPath,
                    request.File.DestinationPath,
                    new string('C', 64),
                    new string('D', 64),
                    "pending-attempt",
                    2,
                    0)));
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Retry is not configured for this test.");

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => snapshot;
    }

    private sealed class NoopOperatorShell : IOperatorShell
    {
        public void OpenFolder(string path)
        {
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken) => Task.FromResult(@"C:\pending-only\diagnostics.json");
    }

    private sealed class HealthyWorkerService : IWorkerHealthService
    {
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Task.FromResult(WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy));
    }

    private sealed class NoopRepairService : IWorkerRepairService
    {
        public void Dispose()
        {
        }

        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Repair is not configured for this test.");
    }
}
