using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
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

public sealed class WorkerHealthRepairOrchestrationTestsTodo6
{
    public static TheoryData<WorkerLaunchReason, SigningMode> SigningAvailabilityCases
    {
        get
        {
            var cases = new TheoryData<WorkerLaunchReason, SigningMode>();
            foreach (WorkerLaunchReason reason in Enum.GetValues<WorkerLaunchReason>())
            {
                cases.Add(reason, SigningMode.Single);
                cases.Add(reason, SigningMode.Dual);
            }

            return cases;
        }
    }

    public static TheoryData<Type, string> OpenLogDirectoryFailureCases => new()
    {
        { typeof(ArgumentException), "无法打开日志目录：日志目录路径无效。" },
        { typeof(NotSupportedException), "无法打开日志目录：日志目录路径无效。" },
        { typeof(PathTooLongException), "无法打开日志目录：日志目录路径无效。" },
        { typeof(UnauthorizedAccessException), "无法打开日志目录：无法创建或访问日志目录。" },
        { typeof(DirectoryNotFoundException), "无法打开日志目录：无法创建或访问日志目录。" },
        { typeof(IOException), "无法打开日志目录：无法创建或访问日志目录。" },
        { typeof(Win32Exception), "无法打开日志目录：无法启动文件资源管理器。" },
        { typeof(InvalidOperationException), "无法打开日志目录：无法启动文件资源管理器。" }
    };

    [Fact]
    public async Task StartupInitializationIsOneSharedTaskPerViewModelAndDoesNotPoll()
    {
        var firstCompletion = new TaskCompletionSource<WorkerLaunchDiagnostic>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var firstHealth = new TestWorkerHealthService(_ => firstCompletion.Task);
        var firstBatch = new TestBatchAdapter();
        await using var first = CreateViewModel(health: firstHealth, batch: firstBatch);

        Task firstCall = first.InitializeAsync();
        Task repeatedCall = first.InitializeAsync();
        try
        {
            Assert.Same(firstCall, repeatedCall);
            Assert.Equal(1, firstHealth.CallCount);
            Assert.Equal(WorkerHealthState.Checking, first.WorkerHealthState);
        }
        finally
        {
            firstCompletion.TrySetResult(Diagnostic(WorkerLaunchReason.Healthy));
            await Task.WhenAll(firstCall, repeatedCall).WaitAsync(TimeSpan.FromSeconds(5));
        }

        await Task.Delay(250);

        Assert.Equal(1, firstHealth.CallCount);
        Assert.Equal(0, firstBatch.RunCount);
        Assert.Equal(0, firstBatch.ResumeCount);

        var secondHealth = new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Healthy));
        await using var second = CreateViewModel(health: secondHealth);
        await second.InitializeAsync();
        Assert.Equal(1, secondHealth.CallCount);
    }

    [Fact]
    public async Task StartupDefersReadinessCertificateAndSimplySignWorkUntilExplicitRefresh()
    {
        var readiness = new TrackingReadinessAdapter(ReadySnapshot(Certificate('A'), Certificate('B')));
        var health = new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Healthy));
        var batch = new TestBatchAdapter();
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(request.ItemId, BatchItemState.Published, PublishedReceipt(request));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: health,
            batch: batch,
            readiness: readiness,
            prepareReadiness: false);

        await viewModel.InitializeAsync();

        Assert.Equal(1, health.CallCount);
        Assert.Equal(0, readiness.ReadinessProbeCount);
        Assert.Equal(0, readiness.CertificateCatalogEnumerationCount);
        Assert.Equal(0, readiness.PrivateKeyInspectionCount);
        Assert.Equal(0, readiness.SimplySignDetectionCount);
        Assert.Empty(viewModel.Certificates);
        Assert.Null(viewModel.PrimaryCertificate);
        Assert.Null(viewModel.SecondaryCertificate);
        Assert.False(viewModel.CanSign);
        Assert.Equal("请选择一个签名文件项目", viewModel.SignDisabledReason);

        await viewModel.QueueFilesAndWaitAsync([@"C:\release\todo9.exe"]);
        await viewModel.SignAsync();
        Assert.False(viewModel.CanSign);
        Assert.Equal(0, batch.RunCount);
        Assert.Equal(0, readiness.ReadinessProbeCount);

        await viewModel.RefreshReadinessAsync();

        Assert.Equal(2, health.CallCount);
        Assert.Equal(1, readiness.ReadinessProbeCount);
        Assert.Equal(1, readiness.CertificateCatalogEnumerationCount);
        Assert.Equal(2, readiness.PrivateKeyInspectionCount);
        Assert.Equal(1, readiness.SimplySignDetectionCount);
        Assert.Equal(2, viewModel.Certificates.Count);
        Assert.Same(viewModel.Certificates[0], viewModel.PrimaryCertificate);
        Assert.Null(viewModel.SecondaryCertificate);
        await viewModel.ReplanOutputRootAsync(@"C:\release\out");
        Assert.True(viewModel.CanSign, viewModel.SignDisabledReason);

        await viewModel.SignAsync();

        Assert.Equal(1, batch.RunCount);
    }

    [Fact]
    public void StartupSourceHasNoTimerDelayOrRecurringScheduler()
    {
        string source = File.ReadAllText(Path.Combine(
            ResolveRepositoryRoot(),
            "src",
            "CodeSigner.App",
            "ViewModels",
            "SigningWorkbenchViewModel.WorkerRecovery.cs"));

        Assert.DoesNotContain("PeriodicTimer", source, StringComparison.Ordinal);
        Assert.DoesNotContain("System.Threading.Timer", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Task.Delay", source, StringComparison.Ordinal);
        Assert.DoesNotContain("while (", source, StringComparison.Ordinal);
        Assert.DoesNotContain("RegisterRecurring", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisposeCancelsAndAwaitsTheSharedStartupProbeBeforeDisposingRepair()
    {
        var probeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var probeCompletion = new TaskCompletionSource<WorkerLaunchDiagnostic>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new TestWorkerHealthService(token =>
        {
            probeStarted.TrySetResult();
            token.Register(() =>
            {
                cancellationObserved.TrySetResult();
                probeCompletion.TrySetCanceled(token);
            });
            return probeCompletion.Task;
        });
        var repair = new TestWorkerRepairService();
        SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, repair: repair);
        Task startup = viewModel.InitializeAsync();
        await probeStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task disposal = viewModel.DisposeAsync().AsTask();
        try
        {
            await cancellationObserved.Task.WaitAsync(TimeSpan.FromMilliseconds(500));
            await disposal.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => startup);
            Assert.Equal(1, repair.DisposeCount);
            Assert.Equal(1, health.CallCount);
        }
        finally
        {
            probeCompletion.TrySetResult(Diagnostic(WorkerLaunchReason.Healthy));
            await disposal.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Theory]
    [MemberData(nameof(SigningAvailabilityCases))]
    public async Task OtherwiseValidSignAndRetryRemainAvailableForEveryWorkerReasonInBothModes(
        WorkerLaunchReason reason,
        SigningMode mode)
    {
        var batch = new TestBatchAdapter();
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                FailedReceipt(request, BatchResultCode.WorkerFailure));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(
            health: new TestWorkerHealthService(Diagnostic(reason)),
            batch: batch);
        await viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, mode);

        Assert.True(viewModel.CanSign, $"{reason}/{mode}: {viewModel.SignDisabledReason}");
        Assert.True(viewModel.SignCommand.CanExecute(null));
        await viewModel.SignAsync();

        Assert.Equal(1, batch.RunCount);
        Assert.True(viewModel.RetryCommand.CanExecute(null), $"{reason}/{mode} should permit retry.");
    }

    [Fact]
    public async Task OutputSaveFailureRemainsDedicatedInRowAndStatusDiagnostics()
    {
        var batch = new TestBatchAdapter();
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                FailedReceipt(request, BatchResultCode.OutputSaveFailed));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch: batch);
        await viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, SigningMode.Single);

        await viewModel.SignAsync();

        QueueItemViewModel row = Assert.Single(viewModel.Rows);
        Assert.Equal(BatchResultCode.OutputSaveFailed, row.Receipt?.Code);
        Assert.Contains("更改输出位置", row.ResultText, StringComparison.Ordinal);
        Assert.Equal(QueueItemViewModel.OutputSaveRecoveryMessage, viewModel.StatusMessage);
        Assert.Equal("OutputRootTextBox", viewModel.FocusTargetAutomationId);
    }

    [Fact]
    public async Task UnknownCheckingAndRepairingDoNotReplaceGenuineSigningPrerequisites()
    {
        await using SigningWorkbenchViewModel unknown = CreateViewModel();
        Assert.False(unknown.CanSign);
        Assert.Equal("请选择一个签名文件项目", unknown.SignDisabledReason);
        await PrepareQueueAsync(unknown, SigningMode.Single);
        Assert.Equal(WorkerHealthState.Unknown, unknown.WorkerHealthState);
        Assert.True(unknown.CanSign);

        var checkingCompletion = new TaskCompletionSource<WorkerLaunchDiagnostic>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        await using SigningWorkbenchViewModel checking = CreateViewModel(
            health: new TestWorkerHealthService(_ => checkingCompletion.Task));
        Task initialization = checking.InitializeAsync();
        try
        {
            await PrepareQueueAsync(checking, SigningMode.Dual);
            Assert.Equal(WorkerHealthState.Checking, checking.WorkerHealthState);
            Assert.True(checking.CanSign);
        }
        finally
        {
            checkingCompletion.TrySetResult(Diagnostic(WorkerLaunchReason.Healthy));
            await initialization;
        }

        var repairCompletion = new TaskCompletionSource<WorkerRepairResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var repair = new TestWorkerRepairService(_ => repairCompletion.Task);
        var repairBatch = new TestBatchAdapter();
        repairBatch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return repairBatch.Emit(request.ItemId, BatchItemState.Published, PublishedReceipt(request));
        };
        await using SigningWorkbenchViewModel repairing = CreateViewModel(
            health: new TestWorkerHealthService(
                Diagnostic(WorkerLaunchReason.Missing),
                Diagnostic(WorkerLaunchReason.Healthy)),
            repair: repair,
            batch: repairBatch);
        await repairing.InitializeAsync();
        await PrepareQueueAsync(repairing, SigningMode.Single);
        Task activeRepair = repairing.RepairWorkerAsync();
        try
        {
            await repair.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(WorkerHealthState.Repairing, repairing.WorkerHealthState);
            Assert.True(repairing.CanSign);

            await repairing.SignAsync();
            Assert.Equal(1, repairBatch.RunCount);
        }
        finally
        {
            repairCompletion.TrySetResult(SuccessfulRepair());
            await activeRepair;
        }
    }

    [Fact]
    public async Task LateStartupSuccessCannotOverwriteNewerSignFailureAndBothOperationsComplete()
    {
        var startupCompletion = new TaskCompletionSource<WorkerLaunchDiagnostic>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new TestWorkerHealthService(_ => startupCompletion.Task);
        var batch = new TestBatchAdapter();
        WorkerLaunchDiagnostic missing = Diagnostic(WorkerLaunchReason.Missing);
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                WorkerLaunchFailureReceipt(request, missing));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, batch: batch);
        Task startup = viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, SigningMode.Single);

        await viewModel.SignAsync();
        startupCompletion.SetResult(Diagnostic(WorkerLaunchReason.Healthy));
        await startup;

        Assert.Equal(1, health.CallCount);
        Assert.Equal(1, batch.RunCount);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Same(missing, viewModel.WorkerDiagnostic);
    }

    [Fact]
    public async Task LateStartupFailureCannotOverwriteNewerSuccessfulSignAndBothOperationsComplete()
    {
        var startupCompletion = new TaskCompletionSource<WorkerLaunchDiagnostic>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new TestWorkerHealthService(_ => startupCompletion.Task);
        var batch = new TestBatchAdapter();
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(request.ItemId, BatchItemState.Published, PublishedReceipt(request));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, batch: batch);
        Task startup = viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, SigningMode.Single);

        await viewModel.SignAsync();
        startupCompletion.SetResult(Diagnostic(WorkerLaunchReason.Timeout));
        await startup;

        Assert.Equal(1, health.CallCount);
        Assert.Equal(1, batch.RunCount);
        Assert.Equal(WorkerHealthState.Healthy, viewModel.WorkerHealthState);
        Assert.Equal(WorkerLaunchReason.Healthy, viewModel.WorkerDiagnostic?.Reason);
    }

    [Fact]
    public async Task StartupHealthyNotificationCannotOverwriteReentrantSignFailureDiagnostic()
    {
        var health = new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Healthy));
        var batch = new TestBatchAdapter();
        WorkerLaunchDiagnostic missing = Diagnostic(WorkerLaunchReason.Missing);
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                WorkerLaunchFailureReceipt(request, missing));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(health: health, batch: batch);
        await PrepareQueueAsync(viewModel, SigningMode.Single);

        bool signReentered = false;
        viewModel.PropertyChanged += (_, args) =>
        {
            if (!signReentered &&
                args.PropertyName == nameof(SigningWorkbenchViewModel.WorkerHealthState) &&
                viewModel.WorkerHealthState == WorkerHealthState.Healthy)
            {
                signReentered = true;
                viewModel.SignAsync().GetAwaiter().GetResult();
            }
        };

        await viewModel.InitializeAsync();

        Assert.True(signReentered);
        Assert.Equal(1, health.CallCount);
        Assert.Equal(1, batch.RunCount);
        Assert.Equal(WorkerHealthState.Unhealthy, viewModel.WorkerHealthState);
        Assert.Same(missing, viewModel.WorkerDiagnostic);
    }

    [Fact]
    public async Task OpenLogDirectoryIsAlwaysEnabledUsesOnlyTheDefaultRootAndDoesNotChangeEligibility()
    {
        var shell = new TestOperatorShell();
        var batchCompletion = new TaskCompletionSource<BatchProgressUpdate>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var batch = new TestBatchAdapter
        {
            RunAsyncBehavior = (_, _) => batchCompletion.Task
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch: batch, shell: shell);
        await viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, SigningMode.Single);
        RelayCommand command = GetOpenLogDirectoryCommand(viewModel);

        Assert.True(command.CanExecute(null));
        bool canSignBefore = viewModel.CanSign;
        command.Execute(null);
        Assert.Equal(SigningRuntimeEventLog.DefaultDiagnosticsRoot, shell.OpenedFolder);
        Assert.Equal(canSignBefore, viewModel.CanSign);

        Task signing = viewModel.SignAsync();
        Assert.True(viewModel.IsBusy);
        Assert.True(command.CanExecute(null));
        command.Execute(null);
        Assert.Equal(2, shell.OpenFolderCount);
        BatchItemRequest request = Assert.Single(batch.LastRequests);
        batchCompletion.SetResult(batch.Emit(
            request.ItemId,
            BatchItemState.Published,
            PublishedReceipt(request)));
        await signing;
        Assert.Equal(1, batch.RunCount);
    }

    [Theory]
    [MemberData(nameof(OpenLogDirectoryFailureCases))]
    public async Task OpenLogDirectoryMapsEveryFailureWithoutChangingWorkerQueueOrCommands(
        Type exceptionType,
        string expectedMessage)
    {
        var shell = new TestOperatorShell
        {
            OpenFailure = (Exception)Activator.CreateInstance(exceptionType)!
        };
        var batch = new TestBatchAdapter();
        batch.RunBehavior = requests =>
        {
            BatchItemRequest request = Assert.Single(requests);
            return batch.Emit(
                request.ItemId,
                BatchItemState.Failed,
                FailedReceipt(request, BatchResultCode.WorkerFailure));
        };
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(batch: batch, shell: shell);
        await viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, SigningMode.Single);
        await viewModel.SignAsync();
        WorkerHealthState healthBefore = viewModel.WorkerHealthState;
        WorkerLaunchDiagnostic? diagnosticBefore = viewModel.WorkerDiagnostic;
        int rowsBefore = viewModel.Rows.Count;
        bool signBefore = viewModel.CanSign;
        bool retryBefore = viewModel.RetryCommand.CanExecute(null);
        bool exportBefore = viewModel.ExportDiagnosticsCommand.CanExecute(null);

        GetOpenLogDirectoryCommand(viewModel).Execute(null);

        Assert.Equal(expectedMessage, viewModel.StatusMessage);
        Assert.Equal("SummaryRegion", viewModel.FocusTargetAutomationId);
        Assert.Equal(healthBefore, viewModel.WorkerHealthState);
        Assert.Same(diagnosticBefore, viewModel.WorkerDiagnostic);
        Assert.Equal(rowsBefore, viewModel.Rows.Count);
        Assert.Equal(signBefore, viewModel.CanSign);
        Assert.Equal(retryBefore, viewModel.RetryCommand.CanExecute(null));
        Assert.Equal(exportBefore, viewModel.ExportDiagnosticsCommand.CanExecute(null));
    }

    [Fact]
    public void ProductionShellCreatesAndPreservesChineseSpacePathAndTreatsNullStartAsFailure()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner 日志 shell " + Guid.NewGuid().ToString("N"));
        string target = Path.Combine(root, "中文 目录");
        ProcessStartInfo? captured = null;
        Process? returned = null;
        string? explorerArgument = null;
        string? explorerFileName = null;
        bool directoryCreated = false;
        bool useShellExecute = false;
        bool nullStartRejected = false;
        try
        {
            WindowsOperatorShell shell = CreateProductionShell(startInfo =>
            {
                captured = startInfo;
                returned = new Process();
                return returned;
            });

            shell.OpenFolder(target);

            directoryCreated = Directory.Exists(target);
            Assert.True(directoryCreated);
            Assert.NotNull(captured);
            Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), captured.FileName);
            Assert.True(captured.UseShellExecute);
            explorerFileName = captured.FileName;
            useShellExecute = captured.UseShellExecute;
            explorerArgument = Assert.Single(captured.ArgumentList);
            Assert.Equal(Path.GetFullPath(target), explorerArgument);

            WindowsOperatorShell nullShell = CreateProductionShell(_ => null);
            Assert.Throws<InvalidOperationException>(() => nullShell.OpenFolder(target));
            nullStartRejected = true;
        }
        finally
        {
            returned?.Dispose();
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }

        bool cleanupConfirmed = !Directory.Exists(root);
        Assert.True(cleanupConfirmed);
        string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
        if (!string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            evidenceDirectory = Path.GetFullPath(evidenceDirectory);
            Directory.CreateDirectory(evidenceDirectory);
            File.WriteAllText(
                Path.Combine(evidenceDirectory, "production-shell-path-receipt.json"),
                JsonSerializer.Serialize(
                    new
                    {
                        scenario = "production shell creates and preserves a Chinese space path",
                        targetPath = target,
                        expectedPath = Path.GetFullPath(target),
                        directoryCreated,
                        explorerFileName,
                        useShellExecute,
                        explorerArgument,
                        nullStartRejected,
                        cleanupConfirmed
                    }));
        }
    }

    [Fact]
    public async Task NullExplorerStartMapsThroughTheViewModelAsLaunchFailure()
    {
        WindowsOperatorShell shell = CreateProductionShell(_ => null);
        await using SigningWorkbenchViewModel viewModel = CreateViewModel(shell: shell);
        await viewModel.InitializeAsync();
        await PrepareQueueAsync(viewModel, SigningMode.Single);
        bool canSignBefore = viewModel.CanSign;

        GetOpenLogDirectoryCommand(viewModel).Execute(null);

        Assert.Equal("无法打开日志目录：无法启动文件资源管理器。", viewModel.StatusMessage);
        Assert.Equal("SummaryRegion", viewModel.FocusTargetAutomationId);
        Assert.Equal(canSignBefore, viewModel.CanSign);
    }

    [Fact]
    public async Task ProductionCompositionSharesExactlyOneRuntimeLogAcrossProbeAndBatch()
    {
        await using SigningWorkbenchViewModel viewModel = ProductionComposition.CreateViewModel();
        object batch = GetPrivateField(viewModel, "batchAdapter");
        object health = GetPrivateField(viewModel, "workerHealthService");
        object? batchLog = GetPrivateField(batch, "runtimeEventLog");
        object? healthLog = GetPrivateField(health, "runtimeEventLog");

        Assert.NotNull(batchLog);
        Assert.Same(batchLog, healthLog);
        var runtimeLog = Assert.IsType<SigningRuntimeEventLog>(batchLog);
        Assert.Equal(runtimeLog.Path, Assert.IsAssignableFrom<IBatchAdapter>(batch).RuntimeEventLogPath);

        string source = File.ReadAllText(Path.Combine(
            ResolveRepositoryRoot(),
            "src",
            "CodeSigner.App",
            "Services",
            "ProductionAdapters.cs"));
        int first = source.IndexOf("SigningRuntimeEventLog? runtimeEventLog = CreateRuntimeEventLog();", StringComparison.Ordinal);
        Assert.True(first >= 0);
        Assert.Equal(first, source.LastIndexOf(
            "SigningRuntimeEventLog? runtimeEventLog = CreateRuntimeEventLog();",
            StringComparison.Ordinal));
    }

    [Fact]
    public void MainWindowHasOneExactLogButtonAdjacentToDiagnosticsAndNoneInRecovery()
    {
        string root = ResolveRepositoryRoot();
        XDocument document = XDocument.Load(Path.Combine(root, "src", "CodeSigner.App", "MainWindow.xaml"));
        XElement[] buttons = document.Descendants()
            .Where(static element => element.Name.LocalName == "Button")
            .ToArray();
        XElement open = Assert.Single(
            buttons,
            button => Attribute(button, "AutomationProperties.AutomationId") == "OpenLogDirectoryButton");

        Assert.Equal("打开本地日志目录", Attribute(open, "ToolTip"));
        Assert.Equal("打开日志目录", Attribute(open, "AutomationProperties.Name"));
        Assert.Equal(
            "在文件资源管理器中打开本机日志目录：%LOCALAPPDATA%\\CodeSigner\\Diagnostics",
            Attribute(open, "AutomationProperties.HelpText"));
        Assert.Equal("{Binding OpenLogDirectoryCommand}", Attribute(open, "Command"));
        Assert.Single(open.Elements(), static element => element.Name.LocalName == "TextBlock");

        XElement parent = Assert.IsType<XElement>(open.Parent);
        XElement[] siblings = parent.Elements()
            .Where(static element => element.Name.LocalName == "Button")
            .ToArray();
        int exportIndex = Array.FindIndex(siblings, button =>
            Attribute(button, "AutomationProperties.AutomationId") == "ExportDiagnosticsButton");
        int openIndex = Array.IndexOf(siblings, open);
        Assert.Equal(exportIndex + 1, openIndex);

        XElement recovery = Assert.Single(
            document.Descendants(),
            element => Attribute(element, "AutomationProperties.AutomationId") == "WorkerRecoveryRegion");
        Assert.DoesNotContain(recovery.Descendants(), element =>
            Attribute(element, "AutomationProperties.AutomationId") == "OpenLogDirectoryButton");
    }

    [Fact]
    public void PrimitiveShowcaseBranchDoesNotConstructTheProductionWorkbench()
    {
        string root = ResolveRepositoryRoot();
        string app = File.ReadAllText(Path.Combine(root, "src", "CodeSigner.App", "App.xaml.cs"));
        string showcase = File.ReadAllText(Path.Combine(root, "src", "CodeSigner.App", "PrimitiveShowcaseWindow.xaml.cs"));

        Assert.Contains("new PrimitiveShowcaseWindow()", app, StringComparison.Ordinal);
        Assert.DoesNotContain("ProductionComposition", showcase, StringComparison.Ordinal);
        Assert.DoesNotContain("SigningWorkbenchViewModel", showcase, StringComparison.Ordinal);
    }

    private static SigningWorkbenchViewModel CreateViewModel(
        TestWorkerHealthService? health = null,
        TestWorkerRepairService? repair = null,
        TestBatchAdapter? batch = null,
        IOperatorShell? shell = null,
        IReadinessAdapter? readiness = null,
        bool prepareReadiness = true)
    {
        var viewModel = new SigningWorkbenchViewModel(
            readiness ?? new TestReadinessAdapter(ReadySnapshot(Certificate('A'), Certificate('B'))),
            new TestIntakeAdapter(),
            batch ?? new TestBatchAdapter(),
            shell ?? new TestOperatorShell(),
            health ?? new TestWorkerHealthService(Diagnostic(WorkerLaunchReason.Healthy)),
            repair ?? new TestWorkerRepairService(),
            static _ => ValueTask.FromResult(true));

        if (prepareReadiness)
        {
            Assert.True(viewModel.ApplySettings(
                viewModel.TimestampUri.AbsoluteUri,
                viewModel.DiagnosticRetentionDays));
        }

        return viewModel;
    }

    private static async Task PrepareQueueAsync(SigningWorkbenchViewModel viewModel, SigningMode mode)
    {
        viewModel.SelectedMode = mode;
        if (mode == SigningMode.Dual)
        {
            viewModel.SecondaryCertificate = viewModel.Certificates[1];
        }

        await viewModel.ReplanOutputRootAsync(@"C:\release\out");
        await viewModel.QueueFilesAndWaitAsync([@"C:\release\todo6.exe"]);
    }

    private static RelayCommand GetOpenLogDirectoryCommand(SigningWorkbenchViewModel viewModel)
    {
        PropertyInfo? property = typeof(SigningWorkbenchViewModel).GetProperty("OpenLogDirectoryCommand");
        Assert.NotNull(property);
        return Assert.IsType<RelayCommand>(property.GetValue(viewModel));
    }

    private static WindowsOperatorShell CreateProductionShell(Func<ProcessStartInfo, Process?> startProcess)
    {
        object? shell = Activator.CreateInstance(
            typeof(WindowsOperatorShell),
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [startProcess],
            culture: null);
        return Assert.IsType<WindowsOperatorShell>(shell);
    }

    private static object GetPrivateField(object instance, string fieldName)
    {
        FieldInfo? field = instance.GetType().GetField(
            fieldName,
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        object? value = field.GetValue(instance);
        Assert.NotNull(value);
        return value;
    }

    private static string? Attribute(XElement element, string localName) =>
        element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == localName)?.Value;

    private static string ResolveRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return Assert.IsType<DirectoryInfo>(directory).FullName;
    }

    private static WorkerLaunchDiagnostic Diagnostic(WorkerLaunchReason reason) =>
        WorkerLaunchDiagnosticMapper.ForReason(reason);

    private static WorkerRepairResult SuccessfulRepair() => new(
        WorkerRepairOutcome.Succeeded,
        new CodeSignerInstallation(
            CodeSignerInstallationStatus.Installed,
            CodeSignerInstallationProbe.ObservedUpgradeCode,
            "{11111111-1111-1111-1111-111111111111}",
            CodeSignerInstallationProbe.ObservedProductName,
            CodeSignerInstallationProbe.ObservedPublisher,
            "1.0.2"),
        null,
        0,
        null,
        true);

    private static EligibleCertificate Certificate(char thumbprint) => new(
        StoreLocation.CurrentUser,
        "My",
        new string(thumbprint, 40),
        $"CN=Todo6-{thumbprint}",
        "CN=Issuing CA",
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddYears(1),
        true,
        [CertificateCatalogProbe.CodeSigningEkuOid]);

    private static ReadinessSnapshot ReadySnapshot(params EligibleCertificate[] certificates) => new(
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
            [new CertificateStoreDiagnostic(StoreLocation.CurrentUser, "My", CertificateStoreReadStatus.Success)]),
        new TimestampConfiguration(TimestampConfigurationStatus.Configured, new Uri(TimestampPolicy.DefaultUri)),
        ProviderAuthorizationStatus.AuthorizationUnknown);

    private static BatchItemReceipt PublishedReceipt(BatchItemRequest request) => new(
        request.ItemId,
        BatchItemState.Published,
        BatchResultCode.Published,
        request.File.OriginalPath,
        request.File.DestinationPath,
        new string('1', 64),
        new string('2', 64),
        "TODO6-ATTEMPT",
        101,
        0);

    private static BatchItemReceipt FailedReceipt(BatchItemRequest request, BatchResultCode code) => new(
        request.ItemId,
        BatchItemState.Failed,
        code,
        request.File.OriginalPath,
        request.File.DestinationPath,
        null,
        null,
        null,
        101,
        unchecked((int)0x80004005));

    private static BatchItemReceipt WorkerLaunchFailureReceipt(
        BatchItemRequest request,
        WorkerLaunchDiagnostic diagnostic) => new(
        request.ItemId,
        BatchItemState.Failed,
        BatchResultCode.WorkerLaunchFailed,
        request.File.OriginalPath,
        request.File.DestinationPath,
        null,
        null,
        null,
        null,
        diagnostic.HResult,
        diagnostic);

    private sealed class TestWorkerHealthService : IWorkerHealthService
    {
        private readonly Queue<Func<CancellationToken, Task<WorkerLaunchDiagnostic>>> results;
        private Func<CancellationToken, Task<WorkerLaunchDiagnostic>>? last;

        public TestWorkerHealthService(params WorkerLaunchDiagnostic[] results)
            : this(results.Select(result =>
                new Func<CancellationToken, Task<WorkerLaunchDiagnostic>>(_ => Task.FromResult(result))))
        {
        }

        public TestWorkerHealthService(Func<CancellationToken, Task<WorkerLaunchDiagnostic>> result)
            : this([result])
        {
        }

        private TestWorkerHealthService(
            IEnumerable<Func<CancellationToken, Task<WorkerLaunchDiagnostic>>> results) =>
            this.results = new Queue<Func<CancellationToken, Task<WorkerLaunchDiagnostic>>>(results);

        public int CallCount { get; private set; }

        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            if (results.Count > 0)
            {
                last = results.Dequeue();
            }

            return (last ?? throw new InvalidOperationException("No worker diagnostic was configured."))(
                cancellationToken);
        }
    }

    private sealed class TestWorkerRepairService : IWorkerRepairService
    {
        private readonly Func<CancellationToken, Task<WorkerRepairResult>> behavior;

        public TestWorkerRepairService()
            : this(_ => Task.FromResult(SuccessfulRepair()))
        {
        }

        public TestWorkerRepairService(Func<CancellationToken, Task<WorkerRepairResult>> behavior) =>
            this.behavior = behavior;

        public int DisposeCount { get; private set; }

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<WorkerRepairResult> RepairAsync(CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            return behavior(cancellationToken);
        }

        public void Dispose() => DisposeCount++;
    }

    private sealed class TestReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public ReadinessSnapshot Probe(Uri timestampUri) => snapshot;
    }

    private sealed class TrackingReadinessAdapter(ReadinessSnapshot snapshot) : IReadinessAdapter
    {
        public int ReadinessProbeCount { get; private set; }

        public int CertificateCatalogEnumerationCount { get; private set; }

        public int PrivateKeyInspectionCount { get; private set; }

        public int SimplySignDetectionCount { get; private set; }

        public ReadinessSnapshot Probe(Uri timestampUri)
        {
            ReadinessProbeCount++;
            CertificateCatalogEnumerationCount++;
            PrivateKeyInspectionCount += snapshot.CertificateCatalog.Certificates.Count;
            SimplySignDetectionCount++;
            return snapshot;
        }
    }

    private sealed class TestIntakeAdapter : StagedIntakeAdapterFake
    {
        protected override Task<IntakePlan> BuildPlanAsync(
            IReadOnlyCollection<string> inputs,
            bool recurseDirectories,
            string? outputRoot,
            CancellationToken cancellationToken)
        {
            string original = Assert.Single(inputs);
            string destinationRoot = outputRoot ?? @"C:\release\todo6-signed";
            return Task.FromResult(new IntakePlan(
                destinationRoot,
                [new IntakeFile(
                    original,
                    Path.GetFileName(original),
                    Path.Combine(destinationRoot, Path.GetFileName(original)),
                    destinationRoot,
                    new StableFileIdentity(6, "TODO6-FILE"),
                    new SignableSubject(SignableFileType.PortableExecutable, Guid.NewGuid()))]));
        }
    }

    private sealed class TestBatchAdapter : IBatchAdapter
    {
        public event EventHandler<BatchProgressChangedEventArgs>? ProgressChanged;

        public int RunCount { get; private set; }

        public int ResumeCount { get; private set; }

        public IReadOnlyList<BatchItemRequest> LastRequests { get; private set; } = [];

        public Func<IReadOnlyList<BatchItemRequest>, BatchProgressUpdate>? RunBehavior { get; set; }

        public Func<IReadOnlyList<BatchItemRequest>, CancellationToken, Task<BatchProgressUpdate>>?
            RunAsyncBehavior { get; init; }

        public Task<BatchProgressUpdate> RunAsync(
            BatchItemRequest request,
            CancellationToken cancellationToken)
        {
            RunCount++;
            IReadOnlyList<BatchItemRequest> requests = [request];
            LastRequests = requests;
            if (RunAsyncBehavior is not null)
            {
                return RunAsyncBehavior(requests, cancellationToken);
            }

            return Task.FromResult(RunBehavior?.Invoke(requests)
                ?? throw new InvalidOperationException("The test batch run was not configured."));
        }

        public Task<BatchProgressUpdate> ResumeAsync(string itemId, bool retryFailed, CancellationToken cancellationToken)
        {
            ResumeCount++;
            throw new InvalidOperationException("Resume was not configured for this test.");
        }

        public void PruneItems(IReadOnlyCollection<string> itemIds)
        {
        }

        public Task CancelAsync(string itemId, CancellationToken cancellationToken) => Task.CompletedTask;

        public BatchProgressUpdate Emit(
            string itemId,
            BatchItemState state,
            BatchItemReceipt? receipt = null)
        {
            var update = new BatchProgressUpdate(itemId, state, receipt);
            ProgressChanged?.Invoke(this, new BatchProgressChangedEventArgs(update));
            return update;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class TestOperatorShell : IOperatorShell
    {
        public Exception? OpenFailure { get; init; }

        public string? OpenedFolder { get; private set; }

        public int OpenFolderCount { get; private set; }

        public void OpenFolder(string path)
        {
            if (OpenFailure is not null)
            {
                throw OpenFailure;
            }

            OpenedFolder = path;
            OpenFolderCount++;
        }

        public Task<string> ExportDiagnosticsAsync(
            IReadOnlyDictionary<string, object?> diagnostics,
            int retentionDays,
            CancellationToken cancellationToken) =>
            Task.FromResult(@"C:\diagnostics\todo6.json");
    }
}
