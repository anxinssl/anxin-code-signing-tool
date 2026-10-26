using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;
using Image = System.Windows.Controls.Image;
using MenuItem = System.Windows.Controls.MenuItem;
using Size = System.Windows.Size;

namespace CodeSigner.App.Tests;

[Collection("WpfPresentation")]
public sealed class RefreshPresentationTests
{
    [Fact]
    public async Task UnknownMissingCertificatesUnsupportedAndFailedAreDistinct()
    {
        var readiness = new MutableReadiness();
        var health = new ControlledHealth();
        await using SigningWorkbenchViewModel model = CreateModel(readiness, health);
        Assert.Equal("系统环境待检查", model.WorkstationStatus);
        Assert.Equal("签名环境待检查", model.NativeApiStatus);
        Assert.Equal("时间戳配置待检查", model.TimestampStatus);
        Assert.Equal("尚未刷新证书", model.CertificateStatus);

        await model.RefreshReadinessAsync();
        Assert.Equal("系统环境符合要求", model.WorkstationStatus);
        Assert.Equal("未发现可用证书", model.CertificateStatus);
        Assert.Equal("时间戳已配置", model.TimestampStatus);

        foreach ((string code, string expected) in new[]
        {
            ("RequiresX64", "需要 x64 系统"),
            ("RequiresWindows10Or11Nt10", "需要 Windows 10 或 11"),
            ("RequiresWorkstation", "系统类型不符合运行要求")
        })
        {
            readiness.Snapshot = Snapshot() with
            {
                Workstation = new WorkstationReadiness(WorkstationSupportStatus.Unsupported, code)
            };
            await model.RefreshReadinessAsync();
            Assert.Equal(expected, model.WorkstationStatus);
        }

        readiness.Fail = true;
        await model.RefreshReadinessAsync();
        Assert.Equal("环境检查失败，请重试", model.WorkstationStatus);
        Assert.Equal("证书读取失败，请重试", model.CertificateStatus);
        Assert.Equal("刷新证书", model.RefreshButtonText);
        readiness.Fail = false;
        readiness.Snapshot = Snapshot(withCertificate: true);
        await model.RefreshReadinessAsync();
        Assert.Equal("系统环境符合要求", model.WorkstationStatus);
        Assert.Equal("已读取 1 张代码签名证书", model.CertificateStatus);
    }

    [Fact]
    public async Task RefreshProgressResetsAfterSuccessAndCancellation()
    {
        var readiness = new MutableReadiness();
        var health = new ControlledHealth { Gate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        await using SigningWorkbenchViewModel model = CreateModel(readiness, health);
        Task refreshing = model.RefreshReadinessAsync();
        Assert.Equal("正在刷新…", model.RefreshButtonText);
        Assert.Equal("正在检查环境", model.WorkstationStatus);
        Assert.Equal("正在读取证书…", model.CertificateStatus);
        health.Gate.SetResult(Healthy());
        await refreshing;
        Assert.Equal("刷新证书", model.RefreshButtonText);

        health.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        refreshing = model.RefreshReadinessAsync();
        health.Gate.SetCanceled();
        await refreshing;
        Assert.Equal("刷新证书", model.RefreshButtonText);
        Assert.DoesNotContain("正在", model.WorkstationStatus, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1180, 940, false)]
    [InlineData(1180, 940, true)]
    [InlineData(1180, 1100, true)]
    [InlineData(992, 736, true)]
    [InlineData(650, 480, true)]
    [InlineData(480, 352, true)]
    public void RefreshDoesNotMoveToolbarQueueOrOutputAcrossAllCertificateStates(int width, int height, bool dual)
    {
        RunOnSta(async () =>
        {
            var readiness = new MutableReadiness();
            var health = new ControlledHealth();
            await using SigningWorkbenchViewModel model = CreateModel(readiness, health);
            model.IsDualMode = dual;
            ResourceDictionary resources = (ResourceDictionary)System.Windows.Application.LoadComponent(
                new Uri("/CodeSigner.App;component/Themes/DesignTokens.xaml", UriKind.Relative));
            var window = new MainWindow(model, UiPresentationSmokeTests.NoProductServices.Create<IWorkbenchDialogs>(), resources)
            {
                Width = width, Height = height
            };
            var root = (Grid)window.Content;
            window.Content = null;
            root.DataContext = model;
            root.Resources = window.Resources;
            var wrapper = new Grid { Background = (Brush)resources["Brush.PageBackground"] };
            wrapper.SetValue(TextElement.FontFamilyProperty, resources["Font.Body"]);
            wrapper.SetValue(TextElement.FontSizeProperty, resources["Typography.Body.Size"]);
            wrapper.SetValue(TextElement.ForegroundProperty, resources["Color.Text.Primary"]);
            wrapper.UseLayoutRounding = true;
            wrapper.Children.Add(root);
            window.UpdateResponsiveLayout(width, height);
            Layout();
            string[] stableNames = ["CommandActionsPanel", "ConfigurationBand", "QueueRegion", "QueueGrid", "ActionBand", "SupportFooter"];
            Rect[] before = stableNames.Select(Bounds).ToArray();
            Rect buttonBefore = Bounds("RefreshButton");
            Assert.True(Bounds("SettingsButton").Right <= width);
            Assert.True(Bounds("AddFilesButton").Width > 0);
            Assert.IsType<StackPanel>(window.FindName("CommandActionsPanel"));
            Assert.IsNotType<WrapPanel>(window.FindName("CommandActionsPanel"));
            Assert.Equal(Visibility.Visible, ((FrameworkElement)window.FindName("CommandActionsPanel")).Visibility);
            Assert.Same(model.RefreshCommand, ((Button)window.FindName("RefreshButton")).Command);
            Assert.Same(model.RemoveCommand, ((MenuItem)window.FindName("OverflowRemove")).Command);
            Assert.Same(model.RetryCommand, ((MenuItem)window.FindName("OverflowRetry")).Command);
            Assert.Same(model.OpenOutputCommand, ((MenuItem)window.FindName("OverflowOutput")).Command);
            Assert.Same(model.OpenLogDirectoryCommand, ((MenuItem)window.FindName("OpenLogDirectoryButton")).Command);
            Assert.Equal(width >= 1000 ? Visibility.Visible : Visibility.Collapsed,
                ((FrameworkElement)window.FindName("ExtendedActionsPanel")).Visibility);

            for (int phase = 0; phase < 4; phase++)
            {
                readiness.Snapshot = Snapshot(withCertificate: phase % 2 == 0);
                readiness.Fail = phase == 3;
                health.Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
                Task refreshing = model.RefreshReadinessAsync();
                Layout();
                Assert.Equal("正在刷新…", ((TextBlock)window.FindName("RefreshButtonLabel")).Text);
                AssertStable();
                health.Gate.SetResult(Healthy());
                await refreshing;
                Layout();
                Assert.Equal("刷新证书", ((TextBlock)window.FindName("RefreshButtonLabel")).Text);
                AssertStable();
            }
            SavePreview(wrapper, width, height, $"stable-refresh-{width}-{height}-{dual}.png");

            void Layout()
            {
                wrapper.Measure(new Size(width, height));
                wrapper.Arrange(new Rect(0, 0, width, height));
                wrapper.UpdateLayout();
            }
            Rect Bounds(string name)
            {
                var element = (FrameworkElement)window.FindName(name);
                return element.TransformToAncestor(wrapper).TransformBounds(new Rect(element.RenderSize));
            }
            void AssertStable()
            {
                for (int i = 0; i < stableNames.Length; i++)
                {
                    Rect after = Bounds(stableNames[i]);
                    Assert.Equal(before[i], after);
                }
                Assert.Equal(buttonBefore, Bounds("RefreshButton"));
                Assert.Equal(width, window.Width);
                Assert.Equal(height, window.Height);
                Assert.Equal(SizeToContent.Manual, window.SizeToContent);
                Assert.True(Bounds("QueueRegion").Bottom <= Bounds("ActionBand").Top);
                Assert.True(Bounds("SupportFooter").Bottom <= height);
            }
        });
    }

    private static SigningWorkbenchViewModel CreateModel(MutableReadiness readiness, ControlledHealth health) => new(
        readiness,
        UiPresentationSmokeTests.NoProductServices.Create<IIntakeAdapter>(),
        UiPresentationSmokeTests.NoProductServices.Create<IBatchAdapter>(),
        UiPresentationSmokeTests.NoProductServices.Create<IOperatorShell>(),
        health,
        UiPresentationSmokeTests.NoProductServices.Create<IWorkerRepairService>(),
        _ => throw new InvalidOperationException("No repair in presentation tests."));

    [Theory]
    [InlineData(1180, 940)]
    [InlineData(650, 480)]
    public void RefreshWithQueuedFileKeepsListAndActionsStableWithoutStartingSigning(int width, int height)
    {
        RunOnSta(async () =>
        {
            using var fixture = new SelectedFilePreflightTests.PreflightFixture("refresh-layout.exe");
            var batch = new SelectedFilePreflightTests.RecordingBatchAdapter();
            await using SigningWorkbenchViewModel model = fixture.CreateViewModel(
                new SelectedFilePreflightTests.RecordingAuditSink(), batch);
            await fixture.QueueAndPreflightAsync(model);
            string originalHash = fixture.SourceHash();
            ResourceDictionary resources = (ResourceDictionary)System.Windows.Application.LoadComponent(
                new Uri("/CodeSigner.App;component/Themes/DesignTokens.xaml", UriKind.Relative));
            var window = new MainWindow(model, UiPresentationSmokeTests.NoProductServices.Create<IWorkbenchDialogs>(), resources);
            var content = (Grid)window.Content;
            window.Content = null;
            content.Resources = window.Resources;
            content.DataContext = model;
            var wrapper = new Grid { Background = (Brush)resources["Brush.PageBackground"] };
            wrapper.SetValue(TextElement.FontFamilyProperty, resources["Font.Body"]);
            wrapper.SetValue(TextElement.FontSizeProperty, resources["Typography.Body.Size"]);
            wrapper.SetValue(TextElement.ForegroundProperty, resources["Color.Text.Primary"]);
            wrapper.Children.Add(content);
            window.UpdateResponsiveLayout(width, height);
            Layout();
            string[] names = ["CommandActionsPanel", "ConfigurationBand", "QueueRegion", "QueueGrid", "ActionBand", "SupportFooter"];
            Rect[] before = names.Select(Bounds).ToArray();
            for (int phase = 0; phase < 4; phase++)
            {
                fixture.Readiness.Snapshot = SelectedFilePreflightTests.PreflightFixture.ReadySnapshot(
                    catalogAvailable: phase % 2 == 0, providerInstalled: false);
                fixture.Readiness.Error = phase == 3 ? new IOException("Test refresh failure") : null;
                await model.RefreshReadinessAsync();
                await model.InvalidateCurrentPreflightAsync();
                await Dispatcher.Yield(DispatcherPriority.Background);
                Layout();
                for (int i = 0; i < names.Length; i++) Assert.Equal(before[i], Bounds(names[i]));
                Assert.Equal(0, batch.ProductionCalls);
                Assert.Equal(originalHash, fixture.SourceHash());
            }
            SavePreview(wrapper, width, height, $"queued-refresh-{width}-{height}.png");
            void Layout()
            {
                wrapper.Measure(new Size(width, height));
                wrapper.Arrange(new Rect(0, 0, width, height));
                wrapper.UpdateLayout();
            }
            Rect Bounds(string name)
            {
                var element = (FrameworkElement)window.FindName(name);
                return element.TransformToAncestor(wrapper).TransformBounds(new Rect(element.RenderSize));
            }
        });
    }

    private static WorkerLaunchDiagnostic Healthy() => WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Healthy);

    private static ReadinessSnapshot Snapshot(bool withCertificate = false) => new(
        new(WorkstationSupportStatus.Supported, "SupportedWindowsWorkstationX64"),
        NativeApiAvailability.Available,
        new(SimplySignInstallationStatus.NotInstalled, "", null, null, null, null),
        new(withCertificate ? CertificateAvailabilityStatus.CertificateAvailable : CertificateAvailabilityStatus.Unavailable,
            withCertificate ? [new EligibleCertificate(StoreLocation.CurrentUser, "My", new string('A', 40),
                "CN=界面验证示例证书 公司名称较长也不改变布局", "CN=示例颁发者",
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), true,
                [CertificateCatalogProbe.CodeSigningEkuOid])] : [], []),
        new(TimestampConfigurationStatus.Configured, new Uri("http://time.certum.pl")),
        ProviderAuthorizationStatus.AuthorizationUnknown,
        new(WindowsPowerShellBridgeStatus.Available, null, "5.1", "test"));

    private sealed class MutableReadiness : IReadinessAdapter
    {
        public ReadinessSnapshot Snapshot { get; set; } = RefreshPresentationTests.Snapshot();
        public bool Fail { get; set; }
        public ReadinessSnapshot Probe(Uri timestampUri) => Fail ? throw new IOException("Test-only read failure") : Snapshot;
    }

    private sealed class ControlledHealth : IWorkerHealthService
    {
        public TaskCompletionSource<WorkerLaunchDiagnostic>? Gate { get; set; }
        public Task<WorkerLaunchDiagnostic> ProbeAsync(CancellationToken cancellationToken) =>
            Gate?.Task ?? Task.FromResult(Healthy());
    }

    private static void RunOnSta(Func<Task> action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            Dispatcher dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.InvokeAsync(async () =>
            {
                try { await action(); }
                catch (Exception exception) { failure = exception; }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            });
            Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "Presentation test timed out.");
        if (failure is not null) throw new InvalidOperationException("Presentation test failed.", failure);
    }

    private static void SavePreview(FrameworkElement view, int width, int height, string name)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln"))) directory = directory.Parent;
        string output = Path.Combine(directory!.FullName, "artifacts", "presentation-1.0.43");
        Directory.CreateDirectory(output);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(view);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream stream = File.Create(Path.Combine(output, name));
        encoder.Save(stream);
    }
}
