using System.Reflection;
using System.IO;
using CodeSigner.App.Services;
using CodeSigner.App.ViewModels;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.Tests;

public sealed class QueueIntakeCompositionTests
{
    [Fact]
    public void IntakeContractExposesOnlyTypedStagedOperations()
    {
        MethodInfo[] methods = typeof(IIntakeAdapter).GetMethods();

        Assert.Equal(
            ["AdmitAsync", "DetectAsync", "PlanOutputAsync", "VerifyIntegrityAsync"],
            methods.Select(method => method.Name).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(methods, method => method.Name == "CreateAsync");
    }

    [Fact]
    public async Task ProductionCompositionInjectsTypedProductionIntakeAdapter()
    {
        await using SigningWorkbenchViewModel viewModel = ProductionComposition.CreateViewModel();
        FieldInfo field = typeof(SigningWorkbenchViewModel).GetField(
            "intakeAdapter",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("The intake adapter field is unavailable.");

        Assert.IsType<ProductionIntakeAdapter>(field.GetValue(viewModel));
    }

    [Fact]
    public async Task PlanOutputAsyncConsumesCachedDetectionWithoutDetectingAgain()
    {
        string root = Path.Combine(Path.GetTempPath(), $"codesigner-intake-{Guid.NewGuid():N}");
        string outputRoot = Path.Combine(root, "output");
        string missingSource = Path.Combine(root, "missing.exe");
        Directory.CreateDirectory(outputRoot);
        try
        {
            var source = new QueuedSource(
                missingSource,
                "missing.exe",
                new StableFileIdentity(17, "CACHED-FILE"));
            var detected = new DetectedQueuedSource(
                source,
                new SignableSubject(
                    SigningSubject.TryCreateForExtension(".exe").Value
                        ?? throw new InvalidOperationException("The PE signing policy is unavailable."),
                    Guid.NewGuid(),
                    scriptProfile: null),
                new SourceFingerprint(source.Identity, 123, DateTime.UnixEpoch, new string('A', 64)));
            var adapter = new ProductionIntakeAdapter();

            IntakeFile planned = await adapter.PlanOutputAsync(detected, outputRoot, CancellationToken.None);

            Assert.Equal(missingSource, planned.OriginalPath);
            Assert.Equal(Path.Combine(outputRoot, "missing.exe"), planned.DestinationPath);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
