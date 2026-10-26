using System.Security.Cryptography;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class QueuedSourceDetectionTests
{
    [Fact]
    public void DetectIsItemLocalAndPlanningUsesCachedDetectionWithoutAnotherProbe()
    {
        using TestTree tree = new();
        string supportedPath = tree.Write("supported.exe", "supported");
        string blockedPath = tree.Write("blocked.exe", "blocked");
        string supportedHashBefore = Hash(supportedPath);
        IReadOnlyList<QueuedSource> sources = QueuedSourceAdmission.Admit(
            [supportedPath, blockedPath], false, CancellationToken.None).Sources;
        CountingProbe probe = new(blockedPath);
        IntakePlanner planner = new(probe);

        QueuedSourceDetectionResult supported = planner.Detect(
            sources.Single(source => source.CanonicalPath == supportedPath), CancellationToken.None);
        QueuedSourceDetectionResult blocked = planner.Detect(
            sources.Single(source => source.CanonicalPath == blockedPath), CancellationToken.None);

        Assert.Equal(QueuedSourceDetectionStatus.Supported, supported.Status);
        Assert.NotNull(supported.DetectedSource);
        Assert.Equal(QueuedSourceDetectionStatus.Blocked, blocked.Status);
        Assert.Null(blocked.DetectedSource);
        Assert.Equal(IntakeError.NotSignableSubject, blocked.Error);
        Assert.Equal(1, probe.CallsByPath[supportedPath]);
        Assert.Equal(1, probe.CallsByPath[blockedPath]);

        IntakeFile first = IntakePlanner.PlanOutput(
            supported.DetectedSource!, tree.PathOf("out-a"), CancellationToken.None);
        IntakeFile second = IntakePlanner.PlanOutput(
            supported.DetectedSource!, tree.PathOf("out-b"), CancellationToken.None);

        Assert.Equal(Path.Combine(tree.PathOf("out-a"), "supported.exe"), first.DestinationPath);
        Assert.Equal(Path.Combine(tree.PathOf("out-b"), "supported.exe"), second.DestinationPath);
        Assert.Equal(1, probe.CallsByPath[supportedPath]);
        Assert.Equal(supportedHashBefore, Hash(supportedPath));
        Console.WriteLine($"replan-source-sha256 before={supportedHashBefore} after={Hash(supportedPath)}");
    }

    [Fact]
    public void DetectionReturnsUnavailableWhenAdmittedSourceBecomesInaccessible()
    {
        using TestTree tree = new();
        string sourcePath = tree.Write("locked.exe", "payload");
        QueuedSource source = Assert.Single(QueuedSourceAdmission.Admit(
            [sourcePath], false, CancellationToken.None).Sources);
        using FileStream held = new(sourcePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        QueuedSourceDetectionResult result = new IntakePlanner(new CountingProbe()).Detect(
            source,
            CancellationToken.None);

        Assert.Equal(QueuedSourceDetectionStatus.Unavailable, result.Status);
        Assert.Null(result.DetectedSource);
        Assert.Equal(IntakeError.InaccessibleInput, result.Error);
    }

    [Fact]
    public void FingerprintUsesUppercaseSha256AndDetectsSameSizeRestoredTimestampMutation()
    {
        using TestTree tree = new();
        string sourcePath = tree.Write("source.exe", "AAAA");
        QueuedSource source = Assert.Single(QueuedSourceAdmission.Admit(
            [sourcePath], false, CancellationToken.None).Sources);
        IntakePlanner planner = new(new CountingProbe());
        QueuedSourceDetectionResult detection = planner.Detect(source, CancellationToken.None);
        DetectedQueuedSource detected = Assert.IsType<DetectedQueuedSource>(detection.DetectedSource);
        DateTime originalWriteTime = File.GetLastWriteTimeUtc(sourcePath);

        Assert.Matches("^[0-9A-F]{64}$", detected.Fingerprint.Sha256);
        Assert.Equal(4, detected.Fingerprint.Length);
        Assert.Equal(source.Identity, detected.Fingerprint.Identity);

        File.WriteAllText(sourcePath, "BBBB");
        File.SetLastWriteTimeUtc(sourcePath, originalWriteTime);

        QueuedSourceDetectionResult integrity = IntakePlanner.VerifyIntegrity(detected, CancellationToken.None);

        Assert.Equal(QueuedSourceDetectionStatus.Changed, integrity.Status);
        Assert.Null(integrity.DetectedSource);
    }

    [Fact]
    public void DetectionReturnsTypedUnavailableAndChangedResults()
    {
        using TestTree tree = new();
        string unavailablePath = tree.Write("unavailable.exe", "payload");
        string changedPath = tree.Write("changed.exe", "payload");
        QueuedSource unavailable = Assert.Single(QueuedSourceAdmission.Admit(
            [unavailablePath], false, CancellationToken.None).Sources);
        QueuedSource changed = Assert.Single(QueuedSourceAdmission.Admit(
            [changedPath], false, CancellationToken.None).Sources);
        File.Delete(unavailablePath);
        File.Delete(changedPath);
        File.WriteAllText(changedPath, "payload");
        IntakePlanner planner = new(new CountingProbe());

        Assert.Equal(
            QueuedSourceDetectionStatus.Unavailable,
            planner.Detect(unavailable, CancellationToken.None).Status);
        Assert.Equal(
            QueuedSourceDetectionStatus.Changed,
            planner.Detect(changed, CancellationToken.None).Status);
    }

    [Fact]
    public void PlanOutputRejectsEscapesAndExistingDestinationsWithoutProbing()
    {
        using TestTree tree = new();
        string sourcePath = tree.Write("source.exe", "payload");
        QueuedSource source = Assert.Single(QueuedSourceAdmission.Admit(
            [sourcePath], false, CancellationToken.None).Sources);
        CountingProbe probe = new();
        IntakePlanner planner = new(probe);
        DetectedQueuedSource detected = Assert.IsType<DetectedQueuedSource>(
            planner.Detect(source, CancellationToken.None).DetectedSource);
        string outputRoot = tree.PathOf("out");
        tree.Write("out/source.exe", "existing");

        IntakeValidationException existing = Assert.Throws<IntakeValidationException>(() =>
            IntakePlanner.PlanOutput(detected, outputRoot, CancellationToken.None));
        DetectedQueuedSource escaping = detected with
        {
            Source = detected.Source with { RelativePath = Path.Combine("..", "escape.exe") }
        };
        IntakeValidationException escape = Assert.Throws<IntakeValidationException>(() =>
            IntakePlanner.PlanOutput(escaping, tree.PathOf("safe"), CancellationToken.None));

        Assert.Equal(IntakeError.DestinationExists, existing.Error);
        Assert.Equal(IntakeError.InvalidInput, escape.Error);
        Assert.Equal(1, probe.CallsByPath[sourcePath]);
    }

    private sealed class CountingProbe(string? blockedPath = null) : ISignableSubjectProbe
    {
        public Dictionary<string, int> CallsByPath { get; } = new(StringComparer.OrdinalIgnoreCase);

        public SignableSubject Probe(string path)
        {
            CallsByPath[path] = CallsByPath.GetValueOrDefault(path) + 1;
            if (path.Equals(blockedPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new SignableSubjectProbeException(
                    SignableSubjectProbeError.MalformedContent,
                    "blocked fixture");
            }

            return new SignableSubject(SignableFileType.PortableExecutable, Guid.Parse("11111111-1111-1111-1111-111111111111"));
        }
    }

    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
