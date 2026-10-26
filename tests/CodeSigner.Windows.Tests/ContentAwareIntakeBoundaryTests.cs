using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class ContentAwareIntakeBoundaryTests
{
    private static readonly Guid PeSubjectGuid = Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee");
    private static readonly Guid InstallerSubjectGuid = Guid.Parse("000c10f1-0000-0000-c000-000000000046");
    private static readonly Guid CabinetSubjectGuid = Guid.Parse("c689aaba-8e78-11d0-8c47-00c04fc295ee");

    [Theory]
    [InlineData("valid-unsigned.dll", "library.dll", SignableFileType.PortableExecutable)]
    [InlineData("valid-unsigned.msi", "installer.msi", SignableFileType.WindowsInstaller)]
    [InlineData("valid-unsigned.cab", "archive.cab", SignableFileType.Cabinet)]
    [InlineData("valid-unsigned.ocx", "control.ocx", SignableFileType.PortableExecutable)]
    [Trait("Category", "SigningIntegration")]
    public async Task ValidSupportedInputIsClassifiedByContentWithoutOutputCreation(
        string fixtureName,
        string fileName,
        SignableFileType expectedFileType)
    {
        using TestTree tree = new();
        string input = CopyFixture(tree, fileName, fixtureName);
        string output = tree.PathOf("Signed");
        var sip = new StubSipSubjectGuidRetriever(path =>
            new SipSubjectGuidLookup(true, SubjectGuidFor(Path.GetExtension(path)), 0));

        IntakePlan plan = await new IntakePlanner(new CryptSipSignableSubjectProbe(sip)).CreateAsync(
            [input],
            false,
            output,
            CancellationToken.None);

        IntakeFile planned = Assert.Single(plan.Files);
        Assert.Equal(expectedFileType, planned.Subject.FileType);
        Assert.Equal(Path.GetExtension(fileName), planned.Subject.PolicySubject.Extension);
        Assert.Equal(1, sip.CallCount);
        Assert.True(File.Exists(input));
        Assert.False(Directory.Exists(output));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task DirectoryContainingOneCandidateProducesOneMappedContentProbeWithoutOutputCreation()
    {
        using TestTree tree = new();
        string inputRoot = tree.PathOf("input");
        string input = tree.Write("input/nested/application.exe", "exe");
        string output = tree.PathOf("Signed");
        var probe = new CountingProbe();

        IntakePlan plan = await new IntakePlanner(probe).CreateAsync(
            [inputRoot],
            true,
            output,
            CancellationToken.None);

        IntakeFile file = Assert.Single(plan.Files);
        Assert.Equal(Path.GetFullPath(input), file.OriginalPath);
        Assert.Equal(Path.Combine("nested", "application.exe"), file.RelativePath);
        Assert.Equal(Path.Combine(output, "nested", "application.exe"), file.DestinationPath);
        Assert.Equal([Path.GetFullPath(input)], probe.ProbedPaths);
        Assert.True(File.Exists(input));
        Assert.False(Directory.Exists(output));
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task DirectoryIntakePassesEveryCandidateToContentProbeBeforeOutputCreation()
    {
        using TestTree tree = new();
        string input = tree.PathOf("input");
        tree.Write("input/application.exe", "exe");
        tree.Write("input/library.dll", "dll");
        tree.Write("input/installer.msi", "msi");
        tree.Write("input/archive.cab", "cab");
        tree.Write("input/control.ocx", "ocx");
        var probe = new CountingProbe();
        string output = tree.PathOf("Signed");

        IntakePlan plan = await new IntakePlanner(probe).CreateAsync(
            [input],
            true,
            output,
            CancellationToken.None);

        Assert.Equal(5, plan.Files.Count);
        Assert.Equal(5, probe.CallCount);
        Assert.False(Directory.Exists(output));
    }

    [Theory]
    [InlineData("malformed.exe", SignableSubjectProbeError.MalformedContent)]
    [InlineData("truncated.dll", SignableSubjectProbeError.MalformedContent)]
    [InlineData("malformed.msi", SignableSubjectProbeError.InvalidCompoundFile)]
    [InlineData("msi-disguised-as-exe.exe", SignableSubjectProbeError.ContentTypeMismatch)]
    [InlineData("pe-disguised-as-msi.msi", SignableSubjectProbeError.ContentTypeMismatch)]
    [Trait("Category", "SigningIntegration")]
    public async Task MalformedOrSpoofedSupportedExtensionReturnsTypedErrorBeforeOutputCreation(
        string fixtureName,
        SignableSubjectProbeError expectedProbeError)
    {
        using TestTree tree = new();
        string fixture = Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fixtureName);
        string input = fixture;
        string output = tree.PathOf("Signed");

        IntakeValidationException error = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            new IntakePlanner(new CryptSipSignableSubjectProbe(
                new StubSipSubjectGuidRetriever(path =>
                    new SipSubjectGuidLookup(true, SubjectGuidFor(Path.GetExtension(path)), 0)))).CreateAsync(
                [input],
                false,
                output,
                CancellationToken.None));

        Assert.Equal(IntakeError.NotSignableSubject, error.Error);
        Assert.Equal(
            expectedProbeError,
            Assert.IsType<SignableSubjectProbeException>(error.InnerException).Error);
        Assert.True(File.Exists(input));
        Assert.False(Directory.Exists(output));
    }

    private static string CopyFixture(TestTree tree, string fileName, string fixtureName)
    {
        string destination = tree.PathOf(fileName);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fixtureName), destination);
        return destination;
    }

    private static Guid SubjectGuidFor(string extension) => extension.ToLowerInvariant() switch
    {
        ".dll" or ".ocx" or ".exe" => PeSubjectGuid,
        ".msi" => InstallerSubjectGuid,
        ".cab" => CabinetSubjectGuid,
        _ => throw new ArgumentOutOfRangeException(nameof(extension), extension, "Unexpected test extension.")
    };

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

    private sealed class CountingProbe : ISignableSubjectProbe
    {
        private readonly List<string> probedPaths = [];

        public int CallCount { get; private set; }
        public IReadOnlyList<string> ProbedPaths => probedPaths;

        public SignableSubject Probe(string path)
        {
            CallCount++;
            probedPaths.Add(path);
            return new SignableSubject(SignableFileType.PortableExecutable, Guid.Empty);
        }
    }

    private sealed class StubSipSubjectGuidRetriever(Func<string, SipSubjectGuidLookup> retrieve)
        : ICryptSipSubjectGuidRetriever
    {
        public int CallCount { get; private set; }

        public SipSubjectGuidLookup Retrieve(string path)
        {
            CallCount++;
            return retrieve(path);
        }
    }
}
