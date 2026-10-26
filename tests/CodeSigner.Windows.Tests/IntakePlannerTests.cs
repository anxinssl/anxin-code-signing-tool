using System.Buffers.Binary;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class IntakePlannerTests
{
    [Fact]
    public async Task IntakeCharacterizationPreservesIdentityRelativePathAndDeferredOutputCreation()
    {
        using TestTree tree = new();
        string inputRoot = tree.PathOf("source");
        string original = tree.Write("source/nested/app.exe", "payload");
        string outputRoot = tree.PathOf("signed");

        IntakePlan plan = await Planner().CreateAsync(
            [inputRoot],
            recurseDirectories: true,
            outputRoot,
            CancellationToken.None);

        IntakeFile intakeFile = Assert.Single(plan.Files);
        Assert.Equal(Path.GetFullPath(original), intakeFile.OriginalPath);
        Assert.Equal(Path.Combine("nested", "app.exe"), intakeFile.RelativePath);
        Assert.Equal(Path.Combine(outputRoot, "nested", "app.exe"), intakeFile.DestinationPath);
        Assert.NotEmpty(intakeFile.Identity.FileId);
        Assert.NotEqual(0UL, intakeFile.Identity.VolumeSerialNumber);
        Assert.False(Directory.Exists(outputRoot));
        Assert.Equal("payload", File.ReadAllText(original));
    }

    [Fact]
    public async Task NormalizesUnicodeSpacesLongPathsAndDefaultsOutputBesideFirstInput()
    {
        using TestTree tree = new();
        string nested = string.Join(Path.DirectorySeparatorChar, Enumerable.Repeat("长路径 segment", 24));
        string original = tree.Write(Path.Combine("输入 folder", nested, "程序.exe"), "payload");

        IntakePlan plan = await Planner().CreateAsync([original], false, null, CancellationToken.None);

        Assert.Equal(Path.GetFullPath(original), plan.Files.Single().OriginalPath);
        Assert.True(original.Length > 260);
        Assert.Equal(Path.Combine(Path.GetDirectoryName(original)!, "Signed"), plan.OutputRoot);
        Assert.Equal(Path.Combine(plan.OutputRoot, "程序.exe"), plan.Files.Single().DestinationPath);
    }

    [Fact]
    public async Task DirectoryRecursionPreservesRelativePathsAndNonRecursiveModeDoesNotDescend()
    {
        using TestTree tree = new();
        string root = tree.PathOf("source");
        tree.Write("source/top.exe", "top");
        tree.Write("source/nested/deep.exe", "deep");

        IntakePlan recursive = await Planner().CreateAsync([root], true, tree.PathOf("recursive-out"), CancellationToken.None);
        IntakePlan shallow = await Planner().CreateAsync([root], false, tree.PathOf("shallow-out"), CancellationToken.None);

        Assert.Equal(["nested/deep.exe", "top.exe"], recursive.Files.Select(file => file.RelativePath.Replace('\\', '/')).ToArray());
        Assert.Equal("top.exe", shallow.Files.Single().RelativePath);
    }

    [Fact]
    public async Task DeduplicatesHardLinkAliasesByStableFileIdentity()
    {
        using TestTree tree = new();
        string first = tree.Write("first.exe", "same-file");
        string alias = tree.CreateHardLink("ALIAS.exe", first);

        IntakePlan plan = await Planner().CreateAsync([alias, first], false, tree.PathOf("out"), CancellationToken.None);

        Assert.Single(plan.Files);
        Assert.NotEmpty(plan.Files[0].Identity.FileId);
        Assert.NotEqual(0UL, plan.Files[0].Identity.VolumeSerialNumber);
    }

    [Fact]
    public async Task RejectsDuplicateDestinationsWithoutAutoRenaming()
    {
        using TestTree tree = new();
        string first = tree.Write("a/same.exe", "first");
        string second = tree.Write("b/same.exe", "second");

        IntakeValidationException exception = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([first, second], false, tree.PathOf("out"), CancellationToken.None));

        Assert.Equal(IntakeError.DestinationCollision, exception.Error);
    }

    [Fact]
    public async Task RejectsExistingDestinationAndExplicitInputInsideOutputRoot()
    {
        using TestTree tree = new();
        string original = tree.Write("source/app.exe", "source");
        string outputRoot = tree.PathOf("out");
        tree.Write("out/app.exe", "existing");
        IntakeValidationException collision = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([original], false, outputRoot, CancellationToken.None));
        Assert.Equal(IntakeError.DestinationExists, collision.Error);

        string inside = tree.Write("out/inside.exe", "inside");
        IntakeValidationException recursion = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([inside], false, outputRoot, CancellationToken.None));
        Assert.Equal(IntakeError.InputInsideOutputRoot, recursion.Error);
    }

    [Fact]
    public async Task DirectoryEnumerationNeverRecursesIntoOutputRoot()
    {
        using TestTree tree = new();
        string root = tree.PathOf("source");
        tree.Write("source/top.exe", "top");
        tree.Write("source/Signed/stale.exe", "stale");

        IntakePlan plan = await Planner().CreateAsync([root], true, Path.Combine(root, "Signed"), CancellationToken.None);

        Assert.Equal("top.exe", plan.Files.Single().RelativePath);
    }

    [RequiresSymbolicLinksFact]
    public async Task RejectsUnsupportedExtensionReparsePointAndLockedInput()
    {
        using TestTree tree = new();
        string unsupported = tree.Write("file.txt", "text");
        IntakeValidationException unsupportedError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            new IntakePlanner(new UnsupportedSubjectProbe()).CreateAsync(
                [unsupported],
                false,
                tree.PathOf("out-a"),
                CancellationToken.None));
        Assert.Equal(IntakeError.UnsupportedExtension, unsupportedError.Error);

        string target = tree.Write("target.exe", "target");
        string link = tree.PathOf("link.exe");
        File.CreateSymbolicLink(link, target);
        IntakeValidationException linkError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([link], false, tree.PathOf("out-b"), CancellationToken.None));
        Assert.Equal(IntakeError.ReparsePoint, linkError.Error);

        string locked = tree.Write("locked.exe", "locked");
        using FileStream held = new(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        IntakeValidationException lockedError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([locked], false, tree.PathOf("out-c"), CancellationToken.None));
        Assert.Equal(IntakeError.InaccessibleInput, lockedError.Error);
    }

    [RequiresSymbolicLinksFact]
    public async Task RejectsReparsePointInAnAncestorAndUsesBoundaryAwareOutputContainment()
    {
        using TestTree tree = new();
        string targetDirectory = tree.PathOf("real");
        tree.Write("real/nested/app.exe", "payload");
        string linkedDirectory = tree.PathOf("linked");
        Directory.CreateSymbolicLink(linkedDirectory, targetDirectory);

        IntakeValidationException linkError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([Path.Combine(linkedDirectory, "nested", "app.exe")], false, tree.PathOf("out"), CancellationToken.None));
        Assert.Equal(IntakeError.ReparsePoint, linkError.Error);

        string adjacent = tree.Write("output-adjacent/app.exe", "adjacent");
        IntakePlan adjacentPlan = await Planner().CreateAsync([adjacent], false, tree.PathOf("output"), CancellationToken.None);
        Assert.Single(adjacentPlan.Files);
    }

    [Fact]
    public async Task RejectsUnsupportedAndLockedInputWithoutSymbolicLinkPrivilege()
    {
        using TestTree tree = new();
        string unsupported = tree.Write("file.txt", "text");
        IntakeValidationException unsupportedError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            new IntakePlanner(new UnsupportedSubjectProbe()).CreateAsync(
                [unsupported], false, tree.PathOf("out-a"), CancellationToken.None));
        Assert.Equal(IntakeError.UnsupportedExtension, unsupportedError.Error);
        string locked = tree.Write("locked.exe", "locked");
        using FileStream held = new(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        IntakeValidationException lockedError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            Planner().CreateAsync([locked], false, tree.PathOf("out-b"), CancellationToken.None));
        Assert.Equal(IntakeError.InaccessibleInput, lockedError.Error);
        Assert.False(Directory.Exists(tree.PathOf("out-b")));
    }

    [Fact]
    public void NativeSipProbeRejectsExtensionSpoofedPayload()
    {
        using TestTree tree = new();
        string malformed = tree.Write("spoofed.exe", "not a portable executable");

        Assert.ThrowsAny<Exception>(() => new CryptSipSignableSubjectProbe().Probe(malformed));
    }

    [Fact]
    [Trait("Category", "SipValidationRegression")]
    public void ProbeRejectsTruncatedCabinetEvenWhenCryptSipReturnsCabinetSubject()
    {
        string fixture = FixturePath("malformed.cab");

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() =>
            new CryptSipSignableSubjectProbe().Probe(fixture));
        Assert.Equal(SignableSubjectProbeError.InvalidCabinet, error.Error);
    }

    [Fact]
    [Trait("Category", "SipValidationRegression")]
    public void ProbeRejectsMsiBytesDisguisedWithExeExtension()
    {
        string fixture = FixturePath("msi-disguised-as-exe.exe");

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() =>
            new CryptSipSignableSubjectProbe().Probe(fixture));
        Assert.Equal(SignableSubjectProbeError.ContentTypeMismatch, error.Error);
    }

    [Fact]
    [Trait("Category", "SipValidationRegression")]
    public void ProbeRejectsPortableExecutableBytesDisguisedWithMsiExtension()
    {
        string fixture = FixturePath("pe-disguised-as-msi.msi");

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() =>
            new CryptSipSignableSubjectProbe().Probe(fixture));
        Assert.Equal(SignableSubjectProbeError.ContentTypeMismatch, error.Error);
    }

    [Theory]
    [InlineData(37)]
    [InlineData(43)]
    [Trait("Category", "SipValidationRegression")]
    public void ProbeRejectsCabinetWhoseDeclaredFolderTableIsPhysicallyTruncated(int fileLength)
    {
        using TestTree tree = new();
        string fixture = WriteCabinetBoundaryFixture(tree, fileLength, filesOffset: 36);

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() =>
            new CryptSipSignableSubjectProbe().Probe(fixture));
        Assert.Equal(SignableSubjectProbeError.InvalidCabinet, error.Error);
    }

    [Fact]
    [Trait("Category", "SipValidationRegression")]
    public void ProbeRejectsCabinetWhoseFilesOffsetOverlapsCompleteFolderTable()
    {
        using TestTree tree = new();
        string fixture = WriteCabinetBoundaryFixture(tree, fileLength: 44, filesOffset: 36);

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() =>
            new CryptSipSignableSubjectProbe().Probe(fixture));
        Assert.Equal(SignableSubjectProbeError.InvalidCabinet, error.Error);
    }

    [Fact]
    public async Task SubjectProbeFailureRejectsMalformedOrSpoofedFile()
    {
        using TestTree tree = new();
        string malformed = tree.Write("malformed.exe", "not-a-real-subject");
        IntakePlanner planner = new(new RejectingSubjectProbe());

        IntakeValidationException exception = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            planner.CreateAsync([malformed], false, tree.PathOf("out"), CancellationToken.None));

        Assert.Equal(IntakeError.NotSignableSubject, exception.Error);
    }

    private static IntakePlanner Planner() => new(new AcceptingSubjectProbe());

    private static string FixturePath(string fileName)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "global.json")))
        {
            directory = directory.Parent;
        }

        string repositoryRoot = directory?.FullName
            ?? throw new InvalidOperationException("Repository root containing global.json was not found.");
        return Path.Combine(repositoryRoot, "tests", "fixtures", "generated", fileName);
    }

    private static string WriteCabinetBoundaryFixture(TestTree tree, int fileLength, uint filesOffset)
    {
        byte[] bytes = new byte[fileLength];
        "MSCF"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), (uint)fileLength);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(16, 4), filesOffset);
        bytes[24] = 3;
        bytes[25] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(26, 2), 1);
        string path = tree.PathOf($"cffolder-{fileLength}-{filesOffset}.cab");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private sealed class AcceptingSubjectProbe : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => new(SignableFileType.PortableExecutable, Guid.NewGuid());
    }

    private sealed class RejectingSubjectProbe : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => throw new InvalidDataException("not signable");
    }

    private sealed class UnsupportedSubjectProbe : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => throw new SignableSubjectProbeException(
            SignableSubjectProbeError.UnsupportedExtension,
            "unsupported");
    }
}
