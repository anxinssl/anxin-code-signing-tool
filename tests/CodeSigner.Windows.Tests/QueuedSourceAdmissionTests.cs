using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using System.Security.Cryptography;

namespace CodeSigner.Windows.Tests;

public sealed class QueuedSourceAdmissionTests
{
    [Fact]
    public void BaselineCharacterizationKnownExtensionIsRecognizedByPolicyWithoutContent()
    {
        PolicyResult<SigningSubject> result = SigningSubject.TryCreateForExtension(".exe");

        Assert.NotNull(result.Value);
        Assert.Equal(".exe", result.Value.Extension);
    }

    [Fact]
    public void ExplicitUnknownExtensionIsAdmittedWithoutChangingSourceBytes()
    {
        using TestTree tree = new();
        string source = tree.Write("unknown.payload", "unrecognized payload");
        string before = Hash(source);

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [source],
            recurseDirectories: false,
            CancellationToken.None);

        QueuedSource admitted = Assert.Single(result.Sources);
        Assert.Empty(result.Failures);
        Assert.Equal(Path.GetFullPath(source), admitted.CanonicalPath);
        Assert.Equal(Path.GetFileName(source), admitted.RelativePath);
        Assert.NotEmpty(admitted.Identity.FileId);
        Assert.Equal(before, Hash(source));
        Console.WriteLine($"unknown-source-sha256 before={before} after={Hash(source)}");
    }

    [Fact]
    public void DirectoryAdmissionPreservesInputRootRelativePath()
    {
        using TestTree tree = new();
        string directory = tree.PathOf("drop");
        string source = tree.Write("drop/nested/app.exe", "payload");

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [directory],
            recurseDirectories: true,
            CancellationToken.None);

        QueuedSource admitted = Assert.Single(result.Sources);
        Assert.Equal(Path.GetFullPath(source), admitted.CanonicalPath);
        Assert.Equal(Path.Combine("nested", "app.exe"), admitted.RelativePath);
    }

    [Fact]
    public void SeparateAdmissionDeduplicatesAgainstExistingPhysicalIdentity()
    {
        using TestTree tree = new();
        string source = tree.Write("source.exe", "payload");
        string alias = tree.CreateHardLink("alias.exe", source);
        QueuedSource existing = Assert.Single(QueuedSourceAdmission.Admit(
            [source],
            recurseDirectories: false,
            CancellationToken.None).Sources);

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [alias],
            recurseDirectories: false,
            existingSources: [existing],
            CancellationToken.None);

        Assert.Empty(result.Sources);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void DirectoryAdmissionFiltersUnknownExtensionsWithoutContentProbe()
    {
        using TestTree tree = new();
        string directory = tree.PathOf("drop");
        string supported = tree.Write("drop/malformed.exe", "not a portable executable");
        string ignored = tree.Write("drop/ignored.payload", "unknown payload");
        string supportedBefore = Hash(supported);
        string ignoredBefore = Hash(ignored);

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [directory],
            recurseDirectories: false,
            CancellationToken.None);

        QueuedSource admitted = Assert.Single(result.Sources);
        Assert.Empty(result.Failures);
        Assert.Equal(Path.GetFullPath(supported), admitted.CanonicalPath);
        Assert.Equal(supportedBefore, Hash(supported));
        Assert.Equal(ignoredBefore, Hash(ignored));
        Console.WriteLine($"directory-supported-sha256 before={supportedBefore} after={Hash(supported)}");
        Console.WriteLine($"directory-ignored-sha256 before={ignoredBefore} after={Hash(ignored)}");
        Assert.DoesNotContain(
            typeof(QueuedSourceAdmission).GetMethods().SelectMany(method => method.GetParameters()),
            parameter => parameter.ParameterType == typeof(ISignableSubjectProbe));
    }

    [Fact]
    public void AdmissionDeduplicatesCanonicalPathsAndHardLinks()
    {
        using TestTree tree = new();
        string source = tree.Write("source.exe", "source");
        string alternateCasing = Path.Combine(Path.GetDirectoryName(source)!, "SOURCE.EXE");
        string hardLink = tree.CreateHardLink("alias.exe", source);

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [source, alternateCasing, hardLink],
            recurseDirectories: false,
            CancellationToken.None);

        QueuedSource admitted = Assert.Single(result.Sources);
        Assert.Empty(result.Failures);
        Assert.Equal(Path.GetFullPath(source), admitted.CanonicalPath);
    }

    [RequiresSymbolicLinksFact]
    public void MissingReparseAndInaccessibleInputsReturnTypedFailuresWithoutSources()
    {
        using TestTree tree = new();
        string missing = tree.PathOf("missing.exe");
        string target = tree.Write("target.exe", "target");
        string reparse = tree.PathOf("link.exe");
        File.CreateSymbolicLink(reparse, target);
        string inaccessible = tree.Write("locked.exe", "locked");
        using FileStream held = new(inaccessible, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [missing, reparse, inaccessible],
            recurseDirectories: false,
            CancellationToken.None);

        Assert.Empty(result.Sources);
        Assert.Equal(
            [
                QueuedSourceAdmissionError.InputNotFound,
                QueuedSourceAdmissionError.ReparsePoint,
                QueuedSourceAdmissionError.InaccessibleInput
            ],
            result.Failures.Select(failure => failure.Error).ToArray());
    }

    [RequiresSymbolicLinksFact]
    public void FileReplacedBySymlinkAfterPathCheckDoesNotAdmitOutsideTarget()
    {
        using TestTree tree = new();
        string source = tree.Write("selected/source.exe", "selected");
        string outside = tree.Write("outside/target.exe", "outside");

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [source],
            recurseDirectories: false,
            (point, path) =>
            {
                if (point == QueuedSourceAdmissionTestPoint.BeforeFileOpen &&
                    path.Equals(source, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(source);
                    File.CreateSymbolicLink(source, outside);
                }
            },
            CancellationToken.None);

        Assert.Empty(result.Sources);
        QueuedSourceAdmissionFailure failure = Assert.Single(result.Failures);
        Assert.Equal(QueuedSourceAdmissionError.ReparsePoint, failure.Error);
        Assert.Equal("outside", File.ReadAllText(outside));
    }

    [RequiresSymbolicLinksFact]
    public void DirectoryReplacedByLinkAfterPathCheckDoesNotTraverseOutsideTarget()
    {
        using TestTree tree = new();
        string inputRoot = tree.PathOf("selected");
        string nested = tree.Write("selected/nested/placeholder.txt", "placeholder");
        string nestedDirectory = Path.GetDirectoryName(nested)!;
        string outsideFile = tree.Write("outside/target.exe", "outside");
        string outsideDirectory = Path.GetDirectoryName(outsideFile)!;

        QueuedSourceAdmissionResult result = QueuedSourceAdmission.Admit(
            [inputRoot],
            recurseDirectories: true,
            (point, path) =>
            {
                if (point == QueuedSourceAdmissionTestPoint.BeforeDirectoryEnumeration &&
                    path.Equals(nestedDirectory, StringComparison.OrdinalIgnoreCase))
                {
                    Directory.Delete(nestedDirectory, recursive: true);
                    Directory.CreateSymbolicLink(nestedDirectory, outsideDirectory);
                }
            },
            CancellationToken.None);

        Assert.Empty(result.Sources);
        QueuedSourceAdmissionFailure failure = Assert.Single(result.Failures);
        Assert.Equal(QueuedSourceAdmissionError.ReparsePoint, failure.Error);
        Assert.Equal("outside", File.ReadAllText(outsideFile));
    }

    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
