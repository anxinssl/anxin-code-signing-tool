using System.Diagnostics;
using System.Security.Cryptography;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class SdkSignToolLocatorTests
{
    [Fact]
    public void LocatorAcceptsSyntheticTrustedCanonicalCandidate()
    {
        using SdkTree tree = new();
        string path = tree.AddCandidate("10.0.26100.0");
        var inspector = new StubInspector(_ => ValidInspection());
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(inspector));

        SdkSignToolDiscoveryResult result = locator.Discover();

        Assert.True(result.IsAvailable);
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(result.Candidate);
        Assert.Equal(Path.GetFullPath(path), candidate.Path);
        Assert.Equal(new Version(10, 0, 26100, 0), candidate.SdkVersion);
        Assert.Equal(new Version(10, 0, 26100, 7463), candidate.ProductVersion);
        Assert.Equal(WindowsTrustedSdkSignToolCandidateValidator.ExpectedPublisher, candidate.Publisher);
        Assert.Equal(WindowsTrustedSdkSignToolCandidateValidator.ExpectedCompanyName, candidate.CompanyName);
        Assert.Equal(WindowsTrustedSdkSignToolCandidateValidator.ExpectedProductName, candidate.ProductName);
        Assert.Single(inspector.Paths);
    }

    [Fact]
    public void LocatorRejectsPathCandidateWithoutConsultingPath()
    {
        using SdkTree tree = new();
        string pathDirectory = Path.Combine(tree.Root, "path-only");
        Directory.CreateDirectory(pathDirectory);
        string pathCandidate = Path.Combine(pathDirectory, "signtool.exe");
        File.WriteAllBytes(pathCandidate, [0x4D, 0x5A]);
        var inspector = new StubInspector(_ => ValidInspection());
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(inspector));

        SdkSignToolDiscoveryResult discovery = locator.Discover();
        SdkSignToolDiscoveryResult revalidation = locator.Revalidate(Candidate(pathCandidate));

        Assert.Equal(SdkSignToolDiscoveryStatus.Unavailable, discovery.Status);
        Assert.Equal(SdkSignToolRejectionReason.OutsideCanonicalHierarchy, revalidation.RejectionReason);
        Assert.Empty(inspector.Paths);
    }

    [Fact]
    public void LocatorRejectsReparsePointCandidateBeforeMetadataProbe()
    {
        using SdkTree tree = new();
        string path = tree.AddCandidate("10.0.26100.0");
        tree.FileSystem.ReparsePaths.Add(Path.GetDirectoryName(path)!);
        var inspector = new StubInspector(_ => ValidInspection());
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(inspector));

        SdkSignToolDiscoveryResult result = locator.Discover();

        Assert.Equal(SdkSignToolDiscoveryStatus.Rejected, result.Status);
        Assert.Equal(SdkSignToolRejectionReason.ReparsePoint, result.RejectionReason);
        Assert.Empty(inspector.Paths);
    }

    [Theory]
    [InlineData("non-x64", SdkSignToolRejectionReason.NotX64PortableExecutable)]
    [InlineData("untrusted", SdkSignToolRejectionReason.WindowsTrustFailed)]
    [InlineData("publisher", SdkSignToolRejectionReason.PublisherMismatch)]
    [InlineData("company", SdkSignToolRejectionReason.CompanyMismatch)]
    [InlineData("product", SdkSignToolRejectionReason.ProductMismatch)]
    [InlineData("identity", SdkSignToolRejectionReason.IdentityMismatch)]
    [InlineData("version", SdkSignToolRejectionReason.InvalidVersionMetadata)]
    public void LocatorRejectsNonX64UntrustedOrWrongMicrosoftMetadata(
        string mutation,
        SdkSignToolRejectionReason expectedReason)
    {
        using SdkTree tree = new();
        tree.AddCandidate("10.0.26100.0");
        SdkSignToolExecutableInspection inspection = mutation switch
        {
            "non-x64" => ValidInspection() with { PeMachine = 0x014c },
            "untrusted" => ValidInspection() with { WindowsTrustValid = false },
            "publisher" => ValidInspection() with { Publisher = "Microsoft Windows" },
            "company" => ValidInspection() with { CompanyName = "Microsoft" },
            "product" => ValidInspection() with { ProductName = "Windows SDK" },
            "identity" => ValidInspection() with { OriginalFileName = "renamed.exe" },
            "version" => ValidInspection() with { ProductVersion = null },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown test mutation.")
        };
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(new StubInspector(_ => inspection)));

        SdkSignToolDiscoveryResult result = locator.Discover();

        Assert.Equal(SdkSignToolDiscoveryStatus.Rejected, result.Status);
        Assert.Equal(expectedReason, result.RejectionReason);
    }

    [Fact]
    public void LocatorRejectsMalformedVersionDirectoryWithoutInspectingCandidate()
    {
        using SdkTree tree = new();
        tree.AddCandidate("10.0.preview.0");
        var inspector = new StubInspector(_ => ValidInspection());
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(inspector));

        SdkSignToolDiscoveryResult result = locator.Discover();

        Assert.Equal(SdkSignToolDiscoveryStatus.Rejected, result.Status);
        Assert.Equal(SdkSignToolRejectionReason.MalformedSdkVersion, result.RejectionReason);
        Assert.Empty(inspector.Paths);
    }

    [Fact]
    public void LocatorChoosesHighestValidSdkVersion()
    {
        using SdkTree tree = new();
        tree.AddCandidate("10.0.22621.0");
        string highest = tree.AddCandidate("10.0.26100.0");
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(new StubInspector(_ => ValidInspection())));

        SdkSignToolDiscoveryResult result = locator.Discover();

        Assert.True(result.IsAvailable);
        Assert.Equal(Path.GetFullPath(highest), result.Candidate!.Path);
        Assert.Equal(new Version(10, 0, 26100, 0), result.Candidate.SdkVersion);
    }

    [Fact]
    public void RevalidationRejectsAStaleCandidateHash()
    {
        using SdkTree tree = new();
        tree.AddCandidate("10.0.26100.0");
        string currentHash = new('A', 64);
        var inspector = new StubInspector(_ => ValidInspection() with { Sha256 = currentHash });
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(inspector));
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            locator.Discover().Candidate);
        currentHash = new string('B', 64);

        SdkSignToolDiscoveryResult result = locator.Revalidate(candidate);

        Assert.Equal(SdkSignToolDiscoveryStatus.Rejected, result.Status);
        Assert.Equal(SdkSignToolRejectionReason.CandidateChanged, result.RejectionReason);
    }

    [Theory]
    [InlineData("publisher")]
    [InlineData("company")]
    [InlineData("product")]
    public void RevalidationRejectsForgedSnapshotMetadataEvenWhenCurrentFileRemainsTrusted(
        string mutation)
    {
        using SdkTree tree = new();
        tree.AddCandidate("10.0.26100.0");
        var locator = new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(
                new StubInspector(_ => ValidInspection())));
        TrustedSdkSignToolCandidate discovered = Assert.IsType<TrustedSdkSignToolCandidate>(
            locator.Discover().Candidate);
        TrustedSdkSignToolCandidate forged = mutation switch
        {
            "publisher" => discovered with { Publisher = "Microsoft Windows" },
            "company" => discovered with { CompanyName = "Microsoft" },
            "product" => discovered with { ProductName = "Windows SDK" },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown mutation.")
        };

        SdkSignToolDiscoveryResult result = locator.Revalidate(forged);

        Assert.Equal(SdkSignToolDiscoveryStatus.Rejected, result.Status);
        Assert.Equal(SdkSignToolRejectionReason.CandidateChanged, result.RejectionReason);
    }

    [Fact]
    public void LaunchLeaseRejectsCandidateReboundAfterSuccessfulRevalidation()
    {
        using SdkTree tree = new();
        string path = tree.AddCandidate("10.0.26100.0");
        TrustedSdkSignToolLocator locator = CreateExactHashLocator(tree, path);
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            locator.Discover().Candidate);
        Assert.True(locator.Revalidate(candidate).IsAvailable);
        File.Move(path, $"{path}.validated");
        File.WriteAllBytes(path, [0x4D, 0x5A, 0xDE, 0xAD]);

        SdkSignToolLaunchLeaseResult result = locator.AcquireLaunchLease(candidate);

        Assert.False(result.IsAvailable);
        Assert.Equal(SdkSignToolRejectionReason.CandidateChanged, result.Revalidation.RejectionReason);
        Assert.Null(result.Lease);
    }

    [Fact]
    public void LaunchLeasePinsStableIdentityAndSha256()
    {
        using SdkTree tree = new();
        string path = tree.AddCandidate("10.0.26100.0");
        TrustedSdkSignToolLocator locator = CreateExactHashLocator(tree, path);
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            locator.Discover().Candidate);

        SdkSignToolLaunchLeaseResult result = locator.AcquireLaunchLease(candidate);

        using ITrustedSdkSignToolLaunchLease lease =
            Assert.IsAssignableFrom<ITrustedSdkSignToolLaunchLease>(result.Lease);
        using FileStream currentPath = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.True(result.IsAvailable);
        Assert.Equal(candidate, lease.Candidate);
        Assert.Equal(WindowsFileIdentity.FromHandle(currentPath.SafeFileHandle), lease.Identity);
        Assert.Equal(candidate.Sha256, lease.Sha256, ignoreCase: true);
        Assert.Equal(candidate.Sha256, Convert.ToHexString(SHA256.HashData(currentPath)), ignoreCase: true);
    }

    [Fact]
    public void LaunchLeaseDeniesWriteDeleteAndRenameUntilDisposed()
    {
        using SdkTree tree = new();
        string path = tree.AddCandidate("10.0.26100.0");
        TrustedSdkSignToolLocator locator = CreateExactHashLocator(tree, path);
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            locator.Discover().Candidate);
        SdkSignToolLaunchLeaseResult result = locator.AcquireLaunchLease(candidate);

        using (ITrustedSdkSignToolLaunchLease lease =
               Assert.IsAssignableFrom<ITrustedSdkSignToolLaunchLease>(result.Lease))
        {
            string architectureDirectory = Path.GetDirectoryName(path)!;
            Assert.ThrowsAny<IOException>(() =>
                Directory.Move(architectureDirectory, $"{architectureDirectory}.moved"));
            Assert.ThrowsAny<IOException>(() => File.WriteAllBytes(path, [0x4D, 0x5A, 1]));
            Assert.ThrowsAny<IOException>(() => File.Move(path, $"{path}.moved"));
            Assert.ThrowsAny<IOException>(() => File.Delete(path));
            Assert.Equal(candidate.Sha256, lease.Sha256, ignoreCase: true);
        }

        File.Move(path, $"{path}.moved");
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task LaunchLeaseAllowsBenignExplicitExecutableToStartWithoutSigningArguments()
    {
        using SdkTree tree = new();
        string path = tree.AddCandidate("10.0.26100.0");
        string commandInterpreter = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        File.Copy(commandInterpreter, path, overwrite: true);
        TrustedSdkSignToolLocator locator = CreateExactHashLocator(tree, path);
        TrustedSdkSignToolCandidate candidate = Assert.IsType<TrustedSdkSignToolCandidate>(
            locator.Discover().Candidate);
        SdkSignToolLaunchLeaseResult leaseResult = locator.AcquireLaunchLease(candidate);
        using ITrustedSdkSignToolLaunchLease lease =
            Assert.IsAssignableFrom<ITrustedSdkSignToolLaunchLease>(leaseResult.Lease);
        var startInfo = new ProcessStartInfo
        {
            FileName = candidate.Path,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("exit 0");

        SdkSignToolProcessResult process = await new TrustedSdkSignToolProcessRunner().RunAsync(
            startInfo,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.True(leaseResult.IsAvailable);
        Assert.Equal(SdkSignToolProcessOutcome.Exited, process.Outcome);
        Assert.Equal(0, process.ExitCode);
        Assert.Empty(process.StandardOutput);
        Assert.Empty(process.StandardError);
    }

    [Fact]
    public void SessionReadinessEnablesFallbackOnlyAfterSuccessfulRefresh()
    {
        TrustedSdkSignToolCandidate candidate = Candidate(
            "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe");
        var locator = new FixedLocator(SdkSignToolDiscoveryResult.Available(candidate));
        var readiness = new SdkSignToolReadinessState(locator);

        Assert.False(readiness.Current.IsAvailable);

        SdkSignToolDiscoveryResult result = readiness.Refresh();

        Assert.True(result.IsAvailable);
        Assert.True(readiness.Current.IsAvailable);
        Assert.Equal(1, locator.DiscoveryCount);
    }

    private static SdkSignToolExecutableInspection ValidInspection() => new(
        PeMachine: 0x8664,
        WindowsTrustValid: true,
        WindowsTrustedSdkSignToolCandidateValidator.ExpectedPublisher,
        WindowsTrustedSdkSignToolCandidateValidator.ExpectedCompanyName,
        WindowsTrustedSdkSignToolCandidateValidator.ExpectedProductName,
        OriginalFileName: "SIGNTOOL.EXE",
        FileDescription: "Authenticode(R) - signing and verifying tool",
        ProductVersion: new Version(10, 0, 26100, 7463),
        Sha256: new string('A', 64));

    private static TrustedSdkSignToolLocator CreateExactHashLocator(SdkTree tree, string path)
    {
        string sha256;
        using (FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            sha256 = Convert.ToHexString(SHA256.HashData(stream));
        }

        return new TrustedSdkSignToolLocator(
            tree.FileSystem,
            new WindowsTrustedSdkSignToolCandidateValidator(
                new StubInspector(_ => ValidInspection() with { Sha256 = sha256 })));
    }

    private static TrustedSdkSignToolCandidate Candidate(string path) => new(
        Path.GetFullPath(path),
        new Version(10, 0, 26100, 0),
        new Version(10, 0, 26100, 7463),
        WindowsTrustedSdkSignToolCandidateValidator.ExpectedPublisher,
        WindowsTrustedSdkSignToolCandidateValidator.ExpectedCompanyName,
        WindowsTrustedSdkSignToolCandidateValidator.ExpectedProductName,
        new string('A', 64));

    private sealed class StubInspector(Func<string, SdkSignToolExecutableInspection> inspect)
        : ISdkSignToolExecutableInspector
    {
        public List<string> Paths { get; } = [];

        public SdkSignToolExecutableInspection Inspect(string path)
        {
            Paths.Add(path);
            return inspect(path);
        }
    }

    private sealed class FixedLocator(SdkSignToolDiscoveryResult result) : ITrustedSdkSignToolLocator
    {
        public int DiscoveryCount { get; private set; }

        public SdkSignToolDiscoveryResult Discover()
        {
            DiscoveryCount++;
            return result;
        }

        public SdkSignToolDiscoveryResult Revalidate(TrustedSdkSignToolCandidate candidate) => result;
    }

    private sealed class SdkTree : IDisposable
    {
        public SdkTree()
        {
            Root = Directory.CreateTempSubdirectory("codesigner-sdk-locator-").FullName;
            FileSystem = new TestFileSystem(Root);
        }

        public string Root { get; }

        public TestFileSystem FileSystem { get; }

        public string AddCandidate(string version)
        {
            string directory = Path.Combine(
                Root,
                "Windows Kits",
                "10",
                "bin",
                version,
                "x64");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "signtool.exe");
            File.WriteAllBytes(path, [0x4D, 0x5A, 0, 0]);
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

    private sealed class TestFileSystem(string root) : ITrustedSdkSignToolFileSystem
    {
        public HashSet<string> ReparsePaths { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string ProgramFilesX86 => root;

        public string GetFullPath(string path) => Path.GetFullPath(path);

        public bool DirectoryExists(string path) => Directory.Exists(path);

        public bool FileExists(string path) => File.Exists(path);

        public IEnumerable<string> EnumerateDirectories(string path) =>
            Directory.EnumerateDirectories(path, "*", SearchOption.TopDirectoryOnly);

        public FileAttributes GetAttributes(string path)
        {
            FileAttributes attributes = File.GetAttributes(path);
            return ReparsePaths.Contains(Path.GetFullPath(path))
                ? attributes | FileAttributes.ReparsePoint
                : attributes;
        }
    }
}
