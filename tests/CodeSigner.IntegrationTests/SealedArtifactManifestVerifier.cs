using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.IntegrationTests;

internal sealed record ManifestVerificationResult(
    int ArtifactCount,
    int TotalTrxTests,
    int FailedTrxCount);

internal readonly record struct ManifestFileIdentity(uint VolumeSerialNumber, ulong FileIndex);

internal interface IManifestArtifactHandle : IDisposable
{
    string FinalPath { get; }

    ManifestFileIdentity Identity { get; }

    long Length { get; }

    Stream Content { get; }

    string ComputeSha256();
}

internal interface IManifestFileSystem
{
    FileAttributes GetAttributes(string path);

    IManifestArtifactHandle OpenRead(string path);
}

internal sealed class WindowsManifestFileSystem : IManifestFileSystem
{
    internal static WindowsManifestFileSystem Instance { get; } = new();

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);

    public IManifestArtifactHandle OpenRead(string path) => new WindowsManifestArtifactHandle(path);
}

internal sealed class WindowsManifestArtifactHandle : IManifestArtifactHandle
{
    private readonly FileStream stream;

    internal WindowsManifestArtifactHandle(string path)
    {
        stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        try
        {
            SafeFileHandle handle = stream.SafeFileHandle;
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Could not read Windows file identity: {path}");
            }

            ulong fileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
            Identity = new ManifestFileIdentity(information.VolumeSerialNumber, fileIndex);
            FinalPath = ReadFinalPath(handle, path);
            Length = stream.Length;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public string FinalPath { get; }

    public ManifestFileIdentity Identity { get; }

    public long Length { get; }

    public Stream Content => stream;

    public string ComputeSha256()
    {
        stream.Position = 0;
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public void Dispose() => stream.Dispose();

    private static string ReadFinalPath(SafeFileHandle handle, string originalPath)
    {
        StringBuilder buffer = new(capacity: 512);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Could not read final Windows path: {originalPath}");
        }

        if (length >= buffer.Capacity)
        {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Could not read complete final Windows path: {originalPath}");
            }
        }

        string finalPath = buffer.ToString();
        if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + finalPath[8..];
        }

        return finalPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
            ? finalPath[4..]
            : finalPath;
    }

    [SuppressMessage("Interoperability", "SYSLIB1054", Justification = "The test project does not enable unsafe source-generated interop.")]
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [SuppressMessage("Interoperability", "SYSLIB1054", Justification = "The test project does not enable unsafe source-generated interop.")]
    [SuppressMessage("Performance", "CA1838", Justification = "The bounded test-only interop reads a variable-length Windows path.")]
    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFinalPathNameByHandleW",
        CharSet = CharSet.Unicode,
        SetLastError = true,
        ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }
}

internal static class SealedArtifactManifestVerifier
{
    private static readonly string[] CurrentTrxPaths =
    [
        "verification/blocker-fix/final-v5/trx/concurrency/exact-concurrency.trx",
        "verification/blocker-fix/final-v5/trx/targeted/targeted-windows.trx",
        "verification/blocker-fix/final-v5/trx/targeted/targeted-integration.trx",
        "verification/blocker-fix/final-v5/trx/native/native-windows.trx",
        "verification/blocker-fix/final-v5/trx/native/native-integration.trx",
        "verification/blocker-fix/final-v5/trx/full/full-app.trx",
        "verification/blocker-fix/final-v5/trx/full/full-core.trx",
        "verification/blocker-fix/final-v5/trx/full/full-windows.trx",
        "verification/blocker-fix/final-v5/trx/full/full-integration.trx"
    ];

    private static readonly string[] RequiredClosurePaths =
    [
        "run-store-retained-sha1-diagnostic-interactive.cmd",
        "SignerSignEx3-Store保留诊断流程.md",
        "PREPARED.json",
        "static-validation.json",
        "cleanup-receipt.json",
        "concurrency-smoke.json",
        "final-smoke-summary.json",
        "verification/blocker-fix/final-v5/release-build.log",
        "verification/blocker-fix/final-v5/format.log",
        "verification/blocker-fix/final-v5/tdd/object-binding-red.log",
        "verification/blocker-fix/final-v5/tdd/object-binding-red.trx",
        "verification/blocker-fix/final-v5/tdd/green/run-10/verifier-green-10.log",
        "verification/blocker-fix/final-v5/tdd/green/run-10/verifier-green-10.trx",
        "verification/blocker-fix/final-v5/reviewer-rereview-20260718-155300/reviewer-rereview.trx",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.CompatibilityProbe.deps.json",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.CompatibilityProbe.dll",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.CompatibilityProbe.exe",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.CompatibilityProbe.pdb",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.CompatibilityProbe.runtimeconfig.json",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.Core.dll",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.Core.pdb",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.Windows.dll",
        "tools/compatibility-probe/bin/Release/net10.0-windows/win-x64/CodeSigner.Windows.pdb",
        "src/CodeSigner.Windows/Signing/SigningCertificateLifetime.cs",
        "src/CodeSigner.Windows/Signing/CompatibilityGateRunner.cs",
        "src/CodeSigner.Windows/Signing/NativeSigningModels.cs",
        "tools/compatibility-probe/Signing/StoreRetainedSha1DiagnosticCommand.cs",
        "tests/CodeSigner.Windows.Tests/StoreRetainedCertificateLifetimeTests.cs",
        "tests/CodeSigner.Windows.Tests/CompatibilityGateRunnerTests.cs",
        "tests/CodeSigner.IntegrationTests/StoreRetainedSha1DiagnosticCommandTests.cs",
        "tests/CodeSigner.IntegrationTests/StoreRetainedSha1DiagnosticLauncherTests.cs",
        "tests/CodeSigner.IntegrationTests/SealedArtifactManifestVerifier.cs",
        "tests/CodeSigner.IntegrationTests/SealedArtifactManifestVerifierTests.cs"
    ];

    internal static ManifestVerificationResult Verify(
        string workspaceRoot,
        string evidenceRoot,
        string manifestPath,
        string sidecarPath,
        IReadOnlyList<string>? currentTrxPaths = null,
        IManifestFileSystem? manifestFileSystem = null)
    {
        IManifestFileSystem fileSystem = manifestFileSystem ?? WindowsManifestFileSystem.Instance;
        string workspace = Path.GetFullPath(workspaceRoot);
        string evidence = Path.GetFullPath(evidenceRoot);
        using JsonDocument manifestDocument = JsonDocument.Parse(File.ReadAllText(manifestPath));
        JsonElement manifest = manifestDocument.RootElement;
        string manifestStatus = manifest.GetProperty("status").GetString()
            ?? throw new InvalidDataException("Manifest status is null.");
        RequireEqual("SEALED", manifestStatus, "Manifest status");
        JsonElement.ArrayEnumerator artifactEnumerator = manifest.GetProperty("artifacts").EnumerateArray();
        JsonElement[] artifacts = artifactEnumerator.ToArray();
        RequireEqual(artifacts.Length, manifest.GetProperty("artifactCount").GetInt32(), "Manifest artifactCount");

        string manifestHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(manifestPath)));
        string[] sidecarParts = File.ReadAllText(sidecarPath).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (sidecarParts.Length != 2 ||
            !string.Equals(sidecarParts[0], manifestHash, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(sidecarParts[1], "*artifact-manifest.json", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Manifest sidecar hash does not match artifact-manifest.json.");
        }

        Dictionary<string, IManifestArtifactHandle> boundArtifacts = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> manifestPaths = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<ManifestFileIdentity, string> fileIdentities = [];
        List<IManifestArtifactHandle> openHandles = [];
        try
        {
            foreach (JsonElement artifact in artifacts)
            {
                string path = artifact.GetProperty("path").GetString()
                    ?? throw new InvalidDataException("Manifest artifact path is null.");
                if (!manifestPaths.Add(path))
                {
                    throw new InvalidDataException($"Manifest contains duplicate artifact path: {path}");
                }

                ValidateRelativeManifestPath(path);
                string resolved = ResolveArtifact(workspace, evidence, path, fileSystem);
                IManifestArtifactHandle handle = fileSystem.OpenRead(resolved);
                openHandles.Add(handle);
                ValidateBoundFinalPath(workspace, evidence, resolved, handle.FinalPath, path);
                ManifestFileIdentity identity = handle.Identity;
                if (!fileIdentities.TryAdd(identity, path))
                {
                    throw new InvalidDataException(
                        $"Manifest contains duplicate Windows file identity paths: {fileIdentities[identity]} and {path}");
                }

                RequireEqual(handle.Length, artifact.GetProperty("bytes").GetInt64(), $"Artifact byte count for {path}");
                string expectedHash = artifact.GetProperty("sha256").GetString()
                    ?? throw new InvalidDataException($"Manifest SHA-256 is null for {path}.");
                string actualHash = handle.ComputeSha256();
                if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"Artifact SHA-256 mismatch for {path}.");
                }

                boundArtifacts.Add(path, handle);
            }

            IReadOnlyList<string> trxPaths = currentTrxPaths ?? CurrentTrxPaths;
            foreach (string path in RequiredClosurePaths.Concat(trxPaths))
            {
                if (!boundArtifacts.ContainsKey(path))
                {
                    throw new InvalidDataException($"Required closure artifact is missing: {path}");
                }
            }

            using JsonDocument preparedDocument = JsonDocument.Parse(Rewind(boundArtifacts["PREPARED.json"]));
            JsonElement prepared = preparedDocument.RootElement;
            string preparedStatus = prepared.GetProperty("status").GetString()
                ?? throw new InvalidDataException("PREPARED status is null.");
            string closureStatus = prepared.GetProperty("closureStatus").GetString()
                ?? throw new InvalidDataException("PREPARED closureStatus is null.");
            string manifestName = prepared.GetProperty("artifactManifest").GetString()
                ?? throw new InvalidDataException("PREPARED manifest name is null.");
            string sidecarName = prepared.GetProperty("artifactManifestSidecar").GetString()
                ?? throw new InvalidDataException("PREPARED sidecar name is null.");
            RequireEqual("PREPARED", preparedStatus, "PREPARED status");
            RequireEqual("SEALED", closureStatus, "PREPARED closureStatus");
            RequireEqual("artifact-manifest.json", manifestName, "PREPARED manifest name");
            RequireEqual("artifact-manifest.sha256", sidecarName, "PREPARED sidecar name");

            int total = 0;
            int failed = 0;
            Dictionary<string, int> groupTotals = new(StringComparer.OrdinalIgnoreCase);
            foreach (string path in trxPaths)
            {
                TrxCounters counters = ReadTrxCounters(Rewind(boundArtifacts[path]));
                if (counters.Total <= 0 || counters.Executed != counters.Total || counters.Passed != counters.Total || counters.Failed != 0)
                {
                    throw new InvalidDataException($"Current TRX is not nonzero and fully passing: {path}");
                }

                total += counters.Total;
                failed += counters.Failed;
                string group = TrxGroup(path);
                groupTotals[group] = groupTotals.GetValueOrDefault(group) + counters.Passed;
            }

            if (currentTrxPaths is null)
            {
                JsonElement verification = prepared.GetProperty("verification");
                RequireEqual(groupTotals["full"], verification.GetProperty("fullSuitePassed").GetInt32(), "Full-suite TRX count");
                RequireEqual(groupTotals["native"], verification.GetProperty("nativeSigningPassed").GetInt32(), "NativeSigning TRX count");
                RequireEqual(groupTotals["targeted"], verification.GetProperty("targetedFreshPassed").GetInt32(), "Targeted TRX count");
                RequireEqual(groupTotals["concurrency"], verification.GetProperty("exactConcurrencyPassed").GetInt32(), "Concurrency TRX count");
            }

            return new ManifestVerificationResult(artifacts.Length, total, failed);
        }
        finally
        {
            for (int index = openHandles.Count - 1; index >= 0; index--)
            {
                openHandles[index].Dispose();
            }
        }
    }

    private static string ResolveArtifact(
        string workspaceRoot,
        string evidenceRoot,
        string relativePath,
        IManifestFileSystem fileSystem)
    {
        if (Path.IsPathRooted(relativePath))
        {
            throw new InvalidDataException($"Manifest path must be relative: {relativePath}");
        }

        string evidenceCandidate = Path.GetFullPath(Path.Combine(evidenceRoot, relativePath));
        string workspaceCandidate = Path.GetFullPath(Path.Combine(workspaceRoot, relativePath));
        bool inEvidence = ExistsUnderApprovedRoot(evidenceRoot, evidenceCandidate, fileSystem);
        bool inWorkspace = ExistsUnderApprovedRoot(workspaceRoot, workspaceCandidate, fileSystem);
        if (inEvidence == inWorkspace)
        {
            throw new InvalidDataException(inEvidence
                ? $"Manifest path resolves ambiguously: {relativePath}"
                : $"Manifest artifact is missing: {relativePath}");
        }

        return inEvidence ? evidenceCandidate : workspaceCandidate;
    }

    private static void ValidateBoundFinalPath(
        string workspaceRoot,
        string evidenceRoot,
        string requestedPath,
        string finalPath,
        string relativePath)
    {
        if (!Path.IsPathRooted(finalPath))
        {
            throw new InvalidDataException($"Bound artifact final path is outside approved root: {relativePath}");
        }

        string normalizedFinalPath = Path.GetFullPath(finalPath);
        if (!IsWithin(workspaceRoot, normalizedFinalPath) && !IsWithin(evidenceRoot, normalizedFinalPath))
        {
            throw new InvalidDataException($"Bound artifact final path is outside approved root: {relativePath}");
        }

        if (!string.Equals(Path.GetFullPath(requestedPath), normalizedFinalPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Bound artifact final path indicates reparse redirection: {relativePath}");
        }
    }

    private static bool IsWithin(string root, string candidate)
    {
        string relative = Path.GetRelativePath(root, candidate);
        return !relative.Equals("..", StringComparison.Ordinal) &&
             !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static void ValidateRelativeManifestPath(string path)
    {
        string normalized = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        string[] segments = normalized.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is "." or ".."))
        {
            throw new InvalidDataException($"Manifest path contains a traversal segment: {path}");
        }
    }

    private static bool ExistsUnderApprovedRoot(
        string approvedRoot,
        string candidate,
        IManifestFileSystem fileSystem)
    {
        if (!IsWithin(approvedRoot, candidate))
        {
            return false;
        }

        try
        {
            EnsureNoReparseComponents(candidate, fileSystem);
            return File.Exists(candidate);
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void EnsureNoReparseComponents(string path, IManifestFileSystem fileSystem)
    {
        string fullPath = Path.GetFullPath(path);
        string pathRoot = Path.GetPathRoot(fullPath)
            ?? throw new InvalidDataException($"Artifact path has no root: {path}");
        string current = pathRoot;
        string relative = Path.GetRelativePath(pathRoot, fullPath);
        string[] segments = relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if ((fileSystem.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Manifest artifact path contains a reparse point component: {current}");
        }

        foreach (string segment in segments)
        {
            current = Path.Combine(current, segment);
            if ((fileSystem.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"Manifest artifact path contains a reparse point component: {current}");
            }
        }
    }

    private static Stream Rewind(IManifestArtifactHandle handle)
    {
        Stream content = handle.Content;
        if (!content.CanSeek)
        {
            throw new InvalidDataException("Bound artifact content stream must be seekable.");
        }

        content.Position = 0;
        return content;
    }

    private static TrxCounters ReadTrxCounters(Stream content)
    {
        XDocument document = XDocument.Load(content);
        XElement counters = document.Descendants().First(element => element.Name.LocalName == "Counters");
        return new TrxCounters(
            ReadCounter(counters, "total"),
            ReadCounter(counters, "executed"),
            ReadCounter(counters, "passed"),
            ReadCounter(counters, "failed"));
    }

    private static int ReadCounter(XElement counters, string name) =>
        int.Parse(counters.Attribute(name)?.Value ?? "0", CultureInfo.InvariantCulture);

    private static string TrxGroup(string path)
    {
        string[] parts = path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        int trxIndex = Array.IndexOf(parts, "trx");
        return trxIndex >= 0 && trxIndex + 1 < parts.Length
            ? parts[trxIndex + 1]
            : throw new InvalidDataException($"Current TRX path has no group: {path}");
    }

    private static void RequireEqual<T>(T actual, T expected, string label)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(actual, expected))
        {
            throw new InvalidDataException($"{label} mismatch. Actual={actual}; Expected={expected}.");
        }
    }

    private sealed record TrxCounters(int Total, int Executed, int Passed, int Failed);
}
