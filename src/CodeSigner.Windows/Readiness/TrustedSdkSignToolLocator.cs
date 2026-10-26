using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Readiness;

public sealed class TrustedSdkSignToolLocator :
    ITrustedSdkSignToolLocator,
    ITrustedSdkSignToolLaunchLeaseProvider
{
    private const string WindowsKitsDirectoryName = "Windows Kits";
    private const string KitMajorVersionDirectoryName = "10";
    private const string BinDirectoryName = "bin";
    private const string ArchitectureDirectoryName = "x64";
    private const string ExecutableFileName = "signtool.exe";

    private readonly ITrustedSdkSignToolFileSystem fileSystem;
    private readonly ITrustedSdkSignToolCandidateValidator validator;

    public TrustedSdkSignToolLocator()
        : this(new WindowsTrustedSdkSignToolFileSystem(), new WindowsTrustedSdkSignToolCandidateValidator())
    {
    }

    internal TrustedSdkSignToolLocator(
        ITrustedSdkSignToolFileSystem fileSystem,
        ITrustedSdkSignToolCandidateValidator validator)
    {
        this.fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        this.validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    public SdkSignToolDiscoveryResult Discover()
    {
        try
        {
            string binRoot = GetBinRoot();
            if (!fileSystem.DirectoryExists(binRoot))
            {
                return SdkSignToolDiscoveryResult.Unavailable();
            }

            var accepted = new List<TrustedSdkSignToolCandidate>();
            var rejected = new List<RejectedCandidate>();
            foreach (string versionDirectory in fileSystem.EnumerateDirectories(binRoot))
            {
                string versionName = Path.GetFileName(Path.TrimEndingDirectorySeparator(versionDirectory));
                string candidatePath = Path.Combine(
                    versionDirectory,
                    ArchitectureDirectoryName,
                    ExecutableFileName);
                if (!fileSystem.FileExists(candidatePath))
                {
                    continue;
                }

                if (!TryParseSdkVersion(versionName, out Version? sdkVersion) || sdkVersion is null)
                {
                    rejected.Add(new RejectedCandidate(
                        Version: null,
                        candidatePath,
                        SdkSignToolRejectionReason.MalformedSdkVersion));
                    continue;
                }

                SdkSignToolDiscoveryResult result = ValidateCanonicalCandidate(candidatePath, sdkVersion);
                if (result.IsAvailable)
                {
                    accepted.Add(result.Candidate!);
                }
                else
                {
                    rejected.Add(new RejectedCandidate(sdkVersion, candidatePath, result.RejectionReason));
                }
            }

            TrustedSdkSignToolCandidate? selected = accepted
                .OrderByDescending(static candidate => candidate.SdkVersion)
                .ThenByDescending(static candidate => candidate.ProductVersion)
                .ThenBy(static candidate => candidate.Path, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
            if (selected is not null)
            {
                return SdkSignToolDiscoveryResult.Available(selected);
            }

            RejectedCandidate? rejection = rejected
                .OrderByDescending(static candidate => candidate.Version)
                .ThenBy(static candidate => candidate.Path, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
            return rejection is null
                ? SdkSignToolDiscoveryResult.Unavailable()
                : SdkSignToolDiscoveryResult.Rejected(rejection.Reason, rejection.Path);
        }
        catch (Exception exception) when (IsDiscoveryFailure(exception))
        {
            return SdkSignToolDiscoveryResult.Rejected(SdkSignToolRejectionReason.ProbeFailed);
        }
    }

    public SdkSignToolDiscoveryResult Revalidate(TrustedSdkSignToolCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        try
        {
            if (!TryResolveCanonicalCandidate(candidate.Path, out Version? sdkVersion) || sdkVersion is null)
            {
                return SdkSignToolDiscoveryResult.Rejected(
                    SdkSignToolRejectionReason.OutsideCanonicalHierarchy,
                    candidate.Path);
            }

            if (sdkVersion != candidate.SdkVersion)
            {
                return SdkSignToolDiscoveryResult.Rejected(
                    SdkSignToolRejectionReason.CandidateChanged,
                    candidate.Path);
            }

            SdkSignToolDiscoveryResult current = ValidateCanonicalCandidate(candidate.Path, sdkVersion);
            if (!current.IsAvailable)
            {
                return current;
            }

            TrustedSdkSignToolCandidate refreshed = current.Candidate!;
            return !CandidateMatches(candidate, refreshed)
                ? SdkSignToolDiscoveryResult.Rejected(
                    SdkSignToolRejectionReason.CandidateChanged,
                    candidate.Path)
                : current;
        }
        catch (Exception exception) when (IsDiscoveryFailure(exception))
        {
            return SdkSignToolDiscoveryResult.Rejected(
                SdkSignToolRejectionReason.ProbeFailed,
                candidate.Path);
        }
    }

    SdkSignToolLaunchLeaseResult ITrustedSdkSignToolLaunchLeaseProvider.AcquireLaunchLease(
        TrustedSdkSignToolCandidate candidate) => AcquireLaunchLease(candidate);

    internal SdkSignToolLaunchLeaseResult AcquireLaunchLease(
        TrustedSdkSignToolCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        FileStream? lockedStream = null;
        try
        {
            if (!TryResolveCanonicalCandidate(candidate.Path, out Version? sdkVersion) ||
                sdkVersion is null ||
                sdkVersion != candidate.SdkVersion)
            {
                return SdkSignToolLaunchLeaseResult.CandidateChanged(candidate.Path);
            }

            lockedStream = new FileStream(
                candidate.Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            StableFileIdentity lockedIdentity = WindowsFileIdentity.FromHandle(lockedStream.SafeFileHandle);
            string lockedSha256 = Convert.ToHexString(SHA256.HashData(lockedStream));

            if (!TryResolveCanonicalCandidate(candidate.Path, out Version? lockedSdkVersion) ||
                lockedSdkVersion != candidate.SdkVersion ||
                HasReparsePoint(candidate.Path))
            {
                return SdkSignToolLaunchLeaseResult.CandidateChanged(candidate.Path);
            }

            SdkSignToolDiscoveryResult current = ValidateCanonicalCandidate(
                candidate.Path,
                candidate.SdkVersion);
            if (!current.IsAvailable ||
                !CandidateMatches(candidate, current.Candidate!) ||
                !lockedSha256.Equals(current.Candidate!.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return SdkSignToolLaunchLeaseResult.CandidateChanged(candidate.Path);
            }

            using FileStream currentPath = new(
                candidate.Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 1,
                FileOptions.None);
            if (WindowsFileIdentity.FromHandle(currentPath.SafeFileHandle) != lockedIdentity)
            {
                return SdkSignToolLaunchLeaseResult.CandidateChanged(candidate.Path);
            }

            var lease = new LockedSdkSignToolLaunchLease(
                lockedStream,
                current.Candidate!,
                lockedIdentity,
                lockedSha256);
            lockedStream = null;
            return SdkSignToolLaunchLeaseResult.Available(lease);
        }
        catch (Exception exception) when (IsDiscoveryFailure(exception))
        {
            return SdkSignToolLaunchLeaseResult.CandidateChanged(candidate.Path);
        }
        finally
        {
            lockedStream?.Dispose();
        }
    }

    private SdkSignToolDiscoveryResult ValidateCanonicalCandidate(string candidatePath, Version sdkVersion)
    {
        if (!TryResolveCanonicalCandidate(candidatePath, out Version? canonicalVersion) ||
            canonicalVersion != sdkVersion)
        {
            return SdkSignToolDiscoveryResult.Rejected(
                SdkSignToolRejectionReason.OutsideCanonicalHierarchy,
                candidatePath);
        }

        if (HasReparsePoint(candidatePath))
        {
            return SdkSignToolDiscoveryResult.Rejected(
                SdkSignToolRejectionReason.ReparsePoint,
                candidatePath);
        }

        TrustedSdkSignToolCandidateValidation validation = validator.Validate(candidatePath, sdkVersion);
        return validation.Candidate is null
            ? SdkSignToolDiscoveryResult.Rejected(validation.RejectionReason, candidatePath)
            : SdkSignToolDiscoveryResult.Available(validation.Candidate);
    }

    private bool TryResolveCanonicalCandidate(string candidatePath, out Version? sdkVersion)
    {
        sdkVersion = null;
        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            return false;
        }

        string canonicalCandidate = fileSystem.GetFullPath(candidatePath);
        string binRoot = GetBinRoot();
        string relative = Path.GetRelativePath(binRoot, canonicalCandidate);
        string[] components = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        if (components.Length != 3 ||
            !components[1].Equals(ArchitectureDirectoryName, StringComparison.OrdinalIgnoreCase) ||
            !components[2].Equals(ExecutableFileName, StringComparison.OrdinalIgnoreCase) ||
            !TryParseSdkVersion(components[0], out sdkVersion))
        {
            return false;
        }

        string expected = fileSystem.GetFullPath(Path.Combine(
            binRoot,
            components[0],
            ArchitectureDirectoryName,
            ExecutableFileName));
        return canonicalCandidate.Equals(expected, StringComparison.OrdinalIgnoreCase) &&
            fileSystem.FileExists(canonicalCandidate);
    }

    private bool HasReparsePoint(string candidatePath)
    {
        string programFilesX86 = fileSystem.GetFullPath(fileSystem.ProgramFilesX86);
        string windowsKits = Path.Combine(programFilesX86, WindowsKitsDirectoryName);
        string kitRoot = Path.Combine(windowsKits, KitMajorVersionDirectoryName);
        string binRoot = Path.Combine(kitRoot, BinDirectoryName);
        string versionRoot = Path.GetDirectoryName(Path.GetDirectoryName(candidatePath)!)!;
        string architectureRoot = Path.GetDirectoryName(candidatePath)!;
        string[] paths = [windowsKits, kitRoot, binRoot, versionRoot, architectureRoot, candidatePath];
        return paths.Any(path =>
            (fileSystem.DirectoryExists(path) || fileSystem.FileExists(path)) &&
            (fileSystem.GetAttributes(path) & FileAttributes.ReparsePoint) != 0);
    }

    private string GetBinRoot()
    {
        string root = fileSystem.GetFullPath(fileSystem.ProgramFilesX86);
        return fileSystem.GetFullPath(Path.Combine(
            root,
            WindowsKitsDirectoryName,
            KitMajorVersionDirectoryName,
            BinDirectoryName));
    }

    private static bool CandidateMatches(
        TrustedSdkSignToolCandidate expected,
        TrustedSdkSignToolCandidate current) =>
        current.Path.Equals(expected.Path, StringComparison.OrdinalIgnoreCase) &&
        current.SdkVersion == expected.SdkVersion &&
        current.ProductVersion == expected.ProductVersion &&
        current.Publisher.Equals(expected.Publisher, StringComparison.Ordinal) &&
        current.CompanyName.Equals(expected.CompanyName, StringComparison.Ordinal) &&
        current.ProductName.Equals(expected.ProductName, StringComparison.Ordinal) &&
        current.Sha256.Equals(expected.Sha256, StringComparison.OrdinalIgnoreCase);

    private static bool TryParseSdkVersion(string value, out Version? version)
    {
        version = null;
        string[] components = value.Split('.', StringSplitOptions.None);
        if (components.Length != 4)
        {
            return false;
        }

        var numbers = new int[components.Length];
        for (int index = 0; index < components.Length; index++)
        {
            string component = components[index];
            if (component.Length == 0 ||
                component.Any(static character => character is < '0' or > '9') ||
                !int.TryParse(component, NumberStyles.None, CultureInfo.InvariantCulture, out numbers[index]))
            {
                return false;
            }
        }

        version = new Version(numbers[0], numbers[1], numbers[2], numbers[3]);
        return true;
    }

    private static bool IsDiscoveryFailure(Exception exception) => exception is
        ArgumentException or
        CryptographicException or
        InvalidOperationException or
        IOException or
        NotSupportedException or
        UnauthorizedAccessException or
        Win32Exception or
        System.Security.SecurityException;

    private sealed record RejectedCandidate(
        Version? Version,
        string Path,
        SdkSignToolRejectionReason Reason);
}

internal interface ITrustedSdkSignToolLaunchLeaseProvider
{
    SdkSignToolLaunchLeaseResult AcquireLaunchLease(TrustedSdkSignToolCandidate candidate);
}

internal interface ITrustedSdkSignToolLaunchLease : IDisposable
{
    TrustedSdkSignToolCandidate Candidate { get; }

    StableFileIdentity Identity { get; }

    string Sha256 { get; }
}

internal sealed record SdkSignToolLaunchLeaseResult(
    SdkSignToolDiscoveryResult Revalidation,
    ITrustedSdkSignToolLaunchLease? Lease)
{
    public bool IsAvailable => Revalidation.IsAvailable && Lease is not null;

    public static SdkSignToolLaunchLeaseResult Available(ITrustedSdkSignToolLaunchLease lease) =>
        new(
            SdkSignToolDiscoveryResult.Available(
                (lease ?? throw new ArgumentNullException(nameof(lease))).Candidate),
            lease);

    public static SdkSignToolLaunchLeaseResult CandidateChanged(string path) =>
        new(
            SdkSignToolDiscoveryResult.Rejected(
                SdkSignToolRejectionReason.CandidateChanged,
                path),
            Lease: null);
}

internal sealed class LockedSdkSignToolLaunchLease(
    FileStream stream,
    TrustedSdkSignToolCandidate candidate,
    StableFileIdentity identity,
    string sha256) : ITrustedSdkSignToolLaunchLease
{
    private readonly FileStream stream = stream ?? throw new ArgumentNullException(nameof(stream));

    public TrustedSdkSignToolCandidate Candidate { get; } =
        candidate ?? throw new ArgumentNullException(nameof(candidate));

    public StableFileIdentity Identity { get; } =
        identity ?? throw new ArgumentNullException(nameof(identity));

    public string Sha256 { get; } =
        !string.IsNullOrWhiteSpace(sha256)
            ? sha256
            : throw new ArgumentException("A launch lease requires a SHA-256 value.", nameof(sha256));

    public void Dispose() => stream.Dispose();
}

internal interface ITrustedSdkSignToolFileSystem
{
    string ProgramFilesX86 { get; }

    string GetFullPath(string path);

    bool DirectoryExists(string path);

    bool FileExists(string path);

    IEnumerable<string> EnumerateDirectories(string path);

    FileAttributes GetAttributes(string path);
}

internal sealed class WindowsTrustedSdkSignToolFileSystem : ITrustedSdkSignToolFileSystem
{
    public string ProgramFilesX86 => Environment.GetEnvironmentVariable("ProgramFiles(x86)")
        ?? throw new InvalidOperationException("The ProgramFiles(x86) environment value is unavailable.");

    public string GetFullPath(string path) => Path.GetFullPath(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public bool FileExists(string path) => File.Exists(path);

    public IEnumerable<string> EnumerateDirectories(string path) =>
        Directory.EnumerateDirectories(path, "*", SearchOption.TopDirectoryOnly);

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
}

internal sealed record TrustedSdkSignToolCandidateValidation(
    TrustedSdkSignToolCandidate? Candidate,
    SdkSignToolRejectionReason RejectionReason)
{
    public static TrustedSdkSignToolCandidateValidation Accepted(TrustedSdkSignToolCandidate candidate) =>
        new(candidate, SdkSignToolRejectionReason.None);

    public static TrustedSdkSignToolCandidateValidation Rejected(SdkSignToolRejectionReason reason) =>
        new(Candidate: null, reason);
}

internal interface ITrustedSdkSignToolCandidateValidator
{
    TrustedSdkSignToolCandidateValidation Validate(string path, Version sdkVersion);
}

internal sealed class WindowsTrustedSdkSignToolCandidateValidator : ITrustedSdkSignToolCandidateValidator
{
    internal const string ExpectedPublisher = "Microsoft Corporation";
    internal const string ExpectedCompanyName = "Microsoft Corporation";
    internal const string ExpectedProductName = "Microsoft® Windows® Operating System";
    private const string ExpectedOriginalFileName = "SIGNTOOL.EXE";
    private const ushort Amd64Machine = 0x8664;
    private static readonly string[] ExpectedDescriptions =
    [
        "File Signing Tool",
        "Authenticode(R) - signing and verifying tool"
    ];

    private readonly ISdkSignToolExecutableInspector inspector;

    public WindowsTrustedSdkSignToolCandidateValidator()
        : this(new WindowsSdkSignToolExecutableInspector())
    {
    }

    internal WindowsTrustedSdkSignToolCandidateValidator(ISdkSignToolExecutableInspector inspector) =>
        this.inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));

    public TrustedSdkSignToolCandidateValidation Validate(string path, Version sdkVersion)
    {
        SdkSignToolExecutableInspection inspection;
        try
        {
            inspection = inspector.Inspect(path);
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            UnauthorizedAccessException or
            System.Security.SecurityException or
            CryptographicException)
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(SdkSignToolRejectionReason.ProbeFailed);
        }

        if (inspection.PeMachine != Amd64Machine)
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.NotX64PortableExecutable);
        }

        if (!inspection.WindowsTrustValid)
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.WindowsTrustFailed);
        }

        if (!string.Equals(inspection.Publisher, ExpectedPublisher, StringComparison.Ordinal))
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.PublisherMismatch);
        }

        if (!string.Equals(inspection.CompanyName, ExpectedCompanyName, StringComparison.Ordinal))
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.CompanyMismatch);
        }

        if (!string.Equals(inspection.ProductName, ExpectedProductName, StringComparison.Ordinal))
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.ProductMismatch);
        }

        if (!string.Equals(
                inspection.OriginalFileName,
                ExpectedOriginalFileName,
                StringComparison.OrdinalIgnoreCase) ||
            !ExpectedDescriptions.Contains(inspection.FileDescription, StringComparer.Ordinal))
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.IdentityMismatch);
        }

        if (inspection.ProductVersion is null)
        {
            return TrustedSdkSignToolCandidateValidation.Rejected(
                SdkSignToolRejectionReason.InvalidVersionMetadata);
        }

        return TrustedSdkSignToolCandidateValidation.Accepted(new TrustedSdkSignToolCandidate(
            Path.GetFullPath(path),
            sdkVersion,
            inspection.ProductVersion,
            inspection.Publisher!,
            inspection.CompanyName!,
            inspection.ProductName!,
            inspection.Sha256));
    }
}

internal sealed record SdkSignToolExecutableInspection(
    ushort PeMachine,
    bool WindowsTrustValid,
    string? Publisher,
    string? CompanyName,
    string? ProductName,
    string? OriginalFileName,
    string? FileDescription,
    Version? ProductVersion,
    string Sha256);

internal interface ISdkSignToolExecutableInspector
{
    SdkSignToolExecutableInspection Inspect(string path);
}

internal sealed class WindowsSdkSignToolExecutableInspector : ISdkSignToolExecutableInspector
{
    public SdkSignToolExecutableInspection Inspect(string path)
    {
        string canonicalPath = Path.GetFullPath(path);
        ushort peMachine = ReadPeMachine(canonicalPath);
        bool trustValid = WindowsExecutableTrustVerifier.IsTrusted(canonicalPath);
        FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(canonicalPath);
        Version? productVersion = Version.TryParse(versionInfo.ProductVersion, out Version? parsed)
            ? parsed
            : null;
        string? publisher = trustValid ? ReadPublisher(canonicalPath) : null;
        string hash;
        using (FileStream stream = new(
                   canonicalPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read | FileShare.Delete))
        {
            hash = Convert.ToHexString(SHA256.HashData(stream));
        }

        return new SdkSignToolExecutableInspection(
            peMachine,
            trustValid,
            publisher,
            versionInfo.CompanyName,
            versionInfo.ProductName,
            versionInfo.OriginalFilename,
            versionInfo.FileDescription,
            productVersion,
            hash);
    }

    private static ushort ReadPeMachine(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length < 64)
        {
            return 0;
        }

        Span<byte> dosHeader = stackalloc byte[64];
        stream.ReadExactly(dosHeader);
        if (dosHeader[0] != (byte)'M' || dosHeader[1] != (byte)'Z')
        {
            return 0;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[60..64]);
        if (peOffset < 64 || peOffset > stream.Length - 6)
        {
            return 0;
        }

        stream.Position = peOffset;
        Span<byte> peHeader = stackalloc byte[6];
        stream.ReadExactly(peHeader);
        return peHeader[..4].SequenceEqual("PE\0\0"u8)
            ? BinaryPrimitives.ReadUInt16LittleEndian(peHeader[4..6])
            : (ushort)0;
    }

    private static string ReadPublisher(string path)
    {
#pragma warning disable SYSLIB0057
        using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
        using X509Certificate2 certificate2 = new(certificate);
#pragma warning restore SYSLIB0057
        return certificate2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
    }
}

internal static class WindowsExecutableTrustVerifier
{
    private const uint WtdUiNone = 2;
    private const uint WtdChoiceFile = 1;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static bool IsTrusted(string path)
    {
        IntPtr pathPointer = Marshal.StringToCoTaskMemUni(path);
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            WinTrustFileInfo fileInfo = new()
            {
                StructureSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = pathPointer
            };
            fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            WinTrustData trustData = new()
            {
                StructureSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = WtdUiNone,
                UnionChoice = WtdChoiceFile,
                FileInfo = fileInfoPointer,
                ProviderFlags = WtdCacheOnlyUrlRetrieval
            };
            Guid action = GenericVerifyV2;
            return NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref trustData) == 0;
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(fileInfoPointer);
            }

            Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    private static class NativeMethods
    {
        [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
        internal static extern int WinVerifyTrust(
            IntPtr windowHandle,
            ref Guid actionId,
            ref WinTrustData trustData);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        internal uint StructureSize;
        internal IntPtr FilePath;
        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        internal uint StructureSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr FileInfo;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
    }
}
