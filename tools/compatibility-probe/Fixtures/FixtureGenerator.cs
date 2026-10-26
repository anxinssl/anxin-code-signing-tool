using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodeSigner.CompatibilityProbe.Fixtures;

public static class FixtureGenerator
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task<FixtureManifest> GenerateAsync(
        string outputDirectory,
        string unsignedExecutable,
        string unsignedLibrary,
        string unsignedInstaller,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        RequireFile(unsignedExecutable);
        RequireFile(unsignedLibrary);
        RequireFile(unsignedInstaller);

        string fullOutput = Path.GetFullPath(outputDirectory);
        if (Directory.Exists(fullOutput) || File.Exists(fullOutput))
        {
            throw new InvalidOperationException("Fixture output already exists.");
        }

        string parent = Path.GetDirectoryName(fullOutput)
            ?? throw new InvalidOperationException("Fixture output must have a parent directory.");
        Directory.CreateDirectory(parent);
        string outputName = Path.GetFileName(fullOutput);
        await using FileStream generationLock = new(
            fullOutput + ".lock",
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 1,
            FileOptions.DeleteOnClose);
        CleanupInterruptedStaging(parent, outputName);
        string staging = Path.Combine(parent, $".{outputName}.{Guid.NewGuid():N}.tmp");
        Directory.CreateDirectory(staging);
        try
        {
            Copy(unsignedExecutable, staging, "valid-unsigned.exe");
            Copy(unsignedLibrary, staging, "valid-unsigned.dll");
            Copy(unsignedLibrary, staging, "valid-unsigned.ocx");
            Copy(unsignedInstaller, staging, "valid-unsigned.msi");
            string payload = Path.Combine(staging, "cab-payload.txt");
            await File.WriteAllTextAsync(payload, "CodeSigner CAB fixture\n", new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
            File.SetLastWriteTimeUtc(payload, new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            await CreateCabinetAsync(payload, Path.Combine(staging, "valid-unsigned.cab"), cancellationToken).ConfigureAwait(false);

            await File.WriteAllBytesAsync(Path.Combine(staging, "malformed.exe"), "not-a-pe"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(staging, "truncated.dll"), [(byte)'M', (byte)'Z'], cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(staging, "malformed.msi"), "not-an-msi"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(staging, "malformed.cab"), "MSCF-truncated"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(staging, "malformed.ocx"), "not-an-ocx"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            Copy(unsignedExecutable, staging, "pe-disguised-as-msi.msi");
            Copy(unsignedInstaller, staging, "msi-disguised-as-exe.exe");

            FixtureManifest manifest = BuildManifest(staging);
            await using (FileStream manifestFile = File.Create(Path.Combine(staging, "manifest.json")))
            {
                await JsonSerializer.SerializeAsync(manifestFile, manifest, ManifestJsonOptions, cancellationToken).ConfigureAwait(false);
                await manifestFile.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            }

            File.Delete(payload);
            Directory.Move(staging, fullOutput);
            return manifest;
        }
        catch
        {
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }

            throw;
        }
    }

    private static FixtureManifest BuildManifest(string staging)
    {
        FixtureSpec[] specs =
        [
            new("valid-unsigned.exe", ".exe", "PortableExecutable", "valid"),
            new("valid-unsigned.dll", ".dll", "PortableExecutable", "valid"),
            new("valid-unsigned.msi", ".msi", "WindowsInstallerDatabase", "valid"),
            new("valid-unsigned.cab", ".cab", "Cabinet", "valid"),
            new("valid-unsigned.ocx", ".ocx", "PortableExecutable", "valid"),
            new("malformed.exe", ".exe", "Malformed", "malformed"),
            new("truncated.dll", ".dll", "Malformed", "malformed"),
            new("malformed.msi", ".msi", "Malformed", "malformed"),
            new("malformed.cab", ".cab", "Malformed", "malformed"),
            new("malformed.ocx", ".ocx", "Malformed", "malformed"),
            new("pe-disguised-as-msi.msi", ".msi", "PortableExecutable", "extension-spoofed"),
            new("msi-disguised-as-exe.exe", ".exe", "WindowsInstallerDatabase", "extension-spoofed")
        ];
        FixtureEntry[] entries = specs.Select(spec => new FixtureEntry(
            spec.FileName,
            spec.Extension,
            spec.ActualKind,
            spec.State,
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(staging, spec.FileName)))),
            "NotSigned")).ToArray();
        return new FixtureManifest(
            SchemaVersion: 1,
            GeneratedBy: "CodeSigner.CompatibilityProbe generate-fixtures",
            ValidationScope: "Structure and unsigned build provenance only; SIP subject validation is intentionally deferred to Todos 5 and 6.",
            Entries: entries);
    }

    private static async Task CreateCabinetAsync(string payload, string destination, CancellationToken cancellationToken)
    {
        string makeCab = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "makecab.exe");
        RequireFile(makeCab);
        ProcessStartInfo startInfo = new()
        {
            FileName = makeCab,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("/D");
        startInfo.ArgumentList.Add("CompressionType=MSZIP");
        startInfo.ArgumentList.Add(payload);
        startInfo.ArgumentList.Add(destination);
        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("makecab.exe did not start.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (process.ExitCode != 0 || !File.Exists(destination))
        {
            throw new InvalidOperationException($"makecab.exe failed with exit code {process.ExitCode}.");
        }
    }

    private static void Copy(string source, string destinationDirectory, string fileName) =>
        File.Copy(source, Path.Combine(destinationDirectory, fileName), overwrite: false);

    private static void CleanupInterruptedStaging(string parent, string outputName)
    {
        string prefix = $".{outputName}.";
        foreach (string candidate in Directory.EnumerateDirectories(parent, $".{outputName}.*.tmp", SearchOption.TopDirectoryOnly))
        {
            string name = Path.GetFileName(candidate);
            if (name.StartsWith(prefix, StringComparison.Ordinal)
                && name.EndsWith(".tmp", StringComparison.Ordinal)
                && Guid.TryParseExact(name[prefix.Length..^4], "N", out _))
            {
                Directory.Delete(candidate, recursive: true);
            }
        }
    }

    private static void RequireFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Required fixture input was not found.", Path.GetFileName(path));
        }
    }

    private sealed record FixtureSpec(string FileName, string Extension, string ActualKind, string State);
}

public sealed record FixtureManifest(
    int SchemaVersion,
    string GeneratedBy,
    string ValidationScope,
    IReadOnlyList<FixtureEntry> Entries);

public sealed record FixtureEntry(
    string FileName,
    string Extension,
    string ActualKind,
    string State,
    string Sha256,
    string SignatureExpectation);
