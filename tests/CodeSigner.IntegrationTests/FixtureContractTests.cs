using System.Security.Cryptography;
using System.Text.Json;

namespace CodeSigner.IntegrationTests;

public sealed class FixtureContractTests
{
    private static readonly string[] ExpectedValidFixtureNames =
    [
        "valid-unsigned.cab",
        "valid-unsigned.dll",
        "valid-unsigned.exe",
        "valid-unsigned.msi",
        "valid-unsigned.ocx"
    ];

    [Fact]
    public void GeneratedFixtureManifestCoversPromisedAndAdversarialFormats()
    {
        string fixtureRoot = Path.Combine(FindRepositoryRoot(), "tests", "fixtures", "generated");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(fixtureRoot, "manifest.json")));
        JsonElement entries = document.RootElement.GetProperty("entries");
        Assert.Equal(12, entries.GetArrayLength());

        string[] validNames = entries.EnumerateArray()
            .Where(entry => entry.GetProperty("state").GetString() == "valid")
            .Select(entry => entry.GetProperty("fileName").GetString())
            .OfType<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(ExpectedValidFixtureNames, validNames);
        Assert.Equal(5, entries.EnumerateArray().Count(entry => entry.GetProperty("state").GetString() == "malformed"));
        Assert.Equal(2, entries.EnumerateArray().Count(entry => entry.GetProperty("state").GetString() == "extension-spoofed"));

        foreach (JsonElement entry in entries.EnumerateArray())
        {
            string fileName = entry.GetProperty("fileName").GetString() ?? throw new InvalidDataException("Fixture fileName is missing.");
            string path = Path.Combine(fixtureRoot, fileName);
            Assert.True(File.Exists(path), fileName);
            string actualHash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
            Assert.Equal(entry.GetProperty("sha256").GetString(), actualHash);
            Assert.Equal(Path.GetExtension(fileName), entry.GetProperty("extension").GetString());
        }
    }

    [Fact]
    public void ValidFixturesHaveTheirDeclaredContainerMagic()
    {
        string fixtureRoot = Path.Combine(FindRepositoryRoot(), "tests", "fixtures", "generated");
        AssertPortableExecutable(Path.Combine(fixtureRoot, "valid-unsigned.exe"));
        AssertPortableExecutable(Path.Combine(fixtureRoot, "valid-unsigned.dll"));
        AssertPortableExecutable(Path.Combine(fixtureRoot, "valid-unsigned.ocx"));
        Assert.Equal("d0cf11e0a1b11ae1", ReadPrefixHex(Path.Combine(fixtureRoot, "valid-unsigned.msi"), 8));
        Assert.Equal("4d534346", ReadPrefixHex(Path.Combine(fixtureRoot, "valid-unsigned.cab"), 4));
    }

    [Fact]
    public void SpoofedFixturesHaveContentThatDisagreesWithTheirExtension()
    {
        string fixtureRoot = Path.Combine(FindRepositoryRoot(), "tests", "fixtures", "generated");
        AssertPortableExecutable(Path.Combine(fixtureRoot, "pe-disguised-as-msi.msi"));
        Assert.Equal("d0cf11e0a1b11ae1", ReadPrefixHex(Path.Combine(fixtureRoot, "msi-disguised-as-exe.exe"), 8));
    }

    private static void AssertPortableExecutable(string path)
    {
        using FileStream stream = File.OpenRead(path);
        Span<byte> header = stackalloc byte[64];
        stream.ReadExactly(header);
        Assert.Equal("MZ", System.Text.Encoding.ASCII.GetString(header[..2]));
        int offset = BitConverter.ToInt32(header[60..64]);
        stream.Position = offset;
        Span<byte> signature = stackalloc byte[4];
        stream.ReadExactly(signature);
        Assert.Equal("50450000", Convert.ToHexStringLower(signature));
    }

    private static string ReadPrefixHex(string path, int count)
    {
        byte[] prefix = new byte[count];
        using FileStream stream = File.OpenRead(path);
        stream.ReadExactly(prefix);
        return Convert.ToHexStringLower(prefix);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "global.json")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root containing global.json was not found.");
    }
}
