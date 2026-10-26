using System.Formats.Asn1;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace CodeSigner.IntegrationTests;

internal static class ExistingSignatureFixtureFactory
{
    private const string Sha256BlockMapMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

    internal static string CreateCatalog(string root, string relativePath)
    {
        string path = PreparePath(root, relativePath);
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
        Asn1Tag explicitContent = new(TagClass.ContextSpecific, 0, isConstructed: true);
        writer.PushSequence(explicitContent);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.3.6.1.4.1.311.10.1");
        writer.PushSequence(explicitContent);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.3.6.1.4.1.311.12.1.1");
        writer.PopSequence();
        writer.PopSequence(explicitContent);
        writer.PopSequence();
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(explicitContent);
        writer.PopSequence();
        File.WriteAllBytes(path, writer.Encode());
        return path;
    }

    internal static string CreateAppPackage(string root, string relativePath)
    {
        string path = PreparePath(root, relativePath);
        byte[] payload = "package-payload"u8.ToArray();
        XNamespace manifestNamespace = "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
        XDocument manifest = new(new XElement(
            manifestNamespace + "Package",
            new XElement(
                manifestNamespace + "Identity",
                new XAttribute("Name", "CodeSigner.Test"),
                new XAttribute("Publisher", "CN=Publisher"))));
        XNamespace blockMapNamespace = "http://schemas.microsoft.com/appx/2010/blockmap";
        XDocument blockMap = new(new XElement(
            blockMapNamespace + "BlockMap",
            new XAttribute("HashMethod", Sha256BlockMapMethod),
            new XElement(
                blockMapNamespace + "File",
                new XAttribute("Name", "payload.bin"),
                new XElement(
                    blockMapNamespace + "Block",
                    new XAttribute("Hash", Convert.ToBase64String(SHA256.HashData(payload)))))));
        XNamespace contentTypesNamespace = "http://schemas.openxmlformats.org/package/2006/content-types";
        XDocument contentTypes = new(new XElement(contentTypesNamespace + "Types"));

        using FileStream file = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        using ZipArchive archive = new(file, ZipArchiveMode.Create, leaveOpen: false);
        WriteEntry(archive, "AppxManifest.xml", Encoding.UTF8.GetBytes(manifest.ToString(SaveOptions.DisableFormatting)));
        WriteEntry(archive, "AppxBlockMap.xml", Encoding.UTF8.GetBytes(blockMap.ToString(SaveOptions.DisableFormatting)));
        WriteEntry(archive, "[Content_Types].xml", Encoding.UTF8.GetBytes(contentTypes.ToString(SaveOptions.DisableFormatting)));
        WriteEntry(archive, "payload.bin", payload);
        return path;
    }

    internal static string CreatePowerShellScript(string root, string relativePath)
    {
        string path = PreparePath(root, relativePath);
        File.WriteAllText(path, "Write-Output 'existing signature test'\r\n", new UTF8Encoding(false, true));
        return path;
    }

    internal static string CreateWindowsScript(string root, string relativePath)
    {
        string path = PreparePath(root, relativePath);
        File.WriteAllText(path, "WScript.Echo \"existing signature test\"\r\n", new UTF8Encoding(false, true));
        return path;
    }

    private static string PreparePath(string root, string relativePath)
    {
        string path = Path.Combine(root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return path;
    }

    private static void WriteEntry(ZipArchive archive, string name, byte[] content)
    {
        ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        using Stream destination = entry.Open();
        destination.Write(content);
    }
}
