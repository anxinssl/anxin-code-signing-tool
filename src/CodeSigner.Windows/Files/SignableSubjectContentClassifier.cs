using System.Buffers.Binary;
using System.Formats.Asn1;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using CodeSigner.Core.Signing;

namespace CodeSigner.Windows.Files;

internal sealed record ClassifiedSignableContent(
    SigningSubject PolicySubject,
    ScriptContentProfile? ScriptProfile);

internal static class SignableSubjectContentClassifier
{
    private const int HeaderProbeLimit = 1024 * 1024;
    private const int StructuredContentLimit = 32 * 1024 * 1024;
    private const int ScriptContentLimit = 4 * 1024 * 1024;
    private const int PackageXmlLimit = 4 * 1024 * 1024;
    private const int PackageEntryLimit = 4096;
    private const string SignedDataOid = "1.2.840.113549.1.7.2";
    private const string CatalogContentTypeOid = "1.3.6.1.4.1.311.10.1";
    private const string Sha256BlockMapMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
    private const string BlockMapNamespace = "http://schemas.microsoft.com/appx/2010/blockmap";
    private const string ContentTypesNamespace = "http://schemas.openxmlformats.org/package/2006/content-types";
    private static readonly byte[] CompoundFileSignature = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
    private static readonly byte[] CatalogListOidEncoding = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x01];
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly UnicodeEncoding StrictUtf16LittleEndian = new(false, false, true);
    private static readonly UnicodeEncoding StrictUtf16BigEndian = new(true, false, true);

    public static ClassifiedSignableContent Classify(string path)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        byte[] prefix = ReadPrefix(path, HeaderProbeLimit);
        PolicyResult<SigningSubject> extensionResult = SigningSubject.TryCreateForExtension(extension);
        PolicyResult<SigningSubject> contentResult = SigningSubject.TryClassify(extension, prefix);

        if (contentResult.IsSuccess && contentResult.Value!.FormatFamily == SigningFormatFamily.PeImage)
        {
            if (extensionResult.IsSuccess && extensionResult.Value!.FormatFamily != SigningFormatFamily.PeImage)
            {
                throw Failure(
                    SignableSubjectProbeError.ContentTypeMismatch,
                    "The approved extension does not match the PE image content.");
            }

            return new ClassifiedSignableContent(contentResult.Value, null);
        }

        if (!extensionResult.IsSuccess)
        {
            throw Failure(
                SignableSubjectProbeError.UnsupportedExtension,
                "The file is neither an approved extension nor a structurally valid PE image.");
        }

        SigningSubject policySubject = extensionResult.Value!;
        if (policySubject.FormatFamily == SigningFormatFamily.PeImage)
        {
            SignableSubjectProbeError error = LooksLikeKnownNonPeContent(prefix)
                ? SignableSubjectProbeError.ContentTypeMismatch
                : SignableSubjectProbeError.MalformedContent;
            throw Failure(error, "The file does not contain a valid PE image header and certificate-table directory.");
        }

        ScriptContentProfile? scriptProfile = policySubject.FormatFamily switch
        {
            SigningFormatFamily.WindowsInstaller => ValidateCompoundFile(path, prefix),
            SigningFormatFamily.Cabinet => ValidateCabinet(path, prefix),
            SigningFormatFamily.Catalog => ValidateCatalog(path),
            SigningFormatFamily.AppPackage => ValidateAppPackage(path, extension),
            SigningFormatFamily.PowerShellScript or SigningFormatFamily.WindowsScript =>
                ValidateScript(path, extension),
            _ => throw Failure(
                SignableSubjectProbeError.UnsupportedExtension,
                "The classified signing family is unsupported by intake.")
        };

        return new ClassifiedSignableContent(policySubject, scriptProfile);
    }

    private static ScriptContentProfile? ValidateCompoundFile(string path, ReadOnlySpan<byte> prefix)
    {
        if (prefix.Length < 512 || !prefix[..CompoundFileSignature.Length].SequenceEqual(CompoundFileSignature))
        {
            throw Failure(SignableSubjectProbeError.InvalidCompoundFile, "The installer is not a complete compound file.");
        }

        ushort majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(prefix[26..28]);
        ushort byteOrder = BinaryPrimitives.ReadUInt16LittleEndian(prefix[28..30]);
        ushort sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(prefix[30..32]);
        ushort miniSectorShift = BinaryPrimitives.ReadUInt16LittleEndian(prefix[32..34]);
        uint fatSectorCount = BinaryPrimitives.ReadUInt32LittleEndian(prefix[44..48]);
        uint firstDirectorySector = BinaryPrimitives.ReadUInt32LittleEndian(prefix[48..52]);
        bool validHeader = byteOrder == 0xfffe &&
            miniSectorShift == 6 &&
            ((majorVersion == 3 && sectorShift == 9) || (majorVersion == 4 && sectorShift == 12)) &&
            prefix[34..40].IndexOfAnyExcept((byte)0) < 0 &&
            fatSectorCount > 0 &&
            firstDirectorySector < 0xfffffffa;
        if (!validHeader || StgIsStorageFile(path) != 0)
        {
            throw Failure(
                SignableSubjectProbeError.InvalidCompoundFile,
                "The installer does not expose a valid compound-storage identity.");
        }

        return null;
    }

    private static ScriptContentProfile? ValidateCabinet(string path, ReadOnlySpan<byte> prefix)
    {
        long fileLength = new FileInfo(path).Length;
        if (prefix.Length < 36 || !prefix[..4].SequenceEqual("MSCF"u8))
        {
            throw Failure(SignableSubjectProbeError.InvalidCabinet, "The cabinet does not contain a complete CFHEADER.");
        }

        uint cabinetSize = BinaryPrimitives.ReadUInt32LittleEndian(prefix[8..12]);
        uint filesOffset = BinaryPrimitives.ReadUInt32LittleEndian(prefix[16..20]);
        ushort folderCount = BinaryPrimitives.ReadUInt16LittleEndian(prefix[26..28]);
        long folderTableEnd = checked(36L + (8L * folderCount));
        bool valid = cabinetSize >= 36 &&
            cabinetSize <= fileLength &&
            filesOffset >= 36 &&
            filesOffset < cabinetSize &&
            folderTableEnd <= filesOffset &&
            folderTableEnd <= cabinetSize &&
            folderTableEnd <= fileLength &&
            prefix[24] == 3 &&
            prefix[25] == 1 &&
            folderCount > 0;
        if (!valid)
        {
            throw Failure(SignableSubjectProbeError.InvalidCabinet, "The cabinet CFHEADER fields are inconsistent.");
        }

        return null;
    }

    private static ScriptContentProfile? ValidateCatalog(string path)
    {
        byte[] content = ReadBoundedFile(path, StructuredContentLimit);
        try
        {
            AsnReader reader = new(content, AsnEncodingRules.BER);
            AsnReader contentInfo = reader.ReadSequence();
            if (!string.Equals(contentInfo.ReadObjectIdentifier(), SignedDataOid, StringComparison.Ordinal))
            {
                throw Failure(SignableSubjectProbeError.InvalidCatalog, "The catalog is not a CMS SignedData container.");
            }

            Asn1Tag explicitContentTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
            AsnReader explicitContent = contentInfo.ReadSequence(explicitContentTag);
            AsnReader signedData = explicitContent.ReadSequence();
            _ = signedData.ReadInteger();
            _ = signedData.ReadSetOf();
            AsnReader encapsulatedContent = signedData.ReadSequence();
            if (!string.Equals(encapsulatedContent.ReadObjectIdentifier(), CatalogContentTypeOid, StringComparison.Ordinal) ||
                content.AsSpan().IndexOf(CatalogListOidEncoding) < 0)
            {
                throw Failure(SignableSubjectProbeError.InvalidCatalog, "The CMS payload is not a Windows catalog list.");
            }
        }
        catch (AsnContentException exception)
        {
            throw Failure(SignableSubjectProbeError.InvalidCatalog, "The catalog CMS structure is malformed.", exception);
        }

        return null;
    }

    private static ScriptContentProfile? ValidateAppPackage(string path, string extension)
    {
        try
        {
            using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using ZipArchive archive = new(file, ZipArchiveMode.Read, leaveOpen: false);
            if (archive.Entries.Count == 0 || archive.Entries.Count > PackageEntryLimit)
            {
                throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The package entry count is invalid.");
            }

            Dictionary<string, ZipArchiveEntry> entries = new(StringComparer.OrdinalIgnoreCase);
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                string normalized = NormalizePackagePath(entry.FullName, allowBackslash: false);
                if (!entries.TryAdd(normalized, entry))
                {
                    throw Failure(SignableSubjectProbeError.UnsafePackagePath, "The package contains colliding entry paths.");
                }
            }

            bool isBundle = extension is ".appxbundle" or ".msixbundle";
            string manifestPath = isBundle ? "AppxMetadata/AppxBundleManifest.xml" : "AppxManifest.xml";
            ZipArchiveEntry manifestEntry = RequirePackageEntry(entries, manifestPath);
            ZipArchiveEntry blockMapEntry = RequirePackageEntry(entries, "AppxBlockMap.xml");
            ZipArchiveEntry contentTypesEntry = RequirePackageEntry(entries, "[Content_Types].xml");
            ValidatePackageManifest(ReadPackageXml(manifestEntry), isBundle);
            ValidatePackageBlockMap(ReadPackageXml(blockMapEntry), entries);
            ValidatePackageContentTypes(ReadPackageXml(contentTypesEntry));
        }
        catch (SignableSubjectProbeException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or XmlException)
        {
            throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The AppX/MSIX container is malformed.", exception);
        }

        return null;
    }

    private static void ValidatePackageManifest(XDocument manifest, bool isBundle)
    {
        string expectedRoot = isBundle ? "Bundle" : "Package";
        if (manifest.Root?.Name.LocalName != expectedRoot ||
            !manifest.Root.Name.NamespaceName.StartsWith("http://schemas.microsoft.com/appx/", StringComparison.Ordinal))
        {
            throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The package manifest root is invalid.");
        }

        XElement? identity = manifest.Root.Elements().FirstOrDefault(element => element.Name.LocalName == "Identity");
        string? name = identity?.Attribute("Name")?.Value;
        string? publisher = identity?.Attribute("Publisher")?.Value;
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(publisher))
        {
            throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The package identity or Publisher is missing.");
        }

        try
        {
            _ = new X500DistinguishedName(publisher);
        }
        catch (CryptographicException exception)
        {
            throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The package Publisher is not a valid distinguished name.", exception);
        }
    }

    private static void ValidatePackageBlockMap(
        XDocument blockMap,
        Dictionary<string, ZipArchiveEntry> entries)
    {
        if (blockMap.Root?.Name.LocalName != "BlockMap" ||
            !string.Equals(blockMap.Root.Name.NamespaceName, BlockMapNamespace, StringComparison.Ordinal) ||
            !string.Equals(
                blockMap.Root.Attribute("HashMethod")?.Value,
                Sha256BlockMapMethod,
                StringComparison.Ordinal))
        {
            throw Failure(
                SignableSubjectProbeError.IncompatibleBlockMapHash,
                "The package block map must declare SHA-256.");
        }

        int fileCount = 0;
        Span<byte> decodedHash = stackalloc byte[64];
        foreach (XElement file in blockMap.Root.Elements().Where(element => element.Name.LocalName == "File"))
        {
            fileCount++;
            string normalized = NormalizePackagePath(file.Attribute("Name")?.Value ?? string.Empty, allowBackslash: true);
            if (!entries.ContainsKey(normalized))
            {
                throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The block map references a missing package entry.");
            }

            XElement[] blocks = file.Elements().Where(element => element.Name.LocalName == "Block").ToArray();
            if (blocks.Length == 0)
            {
                throw Failure(SignableSubjectProbeError.IncompatibleBlockMapHash, "A block-map file has no hashes.");
            }

            foreach (XElement block in blocks)
            {
                string encodedHash = block.Attribute("Hash")?.Value ?? string.Empty;
                if (!Convert.TryFromBase64String(encodedHash, decodedHash, out int bytesWritten) || bytesWritten != 32)
                {
                    throw Failure(
                        SignableSubjectProbeError.IncompatibleBlockMapHash,
                        "A package block-map hash is not a SHA-256 value.");
                }
            }
        }

        if (fileCount == 0)
        {
            throw Failure(SignableSubjectProbeError.InvalidAppPackage, "The package block map is empty.");
        }
    }

    private static void ValidatePackageContentTypes(XDocument contentTypes)
    {
        if (contentTypes.Root?.Name.LocalName != "Types" ||
            !string.Equals(contentTypes.Root.Name.NamespaceName, ContentTypesNamespace, StringComparison.Ordinal))
        {
            throw Failure(
                SignableSubjectProbeError.InvalidAppPackage,
                "The package content-types part is malformed.");
        }
    }

    private static ScriptContentProfile ValidateScript(string path, string extension)
    {
        byte[] content = ReadBoundedFile(path, ScriptContentLimit);
        if (extension is ".jse" or ".vbe")
        {
            return ValidateEncodedScript(content);
        }

        (string text, ScriptEncodingKind encoding) = DecodeScript(content);
        SignatureMarkers markers = SignatureMarkers.ForExtension(extension);
        bool hasSignatureBlock = ValidateTerminalSignatureBlock(text, markers);
        if (extension is ".ps1xml" or ".cdxml" or ".xaml" or ".wsf")
        {
            ValidateScriptXml(text);
        }

        return new ScriptContentProfile(encoding, DetectNewlines(text), hasSignatureBlock, false);
    }

    private static ScriptContentProfile ValidateEncodedScript(ReadOnlySpan<byte> content)
    {
        if (content.IsEmpty || content.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
        {
            throw Failure(
                SignableSubjectProbeError.EncodedScriptUnsupported,
                "Encoded scripts must use the bounded ASCII Windows Script Encoder envelope.");
        }

        string text = Encoding.ASCII.GetString(content).Trim();
        if (!text.StartsWith("#@~^", StringComparison.Ordinal) ||
            !text.EndsWith("^#~@", StringComparison.Ordinal) ||
            text.Length <= 8)
        {
            throw Failure(
                SignableSubjectProbeError.EncodedScriptUnsupported,
                "The .jse/.vbe file does not contain a complete Windows Script Encoder envelope.");
        }

        return new ScriptContentProfile(
            ScriptEncodingKind.WindowsScriptEncoded,
            DetectNewlines(text),
            HasSignatureBlock: false,
            IsEncoded: true);
    }

    private static (string Text, ScriptEncodingKind Encoding) DecodeScript(ReadOnlySpan<byte> content)
    {
        Encoding decoder;
        ScriptEncodingKind encoding;
        ReadOnlySpan<byte> payload;
        if (content.Length >= 3 && content[0] == 0xef && content[1] == 0xbb && content[2] == 0xbf)
        {
            decoder = StrictUtf8;
            encoding = ScriptEncodingKind.Utf8WithBom;
            payload = content[3..];
        }
        else if (content.Length >= 2 && content[0] == 0xff && content[1] == 0xfe)
        {
            decoder = StrictUtf16LittleEndian;
            encoding = ScriptEncodingKind.Utf16LittleEndian;
            payload = content[2..];
        }
        else if (content.Length >= 2 && content[0] == 0xfe && content[1] == 0xff)
        {
            decoder = StrictUtf16BigEndian;
            encoding = ScriptEncodingKind.Utf16BigEndian;
            payload = content[2..];
        }
        else
        {
            decoder = StrictUtf8;
            encoding = ScriptEncodingKind.Utf8;
            payload = content;
        }

        try
        {
            string text = decoder.GetString(payload);
            if (text.Any(character => character == '\0' ||
                (char.IsControl(character) && character is not '\t' and not '\r' and not '\n')))
            {
                throw Failure(SignableSubjectProbeError.InvalidScriptEncoding, "The script contains binary control data.");
            }

            return (text, encoding);
        }
        catch (DecoderFallbackException exception)
        {
            throw Failure(SignableSubjectProbeError.InvalidScriptEncoding, "The script encoding is invalid or unsupported.", exception);
        }
    }

    private static bool ValidateTerminalSignatureBlock(string text, SignatureMarkers markers)
    {
        int begin = text.IndexOf(markers.Begin, StringComparison.Ordinal);
        int end = text.IndexOf(markers.End, StringComparison.Ordinal);
        if (begin < 0 && end < 0)
        {
            return false;
        }

        bool uniqueMarkers = begin >= 0 &&
            end > begin &&
            text.IndexOf(markers.Begin, begin + markers.Begin.Length, StringComparison.Ordinal) < 0 &&
            text.IndexOf(markers.End, end + markers.End.Length, StringComparison.Ordinal) < 0;
        bool beginsOnLine = begin == 0 || text[begin - 1] is '\r' or '\n';
        string payload = uniqueMarkers ? text[(begin + markers.Begin.Length)..end] : string.Empty;
        string trailing = uniqueMarkers ? text[(end + markers.End.Length)..] : string.Empty;
        if (!uniqueMarkers || !beginsOnLine || string.IsNullOrWhiteSpace(payload) || !string.IsNullOrWhiteSpace(trailing))
        {
            throw Failure(
                SignableSubjectProbeError.InvalidSignatureBlock,
                "An existing script signature block must be complete, unique, and terminal.");
        }

        return true;
    }

    private static void ValidateScriptXml(string text)
    {
        try
        {
            XmlReaderSettings settings = new()
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = ScriptContentLimit
            };
            using StringReader input = new(text);
            using XmlReader reader = XmlReader.Create(input, settings);
            _ = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        }
        catch (XmlException exception)
        {
            throw Failure(SignableSubjectProbeError.MalformedContent, "The XML script content is malformed.", exception);
        }
    }

    private static ScriptNewlineKind DetectNewlines(string text)
    {
        bool crLf = false;
        bool lf = false;
        bool cr = false;
        for (int index = 0; index < text.Length; index++)
        {
            if (text[index] == '\r')
            {
                if (index + 1 < text.Length && text[index + 1] == '\n')
                {
                    crLf = true;
                    index++;
                }
                else
                {
                    cr = true;
                }
            }
            else if (text[index] == '\n')
            {
                lf = true;
            }
        }

        int kinds = (crLf ? 1 : 0) + (lf ? 1 : 0) + (cr ? 1 : 0);
        return kinds switch
        {
            0 => ScriptNewlineKind.None,
            > 1 => ScriptNewlineKind.Mixed,
            _ when crLf => ScriptNewlineKind.CrLf,
            _ when lf => ScriptNewlineKind.Lf,
            _ => ScriptNewlineKind.Cr
        };
    }

    private static XDocument ReadPackageXml(ZipArchiveEntry entry)
    {
        if (entry.Length < 1 || entry.Length > PackageXmlLimit)
        {
            throw Failure(SignableSubjectProbeError.InvalidAppPackage, "A required package XML part exceeds its intake bound.");
        }

        XmlReaderSettings settings = new()
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = PackageXmlLimit
        };
        using Stream stream = entry.Open();
        using XmlReader reader = XmlReader.Create(stream, settings);
        return XDocument.Load(reader, LoadOptions.None);
    }

    private static ZipArchiveEntry RequirePackageEntry(
        Dictionary<string, ZipArchiveEntry> entries,
        string name) => entries.TryGetValue(name, out ZipArchiveEntry? entry)
            ? entry
            : throw Failure(SignableSubjectProbeError.InvalidAppPackage, $"The required package part '{name}' is missing.");

    private static string NormalizePackagePath(string path, bool allowBackslash)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0') ||
            (!allowBackslash && path.Contains('\\')))
        {
            throw Failure(SignableSubjectProbeError.UnsafePackagePath, "The package contains an unsafe entry path.");
        }

        string normalized = allowBackslash ? path.Replace('\\', '/') : path;
        normalized = normalized.EndsWith('/') ? normalized[..^1] : normalized;
        string[] segments = normalized.Split('/');
        if (normalized.Length == 0 || normalized.StartsWith('/') ||
            normalized.Contains(':') ||
            segments.Any(segment => segment.Length == 0 || segment is "." or ".."))
        {
            throw Failure(SignableSubjectProbeError.UnsafePackagePath, "The package contains an unsafe entry path.");
        }

        return normalized;
    }

    private static byte[] ReadPrefix(string path, int maximumBytes)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        int count = (int)Math.Min(stream.Length, maximumBytes);
        byte[] content = new byte[count];
        stream.ReadExactly(content);
        return content;
    }

    private static byte[] ReadBoundedFile(string path, int maximumBytes)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maximumBytes)
        {
            throw Failure(
                SignableSubjectProbeError.ContentLimitExceeded,
                "The file exceeds the bounded intake content limit.");
        }

        byte[] content = new byte[checked((int)stream.Length)];
        stream.ReadExactly(content);
        return content;
    }

    private static bool LooksLikeKnownNonPeContent(ReadOnlySpan<byte> content) =>
        content.StartsWith(CompoundFileSignature) ||
        content.StartsWith("MSCF"u8) ||
        content.StartsWith("PK\x03\x04"u8) ||
        (content.Length >= 2 && content[0] == 0x30 && content[1] == 0x82);

    private static SignableSubjectProbeException Failure(
        SignableSubjectProbeError error,
        string message,
        Exception? innerException = null) => new(error, message, innerException: innerException);

    private readonly record struct SignatureMarkers(string Begin, string End)
    {
        public static SignatureMarkers ForExtension(string extension) => extension switch
        {
            ".ps1xml" or ".cdxml" or ".xaml" or ".wsf" =>
                new("<!-- SIG # Begin signature block -->", "<!-- SIG # End signature block -->"),
            ".vbs" => new("'' SIG '' Begin signature block", "'' SIG '' End signature block"),
            ".js" => new("// SIG // Begin signature block", "// SIG // End signature block"),
            _ => new("# SIG # Begin signature block", "# SIG # End signature block")
        };
    }

    [DllImport("ole32.dll", CharSet = CharSet.Unicode)]
    private static extern int StgIsStorageFile(string fileName);
}
