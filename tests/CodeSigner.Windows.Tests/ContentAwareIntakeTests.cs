using System.Buffers.Binary;
using System.Formats.Asn1;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;

namespace CodeSigner.Windows.Tests;

public sealed class ContentAwareIntakeTests
{
    private const string Sha256BlockMapMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static readonly Guid PeSubjectGuid = Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee");
    private static readonly Guid InstallerSubjectGuid = Guid.Parse("000c10f1-0000-0000-c000-000000000046");
    private static readonly Guid CabinetSubjectGuid = Guid.Parse("c689aaba-8e78-11d0-8c47-00c04fc295ee");
    private static readonly Guid CatalogSubjectGuid = Guid.Parse("de351a43-8e59-11d0-8c47-00c04fc295ee");
    private static readonly Guid PowerShellSubjectGuid = Guid.Parse("603bcc1f-4b59-4e08-b724-d2c6297ef351");
    private static readonly Guid VbScriptSubjectGuid = Guid.Parse("1629f04e-2799-4db5-8fe5-ace10f17ebab");
    private static readonly Guid JScriptSubjectGuid = Guid.Parse("06c9e010-38ce-11d4-a2a3-00104bd35090");
    private static readonly Guid WsfSubjectGuid = Guid.Parse("1a610570-38ce-11d4-a2a3-00104bd35090");
    private static readonly Guid AppPackageSubjectGuid = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    public static TheoryData<string, SigningFormatFamily> ApprovedFormats => new()
    {
        { ".exe", SigningFormatFamily.PeImage },
        { ".dll", SigningFormatFamily.PeImage },
        { ".ocx", SigningFormatFamily.PeImage },
        { ".cpl", SigningFormatFamily.PeImage },
        { ".scr", SigningFormatFamily.PeImage },
        { ".sys", SigningFormatFamily.PeImage },
        { ".drv", SigningFormatFamily.PeImage },
        { ".ax", SigningFormatFamily.PeImage },
        { ".acm", SigningFormatFamily.PeImage },
        { ".efi", SigningFormatFamily.PeImage },
        { ".msi", SigningFormatFamily.WindowsInstaller },
        { ".msp", SigningFormatFamily.WindowsInstaller },
        { ".msm", SigningFormatFamily.WindowsInstaller },
        { ".cab", SigningFormatFamily.Cabinet },
        { ".cat", SigningFormatFamily.Catalog },
        { ".appx", SigningFormatFamily.AppPackage },
        { ".appxbundle", SigningFormatFamily.AppPackage },
        { ".msix", SigningFormatFamily.AppPackage },
        { ".msixbundle", SigningFormatFamily.AppPackage },
        { ".ps1", SigningFormatFamily.PowerShellScript },
        { ".psm1", SigningFormatFamily.PowerShellScript },
        { ".psd1", SigningFormatFamily.PowerShellScript },
        { ".ps1xml", SigningFormatFamily.PowerShellScript },
        { ".cdxml", SigningFormatFamily.PowerShellScript },
        { ".xaml", SigningFormatFamily.PowerShellScript },
        { ".vbs", SigningFormatFamily.WindowsScript },
        { ".js", SigningFormatFamily.WindowsScript },
        { ".jse", SigningFormatFamily.WindowsScript },
        { ".vbe", SigningFormatFamily.WindowsScript },
        { ".wsf", SigningFormatFamily.WindowsScript }
    };

    [Theory]
    [MemberData(nameof(ApprovedFormats))]
    public void ApprovedFormatIntakeClassifiesExactFamilyAndCapability(
        string extension,
        SigningFormatFamily expectedFamily)
    {
        using TestTree tree = new();
        string path = CreateApprovedFixture(tree, extension, expectedFamily);

        SignableSubject subject = CreateProbe().Probe(path);

        Assert.Equal(expectedFamily, subject.PolicySubject.FormatFamily);
        Assert.Equal(extension, subject.PolicySubject.Extension);
        Assert.Equal(
            expectedFamily == SigningFormatFamily.PeImage
                ? SigningCapability.PeImageDualCapable
                : SigningCapability.WindowsSipSingleOnly,
            subject.PolicySubject.Capability);
        Assert.Equal(SubjectGuidFor(extension), subject.SubjectGuid);
        Assert.Equal(
            expectedFamily is SigningFormatFamily.PowerShellScript or SigningFormatFamily.WindowsScript,
            subject.ScriptProfile is not null);
    }

    [Theory]
    [InlineData(".exe", SigningFormatFamily.PeImage)]
    [InlineData(".msi", SigningFormatFamily.WindowsInstaller)]
    [InlineData(".cab", SigningFormatFamily.Cabinet)]
    [InlineData(".ps1", SigningFormatFamily.PowerShellScript)]
    [InlineData(".vbs", SigningFormatFamily.WindowsScript)]
    [InlineData(".js", SigningFormatFamily.WindowsScript)]
    [InlineData(".wsf", SigningFormatFamily.WindowsScript)]
    public void NativeSipIntakeAcceptsValidatedFixtureFamilies(
        string extension,
        SigningFormatFamily expectedFamily)
    {
        using TestTree tree = new();
        string path = CreateApprovedFixture(tree, extension, expectedFamily);

        SignableSubject subject = new CryptSipSignableSubjectProbe().Probe(path);

        Assert.Equal(expectedFamily, subject.PolicySubject.FormatFamily);
        Assert.NotEqual(Guid.Empty, subject.SubjectGuid);
    }

    [Fact]
    public async Task UnlistedSuffixPeIntakePreservesOriginalIdentityAndRelativeOutputPath()
    {
        using TestTree tree = new();
        string inputRoot = tree.PathOf("source");
        string input = CopyFixture(tree, "source/nested/firmware.payload", "valid-unsigned.exe");
        string outputRoot = tree.PathOf("signed");

        IntakePlan plan = await new IntakePlanner(CreateProbe()).CreateAsync(
            [inputRoot],
            recurseDirectories: true,
            outputRoot,
            CancellationToken.None);

        IntakeFile file = Assert.Single(plan.Files);
        Assert.Equal(SigningFormatFamily.PeImage, file.Subject.PolicySubject.FormatFamily);
        Assert.Equal(SigningCapability.PeImageDualCapable, file.Subject.PolicySubject.Capability);
        Assert.Equal(".payload", file.Subject.PolicySubject.Extension);
        Assert.Equal(Path.GetFullPath(input), file.OriginalPath);
        Assert.Equal(Path.Combine("nested", "firmware.payload"), file.RelativePath);
        Assert.Equal(Path.Combine(outputRoot, "nested", "firmware.payload"), file.DestinationPath);
        Assert.NotEmpty(file.Identity.FileId);
        Assert.NotEqual(0UL, file.Identity.VolumeSerialNumber);
        Assert.False(Directory.Exists(outputRoot));
        Assert.Equal(File.ReadAllBytes(FixturePath("valid-unsigned.exe")), File.ReadAllBytes(input));
    }

    [Fact]
    public void RawCoffAndMzLikeNonImageIntakeAreRejectedWithoutSipLookup()
    {
        using TestTree tree = new();
        byte[] coff = new byte[20];
        BinaryPrimitives.WriteUInt16LittleEndian(coff, 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(coff.AsSpan(2), 1);
        string rawCoff = WriteBytes(tree, "raw.obj", coff);
        byte[] mzLike = new byte[128];
        "MZ"u8.CopyTo(mzLike);
        BinaryPrimitives.WriteInt32LittleEndian(mzLike.AsSpan(0x3c), 0x40);
        string mz = WriteBytes(tree, "mz-like.bin", mzLike);
        var sip = new StubSipSubjectGuidRetriever(_ => throw new InvalidOperationException("SIP must not run"));
        CryptSipSignableSubjectProbe probe = new(sip);

        SignableSubjectProbeException coffError = Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(rawCoff));
        SignableSubjectProbeException mzError = Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(mz));

        Assert.Equal(SignableSubjectProbeError.UnsupportedExtension, coffError.Error);
        Assert.Equal(SignableSubjectProbeError.UnsupportedExtension, mzError.Error);
        Assert.Equal(0, sip.CallCount);
    }

    [Theory]
    [InlineData("renamed-text.exe", "text")]
    [InlineData("renamed-zip.msix", "zip")]
    [InlineData("renamed-pe.msi", "pe")]
    [InlineData("renamed-cfb.exe", "cfb")]
    public void RenamedContentMismatchIntakeIsRejected(string fileName, string contentKind)
    {
        using TestTree tree = new();
        string path = contentKind switch
        {
            "text" => tree.Write(fileName, "plain text"),
            "zip" => CreateGenericZip(tree, fileName),
            "pe" => CopyFixture(tree, fileName, "valid-unsigned.exe"),
            "cfb" => CopyFixture(tree, fileName, "valid-unsigned.msi"),
            _ => throw new ArgumentOutOfRangeException(nameof(contentKind))
        };

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() => CreateProbe().Probe(path));

        Assert.Contains(
            error.Error,
            new[]
            {
                SignableSubjectProbeError.MalformedContent,
                SignableSubjectProbeError.InvalidAppPackage,
                SignableSubjectProbeError.ContentTypeMismatch
            });
    }

    [Theory]
    [InlineData("broken.exe", "pe", SignableSubjectProbeError.MalformedContent)]
    [InlineData("broken.msi", "installer", SignableSubjectProbeError.InvalidCompoundFile)]
    [InlineData("broken.cab", "cab", SignableSubjectProbeError.InvalidCabinet)]
    [InlineData("broken.cat", "cat", SignableSubjectProbeError.InvalidCatalog)]
    [InlineData("broken.appx", "package", SignableSubjectProbeError.InvalidAppPackage)]
    [InlineData("broken.ps1", "powershell", SignableSubjectProbeError.InvalidScriptEncoding)]
    [InlineData("broken.jse", "encoded", SignableSubjectProbeError.EncodedScriptUnsupported)]
    public void MalformedApprovedFamilyIntakeReturnsExactTypedProbeError(
        string fileName,
        string family,
        SignableSubjectProbeError expectedError)
    {
        using TestTree tree = new();
        string path = family switch
        {
            "pe" => tree.Write(fileName, "MZ-not-a-pe"),
            "installer" => WriteBytes(tree, fileName, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
            "cab" => tree.Write(fileName, "MSCF-truncated"),
            "cat" => WriteBytes(tree, fileName, CreateCatalogContainer("1.2.840.113549.1.7.1")),
            "package" => CreateGenericZip(tree, fileName),
            "powershell" => WriteBytes(tree, fileName, [0xc3, 0x28]),
            "encoded" => tree.Write(fileName, "plain text is not Windows Script Encoder data"),
            _ => throw new ArgumentOutOfRangeException(nameof(family))
        };

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() => CreateProbe().Probe(path));

        Assert.Equal(expectedError, error.Error);
    }

    [Fact]
    public async Task SipUnavailableIntakeIsTypedAndCreatesNoOutput()
    {
        using TestTree tree = new();
        string input = tree.Write("input.ps1", "Write-Output 'test'\r\n");
        string output = tree.PathOf("signed");
        CryptSipSignableSubjectProbe probe = new(
            new StubSipSubjectGuidRetriever(_ => new SipSubjectGuidLookup(false, Guid.Empty, 2)));

        SignableSubjectProbeException direct = Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(input));
        IntakeValidationException intake = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            new IntakePlanner(probe).CreateAsync([input], false, output, CancellationToken.None));

        Assert.Equal(SignableSubjectProbeError.SipUnavailable, direct.Error);
        Assert.Equal(2, direct.NativeErrorCode);
        Assert.Equal(IntakeError.SipUnavailable, intake.Error);
        Assert.IsType<SignableSubjectProbeException>(intake.InnerException);
        Assert.False(Directory.Exists(output));
        Assert.Equal("Write-Output 'test'\r\n", File.ReadAllText(input));
    }

    [Fact]
    public void SipSubjectMismatchIntakeIsRejectedAfterContentValidation()
    {
        using TestTree tree = new();
        string input = CopyFixture(tree, "app.exe", "valid-unsigned.exe");
        CryptSipSignableSubjectProbe probe = new(
            new StubSipSubjectGuidRetriever(_ => new SipSubjectGuidLookup(true, InstallerSubjectGuid, 0)));

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(input));

        Assert.Equal(SignableSubjectProbeError.SipSubjectMismatch, error.Error);
    }

    [Fact]
    public async Task InvalidCabinetAndMalformedAppxIntakeExposeExistingTypedBoundary()
    {
        using TestTree tree = new();
        string cabinet = tree.Write("invalid.cab", "MSCF-truncated");
        string appx = CreateGenericZip(tree, "invalid.appx");
        IntakePlanner planner = new(CreateProbe());

        IntakeValidationException cabinetError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            planner.CreateAsync([cabinet], false, tree.PathOf("cab-out"), CancellationToken.None));
        IntakeValidationException appxError = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            planner.CreateAsync([appx], false, tree.PathOf("appx-out"), CancellationToken.None));

        Assert.Equal(IntakeError.NotSignableSubject, cabinetError.Error);
        Assert.Equal(SignableSubjectProbeError.InvalidCabinet, Assert.IsType<SignableSubjectProbeException>(cabinetError.InnerException).Error);
        Assert.Equal(IntakeError.NotSignableSubject, appxError.Error);
        Assert.Equal(SignableSubjectProbeError.InvalidAppPackage, Assert.IsType<SignableSubjectProbeException>(appxError.InnerException).Error);
    }

    [Fact]
    public async Task UnsupportedTextExtensionIntakeIsTypedWithoutSipLookup()
    {
        using TestTree tree = new();
        string input = tree.Write("notes.txt", "plain text");
        var sip = new StubSipSubjectGuidRetriever(_ => throw new InvalidOperationException("SIP must not run"));

        IntakeValidationException error = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            new IntakePlanner(new CryptSipSignableSubjectProbe(sip)).CreateAsync(
                [input],
                false,
                tree.PathOf("signed"),
                CancellationToken.None));

        Assert.Equal(IntakeError.UnsupportedExtension, error.Error);
        Assert.Equal(0, sip.CallCount);
    }

    [Fact]
    public void AppPackageIntakeRejectsUnsafePathsMissingPublisherAndIncompatibleBlockMapHash()
    {
        using TestTree tree = new();
        string unsafePath = CreateAppPackage(tree, "unsafe.appx", "CN=Publisher", Sha256BlockMapMethod, "../escape.bin");
        string missingPublisher = CreateAppPackage(tree, "publisher.appx", null, Sha256BlockMapMethod, "payload.bin");
        string badHashMethod = CreateAppPackage(
            tree,
            "hash-method.appx",
            "CN=Publisher",
            "http://www.w3.org/2001/04/xmlenc#sha1",
            "payload.bin");
        string badHashValue = CreateAppPackage(
            tree,
            "hash-value.appx",
            "CN=Publisher",
            Sha256BlockMapMethod,
            "payload.bin",
            blockHash: Convert.ToBase64String(new byte[20]));
        CryptSipSignableSubjectProbe probe = CreateProbe();

        Assert.Equal(
            SignableSubjectProbeError.UnsafePackagePath,
            Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(unsafePath)).Error);
        Assert.Equal(
            SignableSubjectProbeError.InvalidAppPackage,
            Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(missingPublisher)).Error);
        Assert.Equal(
            SignableSubjectProbeError.IncompatibleBlockMapHash,
            Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(badHashMethod)).Error);
        Assert.Equal(
            SignableSubjectProbeError.IncompatibleBlockMapHash,
            Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(badHashValue)).Error);
    }

    [Fact]
    public void ScriptIntakeCapturesEncodingNewlinesAndTerminalSignatureBlockEligibility()
    {
        using TestTree tree = new();
        string utf16 = WriteEncodedText(
            tree,
            "module.psm1",
            "function Test-Signature {\r\n    return $true\r\n}\r\n",
            ScriptEncodingKind.Utf16LittleEndian);
        string signedXml = tree.Write(
            "types.ps1xml",
            "<Types />\n<!-- SIG # Begin signature block -->\n<!-- TUlJ -->\n<!-- SIG # End signature block -->\n");
        CryptSipSignableSubjectProbe probe = CreateProbe();

        ScriptContentProfile utf16Profile = Assert.IsType<ScriptContentProfile>(probe.Probe(utf16).ScriptProfile);
        ScriptContentProfile xmlProfile = Assert.IsType<ScriptContentProfile>(probe.Probe(signedXml).ScriptProfile);

        Assert.Equal(ScriptEncodingKind.Utf16LittleEndian, utf16Profile.Encoding);
        Assert.Equal(ScriptNewlineKind.CrLf, utf16Profile.Newlines);
        Assert.False(utf16Profile.HasSignatureBlock);
        Assert.Equal(ScriptEncodingKind.Utf8, xmlProfile.Encoding);
        Assert.Equal(ScriptNewlineKind.Lf, xmlProfile.Newlines);
        Assert.True(xmlProfile.HasSignatureBlock);
    }

    [Theory]
    [InlineData("incomplete.ps1", "Write-Output test\r\n# SIG # Begin signature block\r\n# TUlJ\r\n")]
    [InlineData("trailing.ps1xml", "<Types />\n<!-- SIG # Begin signature block -->\n<!-- TUlJ -->\n<!-- SIG # End signature block -->\n<Extra />")]
    public void IneligibleScriptSignatureBlockIntakeIsRejected(string fileName, string content)
    {
        using TestTree tree = new();
        string path = tree.Write(fileName, content);

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() => CreateProbe().Probe(path));

        Assert.Equal(SignableSubjectProbeError.InvalidSignatureBlock, error.Error);
    }

    [Theory]
    [InlineData("encoded.jse")]
    [InlineData("encoded.vbe")]
    public void EncodedScriptIntakeRequiresWindowsScriptEncoderEnvelope(string fileName)
    {
        using TestTree tree = new();
        string plain = tree.Write(fileName, "plain source");
        string encoded = tree.Write($"valid-{fileName}", "#@~^encoded-body^#~@");
        CryptSipSignableSubjectProbe probe = CreateProbe();

        SignableSubjectProbeException error = Assert.Throws<SignableSubjectProbeException>(() => probe.Probe(plain));
        SignableSubject valid = probe.Probe(encoded);

        Assert.Equal(SignableSubjectProbeError.EncodedScriptUnsupported, error.Error);
        Assert.True(Assert.IsType<ScriptContentProfile>(valid.ScriptProfile).IsEncoded);
    }

    [RequiresSymbolicLinksFact]
    public async Task CollisionAndReparsePointIntakeRemainTypedAndNeverCreateOutput()
    {
        using TestTree tree = new();
        string first = CopyFixture(tree, "first/same.exe", "valid-unsigned.exe");
        string second = CopyFixture(tree, "second/same.exe", "valid-unsigned.exe");
        string target = CopyFixture(tree, "target.exe", "valid-unsigned.exe");
        string link = tree.PathOf("link.exe");
        File.CreateSymbolicLink(link, target);
        string collisionOutput = tree.PathOf("collision-out");
        string linkOutput = tree.PathOf("link-out");
        IntakePlanner planner = new(CreateProbe());

        IntakeValidationException collision = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            planner.CreateAsync([first, second], false, collisionOutput, CancellationToken.None));
        IntakeValidationException reparse = await Assert.ThrowsAsync<IntakeValidationException>(() =>
            planner.CreateAsync([link], false, linkOutput, CancellationToken.None));

        Assert.Equal(IntakeError.DestinationCollision, collision.Error);
        Assert.Equal(IntakeError.ReparsePoint, reparse.Error);
        Assert.False(Directory.Exists(collisionOutput));
        Assert.False(Directory.Exists(linkOutput));
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
        Assert.True(File.Exists(target));
    }

    private static CryptSipSignableSubjectProbe CreateProbe() => new(
        new StubSipSubjectGuidRetriever(path => new SipSubjectGuidLookup(true, SubjectGuidFor(Path.GetExtension(path)), 0)));

    private static string CreateApprovedFixture(TestTree tree, string extension, SigningFormatFamily family) => family switch
    {
        SigningFormatFamily.PeImage => CopyFixture(tree, $"approved/sample{extension}", "valid-unsigned.exe"),
        SigningFormatFamily.WindowsInstaller => CopyFixture(tree, $"approved/sample{extension}", "valid-unsigned.msi"),
        SigningFormatFamily.Cabinet => CopyFixture(tree, $"approved/sample{extension}", "valid-unsigned.cab"),
        SigningFormatFamily.Catalog => WriteBytes(tree, $"approved/sample{extension}", CreateCatalogContainer("1.3.6.1.4.1.311.10.1")),
        SigningFormatFamily.AppPackage => CreateAppPackage(tree, $"approved/sample{extension}", "CN=Publisher", Sha256BlockMapMethod, "payload.bin"),
        SigningFormatFamily.PowerShellScript => CreatePowerShellScript(tree, extension),
        SigningFormatFamily.WindowsScript => CreateWindowsScript(tree, extension),
        _ => throw new ArgumentOutOfRangeException(nameof(family))
    };

    private static string CreatePowerShellScript(TestTree tree, string extension) => extension switch
    {
        ".ps1xml" => tree.Write($"approved/sample{extension}", "<Types />\r\n"),
        ".cdxml" => tree.Write($"approved/sample{extension}", "<PowerShellMetadata />\r\n"),
        ".xaml" => tree.Write($"approved/sample{extension}", "<ResourceDictionary />\r\n"),
        _ => tree.Write($"approved/sample{extension}", "Write-Output 'approved'\r\n")
    };

    private static string CreateWindowsScript(TestTree tree, string extension) => extension switch
    {
        ".jse" or ".vbe" => tree.Write($"approved/sample{extension}", "#@~^encoded-body^#~@"),
        ".wsf" => tree.Write($"approved/sample{extension}", "<job><script language=\"JScript\">test</script></job>\r\n"),
        ".vbs" => tree.Write($"approved/sample{extension}", "WScript.Echo \"approved\"\r\n"),
        _ => tree.Write($"approved/sample{extension}", "WScript.Echo('approved');\r\n")
    };

    private static string CreateAppPackage(
        TestTree tree,
        string relativePath,
        string? publisher,
        string hashMethod,
        string payloadName,
        string? blockHash = null)
    {
        string path = tree.PathOf(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        byte[] payload = "package-payload"u8.ToArray();
        string extension = Path.GetExtension(path).ToLowerInvariant();
        bool isBundle = extension is ".appxbundle" or ".msixbundle";
        XNamespace manifestNamespace = isBundle
            ? "http://schemas.microsoft.com/appx/2013/bundle"
            : "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
        XElement identity = new(manifestNamespace + "Identity", new XAttribute("Name", "CodeSigner.Test"));
        if (publisher is not null)
        {
            identity.Add(new XAttribute("Publisher", publisher));
        }

        XDocument manifest = new(new XElement(
            manifestNamespace + (isBundle ? "Bundle" : "Package"),
            identity));
        XNamespace blockMapNamespace = "http://schemas.microsoft.com/appx/2010/blockmap";
        XDocument blockMap = new(new XElement(
            blockMapNamespace + "BlockMap",
            new XAttribute("HashMethod", hashMethod),
            new XElement(
                blockMapNamespace + "File",
                new XAttribute("Name", payloadName),
                new XElement(
                    blockMapNamespace + "Block",
                    new XAttribute("Hash", blockHash ?? Convert.ToBase64String(SHA256.HashData(payload)))))));
        XNamespace contentTypesNamespace = "http://schemas.openxmlformats.org/package/2006/content-types";
        XDocument contentTypes = new(new XElement(contentTypesNamespace + "Types"));

        using (FileStream file = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        using (ZipArchive archive = new(file, ZipArchiveMode.Create, leaveOpen: false))
        {
            WriteZipEntry(
                archive,
                isBundle ? "AppxMetadata/AppxBundleManifest.xml" : "AppxManifest.xml",
                manifest.ToString(SaveOptions.DisableFormatting));
            WriteZipEntry(archive, "AppxBlockMap.xml", blockMap.ToString(SaveOptions.DisableFormatting));
            WriteZipEntry(archive, "[Content_Types].xml", contentTypes.ToString(SaveOptions.DisableFormatting));
            WriteZipEntry(archive, payloadName, payload);
        }

        return path;
    }

    private static string CreateGenericZip(TestTree tree, string relativePath)
    {
        string path = tree.PathOf(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using FileStream file = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        using ZipArchive archive = new(file, ZipArchiveMode.Create, leaveOpen: false);
        WriteZipEntry(archive, "payload.txt", "generic zip");
        return path;
    }

    private static void WriteZipEntry(ZipArchive archive, string name, string content) =>
        WriteZipEntry(archive, name, Encoding.UTF8.GetBytes(content));

    private static void WriteZipEntry(ZipArchive archive, string name, byte[] content)
    {
        ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        using Stream destination = entry.Open();
        destination.Write(content);
    }

    private static byte[] CreateCatalogContainer(string contentTypeOid)
    {
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
        writer.WriteObjectIdentifier(contentTypeOid);
        if (contentTypeOid == "1.3.6.1.4.1.311.10.1")
        {
            writer.PushSequence(explicitContent);
            writer.PushSequence();
            writer.WriteObjectIdentifier("1.3.6.1.4.1.311.12.1.1");
            writer.PopSequence();
            writer.PopSequence(explicitContent);
        }

        writer.PopSequence();
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(explicitContent);
        writer.PopSequence();
        return writer.Encode();
    }

    private static string WriteEncodedText(
        TestTree tree,
        string relativePath,
        string content,
        ScriptEncodingKind encoding)
    {
        Encoding textEncoding = encoding switch
        {
            ScriptEncodingKind.Utf16LittleEndian => new UnicodeEncoding(false, true, true),
            ScriptEncodingKind.Utf16BigEndian => new UnicodeEncoding(true, true, true),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding))
        };
        byte[] preamble = textEncoding.GetPreamble();
        byte[] body = textEncoding.GetBytes(content);
        byte[] bytes = new byte[preamble.Length + body.Length];
        preamble.CopyTo(bytes, 0);
        body.CopyTo(bytes, preamble.Length);
        return WriteBytes(tree, relativePath, bytes);
    }

    private static string CopyFixture(TestTree tree, string relativePath, string fixtureName) =>
        WriteBytes(tree, relativePath, File.ReadAllBytes(FixturePath(fixtureName)));

    private static string WriteBytes(TestTree tree, string relativePath, byte[] bytes)
    {
        string path = tree.PathOf(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static string FixturePath(string fileName)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        string repositoryRoot = directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
        return Path.Combine(repositoryRoot, "tests", "fixtures", "generated", fileName);
    }

    private static Guid SubjectGuidFor(string extension) => extension.ToLowerInvariant() switch
    {
        ".exe" or ".dll" or ".ocx" or ".cpl" or ".scr" or ".sys" or ".drv" or ".ax" or ".acm" or ".efi" or ".payload" => PeSubjectGuid,
        ".msi" or ".msp" or ".msm" => InstallerSubjectGuid,
        ".cab" => CabinetSubjectGuid,
        ".cat" => CatalogSubjectGuid,
        ".appx" or ".appxbundle" or ".msix" or ".msixbundle" => AppPackageSubjectGuid,
        ".ps1" or ".psm1" or ".psd1" or ".ps1xml" or ".cdxml" or ".xaml" => PowerShellSubjectGuid,
        ".vbs" or ".vbe" => VbScriptSubjectGuid,
        ".js" or ".jse" => JScriptSubjectGuid,
        ".wsf" => WsfSubjectGuid,
        _ => throw new ArgumentOutOfRangeException(nameof(extension), extension, "Unexpected test extension.")
    };

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
