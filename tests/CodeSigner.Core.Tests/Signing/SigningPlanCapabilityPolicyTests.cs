using System.Buffers.Binary;
using CodeSigner.Core.Signing;

namespace CodeSigner.Core.Tests.Signing;

public sealed class SigningPlanCapabilityPolicyTests
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";

    public static TheoryData<string> PeImageExtensions => new()
    {
        ".exe", ".dll", ".ocx", ".cpl", ".scr", ".sys", ".drv", ".ax", ".acm", ".efi"
    };

    public static TheoryData<string, SigningFormatFamily> WindowsSipExtensions => new()
    {
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
    [MemberData(nameof(PeImageExtensions))]
    public void SigningPlanKnownPeExtensionResolvesToDualCapableSubject(string extension)
    {
        SigningSubject subject = Success(SigningSubject.TryCreateForExtension(extension));

        Assert.Equal(SigningFormatFamily.PeImage, subject.FormatFamily);
        Assert.Equal(SigningCapability.PeImageDualCapable, subject.Capability);
        Assert.Equal(extension, subject.Extension);
    }

    [Theory]
    [MemberData(nameof(WindowsSipExtensions))]
    public void SigningPlanKnownSipExtensionResolvesToExactSingleOnlyFamily(
        string extension,
        SigningFormatFamily expectedFamily)
    {
        SigningSubject subject = Success(SigningSubject.TryCreateForExtension(extension));

        Assert.Equal(expectedFamily, subject.FormatFamily);
        Assert.Equal(SigningCapability.WindowsSipSingleOnly, subject.Capability);
        Assert.Equal(extension, subject.Extension);
    }

    [Fact]
    public void SigningPlanArbitrarySuffixRequiresAValidatedPeImage()
    {
        PolicyResult<SigningSubject> withoutContent = SigningSubject.TryCreateForExtension(".payload");
        PolicyResult<SigningSubject> validatedPe = SigningSubject.TryClassify(".payload", CreateMinimalPeImage());
        PolicyResult<SigningSubject> rawCoff = SigningSubject.TryClassify(".obj", CreateRawCoffObject());

        AssertFailure(withoutContent, PolicyErrorCode.UnsupportedFileType, "subject.extension");
        SigningSubject subject = Success(validatedPe);
        Assert.Equal(SigningFormatFamily.PeImage, subject.FormatFamily);
        Assert.Equal(SigningCapability.PeImageDualCapable, subject.Capability);
        AssertFailure(rawCoff, PolicyErrorCode.UnsupportedFileType, "subject.extension");
    }

    [Fact]
    public void SigningPlanSingleAlwaysHasExactlyOneSha256Leg()
    {
        SigningPlan pePlan = Success(SigningPlan.TryCreateSingle(Certificate(), ".dll"));
        SigningPlan sipPlan = Success(SigningPlan.TryCreateSingle(Certificate(), ".msi"));

        AssertSingleSha256(pePlan);
        AssertSingleSha256(sipPlan);
        Assert.Equal(SigningMode.Single, pePlan.RequestedMode);
        Assert.Equal(SigningMode.Single, pePlan.EffectiveMode);
        Assert.Equal(SigningMode.Single, sipPlan.RequestedMode);
        Assert.Equal(SigningMode.Single, sipPlan.EffectiveMode);
    }

    [Fact]
    public void SigningPlanDualUsesTwoOrderedLegsOnlyForPeImage()
    {
        SigningPlan pePlan = Success(SigningPlan.TryCreateDual(
            Certificate(),
            Certificate(SecondaryThumbprint),
            ".sys"));
        SigningPlan sipPlan = Success(SigningPlan.TryCreateDual(Certificate(), null, ".msi"));

        Assert.Equal(SigningMode.Dual, pePlan.RequestedMode);
        Assert.Equal(SigningMode.Dual, pePlan.EffectiveMode);
        Assert.Collection(
            pePlan.Legs,
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha1, leg.FileDigest);
                Assert.False(leg.Append);
            },
            leg =>
            {
                Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
                Assert.True(leg.Append);
            });

        Assert.Equal(SigningMode.Dual, sipPlan.RequestedMode);
        Assert.Equal(SigningMode.Single, sipPlan.EffectiveMode);
        AssertSingleSha256(sipPlan);
        Assert.DoesNotContain("sha1", SigningPlanJson.Serialize(sipPlan), StringComparison.Ordinal);
    }

    [Fact]
    public void SigningPlanJsonRejectsV1ForgedCapabilityAndUnknownSubjectField()
    {
        string valid = SigningPlanJson.Serialize(
            Success(SigningPlan.TryCreateDual(Certificate(), null, ".msi")));

        PolicyResult<SigningPlan> v1 = SigningPlanJson.Parse(
            valid.Replace("\"version\":2", "\"version\":1", StringComparison.Ordinal));
        PolicyResult<SigningPlan> forged = SigningPlanJson.Parse(
            valid.Replace(
                "\"capability\":\"windowsSipSingleOnly\"",
                "\"capability\":\"peImageDualCapable\"",
                StringComparison.Ordinal));
        PolicyResult<SigningPlan> unknown = SigningPlanJson.Parse(
            valid.Replace("\"formatFamily\":", "\"forged\":true,\"formatFamily\":", StringComparison.Ordinal));

        AssertFailure(v1, PolicyErrorCode.UnsupportedVersion, "$.version");
        AssertFailure(forged, PolicyErrorCode.UnsafePolicy, "$.subject.capability");
        AssertFailure(unknown, PolicyErrorCode.UnknownField, "$.subject.forged");
    }

    [Fact]
    public void SigningPlanJsonRejectsTwoLegSipAndSha1SinglePlans()
    {
        string sip = SigningPlanJson.Serialize(
            Success(SigningPlan.TryCreateDual(Certificate(), null, ".msi")));
        string single = SigningPlanJson.Serialize(
            Success(SigningPlan.TryCreateSingle(Certificate(), ".exe")));
        int legEnd = sip.IndexOf("],\"subject\"", StringComparison.Ordinal);
        Assert.True(legEnd > 0);
        int firstLegStart = sip.IndexOf("{\"certificate\"", StringComparison.Ordinal);
        Assert.True(firstLegStart > 0);
        string firstLeg = sip[firstLegStart..legEnd];
        string twoLegSip = sip.Insert(legEnd, "," + firstLeg);
        string sha1Single = single.Replace(
            "\"fileDigest\":\"sha256\"",
            "\"fileDigest\":\"sha1\"",
            StringComparison.Ordinal);

        AssertFailure(SigningPlanJson.Parse(twoLegSip), PolicyErrorCode.InvalidSignatureOrder, "$.legs");
        AssertFailure(SigningPlanJson.Parse(sha1Single), PolicyErrorCode.InvalidSignatureOrder, "$.legs");
    }

    private static void AssertSingleSha256(SigningPlan plan)
    {
        SignatureLeg leg = Assert.Single(plan.Legs);
        Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
        Assert.False(leg.Append);
    }

    private static byte[] CreateMinimalPeImage()
    {
        const int peOffset = 0x80;
        const int optionalHeaderSize = 0xf0;
        byte[] image = new byte[peOffset + 24 + optionalHeaderSize];
        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3c, sizeof(int)), peOffset);
        image[peOffset] = (byte)'P';
        image[peOffset + 1] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 4, sizeof(ushort)), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 6, sizeof(ushort)), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 20, sizeof(ushort)), optionalHeaderSize);
        int optionalHeader = peOffset + 24;
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(optionalHeader, sizeof(ushort)), 0x20b);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optionalHeader + 108, sizeof(uint)), 16);
        return image;
    }

    private static byte[] CreateRawCoffObject()
    {
        byte[] coff = new byte[20];
        BinaryPrimitives.WriteUInt16LittleEndian(coff, 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(coff.AsSpan(2), 1);
        return coff;
    }

    private static CertificateRef Certificate(string thumbprint = PrimaryThumbprint) =>
        Success(CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", thumbprint));

    private static T Success<T>(PolicyResult<T> result) where T : class
    {
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Errors));
        return Assert.IsType<T>(result.Value);
    }

    private static void AssertFailure<T>(
        PolicyResult<T> result,
        PolicyErrorCode expectedCode,
        string expectedPath) where T : class
    {
        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        PolicyError error = Assert.Single(result.Errors);
        Assert.Equal(expectedCode, error.Code);
        Assert.Equal(expectedPath, error.Path);
    }
}
