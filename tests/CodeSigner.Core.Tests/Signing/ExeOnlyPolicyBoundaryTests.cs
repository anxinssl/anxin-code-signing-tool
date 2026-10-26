using CodeSigner.Core.Signing;

namespace CodeSigner.Core.Tests.Signing;

public sealed class SigningCapabilityBoundaryTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Theory]
    [InlineData(".dll", SigningCapability.PeImageDualCapable)]
    [InlineData(".msi", SigningCapability.WindowsSipSingleOnly)]
    [InlineData(".cab", SigningCapability.WindowsSipSingleOnly)]
    [InlineData(".ocx", SigningCapability.PeImageDualCapable)]
    [Trait("Category", "SigningIntegration")]
    public void ApprovedNonExeExtensionsResolveToTheirClosedCapability(
        string extension,
        SigningCapability expectedCapability)
    {
        CertificateRef certificate = Certificate();

        PolicyResult<SigningPlan> single = SigningPlan.TryCreateSingle(certificate, extension);
        PolicyResult<SigningPlan> dual = SigningPlan.TryCreateDual(certificate, certificate, extension);

        Assert.Equal(expectedCapability, AssertPlan(single).Subject.Capability);
        Assert.Equal(expectedCapability, AssertPlan(dual).Subject.Capability);
    }

    [Theory]
    [InlineData("windowsInstaller", ".msi", "peImageDualCapable")]
    [InlineData("cabinet", ".cab", "peImageDualCapable")]
    [InlineData("peImage", ".ocx", "windowsSipSingleOnly")]
    [Trait("Category", "SigningIntegration")]
    public void ForgedCapabilityCannotCrossTheParsingBoundary(
        string formatFamily,
        string extension,
        string forgedCapability)
    {
        SigningPlan valid = Assert.IsType<SigningPlan>(
            SigningPlan.TryCreateSingle(Certificate(), extension).Value);
        string validJson = SigningPlanJson.Serialize(valid);
        Assert.Contains($"\"formatFamily\":\"{formatFamily}\"", validJson, StringComparison.Ordinal);
        string json = validJson.Replace(
                valid.Subject.Capability == SigningCapability.PeImageDualCapable
                    ? "\"capability\":\"peImageDualCapable\""
                    : "\"capability\":\"windowsSipSingleOnly\"",
                $"\"capability\":\"{forgedCapability}\"",
                StringComparison.Ordinal);

        PolicyResult<SigningPlan> result = SigningPlanJson.Parse(json);

        Assert.False(result.IsSuccess);
        PolicyError error = Assert.Single(result.Errors);
        Assert.Equal(PolicyErrorCode.UnsafePolicy, error.Code);
        Assert.Equal("$.subject.capability", error.Path);
    }

    private static CertificateRef Certificate() => Assert.IsType<CertificateRef>(
        CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);

    private static SigningPlan AssertPlan(PolicyResult<SigningPlan> result)
    {
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Errors));
        return Assert.IsType<SigningPlan>(result.Value);
    }
}
