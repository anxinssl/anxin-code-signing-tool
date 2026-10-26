using System.Reflection;

namespace CodeSigner.IntegrationTests;

public sealed class CorrectionV2CategoryCoverageTests
{
    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void RequiredWorkerBoundaryTestsBelongToSigningIntegrationGate()
    {
        AssertSigningIntegration(
            typeof(WorkerProtocolTests),
            nameof(WorkerProtocolTests.OversizedLengthIsRejectedBeforeBodyAllocationOrRead),
            nameof(WorkerProtocolTests.TruncatedOrSpoofedLengthsAreRejected));
        AssertSigningIntegration(
            typeof(WorkerProcessBoundaryTests),
            nameof(WorkerProcessBoundaryTests.MisleadingSuccessOutputOrExitCodeIsRejected),
            nameof(WorkerProcessBoundaryTests.RealWorkerLaunchReturnsTypedResponseAndCleanExit));
    }

    private static void AssertSigningIntegration(Type type, params string[] methodNames)
    {
        foreach (string methodName in methodNames)
        {
            MethodInfo method = Assert.IsAssignableFrom<MethodInfo>(type.GetMethod(methodName));
            Assert.Contains(method.CustomAttributes, IsSigningIntegrationTrait);
        }
    }

    private static bool IsSigningIntegrationTrait(CustomAttributeData attribute) =>
        attribute.AttributeType == typeof(TraitAttribute) &&
        attribute.ConstructorArguments.Count == 2 &&
        string.Equals(attribute.ConstructorArguments[0].Value as string, "Category", StringComparison.Ordinal) &&
        string.Equals(attribute.ConstructorArguments[1].Value as string, "SigningIntegration", StringComparison.Ordinal);
}
