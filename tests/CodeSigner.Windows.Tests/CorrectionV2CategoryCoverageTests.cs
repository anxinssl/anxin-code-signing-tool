using System.Reflection;

namespace CodeSigner.Windows.Tests;

public sealed class CorrectionV2CategoryCoverageTests
{
    [Fact]
    [Trait("Category", "SigningIntegration")]
    public void RequiredTransactionalTestsBelongToSigningIntegrationGate()
    {
        AssertSigningIntegration(
            nameof(TransactionalFilePipelineTests.FailureAndCancellationLeaveNoDestinationOrStagingResidue),
            nameof(TransactionalFilePipelineTests.RecoveryDeletesOnlyRecognizedStaleAttemptsAndAllowsRetry),
            nameof(TransactionalFilePipelineTests.CancellationBeforeCommitLeavesNoOutputButCancellationAfterCommitReturnsPublished));
    }

    private static void AssertSigningIntegration(params string[] methodNames)
    {
        foreach (string methodName in methodNames)
        {
            MethodInfo method = Assert.IsAssignableFrom<MethodInfo>(
                typeof(TransactionalFilePipelineTests).GetMethod(methodName));
            Assert.Contains(method.CustomAttributes, IsSigningIntegrationTrait);
        }
    }

    private static bool IsSigningIntegrationTrait(CustomAttributeData attribute) =>
        attribute.AttributeType == typeof(TraitAttribute) &&
        attribute.ConstructorArguments.Count == 2 &&
        string.Equals(attribute.ConstructorArguments[0].Value as string, "Category", StringComparison.Ordinal) &&
        string.Equals(attribute.ConstructorArguments[1].Value as string, "SigningIntegration", StringComparison.Ordinal);
}
