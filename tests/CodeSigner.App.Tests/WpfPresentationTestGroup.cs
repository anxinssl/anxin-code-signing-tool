namespace CodeSigner.App.Tests;

// WPF shares package resource streams across dispatchers; render tests must be exclusive.
[CollectionDefinition("WpfPresentation", DisableParallelization = true)]
public sealed class WpfPresentationTestGroup
{
}
