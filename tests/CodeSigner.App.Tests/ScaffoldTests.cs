namespace CodeSigner.App.Tests;

public sealed class ScaffoldTests
{
    [Fact]
    public void ApplicationTypeIsAvailable() => Assert.NotNull(typeof(App));
}
