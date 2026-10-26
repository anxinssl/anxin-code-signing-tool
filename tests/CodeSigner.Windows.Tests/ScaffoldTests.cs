namespace CodeSigner.Windows.Tests;

public sealed class ScaffoldTests
{
    [Fact]
    public void TargetIsWindowsX64() => Assert.True(Environment.Is64BitProcess && OperatingSystem.IsWindows());
}
