namespace CodeSigner.Windows.Tests;

[AttributeUsage(AttributeTargets.Method)]
public sealed class RequiresSymbolicLinksFactAttribute : FactAttribute
{
    private static readonly Lazy<bool> Supported = new(CanCreateSymbolicLinks);

    public RequiresSymbolicLinksFactAttribute()
    {
        if (!Supported.Value)
        {
            Skip = "Requires Windows symbolic-link creation privilege or Developer Mode; security assertions remain unchanged.";
        }
    }

    private static bool CanCreateSymbolicLinks()
    {
        string directory = Directory.CreateTempSubdirectory("codesigner-symlink-capability-").FullName;
        try
        {
            string target = Path.Combine(directory, "target");
            File.WriteAllText(target, "capability probe");
            File.CreateSymbolicLink(Path.Combine(directory, "link"), target);
            return true;
        }
        catch (IOException exception) when ((exception.HResult & 0xFFFF) == 1314)
        {
            return false;
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
