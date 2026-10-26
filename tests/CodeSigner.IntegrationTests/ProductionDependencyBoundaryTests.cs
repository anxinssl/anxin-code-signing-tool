using System.Text.Json;
using System.Xml.Linq;

namespace CodeSigner.IntegrationTests;

public sealed class ProductionDependencyBoundaryTests
{
    private static readonly string[] ForbiddenDependencyNames = ["SignTool", "SimplySign"];

    [Fact]
    public void ProductionProjectsDoNotReferenceForbiddenSigningDependencies()
    {
        string root = FindRepositoryRoot();
        string[] projectFiles =
        [
            .. Directory.EnumerateFiles(Path.Combine(root, "src"), "*.csproj", SearchOption.AllDirectories),
            .. Directory.EnumerateFiles(Path.Combine(root, "packaging", "msi"), "*.wixproj", SearchOption.AllDirectories)
        ];

        Assert.NotEmpty(projectFiles);
        foreach (string projectFile in projectFiles)
        {
            XDocument project = XDocument.Load(projectFile, LoadOptions.None);
            IEnumerable<string> dependencyIdentifiers = project
                .Descendants()
                .Where(element => element.Name.LocalName is "PackageReference" or "ProjectReference")
                .Select(element => (string?)element.Attribute("Include"))
                .OfType<string>();
            Assert.All(dependencyIdentifiers, identifier => Assert.DoesNotContain(
                ForbiddenDependencyNames,
                forbidden => identifier.Contains(forbidden, StringComparison.OrdinalIgnoreCase)));
        }
    }

    [Fact]
    public void ProductionLockFilesDoNotContainForbiddenSigningPackages()
    {
        string root = FindRepositoryRoot();
        string[] lockFiles =
        [
            .. Directory.EnumerateFiles(Path.Combine(root, "src"), "packages.lock.json", SearchOption.AllDirectories),
            .. Directory.EnumerateFiles(Path.Combine(root, "packaging", "msi"), "packages.lock.json", SearchOption.AllDirectories)
        ];

        Assert.NotEmpty(lockFiles);
        foreach (string lockFile in lockFiles)
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(lockFile));
            JsonElement dependencies = document.RootElement.GetProperty("dependencies");
            foreach (JsonProperty target in dependencies.EnumerateObject())
            {
                foreach (JsonProperty package in target.Value.EnumerateObject())
                {
                    Assert.DoesNotContain(
                        ForbiddenDependencyNames,
                        forbidden => package.Name.Contains(forbidden, StringComparison.OrdinalIgnoreCase));
                }
            }
        }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "global.json")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root containing global.json was not found.");
    }
}
