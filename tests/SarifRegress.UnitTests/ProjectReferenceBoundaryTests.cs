using System.Xml.Linq;

namespace SarifRegress.UnitTests;

public sealed class ProjectReferenceBoundaryTests
{
    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>>
        AllowedReferences =
            new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
            {
                ["SarifRegress.Core"] = CreateReferenceSet(),
                ["SarifRegress.Sarif"] = CreateReferenceSet("SarifRegress.Core"),
                ["SarifRegress.Match"] = CreateReferenceSet("SarifRegress.Core"),
                ["SarifRegress.Report"] = CreateReferenceSet("SarifRegress.Core"),
                ["SarifRegress.Cli"] = CreateReferenceSet(
                    "SarifRegress.Core",
                    "SarifRegress.Sarif",
                    "SarifRegress.Match",
                    "SarifRegress.Report"),
            };

    [Fact]
    public void Application_project_references_preserve_architectural_boundaries()
    {
        var sourceRoot = Path.Combine(RepositoryLayout.Root, "src");
        var projectFiles = Directory
            .EnumerateFiles(sourceRoot, "*.csproj", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var violations = new List<string>();

        foreach (var projectFile in projectFiles)
        {
            ValidateProjectReferences(sourceRoot, projectFile, violations);
        }

        var discoveredProjects = projectFiles
            .Select(Path.GetFileNameWithoutExtension)
            .ToHashSet(StringComparer.Ordinal);
        var missingProjects = AllowedReferences.Keys
            .Where(projectName => !discoveredProjects.Contains(projectName))
            .Order(StringComparer.Ordinal);

        violations.AddRange(
            missingProjects.Select(projectName => $"Missing application project: {projectName}."));

        Assert.True(
            violations.Count == 0,
            "Project-reference boundary violations:" + Environment.NewLine +
            string.Join(Environment.NewLine, violations));
    }

    private static void ValidateProjectReferences(
        string sourceRoot,
        string projectFile,
        ICollection<string> violations)
    {
        var sourceProject = Path.GetFileNameWithoutExtension(projectFile);
        if (!AllowedReferences.TryGetValue(sourceProject, out var allowedTargets))
        {
            violations.Add($"Unknown application project: {sourceProject}.");
            return;
        }

        var projectDocument = XDocument.Load(projectFile);
        var projectDirectory = Path.GetDirectoryName(projectFile)
            ?? throw new InvalidOperationException(
                $"Project path has no parent directory: {sourceProject}.");

        foreach (var projectReference in projectDocument.Descendants("ProjectReference"))
        {
            var include = projectReference.Attribute("Include")?.Value;
            if (string.IsNullOrWhiteSpace(include))
            {
                violations.Add($"{sourceProject} contains an empty ProjectReference.");
                continue;
            }

            var targetPath = ResolveProjectPath(projectDirectory, include);
            if (!IsWithinDirectory(sourceRoot, targetPath))
            {
                violations.Add(
                    $"{sourceProject} references a project outside src: {include}.");
                continue;
            }

            var targetProject = Path.GetFileNameWithoutExtension(targetPath);
            if (!AllowedReferences.ContainsKey(targetProject))
            {
                violations.Add(
                    $"{sourceProject} references unknown application project {targetProject}.");
                continue;
            }

            if (!allowedTargets.Contains(targetProject))
            {
                var allowedList = allowedTargets.Count == 0
                    ? "none"
                    : string.Join(", ", allowedTargets.Order(StringComparer.Ordinal));
                violations.Add(
                    $"Forbidden project reference: {sourceProject} -> {targetProject}. " +
                    $"Allowed: {allowedList}.");
            }
        }
    }

    private static string ResolveProjectPath(string projectDirectory, string include)
    {
        var normalizedInclude = include
            .Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar);

        return Path.GetFullPath(Path.Combine(projectDirectory, normalizedInclude));
    }

    private static bool IsWithinDirectory(string directory, string path)
    {
        var relativePath = Path.GetRelativePath(directory, path);
        return !string.Equals(relativePath, "..", StringComparison.Ordinal) &&
            !relativePath.StartsWith(
                $"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal);
    }

    private static IReadOnlySet<string> CreateReferenceSet(params string[] projectNames)
    {
        return new HashSet<string>(projectNames, StringComparer.Ordinal);
    }
}
