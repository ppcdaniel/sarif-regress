namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Resolves filesystem identities used to prevent output-path aliasing.
/// </summary>
internal static class PathIdentityResolver
{
    /// <summary>
    /// Gets the platform path comparer.
    /// </summary>
    public static StringComparer Comparer { get; } =
        OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

    /// <summary>
    /// Resolves existing parent-directory links while retaining the final
    /// output name. The writer replaces a final link rather than following it.
    /// </summary>
    public static string ResolveOutputIdentity(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new IOException(
                "The output path has no containing directory.");
        var fileName = Path.GetFileName(fullPath);
        if (fileName.Length == 0)
        {
            throw new IOException("The output path does not name a file.");
        }

        return Path.Combine(
            ResolveExistingComponents(directory),
            fileName);
    }

    /// <summary>
    /// Resolves all existing links in an input path, including a final file
    /// link, so an output cannot replace the physical input through an alias.
    /// </summary>
    public static string ResolveInputIdentity(string path) =>
        ResolveExistingComponents(Path.GetFullPath(path));

    /// <summary>
    /// Determines whether an output path would create or replace an entry
    /// below an input directory, including through an aliased parent.
    /// </summary>
    public static bool IsOutputWithinInputDirectory(
        string outputPath,
        string inputDirectoryPath)
    {
        var fullOutputPath = Path.GetFullPath(outputPath);
        var fullInputDirectoryPath = Path.GetFullPath(inputDirectoryPath);
        if (IsWithinDirectory(fullOutputPath, fullInputDirectoryPath))
        {
            return true;
        }

        return IsWithinDirectory(
            ResolveOutputIdentity(fullOutputPath),
            ResolveInputIdentity(fullInputDirectoryPath));
    }

    // Time: O(D), where D is the number of path segments. Space: O(D).
    private static bool IsWithinDirectory(
        string candidatePath,
        string directoryPath)
    {
        string relativePath = Path.GetRelativePath(
            directoryPath,
            candidatePath);
        if (string.Equals(relativePath, ".", StringComparison.Ordinal))
        {
            return true;
        }

        return !Path.IsPathRooted(relativePath)
            && !string.Equals(relativePath, "..", StringComparison.Ordinal)
            && !relativePath.StartsWith(
                ".." + Path.DirectorySeparatorChar,
                StringComparison.Ordinal)
            && !relativePath.StartsWith(
                ".." + Path.AltDirectorySeparatorChar,
                StringComparison.Ordinal);
    }

    private static string ResolveExistingComponents(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            throw new IOException("The path has no filesystem root.");
        }

        var current = root;
        var relativePath = fullPath[root.Length..];
        foreach (var segment in relativePath.Split(
                     [
                         Path.DirectorySeparatorChar,
                         Path.AltDirectorySeparatorChar,
                     ],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(current, segment);
            if (!TryGetAttributes(candidate, out var attributes))
            {
                current = candidate;
                continue;
            }

            if ((attributes & FileAttributes.ReparsePoint) == 0)
            {
                current = candidate;
                continue;
            }

            FileSystemInfo link =
                Directory.Exists(candidate) ||
                (attributes & FileAttributes.Directory) != 0
                    ? new DirectoryInfo(candidate)
                    : new FileInfo(candidate);
            var target = link.ResolveLinkTarget(returnFinalTarget: true)
                ?? throw new IOException(
                    "A filesystem link target could not be resolved.");
            current = ResolveExistingComponents(target.FullName);
        }

        return Path.GetFullPath(current);
    }

    private static bool TryGetAttributes(
        string path,
        out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            attributes = default;
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            attributes = default;
            return false;
        }
    }
}
