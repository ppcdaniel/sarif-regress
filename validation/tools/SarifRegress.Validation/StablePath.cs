namespace SarifRegress.Validation;

/// <summary>
/// Validates and resolves portable repository-relative paths without accepting aliases.
/// </summary>
public static class StablePath
{
    /// <summary>Validates canonical POSIX spelling and returns the unchanged relative path.</summary>
    public static string RequireRepositoryRelative(string value, string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        if (string.IsNullOrWhiteSpace(value)
            || value.StartsWith("/", StringComparison.Ordinal)
            || value.Contains("\\", StringComparison.Ordinal)
            || value.Contains(":", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Manifest field '{fieldName}' must be a POSIX repository-relative path.");
        }

        string[] segments = value.Split('/');
        if (segments.Any(segment => segment is "" or "." or ".."))
        {
            throw new InvalidDataException(
                $"Manifest field '{fieldName}' contains an empty, dot, or parent segment.");
        }

        return value;
    }

    /// <summary>Resolves one previously validated relative path beneath the repository root.</summary>
    public static string Resolve(string repositoryRoot, string relativePath)
    {
        RequireRepositoryRelative(relativePath, nameof(relativePath));
        string root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(repositoryRoot));
        string path = Path.GetFullPath(
            relativePath.Replace('/', Path.DirectorySeparatorChar),
            root);
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, comparison))
        {
            throw new InvalidDataException(
                $"Repository-relative path '{relativePath}' escapes the repository root.");
        }

        return path;
    }
}
