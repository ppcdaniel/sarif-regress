using SarifRegress.Core.Configuration;
using SarifRegress.Core.Paths;
using SarifRegress.Sarif.Canonicalization;

namespace SarifRegress.Sarif.Configuration;

/// <summary>
/// Enforces the host-independent security policy for explicit URI-base mappings.
/// </summary>
internal static class ConfiguredUriBasePolicy
{
    /// <summary>
    /// Determines whether a mapping is a bounded local logical definition.
    /// </summary>
    /// <param name="mapping">The mapping to validate.</param>
    /// <returns>True only when the mapping is safe to resolve lexically.</returns>
    public static bool IsSafe(UriBaseMapping mapping)
    {
        ArgumentNullException.ThrowIfNull(mapping);
        return IsSafeIdentifier(mapping.Id) &&
            (mapping.UriBaseId is null ||
                IsSafeIdentifier(mapping.UriBaseId)) &&
            IsSafeTarget(mapping);
    }

    /// <summary>
    /// Determines whether a logical URI-base identifier is safe to diagnose
    /// and compare ordinally.
    /// </summary>
    /// <param name="value">The identifier.</param>
    /// <returns>True when the identifier contains no control characters.</returns>
    public static bool IsSafeIdentifier(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return !value.Any(char.IsControl);
    }

    /// <summary>
    /// Determines whether a mapping target is a directory-form local root or
    /// relative base.
    /// </summary>
    /// <param name="mapping">The mapping whose target is validated.</param>
    /// <returns>True when its target cannot change or escape logical roots.</returns>
    public static bool IsSafeTarget(UriBaseMapping mapping)
    {
        ArgumentNullException.ThrowIfNull(mapping);
        return IsSafeTarget(mapping.Uri, mapping.UriBaseId);
    }

    /// <summary>
    /// Determines whether a fully resolved configured chain remains local.
    /// </summary>
    /// <param name="uri">The resolved logical URI root.</param>
    /// <returns>True only for approved repository or local filesystem roots.</returns>
    public static bool IsSafeResolvedRoot(string uri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);
        if (ContainsUnsafeReferenceSyntax(uri) || !IsDirectoryForm(uri))
        {
            return false;
        }

        var normalizedSeparators = uri.Replace('\\', '/');
        if (normalizedSeparators.StartsWith("//", StringComparison.Ordinal) ||
            normalizedSeparators.StartsWith(
                "repo://",
                StringComparison.Ordinal))
        {
            return false;
        }

        if (uri.StartsWith("repo:/", StringComparison.Ordinal))
        {
            return true;
        }

        var kind = PathCanonicalizer.Classify(uri);
        if (kind is PathKind.PosixAbsolute or PathKind.DriveAbsolute)
        {
            return true;
        }

        return kind == PathKind.FileUri &&
            Uri.TryCreate(uri, UriKind.Absolute, out var fileUri) &&
            fileUri.IsFile &&
            !fileUri.IsUnc &&
            string.IsNullOrEmpty(fileUri.Host);
    }

    /// <summary>
    /// Determines whether a relative SARIF artifact reference can be combined
    /// without a URI parser hiding parent-root traversal.
    /// </summary>
    /// <param name="uri">The relative artifact URI.</param>
    /// <returns>True when the lexical reference contains no parent segment.</returns>
    public static bool IsSafeArtifactReference(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return PathCanonicalizer.Classify(uri) ==
                PathKind.RepositoryRelative &&
            !ContainsUnsafeReferenceSyntax(uri);
    }

    /// <summary>
    /// Determines whether one non-root URI-base leg is a safe relative child.
    /// </summary>
    /// <param name="uri">The URI-base leg.</param>
    /// <returns>True when the leg cannot replace or escape its parent root.</returns>
    public static bool IsSafeRelativeDefinition(string uri) =>
        IsSafeArtifactReference(uri) && IsDirectoryForm(uri);

    private static bool IsSafeTarget(string uri, string? parentId)
    {
        if (ContainsUnsafeReferenceSyntax(uri) || !IsDirectoryForm(uri))
        {
            return false;
        }

        var kind = PathCanonicalizer.Classify(uri);
        if (parentId is not null)
        {
            return kind == PathKind.RepositoryRelative;
        }

        return IsSafeResolvedRoot(uri);
    }

    private static bool ContainsUnsafeReferenceSyntax(string value) =>
        value.Any(char.IsControl) ||
        value.Contains('?') ||
        value.Contains('#') ||
        ContainsParentSegment(value);

    private static bool IsDirectoryForm(string value) =>
        value.Length > 0 && (value[^1] is '/' or '\\');

    // Time: O(n), where n is the bounded URI length. Space: O(n).
    private static bool ContainsParentSegment(string value) =>
        NormalizeTraversalEscapes(value)
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Any(segment => string.Equals(
                segment,
                "..",
                StringComparison.Ordinal));

    private static string NormalizeTraversalEscapes(string value) =>
        value
            .Replace("%2e", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("%2f", "/", StringComparison.OrdinalIgnoreCase)
            .Replace("%5c", "\\", StringComparison.OrdinalIgnoreCase);
}
