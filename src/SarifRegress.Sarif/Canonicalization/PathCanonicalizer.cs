using System.Collections.Immutable;
using System.Text;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Paths;

namespace SarifRegress.Sarif.Canonicalization;

/// <summary>
/// Canonicalises path and URI spellings lexically, independently of the host operating system.
/// </summary>
public sealed class PathCanonicalizer
{
    /// <summary>
    /// Gets the path-canonicalisation algorithm identifier.
    /// </summary>
    public const string AlgorithmVersion = "cross-platform-path/v1";

    private const string RepositoryScheme = "repo:/";
    private readonly string? normalizedRepositoryRoot;
    private readonly ImmutableArray<PathRebase> pathRebases;
    private readonly PathCaseSensitivity caseSensitivity;

    /// <summary>
    /// Initializes a canonicalizer from immutable comparison configuration.
    /// </summary>
    /// <param name="configuration">The canonicalisation policy.</param>
    public PathCanonicalizer(SarifRegressConfiguration? configuration = null)
    {
        var effectiveConfiguration =
            configuration ?? SarifRegressConfiguration.Default;
        pathRebases = effectiveConfiguration.PathRebases;
        caseSensitivity =
            effectiveConfiguration.Matching.PathCaseSensitivity;
        normalizedRepositoryRoot = NormalizeRepositoryRoot(
            effectiveConfiguration.RepositoryRoot);
    }

    /// <summary>
    /// Canonicalises one original lexical value and its optional URI-base-resolved value.
    /// </summary>
    /// <param name="originalValue">The source lexical path or URI.</param>
    /// <param name="resolvedValue">The URI-base-resolved logical value, when available.</param>
    /// <param name="sourceReference">The source pointer used by diagnostics.</param>
    /// <returns>A host-independent canonical path.</returns>
    public CanonicalPath Canonicalize(
        string originalValue,
        string? resolvedValue = null,
        SourceReference? sourceReference = null)
    {
        ArgumentNullException.ThrowIfNull(originalValue);

        var diagnostics = new List<Diagnostic>();
        var transformations = new List<TransformationRecord>();
        var originalKind = Classify(originalValue);
        var logicalValue = resolvedValue ?? originalValue;
        DiagnoseLexicalForm(
            originalValue,
            originalKind,
            sourceReference,
            diagnostics);

        logicalValue = ApplyConfiguredRebase(logicalValue, transformations);
        logicalValue = DecodeSafePercentEscapes(logicalValue, transformations);
        var logicalKind = Classify(logicalValue);

        if (TryGetRepositoryRelativePath(
                logicalValue,
                logicalKind,
                out var repositoryRelativePath))
        {
            return CreateRepositoryPath(
                originalValue,
                logicalValue,
                originalKind,
                repositoryRelativePath,
                sourceReference,
                transformations,
                diagnostics);
        }

        var canonicalUri = CanonicalizeExternal(
            logicalValue,
            logicalKind,
            sourceReference,
            transformations,
            diagnostics);

        return new CanonicalPath(
            originalValue,
            logicalValue,
            canonicalUri,
            repositoryRelativePath: null,
            originalKind,
            transformations,
            diagnostics);
    }

    /// <summary>
    /// Classifies a lexical path without consulting the current operating system.
    /// </summary>
    /// <param name="value">The path or URI text.</param>
    /// <returns>The lexical path kind.</returns>
    public static PathKind Classify(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return PathKind.Unknown;
        }

        if (StartsWithOrdinalIgnoreCase(value, @"\\?\UNC\") ||
            StartsWithOrdinalIgnoreCase(value, "//?/UNC/"))
        {
            return PathKind.DeviceUnc;
        }

        if (value.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            value.StartsWith("//?/", StringComparison.Ordinal))
        {
            return PathKind.Device;
        }

        if (value.StartsWith(@"\\", StringComparison.Ordinal) ||
            value.StartsWith("//", StringComparison.Ordinal))
        {
            return PathKind.Unc;
        }

        if (StartsWithOrdinalIgnoreCase(value, "file:"))
        {
            return PathKind.FileUri;
        }

        if (HasUriScheme(value))
        {
            return PathKind.ExternalUri;
        }

        if (IsDrivePrefix(value))
        {
            return value.Length >= 3 && IsSeparator(value[2])
                ? PathKind.DriveAbsolute
                : PathKind.DriveRelative;
        }

        if (value[0] == '\\')
        {
            return PathKind.RootRelative;
        }

        if (value[0] == '/')
        {
            return PathKind.PosixAbsolute;
        }

        return PathKind.RepositoryRelative;
    }

    private CanonicalPath CreateRepositoryPath(
        string originalValue,
        string logicalValue,
        PathKind originalKind,
        string repositoryRelativePath,
        SourceReference? sourceReference,
        ICollection<TransformationRecord> transformations,
        ICollection<Diagnostic> diagnostics)
    {
        var beforeSegments = repositoryRelativePath;
        if (!TryCollapseRootedSegments(
                repositoryRelativePath,
                out repositoryRelativePath))
        {
            diagnostics.Add(
                new Diagnostic(
                    "CANON0001",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Canonicalisation,
                    "The path traverses above the logical repository root.",
                    sourceReference,
                    help: "Remove leading parent-directory segments or configure a safe rebase."));

            var unresolved = NormalizeSeparators(repositoryRelativePath)
                .TrimStart('/');
            return new CanonicalPath(
                originalValue,
                logicalValue,
                $"unresolved://repository/{unresolved}",
                repositoryRelativePath: null,
                originalKind,
                transformations,
                diagnostics);
        }

        RecordChange(
            transformations,
            "collapsed-rooted-segments",
            beforeSegments,
            repositoryRelativePath,
            isLossy: false);

        var normalizedSeparators = NormalizeSeparators(repositoryRelativePath)
            .TrimStart('/');
        RecordChange(
            transformations,
            "canonical-separators",
            repositoryRelativePath,
            normalizedSeparators,
            isLossy: false);
        repositoryRelativePath = normalizedSeparators;

        if (caseSensitivity == PathCaseSensitivity.AsciiInsensitive)
        {
            var foldedPath = FoldAsciiCase(repositoryRelativePath);
            RecordChange(
                transformations,
                "configured-ascii-case-fold",
                repositoryRelativePath,
                foldedPath,
                isLossy: true);
            repositoryRelativePath = foldedPath;
        }

        if (repositoryRelativePath.Length == 0)
        {
            diagnostics.Add(
                new Diagnostic(
                    "CANON0002",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Canonicalisation,
                    "The path identifies the repository root rather than an artifact.",
                    sourceReference));
        }

        return new CanonicalPath(
            originalValue,
            logicalValue,
            $"repo://{repositoryRelativePath}",
            repositoryRelativePath,
            originalKind,
            transformations,
            diagnostics);
    }

    private string CanonicalizeExternal(
        string logicalValue,
        PathKind originalKind,
        SourceReference? sourceReference,
        ICollection<TransformationRecord> transformations,
        ICollection<Diagnostic> diagnostics)
    {
        if (string.IsNullOrWhiteSpace(logicalValue))
        {
            diagnostics.Add(
                new Diagnostic(
                    "CANON0003",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Canonicalisation,
                    "The artifact location is empty.",
                    sourceReference));
            return "unresolved://empty";
        }

        var normalized = NormalizeSeparators(logicalValue);
        RecordChange(
            transformations,
            "canonical-separators",
            logicalValue,
            normalized,
            isLossy: false);

        return originalKind switch
        {
            PathKind.DriveAbsolute =>
                $"win-drive://{NormalizeAbsoluteSegments(normalized)}",
            PathKind.DriveRelative =>
                $"win-drive-relative://{normalized}",
            PathKind.RootRelative =>
                $"win-root://{NormalizeAbsoluteSegments(normalized)}",
            PathKind.Unc =>
                $"unc://{NormalizeAbsoluteSegments(normalized.TrimStart('/'))}",
            PathKind.DeviceUnc =>
                $"win-device-unc://{NormalizeAbsoluteSegments(RemoveDeviceUncPrefix(normalized))}",
            PathKind.Device =>
                $"win-device://{NormalizeAbsoluteSegments(RemoveDevicePrefix(normalized))}",
            PathKind.PosixAbsolute =>
                $"file://{NormalizeAbsoluteSegments(normalized)}",
            PathKind.FileUri => CanonicalizeFileUri(normalized),
            PathKind.ExternalUri => normalized,
            PathKind.RepositoryRelative =>
                $"relative://{normalized}",
            _ => "unresolved://empty",
        };
    }

    private string ApplyConfiguredRebase(
        string value,
        ICollection<TransformationRecord> transformations)
    {
        foreach (var rebase in pathRebases)
        {
            if (!HasCompletePrefix(value, rebase.From))
            {
                continue;
            }

            var rebased = rebase.To + value[rebase.From.Length..];
            RecordChange(
                transformations,
                "configured-path-rebase",
                value,
                rebased,
                isLossy: false);
            return rebased;
        }

        return value;
    }

    private bool TryGetRepositoryRelativePath(
        string logicalValue,
        PathKind originalKind,
        out string repositoryRelativePath)
    {
        if (StartsWithOrdinalIgnoreCase(logicalValue, RepositoryScheme))
        {
            repositoryRelativePath = logicalValue[RepositoryScheme.Length..]
                .TrimStart('/', '\\');
            return true;
        }

        if (originalKind == PathKind.RepositoryRelative &&
            !HasUriScheme(logicalValue))
        {
            repositoryRelativePath = logicalValue;
            return true;
        }

        if (normalizedRepositoryRoot is null)
        {
            repositoryRelativePath = string.Empty;
            return false;
        }

        var comparableValue = NormalizeFileLocation(logicalValue);
        var comparableRoot = normalizedRepositoryRoot;
        if (caseSensitivity == PathCaseSensitivity.AsciiInsensitive)
        {
            comparableValue = FoldAsciiCase(comparableValue);
            comparableRoot = FoldAsciiCase(comparableRoot);
        }

        if (string.Equals(
                comparableValue.TrimEnd('/'),
                comparableRoot,
                StringComparison.Ordinal))
        {
            repositoryRelativePath = string.Empty;
            return true;
        }

        var rootPrefix = comparableRoot + "/";
        if (!comparableValue.StartsWith(rootPrefix, StringComparison.Ordinal))
        {
            repositoryRelativePath = string.Empty;
            return false;
        }

        repositoryRelativePath = comparableValue[rootPrefix.Length..];
        return true;
    }

    private static string DecodeSafePercentEscapes(
        string value,
        ICollection<TransformationRecord> transformations)
    {
        if (value.IndexOf('%') < 0)
        {
            return value;
        }

        StringBuilder? builder = null;
        var copiedThrough = 0;
        for (var index = 0; index + 2 < value.Length; index++)
        {
            if (value[index] != '%' ||
                !TryParseHexByte(value[index + 1], value[index + 2], out var decoded) ||
                !IsRfc3986Unreserved(decoded))
            {
                continue;
            }

            builder ??= new StringBuilder(value.Length);
            builder.Append(value, copiedThrough, index - copiedThrough);
            builder.Append((char)decoded);
            index += 2;
            copiedThrough = index + 1;
        }

        if (builder is null)
        {
            return value;
        }

        builder.Append(value, copiedThrough, value.Length - copiedThrough);
        var canonical = builder.ToString();
        RecordChange(
            transformations,
            "safe-percent-decode",
            value,
            canonical,
            isLossy: false);
        return canonical;
    }

    private static string CanonicalizeFileUri(string normalized)
    {
        var fileLocation = NormalizeFileLocation(normalized);
        if (IsDrivePrefix(fileLocation))
        {
            return "file:///" + NormalizeAbsoluteSegments(fileLocation);
        }

        if (fileLocation.StartsWith("//", StringComparison.Ordinal))
        {
            return "file://" +
                NormalizeAbsoluteSegments(fileLocation.TrimStart('/'));
        }

        var absolutePath = fileLocation.StartsWith("/", StringComparison.Ordinal)
            ? fileLocation
            : "/" + fileLocation;
        return "file://" + NormalizeAbsoluteSegments(absolutePath);
    }

    private static string? NormalizeRepositoryRoot(string? repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot) ||
            string.Equals(repositoryRoot, ".", StringComparison.Ordinal))
        {
            return repositoryRoot is null ? null : ".";
        }

        return NormalizeFileLocation(repositoryRoot).TrimEnd('/');
    }

    private static string NormalizeFileLocation(string value)
    {
        var normalized = NormalizeSeparators(value);
        if (!StartsWithOrdinalIgnoreCase(normalized, "file:"))
        {
            return normalized.TrimEnd('/');
        }

        var withoutScheme = normalized["file:".Length..];
        if (withoutScheme.StartsWith("///", StringComparison.Ordinal))
        {
            withoutScheme = withoutScheme[2..];
        }
        else if (withoutScheme.StartsWith("//localhost/", StringComparison.OrdinalIgnoreCase))
        {
            withoutScheme = withoutScheme["//localhost".Length..];
        }

        if (withoutScheme.Length >= 3 &&
            withoutScheme[0] == '/' &&
            IsDrivePrefix(withoutScheme.AsSpan(1)))
        {
            withoutScheme = withoutScheme[1..];
        }

        return withoutScheme.TrimEnd('/');
    }

    // Time: O(n), where n is the number of path segments. Space: O(n).
    private static bool TryCollapseRootedSegments(
        string value,
        out string collapsed)
    {
        var segments = NormalizeSeparators(value)
            .Split('/', StringSplitOptions.RemoveEmptyEntries);
        var retained = new List<string>(segments.Length);

        foreach (var segment in segments)
        {
            if (segment == ".")
            {
                continue;
            }

            if (segment == "..")
            {
                if (retained.Count == 0)
                {
                    collapsed = value;
                    return false;
                }

                retained.RemoveAt(retained.Count - 1);
                continue;
            }

            retained.Add(segment);
        }

        collapsed = string.Join('/', retained);
        return true;
    }

    private static string NormalizeAbsoluteSegments(string value)
    {
        var hasLeadingSlash = value.Length > 0 && value[0] == '/';
        if (!TryCollapseRootedSegments(value, out var collapsed))
        {
            return value;
        }

        return hasLeadingSlash ? "/" + collapsed : collapsed;
    }

    private static string NormalizeSeparators(string value) =>
        value.Replace('\\', '/');

    private static string RemoveDevicePrefix(string value) =>
        value.StartsWith("//?/", StringComparison.Ordinal) ? value[4..] : value;

    private static string RemoveDeviceUncPrefix(string value) =>
        StartsWithOrdinalIgnoreCase(value, "//?/UNC/") ? value[8..] : value;

    private static string FoldAsciiCase(string value)
    {
        return string.Create(
            value.Length,
            value,
            static (destination, source) =>
            {
                for (var index = 0; index < source.Length; index++)
                {
                    var character = source[index];
                    destination[index] = character is >= 'A' and <= 'Z'
                        ? (char)(character + ('a' - 'A'))
                        : character;
                }
            });
    }

    private static bool HasUriScheme(string value)
    {
        if (value.Length < 2 || !IsAsciiLetter(value[0]))
        {
            return false;
        }

        for (var index = 1; index < value.Length; index++)
        {
            var character = value[index];
            if (character == ':')
            {
                return true;
            }

            if (!IsAsciiLetter(character) &&
                !char.IsAsciiDigit(character) &&
                character is not '+' and not '-' and not '.')
            {
                return false;
            }
        }

        return false;
    }

    private static bool IsDrivePrefix(string value) =>
        IsDrivePrefix(value.AsSpan());

    private static bool IsDrivePrefix(ReadOnlySpan<char> value) =>
        value.Length >= 2 && IsAsciiLetter(value[0]) && value[1] == ':';

    private static bool IsAsciiLetter(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z';

    private static bool IsSeparator(char value) => value is '/' or '\\';

    private bool HasCompletePrefix(string value, string prefix)
    {
        if (prefix.Length == 0)
        {
            return false;
        }

        var prefixMatches =
            caseSensitivity == PathCaseSensitivity.AsciiInsensitive
                ? StartsWithAsciiIgnoreCase(value, prefix)
                : value.StartsWith(prefix, StringComparison.Ordinal);
        if (!prefixMatches)
        {
            return false;
        }

        return value.Length == prefix.Length ||
            IsSeparator(prefix[^1]) ||
            IsSeparator(value[prefix.Length]);
    }

    private static bool StartsWithAsciiIgnoreCase(
        string value,
        string prefix)
    {
        if (value.Length < prefix.Length)
        {
            return false;
        }

        for (var index = 0; index < prefix.Length; index++)
        {
            var valueCharacter = value[index];
            var prefixCharacter = prefix[index];
            if (valueCharacter is >= 'A' and <= 'Z')
            {
                valueCharacter = (char)(valueCharacter + ('a' - 'A'));
            }

            if (prefixCharacter is >= 'A' and <= 'Z')
            {
                prefixCharacter = (char)(prefixCharacter + ('a' - 'A'));
            }

            if (valueCharacter != prefixCharacter)
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryParseHexByte(char high, char low, out byte value)
    {
        var highValue = ParseHexNibble(high);
        var lowValue = ParseHexNibble(low);
        if (highValue < 0 || lowValue < 0)
        {
            value = 0;
            return false;
        }

        value = (byte)((highValue << 4) | lowValue);
        return true;
    }

    private static int ParseHexNibble(char value) =>
        value switch
        {
            >= '0' and <= '9' => value - '0',
            >= 'A' and <= 'F' => value - 'A' + 10,
            >= 'a' and <= 'f' => value - 'a' + 10,
            _ => -1,
        };

    private static bool IsRfc3986Unreserved(byte value) =>
        value >= (byte)'A' && value <= (byte)'Z' ||
        value >= (byte)'a' && value <= (byte)'z' ||
        value >= (byte)'0' && value <= (byte)'9' ||
        value == (byte)'-' ||
        value == (byte)'.' ||
        value == (byte)'_' ||
        value == (byte)'~';

    private static void DiagnoseLexicalForm(
        string value,
        PathKind kind,
        SourceReference? sourceReference,
        ICollection<Diagnostic> diagnostics)
    {
        if (value.IndexOf('\0') >= 0)
        {
            diagnostics.Add(
                new Diagnostic(
                    "CANON0005",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Canonicalisation,
                    "The path contains a null character and was retained as lexical input.",
                    sourceReference));
        }

        if (kind is not PathKind.DriveAbsolute and
            not PathKind.DriveRelative and
            not PathKind.RootRelative and
            not PathKind.Unc and
            not PathKind.Device and
            not PathKind.DeviceUnc and
            not PathKind.FileUri)
        {
            return;
        }

        var segments = NormalizeFileLocation(value)
            .Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (!segments.Any(IsReservedWindowsName))
        {
            return;
        }

        diagnostics.Add(
            new Diagnostic(
                "CANON0004",
                DiagnosticSeverity.Warning,
                DiagnosticStage.Canonicalisation,
                "The path contains a reserved Windows name and was retained without rewriting.",
                sourceReference));
    }

    private static bool IsReservedWindowsName(string segment)
    {
        var trimmed = segment.TrimEnd(' ', '.');
        var extensionIndex = trimmed.IndexOf('.');
        var name = extensionIndex < 0
            ? trimmed
            : trimmed[..extensionIndex];
        if (name.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("NUL", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (name.Length != 4 ||
            name[3] is < '1' or > '9')
        {
            return false;
        }

        return name.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("LPT", StringComparison.OrdinalIgnoreCase);
    }

    private static bool StartsWithOrdinalIgnoreCase(string value, string prefix) =>
        value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    private static void RecordChange(
        ICollection<TransformationRecord> transformations,
        string kind,
        string original,
        string transformed,
        bool isLossy)
    {
        if (string.Equals(original, transformed, StringComparison.Ordinal))
        {
            return;
        }

        transformations.Add(
            new TransformationRecord(
                kind,
                original,
                transformed,
                isLossy,
                AlgorithmVersion));
    }
}
