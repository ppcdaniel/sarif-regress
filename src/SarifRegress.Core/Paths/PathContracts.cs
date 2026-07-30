using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;

namespace SarifRegress.Core.Paths;

/// <summary>
/// Identifies a lexical path or URI form independently of the host operating system.
/// </summary>
public enum PathKind
{
    /// <summary>
    /// No usable path was supplied.
    /// </summary>
    Unknown,

    /// <summary>
    /// A repository-relative path.
    /// </summary>
    RepositoryRelative,

    /// <summary>
    /// A POSIX absolute path.
    /// </summary>
    PosixAbsolute,

    /// <summary>
    /// A Windows drive-absolute path such as <c>C:\repo\file.cs</c>.
    /// </summary>
    DriveAbsolute,

    /// <summary>
    /// A Windows drive-relative path such as <c>C:file.cs</c>.
    /// </summary>
    DriveRelative,

    /// <summary>
    /// A Windows root-relative path such as <c>\repo\file.cs</c>.
    /// </summary>
    RootRelative,

    /// <summary>
    /// A UNC path.
    /// </summary>
    Unc,

    /// <summary>
    /// A Windows device path.
    /// </summary>
    Device,

    /// <summary>
    /// A Windows device UNC path.
    /// </summary>
    DeviceUnc,

    /// <summary>
    /// A file URI.
    /// </summary>
    FileUri,

    /// <summary>
    /// A non-file URI that remains outside the repository namespace.
    /// </summary>
    ExternalUri,
}

/// <summary>
/// Identifies configured path comparison case semantics.
/// </summary>
public enum PathCaseSensitivity
{
    /// <summary>
    /// Compare path text using ordinal case-sensitive semantics.
    /// </summary>
    Sensitive,

    /// <summary>
    /// Compare ASCII path text without case sensitivity.
    /// </summary>
    AsciiInsensitive,
}

/// <summary>
/// Records one observable canonicalisation transformation.
/// </summary>
public sealed record TransformationRecord
{
    /// <summary>
    /// Initializes a transformation record.
    /// </summary>
    /// <param name="kind">The stable transformation identifier.</param>
    /// <param name="originalValue">The value before transformation.</param>
    /// <param name="transformedValue">The value after transformation.</param>
    /// <param name="isLossy">Whether information was discarded.</param>
    /// <param name="algorithmVersion">The versioned algorithm identifier.</param>
    public TransformationRecord(
        string kind,
        string? originalValue,
        string? transformedValue,
        bool isLossy,
        string algorithmVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmVersion);

        Kind = kind;
        OriginalValue = originalValue;
        TransformedValue = transformedValue;
        IsLossy = isLossy;
        AlgorithmVersion = algorithmVersion;
    }

    /// <summary>
    /// Gets the stable transformation identifier.
    /// </summary>
    public string Kind { get; }

    /// <summary>
    /// Gets the value before transformation.
    /// </summary>
    public string? OriginalValue { get; }

    /// <summary>
    /// Gets the value after transformation.
    /// </summary>
    public string? TransformedValue { get; }

    /// <summary>
    /// Gets whether information was discarded.
    /// </summary>
    public bool IsLossy { get; }

    /// <summary>
    /// Gets the versioned algorithm identifier.
    /// </summary>
    public string AlgorithmVersion { get; }
}

/// <summary>
/// Preserves original, logically resolved, and canonical path values.
/// </summary>
public sealed record CanonicalPath
{
    /// <summary>
    /// Initializes a canonical path.
    /// </summary>
    /// <param name="originalValue">The original lexical input.</param>
    /// <param name="resolvedValue">The logically resolved value.</param>
    /// <param name="canonicalUri">The canonical comparison URI.</param>
    /// <param name="repositoryRelativePath">The repository-relative path, when known.</param>
    /// <param name="kind">The original lexical path kind.</param>
    /// <param name="transformations">Applied transformations.</param>
    /// <param name="diagnostics">Path-specific diagnostics.</param>
    public CanonicalPath(
        string originalValue,
        string? resolvedValue,
        string canonicalUri,
        string? repositoryRelativePath,
        PathKind kind,
        IEnumerable<TransformationRecord>? transformations = null,
        IEnumerable<Diagnostic>? diagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(originalValue);
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalUri);

        OriginalValue = originalValue;
        ResolvedValue = resolvedValue;
        CanonicalUri = canonicalUri;
        RepositoryRelativePath = repositoryRelativePath;
        Kind = kind;
        Transformations = transformations?.ToImmutableArray()
            ?? ImmutableArray<TransformationRecord>.Empty;
        Diagnostics = Diagnostic.Sort(diagnostics ?? []);
    }

    /// <summary>
    /// Gets the original lexical input.
    /// </summary>
    public string OriginalValue { get; }

    /// <summary>
    /// Gets the logically resolved value.
    /// </summary>
    public string? ResolvedValue { get; }

    /// <summary>
    /// Gets the canonical comparison URI.
    /// </summary>
    public string CanonicalUri { get; }

    /// <summary>
    /// Gets the repository-relative path, when known.
    /// </summary>
    public string? RepositoryRelativePath { get; }

    /// <summary>
    /// Gets the original lexical path kind.
    /// </summary>
    public PathKind Kind { get; }

    /// <summary>
    /// Gets the applied transformations in deterministic order.
    /// </summary>
    public ImmutableArray<TransformationRecord> Transformations { get; }

    /// <summary>
    /// Gets path-specific diagnostics.
    /// </summary>
    public ImmutableArray<Diagnostic> Diagnostics { get; }
}
