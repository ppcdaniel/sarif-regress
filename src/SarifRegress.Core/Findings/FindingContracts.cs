using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Paths;

namespace SarifRegress.Core.Findings;

/// <summary>
/// Identifies one producer run without exposing the SARIF wire model.
/// </summary>
public sealed record RunIdentity(
    int RunIndex,
    string? AutomationCategory,
    string StableRunKey);

/// <summary>
/// Identifies a static-analysis producer family and observed version.
/// </summary>
public sealed record ProducerIdentity(
    string ToolName,
    string? ToolVersion,
    string Family,
    string? AutomationCategory);

/// <summary>
/// Preserves original and canonical rule identities.
/// </summary>
public sealed record RuleIdentity(
    string OriginalId,
    string CanonicalId,
    bool AliasApplied);

/// <summary>
/// Represents a one-based SARIF region.
/// </summary>
public sealed record Region
{
    /// <summary>
    /// Initializes a region.
    /// </summary>
    public Region(
        int? startLine,
        int? startColumn,
        int? endLine,
        int? endColumn)
    {
        if (!startLine.HasValue)
        {
            throw new ArgumentException(
                "A line-and-column SARIF region must specify a start line.",
                nameof(startLine));
        }

        ValidatePositive(startLine, nameof(startLine));
        ValidatePositive(startColumn, nameof(startColumn));
        ValidatePositive(endLine, nameof(endLine));
        ValidatePositive(endColumn, nameof(endColumn));

        if (startLine.HasValue && endLine.HasValue && endLine < startLine)
        {
            throw new ArgumentException("The end line cannot precede the start line.");
        }

        var effectiveEndLine = endLine ?? startLine.Value;
        var effectiveStartColumn = startColumn ?? 1;
        if (effectiveEndLine == startLine.Value &&
            endColumn.HasValue &&
            endColumn.Value < effectiveStartColumn)
        {
            throw new ArgumentException(
                "The end column cannot precede the start column on the same line.");
        }

        StartLine = startLine;
        StartColumn = startColumn;
        EndLine = endLine;
        EndColumn = endColumn;
    }

    /// <summary>
    /// Gets the one-based start line.
    /// </summary>
    public int? StartLine { get; }

    /// <summary>
    /// Gets the one-based start column.
    /// </summary>
    public int? StartColumn { get; }

    /// <summary>
    /// Gets the one-based end line.
    /// </summary>
    public int? EndLine { get; }

    /// <summary>
    /// Gets the one-based end column.
    /// </summary>
    public int? EndColumn { get; }

    private static void ValidatePositive(int? value, string parameterName)
    {
        if (value is <= 0)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                value,
                "SARIF region coordinates must be positive.");
        }
    }
}

/// <summary>
/// Represents the canonical primary physical location of a finding.
/// </summary>
public sealed record PrimaryLocation(
    CanonicalPath Path,
    Region? Region,
    string? EmbeddedSnippet);

/// <summary>
/// Preserves original and canonical message forms.
/// </summary>
public sealed record MessageIdentity(
    string OriginalText,
    string CanonicalText,
    string ComparisonText,
    ImmutableArray<string> NormalisationFlags);

/// <summary>
/// Preserves selected comparison-relevant metadata from the source SARIF result.
/// </summary>
/// <remarks>
/// These values are retained for auditability only. They do not determine project-level
/// classification or matching eligibility.
/// </remarks>
public sealed record FindingMetadata(
    string? Level,
    string? Kind,
    string? BaselineState);

/// <summary>
/// Identifies whether a producer fingerprint came from a full or partial fingerprint map.
/// </summary>
public enum ProducerFingerprintSource
{
    /// <summary>
    /// The SARIF <c>fingerprints</c> property.
    /// </summary>
    Fingerprint,

    /// <summary>
    /// The SARIF <c>partialFingerprints</c> property.
    /// </summary>
    PartialFingerprint,
}

/// <summary>
/// Describes the assessed reliability of producer-supplied identity evidence.
/// </summary>
public enum FingerprintReliability
{
    /// <summary>
    /// The value is missing or cannot be interpreted safely.
    /// </summary>
    Unknown,

    /// <summary>
    /// The value collided within a coarse run-and-rule bucket.
    /// </summary>
    Degraded,

    /// <summary>
    /// The value is unique in its applicable bucket.
    /// </summary>
    High,
}

/// <summary>
/// Represents one preserved producer fingerprint.
/// </summary>
public sealed record ProducerFingerprint(
    string Name,
    string Family,
    int? Version,
    string Value,
    FingerprintReliability Reliability,
    ProducerFingerprintSource Source);

/// <summary>
/// Represents one project-namespaced derived fingerprint.
/// </summary>
public sealed record DerivedFingerprint(
    string Name,
    string Value,
    string AlgorithmVersion);

/// <summary>
/// Represents bounded source-context evidence.
/// </summary>
public sealed record ContextEvidence(
    string? SnippetHash,
    string? TokenWindowHash,
    string? EnclosingSymbol,
    int? StartLine,
    int? EndLine);

/// <summary>
/// Represents a canonical supporting location.
/// </summary>
public sealed record RelatedLocation(
    CanonicalPath? Path,
    Region? Region,
    string StableKey);

/// <summary>
/// Represents one bounded, canonical code-flow anchor.
/// </summary>
public sealed record CodeFlowAnchor(
    string CanonicalPath,
    string? ContextHash,
    int Ordinal);

/// <summary>
/// Represents sorted supporting code-flow evidence.
/// </summary>
public sealed record CodeFlowEvidence(ImmutableArray<CodeFlowAnchor> Anchors);

/// <summary>
/// Represents one immutable canonical finding consumed by the matching core.
/// </summary>
public sealed record Finding
{
    /// <summary>
    /// Initializes a canonical finding.
    /// </summary>
    public Finding(
        string findingKey,
        SourceReference sourceReference,
        RunIdentity run,
        ProducerIdentity producer,
        RuleIdentity rule,
        PrimaryLocation? primaryLocation,
        MessageIdentity message,
        IEnumerable<ProducerFingerprint>? producerFingerprints = null,
        IEnumerable<DerivedFingerprint>? derivedFingerprints = null,
        ContextEvidence? context = null,
        IEnumerable<RelatedLocation>? relatedLocations = null,
        CodeFlowEvidence? codeFlow = null,
        IEnumerable<string>? lossiness = null,
        IEnumerable<Diagnostic>? diagnostics = null,
        FindingMetadata? metadata = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(findingKey);
        ArgumentNullException.ThrowIfNull(sourceReference);
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(producer);
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(message);

        FindingKey = findingKey;
        SourceReference = sourceReference;
        Run = run;
        Producer = producer;
        Rule = rule;
        PrimaryLocation = primaryLocation;
        Message = message;
        ProducerFingerprints = NormalizeProducerFingerprints(
            producerFingerprints);
        DerivedFingerprints = NormalizeDerivedFingerprints(
            derivedFingerprints);
        Context = context;
        RelatedLocations = NormalizeRelatedLocations(relatedLocations);
        CodeFlow = codeFlow;
        Metadata = metadata ?? new FindingMetadata(
            Level: null,
            Kind: null,
            BaselineState: null);
        Lossiness = NormalizeLossiness(lossiness);
        Diagnostics = diagnostics is null
            ? ImmutableArray<Diagnostic>.Empty
            : Diagnostic.Sort(diagnostics);
    }

    private static ImmutableArray<ProducerFingerprint>
        NormalizeProducerFingerprints(
            IEnumerable<ProducerFingerprint>? producerFingerprints)
    {
        if (TryGetTrivialSequence(producerFingerprints, out var normalized))
        {
            return normalized;
        }

        return producerFingerprints!
            .OrderBy(item => item.Family, StringComparer.Ordinal)
            .ThenByDescending(item => item.Version)
            .ThenBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Value, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static ImmutableArray<DerivedFingerprint>
        NormalizeDerivedFingerprints(
            IEnumerable<DerivedFingerprint>? derivedFingerprints)
    {
        if (TryGetTrivialSequence(derivedFingerprints, out var normalized))
        {
            return normalized;
        }

        return derivedFingerprints!
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Value, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static ImmutableArray<RelatedLocation> NormalizeRelatedLocations(
        IEnumerable<RelatedLocation>? relatedLocations)
    {
        if (TryGetTrivialSequence(relatedLocations, out var normalized))
        {
            return normalized;
        }

        return relatedLocations!
            .OrderBy(item => item.StableKey, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static ImmutableArray<string> NormalizeLossiness(
        IEnumerable<string>? lossiness)
    {
        if (TryGetTrivialSequence(lossiness, out var normalized))
        {
            return normalized;
        }

        return lossiness!
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static bool TryGetTrivialSequence<T>(
        IEnumerable<T>? items,
        out ImmutableArray<T> normalized)
    {
        if (items is null)
        {
            normalized = ImmutableArray<T>.Empty;
            return true;
        }

        if (items is ImmutableArray<T> immutable)
        {
            if (immutable.IsDefault || immutable.Length > 1)
            {
                normalized = default;
                return false;
            }

            normalized = immutable;
            return true;
        }

        if (!items.TryGetNonEnumeratedCount(out var count) || count > 1)
        {
            normalized = default;
            return false;
        }

        normalized = count == 0
            ? ImmutableArray<T>.Empty
            : items.ToImmutableArray();
        return true;
    }

    /// <summary>
    /// Gets the deterministic per-input finding key.
    /// </summary>
    public string FindingKey { get; }

    /// <summary>
    /// Gets the source reference.
    /// </summary>
    public SourceReference SourceReference { get; }

    /// <summary>
    /// Gets the run identity.
    /// </summary>
    public RunIdentity Run { get; }

    /// <summary>
    /// Gets the producer identity.
    /// </summary>
    public ProducerIdentity Producer { get; }

    /// <summary>
    /// Gets the rule identity.
    /// </summary>
    public RuleIdentity Rule { get; }

    /// <summary>
    /// Gets the primary location.
    /// </summary>
    public PrimaryLocation? PrimaryLocation { get; }

    /// <summary>
    /// Gets the canonical message identity.
    /// </summary>
    public MessageIdentity Message { get; }

    /// <summary>
    /// Gets producer-supplied fingerprints.
    /// </summary>
    public ImmutableArray<ProducerFingerprint> ProducerFingerprints { get; }

    /// <summary>
    /// Gets project-derived fingerprints.
    /// </summary>
    public ImmutableArray<DerivedFingerprint> DerivedFingerprints { get; }

    /// <summary>
    /// Gets source-context evidence.
    /// </summary>
    public ContextEvidence? Context { get; }

    /// <summary>
    /// Gets sorted supporting locations.
    /// </summary>
    public ImmutableArray<RelatedLocation> RelatedLocations { get; }

    /// <summary>
    /// Gets bounded code-flow evidence.
    /// </summary>
    public CodeFlowEvidence? CodeFlow { get; }

    /// <summary>
    /// Gets selected source SARIF metadata retained for auditability.
    /// </summary>
    public FindingMetadata Metadata { get; }

    /// <summary>
    /// Gets stable lossiness identifiers.
    /// </summary>
    public ImmutableArray<string> Lossiness { get; }

    /// <summary>
    /// Gets finding-specific diagnostics.
    /// </summary>
    public ImmutableArray<Diagnostic> Diagnostics { get; }
}

/// <summary>
/// Represents all canonical findings and diagnostics from one logical input.
/// </summary>
public sealed record ComparisonInput(
    InputKind Input,
    string LogicalName,
    ImmutableArray<Finding> Findings,
    ImmutableArray<Diagnostic> Diagnostics);
