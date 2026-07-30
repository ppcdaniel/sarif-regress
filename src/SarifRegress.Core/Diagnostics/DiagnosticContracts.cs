using System.Collections.Immutable;

namespace SarifRegress.Core.Diagnostics;

/// <summary>
/// Identifies the logical input that produced a source reference.
/// </summary>
public enum InputKind
{
    /// <summary>
    /// The baseline SARIF input.
    /// </summary>
    Baseline,

    /// <summary>
    /// The candidate SARIF input.
    /// </summary>
    Candidate,

    /// <summary>
    /// The comparison configuration input.
    /// </summary>
    Configuration,

    /// <summary>
    /// A corpus label or case definition.
    /// </summary>
    Corpus,
}

/// <summary>
/// Identifies diagnostic severity without relying on provider-specific labels.
/// </summary>
public enum DiagnosticSeverity
{
    /// <summary>
    /// Informational detail that does not affect processing.
    /// </summary>
    Note,

    /// <summary>
    /// A recoverable condition that may reduce fidelity.
    /// </summary>
    Warning,

    /// <summary>
    /// A condition that invalidates the affected operation.
    /// </summary>
    Error,
}

/// <summary>
/// Identifies the deterministic processing stage that emitted a diagnostic.
/// </summary>
public enum DiagnosticStage
{
    /// <summary>
    /// Input/output handling.
    /// </summary>
    Io,

    /// <summary>
    /// JSON tokenisation or deserialisation.
    /// </summary>
    Parse,

    /// <summary>
    /// SARIF or configuration structural validation.
    /// </summary>
    Schema,

    /// <summary>
    /// Supported-subset handling.
    /// </summary>
    Unsupported,

    /// <summary>
    /// Canonicalisation.
    /// </summary>
    Canonicalisation,

    /// <summary>
    /// Repository-context access.
    /// </summary>
    Repository,

    /// <summary>
    /// Fingerprint derivation or assessment.
    /// </summary>
    Fingerprint,

    /// <summary>
    /// Candidate generation or matching.
    /// </summary>
    Match,

    /// <summary>
    /// GitHub code-scanning compatibility checks.
    /// </summary>
    GithubCompatibility,

    /// <summary>
    /// Security-limit or containment enforcement.
    /// </summary>
    Security,

    /// <summary>
    /// Reporting or export.
    /// </summary>
    Report,

    /// <summary>
    /// An internal invariant.
    /// </summary>
    Internal,
}

/// <summary>
/// Locates an input-derived value using stable logical indexes and an RFC 6901 JSON Pointer.
/// </summary>
public sealed record SourceReference
{
    /// <summary>
    /// Initializes a source reference.
    /// </summary>
    /// <param name="input">The logical input.</param>
    /// <param name="runIndex">The zero-based run index, when applicable.</param>
    /// <param name="resultIndex">The zero-based result index, when applicable.</param>
    /// <param name="jsonPointer">The RFC 6901 JSON Pointer.</param>
    public SourceReference(
        InputKind input,
        int? runIndex,
        int? resultIndex,
        string jsonPointer)
    {
        if (runIndex is < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(runIndex),
                runIndex,
                "Run indexes cannot be negative.");
        }

        if (resultIndex is < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(resultIndex),
                resultIndex,
                "Result indexes cannot be negative.");
        }

        ArgumentNullException.ThrowIfNull(jsonPointer);
        if (jsonPointer.Length > 0 && jsonPointer[0] != '/')
        {
            throw new ArgumentException(
                "A JSON Pointer must be empty or begin with '/'.",
                nameof(jsonPointer));
        }

        Input = input;
        RunIndex = runIndex;
        ResultIndex = resultIndex;
        JsonPointer = jsonPointer;
    }

    /// <summary>
    /// Gets the logical input.
    /// </summary>
    public InputKind Input { get; }

    /// <summary>
    /// Gets the zero-based run index.
    /// </summary>
    public int? RunIndex { get; }

    /// <summary>
    /// Gets the zero-based result index.
    /// </summary>
    public int? ResultIndex { get; }

    /// <summary>
    /// Gets the RFC 6901 JSON Pointer.
    /// </summary>
    public string JsonPointer { get; }

    /// <summary>
    /// Escapes one JSON Pointer path segment according to RFC 6901.
    /// </summary>
    /// <param name="segment">The unescaped segment.</param>
    /// <returns>The escaped segment.</returns>
    public static string EscapePointerSegment(string segment)
    {
        ArgumentNullException.ThrowIfNull(segment);
        return segment
            .Replace("~", "~0", StringComparison.Ordinal)
            .Replace("/", "~1", StringComparison.Ordinal);
    }
}

/// <summary>
/// Represents one deterministic, source-addressable diagnostic.
/// </summary>
public sealed record Diagnostic
{
    /// <summary>
    /// Initializes a diagnostic.
    /// </summary>
    /// <param name="code">The stable diagnostic code.</param>
    /// <param name="severity">The diagnostic severity.</param>
    /// <param name="stage">The processing stage.</param>
    /// <param name="message">The deterministic message.</param>
    /// <param name="sourceReference">The optional source location.</param>
    /// <param name="standardBasis">The optional normative or advisory basis.</param>
    /// <param name="help">The optional deterministic remediation text.</param>
    public Diagnostic(
        string code,
        DiagnosticSeverity severity,
        DiagnosticStage stage,
        string message,
        SourceReference? sourceReference = null,
        string? standardBasis = null,
        string? help = null)
    {
        if (!IsValidCode(code))
        {
            throw new ArgumentException(
                "A diagnostic code must contain an uppercase family and four digits.",
                nameof(code));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        Code = code;
        Severity = severity;
        Stage = stage;
        Message = message;
        SourceReference = sourceReference;
        StandardBasis = NormalizeOptional(standardBasis);
        Help = NormalizeOptional(help);
    }

    /// <summary>
    /// Gets the stable diagnostic code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets the diagnostic severity.
    /// </summary>
    public DiagnosticSeverity Severity { get; }

    /// <summary>
    /// Gets the processing stage.
    /// </summary>
    public DiagnosticStage Stage { get; }

    /// <summary>
    /// Gets the deterministic human-readable message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Gets the source location, when available.
    /// </summary>
    public SourceReference? SourceReference { get; }

    /// <summary>
    /// Gets the normative or advisory basis, when available.
    /// </summary>
    public string? StandardBasis { get; }

    /// <summary>
    /// Gets deterministic remediation guidance, when available.
    /// </summary>
    public string? Help { get; }

    /// <summary>
    /// Sorts diagnostics by their stable public-contract order.
    /// </summary>
    /// <param name="diagnostics">The diagnostics to sort.</param>
    /// <returns>An immutable, deterministically ordered array.</returns>
    public static ImmutableArray<Diagnostic> Sort(IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        return diagnostics
            .OrderBy(item => item.Stage)
            .ThenBy(item => item.Code, StringComparer.Ordinal)
            .ThenBy(item => item.SourceReference?.Input)
            .ThenBy(item => item.SourceReference?.RunIndex)
            .ThenBy(item => item.SourceReference?.ResultIndex)
            .ThenBy(
                item => item.SourceReference?.JsonPointer ?? string.Empty,
                StringComparer.Ordinal)
            .ThenBy(item => item.Message, StringComparer.Ordinal)
            .ThenBy(item => item.Severity)
            .ThenBy(item => item.StandardBasis ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.Help ?? string.Empty, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static bool IsValidCode(string? code)
    {
        if (string.IsNullOrEmpty(code) || code.Length < 5)
        {
            return false;
        }

        var familyLength = code.Length - 4;
        for (var index = 0; index < familyLength; index++)
        {
            if (code[index] is < 'A' or > 'Z')
            {
                return false;
            }
        }

        for (var index = familyLength; index < code.Length; index++)
        {
            if (code[index] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static string? NormalizeOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
