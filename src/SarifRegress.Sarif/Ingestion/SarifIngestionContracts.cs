using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;

namespace SarifRegress.Sarif.Ingestion;

/// <summary>
/// Describes one logical SARIF input and the configuration used to canonicalise it.
/// </summary>
public sealed record SarifIngestionRequest
{
    /// <summary>
    /// Initializes an ingestion request.
    /// </summary>
    /// <param name="input">The logical comparison side.</param>
    /// <param name="logicalName">A stable, user-facing input name.</param>
    /// <param name="configuration">The validated comparison configuration.</param>
    /// <param name="compressedUploadBytes">
    /// The compressed upload size, when a caller has already produced a gzip payload.
    /// </param>
    public SarifIngestionRequest(
        InputKind input,
        string logicalName,
        SarifRegressConfiguration? configuration = null,
        long? compressedUploadBytes = null)
    {
        if (input is not InputKind.Baseline and not InputKind.Candidate)
        {
            throw new ArgumentOutOfRangeException(
                nameof(input),
                input,
                "A SARIF comparison input must be baseline or candidate.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(logicalName);
        if (compressedUploadBytes is < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(compressedUploadBytes),
                compressedUploadBytes,
                "A compressed size cannot be negative.");
        }

        Input = input;
        LogicalName = logicalName;
        Configuration = configuration ?? SarifRegressConfiguration.Default;
        CompressedUploadBytes = compressedUploadBytes;
    }

    /// <summary>
    /// Gets the logical comparison side.
    /// </summary>
    public InputKind Input { get; }

    /// <summary>
    /// Gets the stable input name.
    /// </summary>
    public string LogicalName { get; }

    /// <summary>
    /// Gets the immutable canonicalisation configuration.
    /// </summary>
    public SarifRegressConfiguration Configuration { get; }

    /// <summary>
    /// Gets the optional compressed upload size.
    /// </summary>
    public long? CompressedUploadBytes { get; }
}

/// <summary>
/// Captures GitHub-relevant aggregate facts for one SARIF run without retaining its wire model.
/// </summary>
public sealed record SarifRunSummary(
    int RunIndex,
    int ResultCount,
    int RuleCount,
    int ExtensionCount,
    int MaximumLocationsPerResult,
    int MaximumThreadFlowLocationsPerResult,
    int MaximumTagsPerRule,
    int ResultsWithMultipleLocations,
    int ResultsWithoutPrimaryLocationLineHash,
    int NonRepositoryRelativePrimaryLocations);

/// <summary>
/// Captures bounded aggregate facts about one deserialised SARIF document.
/// </summary>
public sealed record SarifDocumentSummary(
    InputKind Input,
    string? Version,
    long InputBytes,
    long? CompressedUploadBytes,
    ImmutableArray<SarifRunSummary> Runs);

/// <summary>
/// Returns canonical findings together with aggregate compatibility facts.
/// </summary>
public sealed record SarifIngestionResult(
    ComparisonInput ComparisonInput,
    SarifDocumentSummary Summary)
{
    /// <summary>
    /// Gets whether ingestion completed without an error diagnostic.
    /// </summary>
    public bool IsValid =>
        ComparisonInput.Diagnostics.All(
            diagnostic => diagnostic.Severity != DiagnosticSeverity.Error);
}
