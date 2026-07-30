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
    /// Null means that the upload representation was not evaluated; it must not be
    /// inferred from the raw SARIF byte count.
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
    /// Gets the caller-measured gzip payload size, or null when it was not evaluated.
    /// </summary>
    public long? CompressedUploadBytes { get; }
}

/// <summary>
/// Classifies the SARIF-provided source root used by GitHub when an upload does not supply one.
/// </summary>
public enum GithubWorkingDirectoryUriKind
{
    /// <summary>
    /// <c>invocations[0].workingDirectory.uri</c> is absent.
    /// </summary>
    Missing,

    /// <summary>
    /// The value is an absolute URI with a scheme.
    /// </summary>
    AbsoluteUri,

    /// <summary>
    /// The value is a relative URI reference.
    /// </summary>
    RelativeReference,

    /// <summary>
    /// The value is an absolute filesystem path rather than an absolute URI.
    /// </summary>
    AbsolutePath,

    /// <summary>
    /// The value has URI syntax that cannot be parsed as an absolute or relative URI.
    /// </summary>
    Invalid,
}

/// <summary>
/// Captures bounded source-root and absolute-location facts without retaining source paths.
/// </summary>
public sealed record GithubSourceRootFacts(
    int InvocationCount,
    GithubWorkingDirectoryUriKind WorkingDirectoryUriKind,
    int LaterInvocationsWithWorkingDirectory,
    int AbsoluteUriPrimaryLocations,
    int AbsolutePathPrimaryLocations,
    int ConvertibleAbsoluteUriPrimaryLocations,
    int OutsideSourceRootAbsoluteUriPrimaryLocations,
    int SourceRootSchemeMismatchPrimaryLocations);

/// <summary>
/// Counts one known property that is outside GitHub's documented supported subset.
/// </summary>
public sealed record GithubIgnoredPropertyFact(
    string PropertyPath,
    int Occurrences);

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
    int NonRepositoryRelativePrimaryLocations,
    int DriverRuleCount = 0,
    int ExtensionRuleCount = 0,
    int MaximumPartialFingerprintsPerResult = 0,
    int ResultsWithoutDisplayLocation = 0,
    GithubSourceRootFacts? SourceRootFacts = null,
    ImmutableArray<GithubIgnoredPropertyFact> IgnoredProperties = default);

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
