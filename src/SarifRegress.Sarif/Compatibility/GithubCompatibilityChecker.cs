using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.Sarif.Compatibility;

/// <summary>
/// Defines documented GitHub code-scanning SARIF limits independently of network state.
/// </summary>
public sealed record GithubCompatibilityLimits
{
    /// <summary>
    /// Gets the documented default compatibility limits.
    /// </summary>
    public static GithubCompatibilityLimits Default { get; } = new();

    /// <summary>
    /// Gets the maximum compressed upload size.
    /// </summary>
    public long MaximumCompressedUploadBytes { get; init; } = 10L * 1024L * 1024L;

    /// <summary>
    /// Gets the maximum runs per file.
    /// </summary>
    public int MaximumRunsPerFile { get; init; } = 20;

    /// <summary>
    /// Gets the hard result limit per run.
    /// </summary>
    public int MaximumResultsPerRun { get; init; } = 25_000;

    /// <summary>
    /// Gets the result display limit per run.
    /// </summary>
    public int SoftResultsPerRun { get; init; } = 5_000;

    /// <summary>
    /// Gets the maximum rules per run.
    /// </summary>
    public int MaximumRulesPerRun { get; init; } = 25_000;

    /// <summary>
    /// Gets the maximum tool extensions per run.
    /// </summary>
    public int MaximumExtensionsPerRun { get; init; } = 100;

    /// <summary>
    /// Gets the hard thread-flow-location limit per result.
    /// </summary>
    public int MaximumThreadFlowLocationsPerResult { get; init; } = 10_000;

    /// <summary>
    /// Gets the thread-flow-location display limit per result.
    /// </summary>
    public int SoftThreadFlowLocationsPerResult { get; init; } = 1_000;

    /// <summary>
    /// Gets the hard location limit per result.
    /// </summary>
    public int MaximumLocationsPerResult { get; init; } = 1_000;

    /// <summary>
    /// Gets the location display limit per result.
    /// </summary>
    public int SoftLocationsPerResult { get; init; } = 100;

    /// <summary>
    /// Gets the hard tag limit per reporting descriptor.
    /// </summary>
    public int MaximumTagsPerRule { get; init; } = 20;

    /// <summary>
    /// Gets the displayed tag limit per reporting descriptor.
    /// </summary>
    public int SoftTagsPerRule { get; init; } = 10;

    /// <summary>
    /// Gets the repository alert limit.
    /// </summary>
    public int MaximumRepositoryAlerts { get; init; } = 1_000_000;

    /// <summary>
    /// Validates every injected limit.
    /// </summary>
    public void Validate()
    {
        ValidatePositive(MaximumCompressedUploadBytes, nameof(MaximumCompressedUploadBytes));
        ValidatePositive(MaximumRunsPerFile, nameof(MaximumRunsPerFile));
        ValidatePositive(MaximumResultsPerRun, nameof(MaximumResultsPerRun));
        ValidatePositive(SoftResultsPerRun, nameof(SoftResultsPerRun));
        ValidatePositive(MaximumRulesPerRun, nameof(MaximumRulesPerRun));
        ValidatePositive(MaximumExtensionsPerRun, nameof(MaximumExtensionsPerRun));
        ValidatePositive(
            MaximumThreadFlowLocationsPerResult,
            nameof(MaximumThreadFlowLocationsPerResult));
        ValidatePositive(
            SoftThreadFlowLocationsPerResult,
            nameof(SoftThreadFlowLocationsPerResult));
        ValidatePositive(MaximumLocationsPerResult, nameof(MaximumLocationsPerResult));
        ValidatePositive(SoftLocationsPerResult, nameof(SoftLocationsPerResult));
        ValidatePositive(MaximumTagsPerRule, nameof(MaximumTagsPerRule));
        ValidatePositive(SoftTagsPerRule, nameof(SoftTagsPerRule));
        ValidatePositive(MaximumRepositoryAlerts, nameof(MaximumRepositoryAlerts));

        if (SoftResultsPerRun > MaximumResultsPerRun ||
            SoftThreadFlowLocationsPerResult >
                MaximumThreadFlowLocationsPerResult ||
            SoftLocationsPerResult > MaximumLocationsPerResult ||
            SoftTagsPerRule > MaximumTagsPerRule)
        {
            throw new ArgumentException(
                "A GitHub display limit cannot exceed its corresponding hard limit.");
        }
    }

    private static void ValidatePositive(long value, string parameterName)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                value,
                "GitHub compatibility limits must be positive.");
        }
    }
}

/// <summary>
/// Performs deterministic, advisory checks against documented GitHub code-scanning behaviour.
/// </summary>
public sealed class GithubCompatibilityChecker
{
    /// <summary>
    /// Gets the pinned documentation basis for emitted diagnostics.
    /// </summary>
    public const string StandardBasis =
        "github-supported-subset-2026-07-30";

    private const string SupportedSarifVersion = "2.1.0";
    private readonly GithubCompatibilityLimits limits;

    /// <summary>
    /// Initializes an offline compatibility checker with injected limits.
    /// </summary>
    /// <param name="limits">The documented compatibility limits.</param>
    public GithubCompatibilityChecker(
        GithubCompatibilityLimits? limits = null)
    {
        this.limits = limits ?? GithubCompatibilityLimits.Default;
        this.limits.Validate();
    }

    /// <summary>
    /// Checks retained aggregate facts without performing upload or network emulation.
    /// </summary>
    /// <param name="summary">The ingestion summary.</param>
    /// <returns>Advisory diagnostics in deterministic order.</returns>
    public ImmutableArray<Diagnostic> Check(SarifDocumentSummary summary)
    {
        ArgumentNullException.ThrowIfNull(summary);
        var diagnostics = new List<Diagnostic>();
        var documentReference = CreateReference(summary.Input, null, "");

        if (!string.Equals(
                summary.Version,
                SupportedSarifVersion,
                StringComparison.Ordinal))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0001",
                    DiagnosticSeverity.Warning,
                    $"GitHub code scanning supports SARIF version {SupportedSarifVersion}.",
                    documentReference));
        }

        if (summary.CompressedUploadBytes > limits.MaximumCompressedUploadBytes)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0002",
                    DiagnosticSeverity.Warning,
                    $"The compressed SARIF upload exceeds GitHub's documented {limits.MaximumCompressedUploadBytes}-byte limit.",
                    documentReference));
        }

        if (summary.Runs.Length > limits.MaximumRunsPerFile)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0003",
                    DiagnosticSeverity.Warning,
                    $"The SARIF file exceeds GitHub's documented {limits.MaximumRunsPerFile}-run limit.",
                    CreateReference(summary.Input, null, "/runs")));
        }

        long totalResults = 0;
        foreach (var run in summary.Runs.OrderBy(item => item.RunIndex))
        {
            totalResults += run.ResultCount;
            CheckRun(summary.Input, run, diagnostics);
        }

        if (totalResults > limits.MaximumRepositoryAlerts)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0014",
                    DiagnosticSeverity.Warning,
                    $"The SARIF result count exceeds GitHub's documented {limits.MaximumRepositoryAlerts}-alert repository limit.",
                    CreateReference(summary.Input, null, "/runs"),
                    "Result count is an upper-bound compatibility signal; GitHub alert deduplication is not emulated."));
        }

        return Diagnostic.Sort(diagnostics);
    }

    private void CheckRun(
        InputKind input,
        SarifRunSummary run,
        ICollection<Diagnostic> diagnostics)
    {
        var runPointer = $"/runs/{run.RunIndex}";
        var runReference = CreateReference(input, run.RunIndex, runPointer);
        AddThresholdDiagnostic(
            diagnostics,
            run.ResultCount,
            limits.MaximumResultsPerRun,
            "GHCS0004",
            $"The run exceeds GitHub's documented {limits.MaximumResultsPerRun}-result limit.",
            runReference);
        AddThresholdDiagnostic(
            diagnostics,
            run.ResultCount,
            limits.SoftResultsPerRun,
            "GHCS0005",
            $"GitHub displays only the first {limits.SoftResultsPerRun} results per run.",
            runReference,
            DiagnosticSeverity.Note);
        AddThresholdDiagnostic(
            diagnostics,
            run.RuleCount,
            limits.MaximumRulesPerRun,
            "GHCS0006",
            $"The run exceeds GitHub's documented {limits.MaximumRulesPerRun}-rule limit.",
            runReference);
        AddThresholdDiagnostic(
            diagnostics,
            run.ExtensionCount,
            limits.MaximumExtensionsPerRun,
            "GHCS0007",
            $"The run exceeds GitHub's documented {limits.MaximumExtensionsPerRun}-extension limit.",
            runReference);
        AddThresholdDiagnostic(
            diagnostics,
            run.MaximumThreadFlowLocationsPerResult,
            limits.MaximumThreadFlowLocationsPerResult,
            "GHCS0008",
            $"A result exceeds GitHub's documented {limits.MaximumThreadFlowLocationsPerResult}-thread-flow-location limit.",
            runReference);
        AddThresholdDiagnostic(
            diagnostics,
            run.MaximumThreadFlowLocationsPerResult,
            limits.SoftThreadFlowLocationsPerResult,
            "GHCS0009",
            $"GitHub displays only the first {limits.SoftThreadFlowLocationsPerResult} thread-flow locations.",
            runReference,
            DiagnosticSeverity.Note);
        AddThresholdDiagnostic(
            diagnostics,
            run.MaximumLocationsPerResult,
            limits.MaximumLocationsPerResult,
            "GHCS0010",
            $"A result exceeds GitHub's documented {limits.MaximumLocationsPerResult}-location limit.",
            runReference);
        AddThresholdDiagnostic(
            diagnostics,
            run.MaximumLocationsPerResult,
            limits.SoftLocationsPerResult,
            "GHCS0011",
            $"GitHub displays only the first {limits.SoftLocationsPerResult} locations per result.",
            runReference,
            DiagnosticSeverity.Note);
        AddThresholdDiagnostic(
            diagnostics,
            run.MaximumTagsPerRule,
            limits.MaximumTagsPerRule,
            "GHCS0015",
            $"A rule exceeds GitHub's documented {limits.MaximumTagsPerRule}-tag limit.",
            runReference);
        AddThresholdDiagnostic(
            diagnostics,
            run.MaximumTagsPerRule,
            limits.SoftTagsPerRule,
            "GHCS0016",
            $"GitHub displays only the first {limits.SoftTagsPerRule} tags per rule.",
            runReference,
            DiagnosticSeverity.Note);

        if (run.ResultsWithMultipleLocations > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0012",
                    DiagnosticSeverity.Warning,
                    "Only the first result location is used by GitHub code scanning.",
                    runReference,
                    "Secondary locations remain available for local comparison."));
        }

        if (run.ResultsWithoutPrimaryLocationLineHash > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0013",
                    DiagnosticSeverity.Note,
                    "Some results do not provide the recommended primaryLocationLineHash partial fingerprint.",
                    runReference));
        }

        if (run.NonRepositoryRelativePrimaryLocations > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0017",
                    DiagnosticSeverity.Warning,
                    "GitHub recommends repository-relative artifact locations for source files.",
                    runReference));
        }
    }

    private static void AddThresholdDiagnostic(
        ICollection<Diagnostic> diagnostics,
        int actual,
        int maximum,
        string code,
        string message,
        SourceReference sourceReference,
        DiagnosticSeverity severity = DiagnosticSeverity.Warning)
    {
        if (actual <= maximum)
        {
            return;
        }

        diagnostics.Add(
            CreateDiagnostic(code, severity, message, sourceReference));
    }

    private static Diagnostic CreateDiagnostic(
        string code,
        DiagnosticSeverity severity,
        string message,
        SourceReference sourceReference,
        string? help = null) =>
        new(
            code,
            severity,
            DiagnosticStage.GithubCompatibility,
            message,
            sourceReference,
            StandardBasis,
            help);

    private static SourceReference CreateReference(
        InputKind input,
        int? runIndex,
        string pointer) =>
        new(input, runIndex, null, pointer);
}
