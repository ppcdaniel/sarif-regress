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
/// The checker uses a finite retained projection and is not an ingestion, prioritization,
/// deduplication, or repository-state emulator.
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
                    DiagnosticSeverity.Note,
                    $"The file contains more results than GitHub's documented {limits.MaximumRepositoryAlerts}-alert repository limit.",
                    CreateReference(summary.Input, null, "/runs"),
                    "The limit applies to unique alerts across a repository. This file-level result count is only a review signal; SarifRegress does not emulate GitHub alert deduplication or repository state."));
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
            $"GitHub includes only the top {limits.SoftResultsPerRun} results per run after prioritizing by severity.",
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
            $"GitHub includes only {limits.SoftThreadFlowLocationsPerResult} thread-flow locations using its documented prioritization.",
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
            $"GitHub includes only {limits.SoftLocationsPerResult} locations per result.",
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
            $"GitHub includes only {limits.SoftTagsPerRule} tags per rule.",
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

        if (run.ResultsWithoutDisplayLocation > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0018",
                    DiagnosticSeverity.Warning,
                    "Some results have no usable first physical location for GitHub display.",
                    runReference,
                    "GitHub requires at least one result location to display an alert and uses only locations[0] as the primary location."));
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

        CheckSourceRoots(run, runReference, diagnostics);
        foreach (var property in
                 NormalizeIgnoredProperties(run.IgnoredProperties))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0023",
                    DiagnosticSeverity.Note,
                    CreateIgnoredPropertyMessage(property),
                    runReference,
                    "The property remains available to SarifRegress where its supported subset uses it; this advisory describes only GitHub's documented subset."));
        }
    }

    private static void CheckSourceRoots(
        SarifRunSummary run,
        SourceReference runReference,
        ICollection<Diagnostic> diagnostics)
    {
        var facts = run.SourceRootFacts;
        if (facts is null)
        {
            if (run.NonRepositoryRelativePrimaryLocations > 0)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "GHCS0017",
                        DiagnosticSeverity.Warning,
                        "GitHub recommends repository-relative artifact locations for source files.",
                        runReference));
            }

            return;
        }

        if (facts.LaterInvocationsWithWorkingDirectory > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0022",
                    DiagnosticSeverity.Note,
                    "A workingDirectory URI appears after invocations[0], which is not the SARIF source-root position documented by GitHub.",
                    runReference,
                    "Place the SARIF-provided source root at invocations[0].workingDirectory.uri."));
        }

        var absoluteLocationCount =
            facts.AbsoluteUriPrimaryLocations +
            facts.AbsolutePathPrimaryLocations;
        if (absoluteLocationCount == 0)
        {
            return;
        }

        if (facts.AbsolutePathPrimaryLocations > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0017",
                    DiagnosticSeverity.Warning,
                    "Some primary artifactLocation.uri values are absolute filesystem paths rather than repository-relative references or absolute URIs.",
                    runReference,
                    "GitHub recommends repository-relative artifact URIs. Absolute locations require URI syntax and a compatible source root."));
        }

        if (facts.AbsoluteUriPrimaryLocations > 0 &&
            facts.WorkingDirectoryUriKind ==
                GithubWorkingDirectoryUriKind.Missing)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0017",
                    DiagnosticSeverity.Warning,
                    "The SARIF contains absolute primary artifact URIs but does not provide invocations[0].workingDirectory.uri.",
                    runReference,
                    "An uploader can instead supply checkout_path or checkout_uri. Without a compatible source root, GitHub cannot convert absolute URIs to repository-relative URIs."));
        }
        else if (facts.AbsoluteUriPrimaryLocations > 0 &&
                 facts.WorkingDirectoryUriKind is
                     GithubWorkingDirectoryUriKind.RelativeReference or
                     GithubWorkingDirectoryUriKind.AbsolutePath or
                     GithubWorkingDirectoryUriKind.Invalid)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0019",
                    DiagnosticSeverity.Warning,
                    "invocations[0].workingDirectory.uri is not an absolute URI suitable for converting absolute artifact URIs.",
                    runReference,
                    "Use a repository-relative artifact URI or an absolute source-root URI such as file:///workspace/."));
        }

        if (facts.SourceRootSchemeMismatchPrimaryLocations > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0020",
                    DiagnosticSeverity.Warning,
                    "Some absolute artifact URIs use a different URI scheme from invocations[0].workingDirectory.uri.",
                    runReference,
                    "When that SARIF working directory is the selected source root, GitHub documents that a scheme mismatch causes upload rejection. An explicit checkout_path or checkout_uri can take precedence."));
        }

        if (facts.OutsideSourceRootAbsoluteUriPrimaryLocations > 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0021",
                    DiagnosticSeverity.Note,
                    "Some absolute artifact URIs are outside the SARIF-provided working-directory source root.",
                    runReference,
                    "GitHub leaves same-scheme URIs outside the source root absolute. The upload is not rejected for that reason alone, but those locations may not map to committed repository files."));
        }

        var classifiedLocations =
            facts.AbsoluteUriPrimaryLocations +
            facts.AbsolutePathPrimaryLocations;
        if (run.NonRepositoryRelativePrimaryLocations >
            classifiedLocations)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "GHCS0017",
                    DiagnosticSeverity.Warning,
                    "Some primary artifact locations are not repository-relative source paths.",
                    runReference,
                    "GitHub recommends repository-relative artifact URIs for source files."));
        }
    }

    private static ImmutableArray<GithubIgnoredPropertyFact>
        NormalizeIgnoredProperties(
            ImmutableArray<GithubIgnoredPropertyFact> properties) =>
        properties.IsDefault
            ? []
            : properties
                .Where(
                    property =>
                        property is not null &&
                        !string.IsNullOrWhiteSpace(property.PropertyPath) &&
                        property.Occurrences > 0)
                .OrderBy(
                    property => property.PropertyPath,
                    StringComparer.Ordinal)
                .ThenBy(property => property.Occurrences)
                .ToImmutableArray();

    private static string CreateIgnoredPropertyMessage(
        GithubIgnoredPropertyFact property)
    {
        var occurrences = property.Occurrences == 1
            ? "1 occurrence"
            : $"{property.Occurrences} occurrences";
        if (string.Equals(
                property.PropertyPath,
                "result.fingerprints",
                StringComparison.Ordinal))
        {
            return $"GitHub's documented subset does not use result.fingerprints ({occurrences}); alert identity uses partialFingerprints and only primaryLocationLineHash is used.";
        }

        if (string.Equals(
                property.PropertyPath,
                "automationDetails.id.runId",
                StringComparison.Ordinal))
        {
            return $"GitHub stores but does not use the run-id component of automationDetails.id ({occurrences}).";
        }

        return $"GitHub's documented supported-property subset does not use {property.PropertyPath} ({occurrences}).";
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
