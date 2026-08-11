using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.Sarif.Configuration;

/// <summary>
/// Returns a validated immutable configuration and deterministic diagnostics.
/// </summary>
public sealed record ConfigurationReadResult(
    SarifRegressConfiguration? Configuration,
    ImmutableArray<Diagnostic> Diagnostics,
    long InputBytes)
{
    /// <summary>
    /// Gets whether a usable configuration was produced.
    /// </summary>
    public bool IsValid =>
        Configuration is not null &&
        Diagnostics.All(item => item.Severity != DiagnosticSeverity.Error);
}

/// <summary>
/// Stream-deserialises and validates the versioned JSON configuration contract.
/// </summary>
public sealed class SarifConfigurationReader
{
    private readonly ResourceLimits readerLimits;

    /// <summary>
    /// Initializes a bounded configuration reader.
    /// </summary>
    /// <param name="readerLimits">
    /// Bootstrap limits applied before any limits inside the untrusted configuration are accepted.
    /// </param>
    public SarifConfigurationReader(ResourceLimits? readerLimits = null)
    {
        this.readerLimits = readerLimits ?? ResourceLimits.Default;
        this.readerLimits.Validate();
    }

    /// <summary>
    /// Reads one JSON configuration without resolving repository paths against process state.
    /// </summary>
    /// <param name="input">The readable UTF-8 JSON stream.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The immutable configuration and diagnostics.</returns>
    public async ValueTask<ConfigurationReadResult> ReadAsync(
        Stream input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        var diagnostics = new List<Diagnostic>();
        await using var boundedInput = new BoundedReadStream(
            input,
            readerLimits.MaximumInputBytes);

        ConfigurationWire? wire;
        try
        {
            wire = await JsonSerializer.DeserializeAsync<ConfigurationWire>(
                    boundedInput,
                    CreateJsonOptions(readerLimits, cancellationToken),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InputLimitExceededException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0010",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"The configuration exceeds the configured {readerLimits.MaximumInputBytes}-byte limit."));
            return CreateResult(null, diagnostics, boundedInput.BytesRead);
        }
        catch (JsonStringLimitExceededException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0011",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"A configuration string exceeds the configured {readerLimits.MaximumStringCharacters}-character limit."));
            return CreateResult(null, diagnostics, boundedInput.BytesRead);
        }
        catch (JsonCollectionLimitExceededException exception)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0012",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"A configuration {exception.CollectionKind} exceeds the configured {exception.MaximumItems}-item limit."));
            return CreateResult(null, diagnostics, boundedInput.BytesRead);
        }
        catch (JsonException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "PARSE0001",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Parse,
                    "The configuration is not valid JSON."));
            return CreateResult(null, diagnostics, boundedInput.BytesRead);
        }
        catch (IOException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "IO0010",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Io,
                    "The configuration input could not be read."));
            return CreateResult(null, diagnostics, boundedInput.BytesRead);
        }

        if (wire is null)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0001",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "The configuration root must be a JSON object."));
            return CreateResult(null, diagnostics, boundedInput.BytesRead);
        }

        var configuration = ValidateAndCreate(wire, diagnostics);
        return CreateResult(configuration, diagnostics, boundedInput.BytesRead);
    }

    private SarifRegressConfiguration? ValidateAndCreate(
        ConfigurationWire wire,
        ICollection<Diagnostic> diagnostics)
    {
        ReportUnknownProperties(wire.AdditionalProperties, diagnostics);
        if (!string.Equals(
                wire.SchemaVersion,
                SarifRegressConfiguration.SupportedSchemaVersion,
                StringComparison.Ordinal))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0002",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    $"Configuration schemaVersion must be \"{SarifRegressConfiguration.SupportedSchemaVersion}\".",
                    "/schemaVersion"));
        }

        ValidateString(wire.RepositoryRoot, "/repoRoot", diagnostics);
        var uriBaseMappings = ValidateUriBaseMappings(
            wire.UriBaseMappings,
            diagnostics);
        var pathRebases = ValidatePathRebases(wire.PathRebases, diagnostics);
        var pathAliases = ValidatePathAliases(wire.PathAliases, diagnostics);
        var ruleAliases = ValidateRuleAliases(wire.RuleAliases, diagnostics);
        var limits = CreateLimits(wire.Limits, diagnostics);
        var matching = CreateMatching(wire.Matching, limits, diagnostics);
        var policy = CreatePolicy(wire.Policy, diagnostics);
        var reporting = CreateReporting(wire.Reporting, diagnostics);

        if (diagnostics.Any(item => item.Severity == DiagnosticSeverity.Error))
        {
            return null;
        }

        return new SarifRegressConfiguration(
            wire.SchemaVersion!,
            wire.RepositoryRoot,
            pathRebases,
            pathAliases,
            ruleAliases,
            matching,
            policy,
            reporting,
            limits,
            uriBaseMappings);
    }

    private ImmutableArray<UriBaseMapping> ValidateUriBaseMappings(
        List<UriBaseMappingWire?>? values,
        ICollection<Diagnostic> diagnostics)
    {
        ValidateCollectionCount(
            values?.Count ?? 0,
            "/uriBaseMappings",
            diagnostics);
        var result = ImmutableArray.CreateBuilder<UriBaseMapping>();
        var definitionsById =
            new Dictionary<string, UriBaseMapping>(StringComparer.Ordinal);

        for (var index = 0; index < (values?.Count ?? 0); index++)
        {
            var value = values![index];
            var pointer = $"/uriBaseMappings/{index}";
            if (value is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0009",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A URI-base mapping cannot be null.",
                        pointer));
                continue;
            }

            ReportUnknownProperties(
                value.AdditionalProperties,
                diagnostics,
                pointer);
            var validId = ValidateRequiredString(
                value.Id,
                pointer + "/id",
                diagnostics);
            var validUri = ValidateRequiredString(
                value.Uri,
                pointer + "/uri",
                diagnostics);
            var valid = validId && validUri;
            if (value.UriBaseId is not null)
            {
                valid &= ValidateRequiredString(
                    value.UriBaseId,
                    pointer + "/uriBaseId",
                    diagnostics);
            }

            if (!valid)
            {
                continue;
            }

            var mapping = new UriBaseMapping(
                value.Id!,
                value.Uri!,
                value.UriBaseId);
            if (!ConfiguredUriBasePolicy.IsSafeIdentifier(mapping.Id))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0012",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A URI-base identifier cannot contain control characters.",
                        pointer + "/id"));
                continue;
            }

            if (mapping.UriBaseId is not null &&
                !ConfiguredUriBasePolicy.IsSafeIdentifier(
                    mapping.UriBaseId))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0012",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A parent URI-base identifier cannot contain control characters.",
                        pointer + "/uriBaseId"));
                continue;
            }

            if (!ConfiguredUriBasePolicy.IsSafeTarget(mapping))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0012",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A configured URI base must be a bounded local logical root or a relative child of another URI base.",
                        pointer + "/uri"));
                continue;
            }

            if (definitionsById.TryGetValue(
                    mapping.Id,
                    out var existing) &&
                existing != mapping)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0011",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A URI-base identifier cannot map to multiple definitions.",
                        pointer));
                continue;
            }

            definitionsById[mapping.Id] = mapping;
            result.Add(mapping);
        }

        return result
            .Distinct()
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ThenBy(item => item.Uri, StringComparer.Ordinal)
            .ThenBy(
                item => item.UriBaseId ?? string.Empty,
                StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private ImmutableArray<PathRebase> ValidatePathRebases(
        List<PathRebaseWire?>? values,
        ICollection<Diagnostic> diagnostics)
    {
        ValidateCollectionCount(values?.Count ?? 0, "/pathRebases", diagnostics);
        var result = ImmutableArray.CreateBuilder<PathRebase>();
        var targetsBySource = new Dictionary<string, string>(StringComparer.Ordinal);

        for (var index = 0; index < (values?.Count ?? 0); index++)
        {
            var value = values![index];
            var pointer = $"/pathRebases/{index}";
            if (value is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0009",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A path rebase cannot be null.",
                        pointer));
                continue;
            }

            ReportUnknownProperties(
                value.AdditionalProperties,
                diagnostics,
                pointer);
            if (!ValidateRequiredString(value.From, pointer + "/from", diagnostics) ||
                !ValidateRequiredString(value.To, pointer + "/to", diagnostics))
            {
                continue;
            }

            if (targetsBySource.TryGetValue(value.From!, out var existingTarget) &&
                !string.Equals(existingTarget, value.To, StringComparison.Ordinal))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0003",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A path rebase source cannot map to multiple targets.",
                        pointer));
                continue;
            }

            targetsBySource[value.From!] = value.To!;
            result.Add(new PathRebase(value.From!, value.To!));
        }

        return result
            .Distinct()
            .ToImmutableArray();
    }

    private ImmutableArray<PathAlias> ValidatePathAliases(
        List<PathAliasWire?>? values,
        ICollection<Diagnostic> diagnostics)
    {
        ValidateCollectionCount(values?.Count ?? 0, "/pathAliases", diagnostics);
        var result = ImmutableArray.CreateBuilder<PathAlias>();
        var candidatesByBaseline =
            new Dictionary<string, string>(StringComparer.Ordinal);

        for (var index = 0; index < (values?.Count ?? 0); index++)
        {
            var value = values![index];
            var pointer = $"/pathAliases/{index}";
            if (value is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0009",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A path alias cannot be null.",
                        pointer));
                continue;
            }

            ReportUnknownProperties(
                value.AdditionalProperties,
                diagnostics,
                pointer);
            if (!ValidateRequiredString(
                    value.Baseline,
                    pointer + "/baseline",
                    diagnostics) ||
                !ValidateRequiredString(
                    value.Candidate,
                    pointer + "/candidate",
                    diagnostics))
            {
                continue;
            }

            if (candidatesByBaseline.TryGetValue(
                    value.Baseline!,
                    out var existingCandidate) &&
                !string.Equals(
                    existingCandidate,
                    value.Candidate,
                    StringComparison.Ordinal))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0004",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A baseline path alias cannot map to multiple candidate prefixes.",
                        pointer));
                continue;
            }

            candidatesByBaseline[value.Baseline!] = value.Candidate!;
            result.Add(new PathAlias(value.Baseline!, value.Candidate!));
        }

        return result
            .Distinct()
            .ToImmutableArray();
    }

    private ImmutableArray<RuleAlias> ValidateRuleAliases(
        List<RuleAliasWire?>? values,
        ICollection<Diagnostic> diagnostics)
    {
        ValidateCollectionCount(values?.Count ?? 0, "/ruleAliases", diagnostics);
        var result = ImmutableArray.CreateBuilder<RuleAlias>();

        for (var index = 0; index < (values?.Count ?? 0); index++)
        {
            var value = values![index];
            var pointer = $"/ruleAliases/{index}";
            if (value is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0009",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A rule alias cannot be null.",
                        pointer));
                continue;
            }

            ReportUnknownProperties(
                value.AdditionalProperties,
                diagnostics,
                pointer);
            if (!ValidateRequiredString(
                    value.BaselineProducer,
                    pointer + "/baselineProducer",
                    diagnostics) ||
                !ValidateRequiredString(
                    value.BaselineRule,
                    pointer + "/baselineRule",
                    diagnostics) ||
                !ValidateRequiredString(
                    value.CandidateProducer,
                    pointer + "/candidateProducer",
                    diagnostics) ||
                !ValidateRequiredString(
                    value.CandidateRule,
                    pointer + "/candidateRule",
                    diagnostics))
            {
                continue;
            }

            result.Add(
                new RuleAlias(
                    value.BaselineProducer!,
                    value.BaselineRule!,
                    value.CandidateProducer!,
                    value.CandidateRule!));
        }

        return result
            .Distinct()
            .ToImmutableArray();
    }

    private MatchingConfiguration CreateMatching(
        MatchingWire? wire,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        var defaults = SarifRegressConfiguration.Default.Matching;
        ReportUnknownProperties(
            wire?.AdditionalProperties,
            diagnostics,
            "/matching");
        var radius = wire?.SnippetLinesRadius ?? defaults.SnippetLinesRadius;
        if (radius < 0 || radius > limits.MaximumSnippetRadius)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0005",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    $"matching.snippetLinesRadius must be between 0 and {limits.MaximumSnippetRadius}.",
                    "/matching/snippetLinesRadius"));
        }

        var caseSensitivity = wire?.PathCaseSensitivity switch
        {
            null or "sensitive" => PathCaseSensitivity.Sensitive,
            "ascii-insensitive" => PathCaseSensitivity.AsciiInsensitive,
            _ => PathCaseSensitivity.Sensitive,
        };
        if (wire?.PathCaseSensitivity is not null and
            not "sensitive" and
            not "ascii-insensitive")
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0006",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "matching.pathCaseSensitivity must be \"sensitive\" or \"ascii-insensitive\".",
                    "/matching/pathCaseSensitivity"));
        }

        return new MatchingConfiguration(
            wire?.EnableRepositoryContext ??
                defaults.EnableRepositoryContext,
            radius,
            wire?.EnableTokenWindows ?? defaults.EnableTokenWindows,
            wire?.AllowWeakMessageSimilarity ??
                defaults.AllowWeakMessageSimilarity,
            caseSensitivity);
    }

    private PolicyConfiguration CreatePolicy(
        PolicyWire? wire,
        ICollection<Diagnostic> diagnostics)
    {
        ReportUnknownProperties(
            wire?.AdditionalProperties,
            diagnostics,
            "/policy");
        var failOn = wire?.FailOn;
        if (failOn is null)
        {
            return SarifRegressConfiguration.Default.Policy with
            {
                TreatGithubIncompatibilityAsError =
                    wire?.TreatGithubIncompatibilityAsError ??
                    SarifRegressConfiguration.Default.Policy
                        .TreatGithubIncompatibilityAsError,
            };
        }

        ValidateCollectionCount(failOn.Count, "/policy/failOn", diagnostics);
        var classifications = ImmutableArray.CreateBuilder<FindingClassification>();
        for (var index = 0; index < failOn.Count; index++)
        {
            var classification = failOn[index] switch
            {
                "new" => FindingClassification.New,
                "unchanged" => FindingClassification.Unchanged,
                "moved" => FindingClassification.Moved,
                "modified" => FindingClassification.Modified,
                "resolved" => FindingClassification.Resolved,
                "ambiguous" => FindingClassification.Ambiguous,
                _ => (FindingClassification?)null,
            };
            if (classification is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0007",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "policy.failOn contains an unknown classification.",
                        $"/policy/failOn/{index}"));
                continue;
            }

            classifications.Add(classification.Value);
        }

        return new PolicyConfiguration(
            classifications.ToImmutable(),
            wire?.TreatGithubIncompatibilityAsError ?? false);
    }

    private static ReportingConfiguration CreateReporting(
        ReportingWire? wire,
        ICollection<Diagnostic> diagnostics)
    {
        ReportUnknownProperties(
            wire?.AdditionalProperties,
            diagnostics,
            "/reporting");
        var defaults = SarifRegressConfiguration.Default.Reporting;
        return new ReportingConfiguration(
            wire?.EmitCanonicalSarif ?? defaults.EmitCanonicalSarif,
            wire?.EmitHtml ?? defaults.EmitHtml);
    }

    private ResourceLimits CreateLimits(
        LimitsWire? wire,
        ICollection<Diagnostic> diagnostics)
    {
        if (wire is null)
        {
            return readerLimits;
        }

        ReportUnknownProperties(
            wire.AdditionalProperties,
            diagnostics,
            "/limits");
        var limits = readerLimits with
        {
            MaximumInputBytes = SelectLimit(
                wire.MaximumInputBytes,
                readerLimits.MaximumInputBytes,
                "maximumInputBytes",
                diagnostics),
            MaximumJsonDepth = (int)SelectLimit(
                wire.MaximumJsonDepth,
                readerLimits.MaximumJsonDepth,
                "maximumJsonDepth",
                diagnostics),
            MaximumRuns = (int)SelectLimit(
                wire.MaximumRuns,
                readerLimits.MaximumRuns,
                "maximumRuns",
                diagnostics),
            MaximumRunCollectionItems = (int)SelectLimit(
                wire.MaximumRunCollectionItems,
                readerLimits.MaximumRunCollectionItems,
                "maximumRunCollectionItems",
                diagnostics),
            MaximumLocationsPerResult = (int)SelectLimit(
                wire.MaximumLocationsPerResult,
                readerLimits.MaximumLocationsPerResult,
                "maximumLocationsPerResult",
                diagnostics),
            MaximumCodeFlowsPerResult = (int)SelectLimit(
                wire.MaximumCodeFlowsPerResult,
                readerLimits.MaximumCodeFlowsPerResult,
                "maximumCodeFlowsPerResult",
                diagnostics),
            MaximumThreadFlowLocationsPerResult = (int)SelectLimit(
                wire.MaximumThreadFlowLocationsPerResult,
                readerLimits.MaximumThreadFlowLocationsPerResult,
                "maximumThreadFlowLocationsPerResult",
                diagnostics),
            MaximumStringCharacters = (int)SelectLimit(
                wire.MaximumStringCharacters,
                readerLimits.MaximumStringCharacters,
                "maximumStringCharacters",
                diagnostics),
            MaximumUriBaseDepth = (int)SelectLimit(
                wire.MaximumUriBaseDepth,
                readerLimits.MaximumUriBaseDepth,
                "maximumUriBaseDepth",
                diagnostics),
            MaximumRepositoryFileBytes = SelectLimit(
                wire.MaximumRepositoryFileBytes,
                readerLimits.MaximumRepositoryFileBytes,
                "maximumRepositoryFileBytes",
                diagnostics),
            MaximumSnippetRadius = (int)SelectLimit(
                wire.MaximumSnippetRadius,
                readerLimits.MaximumSnippetRadius,
                "maximumSnippetRadius",
                diagnostics),
            MaximumTokenWindowTerms = (int)SelectLimit(
                wire.MaximumTokenWindowTerms,
                readerLimits.MaximumTokenWindowTerms,
                "maximumTokenWindowTerms",
                diagnostics),
            MaximumCandidateEdgesPerFinding = (int)SelectLimit(
                wire.MaximumCandidateEdgesPerFinding,
                readerLimits.MaximumCandidateEdgesPerFinding,
                "maximumCandidateEdgesPerFinding",
                diagnostics),
            MaximumCandidatePairEvaluationsPerFinding = (int)SelectLimit(
                wire.MaximumCandidatePairEvaluationsPerFinding,
                readerLimits.MaximumCandidatePairEvaluationsPerFinding,
                "maximumCandidatePairEvaluationsPerFinding",
                diagnostics),
            MaximumCandidatePairEvaluations = SelectLimit(
                wire.MaximumCandidatePairEvaluations,
                readerLimits.MaximumCandidatePairEvaluations,
                "maximumCandidatePairEvaluations",
                diagnostics),
            MaximumRejectedAlternatives = (int)SelectLimit(
                wire.MaximumRejectedAlternatives,
                readerLimits.MaximumRejectedAlternatives,
                "maximumRejectedAlternatives",
                diagnostics),
            MaximumAssignmentSideSize = (int)SelectLimit(
                wire.MaximumAssignmentSideSize,
                readerLimits.MaximumAssignmentSideSize,
                "maximumAssignmentSideSize",
                diagnostics),
        };

        try
        {
            limits.Validate();
        }
        catch (ArgumentException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0010",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "The configured resource limits are internally inconsistent.",
                    "/limits"));
        }

        return limits;
    }

    private static long SelectLimit(
        long? configured,
        long trustedMaximum,
        string propertyName,
        ICollection<Diagnostic> diagnostics)
    {
        if (configured is null)
        {
            return trustedMaximum;
        }

        var pointer = "/limits/" + propertyName;
        if (configured <= 0)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0008",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "A configured resource limit must be positive.",
                    pointer));
            return trustedMaximum;
        }

        if (configured > trustedMaximum)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0013",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"The configured resource limit cannot exceed the trusted {trustedMaximum} ceiling.",
                    pointer));
            return trustedMaximum;
        }

        return configured.Value;
    }

    private bool ValidateRequiredString(
        string? value,
        string pointer,
        ICollection<Diagnostic> diagnostics)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0009",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "A required configuration string is empty.",
                    pointer));
            return false;
        }

        return ValidateString(value, pointer, diagnostics);
    }

    private bool ValidateString(
        string? value,
        string pointer,
        ICollection<Diagnostic> diagnostics)
    {
        if (value is null ||
            value.Length <= readerLimits.MaximumStringCharacters)
        {
            return true;
        }

        diagnostics.Add(
            CreateDiagnostic(
                "SECURITY0011",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                $"A configuration string exceeds the configured {readerLimits.MaximumStringCharacters}-character limit.",
                pointer));
        return false;
    }

    private void ValidateCollectionCount(
        int count,
        string pointer,
        ICollection<Diagnostic> diagnostics)
    {
        if (count <= readerLimits.MaximumRunCollectionItems)
        {
            return;
        }

        diagnostics.Add(
            CreateDiagnostic(
                "SECURITY0012",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                $"A configuration collection exceeds the configured {readerLimits.MaximumRunCollectionItems}-item limit.",
                pointer));
    }

    private static void ReportUnknownProperties(
        IReadOnlyDictionary<string, object?>? properties,
        ICollection<Diagnostic> diagnostics,
        string parentPointer = "")
    {
        if (properties is null)
        {
            return;
        }

        foreach (var property in properties.Keys.Order(StringComparer.Ordinal))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "UNSUPPORTED0001",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Unsupported,
                    $"The configuration property \"{property}\" is not supported and was ignored.",
                    parentPointer + "/" +
                        SourceReference.EscapePointerSegment(property)));
        }
    }

    private static JsonSerializerOptions CreateJsonOptions(
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
        var constraints = new BoundedJsonReadConstraints(
            limits.MaximumJsonDepth,
            limits.MaximumRunCollectionItems,
            limits.MaximumStringCharacters,
            cancellationToken);
        var options = new JsonSerializerOptions
        {
            MaxDepth = limits.MaximumJsonDepth,
            PropertyNameCaseInsensitive = false,
        };
        options.Converters.Add(
            new BoundedStringConverter(
                limits.MaximumStringCharacters,
                cancellationToken));
        options.Converters.Add(new DiscardingObjectConverter(constraints));
        options.Converters.Add(
            new BoundedJsonObjectConverterFactory(
                type => type.DeclaringType == typeof(SarifConfigurationReader),
                constraints));
        options.Converters.Add(
            new BoundedListConverterFactory(
                _ => limits.MaximumRunCollectionItems,
                constraints));
        options.Converters.Add(
            new BoundedStringDictionaryConverterFactory(
                limits.MaximumRunCollectionItems,
                constraints));
        return options;
    }

    private static ConfigurationReadResult CreateResult(
        SarifRegressConfiguration? configuration,
        IEnumerable<Diagnostic> diagnostics,
        long inputBytes) =>
        new(configuration, Diagnostic.Sort(diagnostics), inputBytes);

    private static Diagnostic CreateDiagnostic(
        string code,
        DiagnosticSeverity severity,
        DiagnosticStage stage,
        string message,
        string pointer = "") =>
        new(
            code,
            severity,
            stage,
            message,
            new SourceReference(InputKind.Configuration, null, null, pointer));

    private sealed class ConfigurationWire
    {
        [JsonPropertyName("schemaVersion")]
        public string? SchemaVersion { get; init; }

        [JsonPropertyName("repoRoot")]
        public string? RepositoryRoot { get; init; }

        [JsonPropertyName("uriBaseMappings")]
        public List<UriBaseMappingWire?>? UriBaseMappings { get; init; }

        [JsonPropertyName("pathRebases")]
        public List<PathRebaseWire?>? PathRebases { get; init; }

        [JsonPropertyName("pathAliases")]
        public List<PathAliasWire?>? PathAliases { get; init; }

        [JsonPropertyName("ruleAliases")]
        public List<RuleAliasWire?>? RuleAliases { get; init; }

        [JsonPropertyName("matching")]
        public MatchingWire? Matching { get; init; }

        [JsonPropertyName("policy")]
        public PolicyWire? Policy { get; init; }

        [JsonPropertyName("reporting")]
        public ReportingWire? Reporting { get; init; }

        [JsonPropertyName("limits")]
        public LimitsWire? Limits { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class UriBaseMappingWire
    {
        [JsonPropertyName("id")]
        public string? Id { get; init; }

        [JsonPropertyName("uri")]
        public string? Uri { get; init; }

        [JsonPropertyName("uriBaseId")]
        public string? UriBaseId { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class PathRebaseWire
    {
        [JsonPropertyName("from")]
        public string? From { get; init; }

        [JsonPropertyName("to")]
        public string? To { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class PathAliasWire
    {
        [JsonPropertyName("baseline")]
        public string? Baseline { get; init; }

        [JsonPropertyName("candidate")]
        public string? Candidate { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class RuleAliasWire
    {
        [JsonPropertyName("baselineProducer")]
        public string? BaselineProducer { get; init; }

        [JsonPropertyName("baselineRule")]
        public string? BaselineRule { get; init; }

        [JsonPropertyName("candidateProducer")]
        public string? CandidateProducer { get; init; }

        [JsonPropertyName("candidateRule")]
        public string? CandidateRule { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class MatchingWire
    {
        [JsonPropertyName("enableRepoContext")]
        public bool? EnableRepositoryContext { get; init; }

        [JsonPropertyName("snippetLinesRadius")]
        public int? SnippetLinesRadius { get; init; }

        [JsonPropertyName("enableTokenWindows")]
        public bool? EnableTokenWindows { get; init; }

        [JsonPropertyName("allowWeakMessageSimilarity")]
        public bool? AllowWeakMessageSimilarity { get; init; }

        [JsonPropertyName("pathCaseSensitivity")]
        public string? PathCaseSensitivity { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class PolicyWire
    {
        [JsonPropertyName("failOn")]
        public List<string?>? FailOn { get; init; }

        [JsonPropertyName("treatGithubIncompatibilityAsError")]
        public bool? TreatGithubIncompatibilityAsError { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class ReportingWire
    {
        [JsonPropertyName("emitCanonicalSarif")]
        public bool? EmitCanonicalSarif { get; init; }

        [JsonPropertyName("emitHtml")]
        public bool? EmitHtml { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }

    private sealed class LimitsWire
    {
        [JsonPropertyName("maximumInputBytes")]
        public long? MaximumInputBytes { get; init; }

        [JsonPropertyName("maximumJsonDepth")]
        public int? MaximumJsonDepth { get; init; }

        [JsonPropertyName("maximumRuns")]
        public int? MaximumRuns { get; init; }

        [JsonPropertyName("maximumRunCollectionItems")]
        public int? MaximumRunCollectionItems { get; init; }

        [JsonPropertyName("maximumLocationsPerResult")]
        public int? MaximumLocationsPerResult { get; init; }

        [JsonPropertyName("maximumCodeFlowsPerResult")]
        public int? MaximumCodeFlowsPerResult { get; init; }

        [JsonPropertyName("maximumThreadFlowLocationsPerResult")]
        public int? MaximumThreadFlowLocationsPerResult { get; init; }

        [JsonPropertyName("maximumStringCharacters")]
        public int? MaximumStringCharacters { get; init; }

        [JsonPropertyName("maximumUriBaseDepth")]
        public int? MaximumUriBaseDepth { get; init; }

        [JsonPropertyName("maximumRepositoryFileBytes")]
        public long? MaximumRepositoryFileBytes { get; init; }

        [JsonPropertyName("maximumSnippetRadius")]
        public int? MaximumSnippetRadius { get; init; }

        [JsonPropertyName("maximumTokenWindowTerms")]
        public int? MaximumTokenWindowTerms { get; init; }

        [JsonPropertyName("maximumCandidateEdgesPerFinding")]
        public int? MaximumCandidateEdgesPerFinding { get; init; }

        [JsonPropertyName("maximumCandidatePairEvaluationsPerFinding")]
        public int? MaximumCandidatePairEvaluationsPerFinding { get; init; }

        [JsonPropertyName("maximumCandidatePairEvaluations")]
        public long? MaximumCandidatePairEvaluations { get; init; }

        [JsonPropertyName("maximumRejectedAlternatives")]
        public int? MaximumRejectedAlternatives { get; init; }

        [JsonPropertyName("maximumAssignmentSideSize")]
        public int? MaximumAssignmentSideSize { get; init; }

        [JsonExtensionData]
        public Dictionary<string, object?>? AdditionalProperties { get; init; }
    }
}
