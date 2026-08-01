using System.Collections.Immutable;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;

namespace SarifRegress.Core.Configuration;

/// <summary>
/// Defines one logical URI or path-prefix rebase.
/// </summary>
public sealed record PathRebase(string From, string To);

/// <summary>
/// Defines one explicit logical URI base supplied by configuration.
/// </summary>
public sealed record UriBaseMapping(
    string Id,
    string Uri,
    string? UriBaseId = null);

/// <summary>
/// Defines baseline and candidate path-prefix equivalence.
/// </summary>
public sealed record PathAlias(string Baseline, string Candidate);

/// <summary>
/// Defines an explicit cross-version or cross-producer rule alias.
/// </summary>
public sealed record RuleAlias(
    string BaselineProducer,
    string BaselineRule,
    string CandidateProducer,
    string CandidateRule);

/// <summary>
/// Controls source-context and weak-evidence matching.
/// </summary>
public sealed record MatchingConfiguration(
    bool EnableRepositoryContext,
    int SnippetLinesRadius,
    bool EnableTokenWindows,
    bool AllowWeakMessageSimilarity,
    PathCaseSensitivity PathCaseSensitivity);

/// <summary>
/// Controls which successful comparison classifications fail policy.
/// </summary>
public sealed record PolicyConfiguration(
    ImmutableArray<FindingClassification> FailOn,
    bool TreatGithubIncompatibilityAsError);

/// <summary>
/// Controls optional report projections.
/// </summary>
public sealed record ReportingConfiguration(
    bool EmitCanonicalSarif,
    bool EmitHtml);

/// <summary>
/// Represents the immutable, validated MVP configuration contract.
/// </summary>
public sealed record SarifRegressConfiguration
{
    /// <summary>
    /// Gets the supported configuration schema version.
    /// </summary>
    public const string SupportedSchemaVersion = "1";

    /// <summary>
    /// Gets the deterministic default configuration.
    /// </summary>
    public static SarifRegressConfiguration Default { get; } = new(
        SupportedSchemaVersion,
        repositoryRoot: null,
        pathRebases: [],
        pathAliases: [],
        ruleAliases: [],
        new MatchingConfiguration(
            EnableRepositoryContext: true,
            SnippetLinesRadius: 3,
            EnableTokenWindows: false,
            AllowWeakMessageSimilarity: false,
            PathCaseSensitivity.Sensitive),
        new PolicyConfiguration(
            [
                FindingClassification.New,
                FindingClassification.Modified,
                FindingClassification.Ambiguous,
            ],
            TreatGithubIncompatibilityAsError: false),
        new ReportingConfiguration(
            EmitCanonicalSarif: false,
            EmitHtml: false),
        ResourceLimits.Default,
        uriBaseMappings: []);

    /// <summary>
    /// Initializes a configuration.
    /// </summary>
    public SarifRegressConfiguration(
        string schemaVersion,
        string? repositoryRoot,
        IEnumerable<PathRebase>? pathRebases,
        IEnumerable<PathAlias>? pathAliases,
        IEnumerable<RuleAlias>? ruleAliases,
        MatchingConfiguration matching,
        PolicyConfiguration policy,
        ReportingConfiguration reporting,
        ResourceLimits limits,
        IEnumerable<UriBaseMapping>? uriBaseMappings = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaVersion);
        ArgumentNullException.ThrowIfNull(matching);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(reporting);
        ArgumentNullException.ThrowIfNull(limits);

        SchemaVersion = schemaVersion;
        RepositoryRoot = string.IsNullOrWhiteSpace(repositoryRoot) ? null : repositoryRoot;
        UriBaseMappings = NormalizeUriBaseMappings(uriBaseMappings);
        PathRebases = (pathRebases ?? [])
            .OrderByDescending(item => item.From.Length)
            .ThenBy(item => item.From, StringComparer.Ordinal)
            .ThenBy(item => item.To, StringComparer.Ordinal)
            .ToImmutableArray();
        PathAliases = (pathAliases ?? [])
            .OrderByDescending(item => item.Baseline.Length)
            .ThenBy(item => item.Baseline, StringComparer.Ordinal)
            .ThenBy(item => item.Candidate, StringComparer.Ordinal)
            .ToImmutableArray();
        RuleAliases = (ruleAliases ?? [])
            .OrderBy(item => item.BaselineProducer, StringComparer.Ordinal)
            .ThenBy(item => item.BaselineRule, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateProducer, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateRule, StringComparer.Ordinal)
            .ToImmutableArray();
        Matching = matching;
        Policy = policy with
        {
            FailOn = policy.FailOn
                .Distinct()
                .Order()
                .ToImmutableArray(),
        };
        Reporting = reporting;
        Limits = limits;
    }

    /// <summary>
    /// Creates a configuration with a different repository root while preserving
    /// every other validated setting.
    /// </summary>
    /// <param name="repositoryRoot">The replacement repository root.</param>
    /// <returns>The equivalent configuration with the requested root.</returns>
    public SarifRegressConfiguration WithRepositoryRoot(string? repositoryRoot) =>
        new(
            SchemaVersion,
            repositoryRoot,
            PathRebases,
            PathAliases,
            RuleAliases,
            Matching,
            Policy,
            Reporting,
            Limits,
            UriBaseMappings);

    /// <summary>
    /// Gets the independent configuration schema version.
    /// </summary>
    public string SchemaVersion { get; }

    /// <summary>
    /// Gets the configured repository root.
    /// </summary>
    public string? RepositoryRoot { get; }

    /// <summary>
    /// Gets configured logical URI bases in ordinal identifier order.
    /// </summary>
    public ImmutableArray<UriBaseMapping> UriBaseMappings { get; }

    /// <summary>
    /// Gets path rebases in longest-prefix-first order.
    /// </summary>
    public ImmutableArray<PathRebase> PathRebases { get; }

    /// <summary>
    /// Gets path aliases in longest-prefix-first order.
    /// </summary>
    public ImmutableArray<PathAlias> PathAliases { get; }

    /// <summary>
    /// Gets explicit rule aliases.
    /// </summary>
    public ImmutableArray<RuleAlias> RuleAliases { get; }

    /// <summary>
    /// Gets matching policy.
    /// </summary>
    public MatchingConfiguration Matching { get; }

    /// <summary>
    /// Gets regression policy.
    /// </summary>
    public PolicyConfiguration Policy { get; }

    /// <summary>
    /// Gets report projection policy.
    /// </summary>
    public ReportingConfiguration Reporting { get; }

    /// <summary>
    /// Gets untrusted-input limits.
    /// </summary>
    public ResourceLimits Limits { get; }

    private static ImmutableArray<UriBaseMapping> NormalizeUriBaseMappings(
        IEnumerable<UriBaseMapping>? mappings)
    {
        var byId = new Dictionary<string, UriBaseMapping>(StringComparer.Ordinal);
        foreach (var mapping in mappings ?? [])
        {
            ArgumentNullException.ThrowIfNull(mapping);
            ArgumentException.ThrowIfNullOrWhiteSpace(mapping.Id);
            ArgumentException.ThrowIfNullOrWhiteSpace(mapping.Uri);
            if (mapping.UriBaseId is not null)
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(mapping.UriBaseId);
            }

            if (byId.TryGetValue(mapping.Id, out var existing) &&
                existing != mapping)
            {
                throw new ArgumentException(
                    "A URI-base identifier cannot map to multiple definitions.",
                    nameof(mappings));
            }

            byId[mapping.Id] = mapping;
        }

        return byId.Values
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ThenBy(item => item.Uri, StringComparer.Ordinal)
            .ThenBy(
                item => item.UriBaseId ?? string.Empty,
                StringComparer.Ordinal)
            .ToImmutableArray();
    }
}
