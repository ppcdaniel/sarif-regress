using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;

namespace SarifRegress.UnitTests;

internal static class MatchingTestData
{
    public static ComparisonInput Input(
        InputKind input,
        params Finding[] findings) =>
        new(
            input,
            input.ToString().ToLowerInvariant(),
            findings.ToImmutableArray(),
            ImmutableArray<Diagnostic>.Empty);

    public static Finding Finding(
        InputKind input,
        string key,
        string? path = "src/example.cs",
        string message = "Example finding.",
        string producerFamily = "scanner",
        string toolName = "Scanner",
        string toolVersion = "1.0.0",
        string? automaticProducerIdentity = null,
        string ruleId = "scanner/rule",
        int? startLine = 10,
        IEnumerable<ProducerFingerprint>? producerFingerprints = null,
        IEnumerable<DerivedFingerprint>? derivedFingerprints = null,
        string? contextHash = null,
        string? tokenWindowHash = null,
        string? enclosingSymbol = null,
        IEnumerable<string>? codeFlowPaths = null,
        IEnumerable<string>? relatedLocationPaths = null,
        IEnumerable<string>? messageNormalisationFlags = null,
        IEnumerable<TransformationRecord>? pathTransformations = null,
        IEnumerable<string>? lossiness = null,
        FindingMetadata? metadata = null)
    {
        var primaryPath = path is null
            ? null
            : CanonicalPath(path, pathTransformations);
        var region = startLine.HasValue
            ? new Region(startLine, 1, startLine, 5)
            : null;
        var context =
            contextHash is null
            && tokenWindowHash is null
            && enclosingSymbol is null
            ? null
            : new ContextEvidence(
                contextHash,
                tokenWindowHash,
                enclosingSymbol,
                startLine,
                startLine);
        var codeFlow = codeFlowPaths is null
            ? null
            : new CodeFlowEvidence(
                codeFlowPaths
                    .Select((flowPath, ordinal) => new CodeFlowAnchor(
                        CanonicalUri(flowPath),
                        ContextHash: null,
                        Ordinal: ordinal))
                    .ToImmutableArray());
        var relatedLocations = relatedLocationPaths?
            .Select((relatedPath, ordinal) => new RelatedLocation(
                CanonicalPath(relatedPath),
                Region: null,
                StableKey: $"related:{ordinal}"))
            .ToImmutableArray();

        return new Finding(
            key,
            new SourceReference(input, 0, 0, "/runs/0/results/0"),
            new RunIdentity(0, AutomationCategory: null, StableRunKey: "run"),
            new ProducerIdentity(
                toolName,
                ToolVersion: toolVersion,
                Family: producerFamily,
                AutomationCategory: null,
                AutomaticIdentity:
                    automaticProducerIdentity ??
                    ProducerIdentityResolver.Resolve(toolName).AutomaticIdentity),
            new RuleIdentity(ruleId, ruleId, AliasApplied: false),
            primaryPath is null
                ? null
                : new PrimaryLocation(primaryPath, region, EmbeddedSnippet: null),
            new MessageIdentity(
                message,
                message,
                message.ToLowerInvariant(),
                (messageNormalisationFlags ?? []).ToImmutableArray()),
            producerFingerprints,
            derivedFingerprints,
            context,
            relatedLocations,
            codeFlow,
            lossiness: lossiness,
            metadata: metadata);
    }

    public static ProducerFingerprint ProducerFingerprint(
        string value,
        int? version = 1,
        FingerprintReliability reliability = FingerprintReliability.High,
        string family = "primary") =>
        new(
            version.HasValue ? $"{family}/v{version.Value}" : family,
            family,
            version,
            value,
            reliability,
            ProducerFingerprintSource.PartialFingerprint);

    public static DerivedFingerprint DerivedFingerprint(
        string value,
        string name = "sarifregress/rule-path-context/v2") =>
        new(name, value, "sarifregress/rule-path-context/v2");

    public static SarifRegressConfiguration Configuration(
        bool allowWeakMessageSimilarity = false,
        IEnumerable<PathAlias>? pathAliases = null,
        IEnumerable<RuleAlias>? ruleAliases = null,
        ResourceLimits? limits = null,
        PathCaseSensitivity? pathCaseSensitivity = null)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            defaults.RepositoryRoot,
            defaults.PathRebases,
            pathAliases ?? defaults.PathAliases,
            ruleAliases ?? defaults.RuleAliases,
            defaults.Matching with
            {
                AllowWeakMessageSimilarity = allowWeakMessageSimilarity,
                PathCaseSensitivity =
                    pathCaseSensitivity ?? defaults.Matching.PathCaseSensitivity,
            },
            defaults.Policy,
            defaults.Reporting,
            limits ?? defaults.Limits);
    }

    private static CanonicalPath CanonicalPath(
        string repositoryRelativePath,
        IEnumerable<TransformationRecord>? transformations = null) =>
        new(
            repositoryRelativePath,
            repositoryRelativePath,
            CanonicalUri(repositoryRelativePath),
            repositoryRelativePath,
            PathKind.RepositoryRelative,
            transformations);

    private static string CanonicalUri(string repositoryRelativePath) =>
        $"repo://{repositoryRelativePath.Replace('\\', '/')}";
}
