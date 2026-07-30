using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Reporting;
using SarifRegress.Core.Security;
using SarifRegress.Report;
using SarifRegress.Sarif.Canonicalization;

namespace SarifRegress.PropertyTests;

internal static class PropertyTestData
{
    public static SarifRegressConfiguration BoundedConfiguration(
        int maximumRunCollectionItems = 8)
    {
        var defaults = SarifRegressConfiguration.Default;
        var limits = ResourceLimits.Default with
        {
            MaximumInputBytes = 4_096,
            MaximumJsonDepth = 16,
            MaximumRuns = 2,
            MaximumRunCollectionItems = maximumRunCollectionItems,
            MaximumLocationsPerResult = 4,
            MaximumCodeFlowsPerResult = 2,
            MaximumThreadFlowLocationsPerResult = 8,
            MaximumStringCharacters = 128,
            MaximumUriBaseDepth = 4,
        };

        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            repositoryRoot: null,
            defaults.PathRebases,
            defaults.PathAliases,
            defaults.RuleAliases,
            defaults.Matching,
            defaults.Policy,
            defaults.Reporting,
            limits);
    }

    public static Finding Finding(
        InputKind input,
        string key,
        int resultIndex,
        string? identityToken,
        string? contextHash = null)
    {
        var resultIndexText = resultIndex.ToString(CultureInfo.InvariantCulture);
        var sourceReference = new SourceReference(
            input,
            runIndex: 0,
            resultIndex,
            $"/runs/0/results/{resultIndexText}");
        const string repositoryPath = "src/shared.cs";
        var canonicalPath = new CanonicalPath(
            repositoryPath,
            repositoryPath,
            $"repo://{repositoryPath}",
            repositoryPath,
            PathKind.RepositoryRelative);
        var producerFingerprints = identityToken is null
            ? ImmutableArray<ProducerFingerprint>.Empty
            :
            [
                new ProducerFingerprint(
                    "primary/v1",
                    "primary",
                    1,
                    identityToken,
                    FingerprintReliability.High,
                    ProducerFingerprintSource.PartialFingerprint),
            ];
        var context = contextHash is null
            ? null
            : new ContextEvidence(
                contextHash,
                TokenWindowHash: null,
                EnclosingSymbol: null,
                StartLine: 7,
                EndLine: 7);

        return new Finding(
            key,
            sourceReference,
            new RunIdentity(0, AutomationCategory: null, StableRunKey: "run:0"),
            new ProducerIdentity(
                "Property scanner",
                ToolVersion: "1.0.0",
                Family: "property-scanner",
                AutomationCategory: null,
                AutomaticIdentity: "property-scanner"),
            new RuleIdentity(
                "RULE-001",
                "property-scanner/RULE-001",
                AliasApplied: false),
            new PrimaryLocation(
                canonicalPath,
                new Region(7, 1, 7, 8),
                EmbeddedSnippet: null),
            MessageCanonicalizer.Canonicalize("Shared property message."),
            producerFingerprints,
            derivedFingerprints: null,
            context);
    }

    public static ComparisonInput Input(
        InputKind input,
        IEnumerable<Finding> findings) =>
        new(
            input,
            input == InputKind.Baseline
                ? "baseline.sarif"
                : "candidate.sarif",
            findings.ToImmutableArray(),
            ImmutableArray<Diagnostic>.Empty);

    public static ComparisonReport Report(MatchResult result) =>
        ComparisonReportFactory.Create(
            result,
            new ComparisonReportMetadata(
                ProductInformation.Version,
                "baseline.sarif",
                "candidate.sarif",
                ProductInformation.MatcherAlgorithmVersion));

    public static string MatchSignature(MatchResult result)
    {
        var builder = new StringBuilder();
        builder.Append(result.CandidateEdgeCount)
            .Append('|')
            .Append(result.ComponentCount)
            .Append('|')
            .Append(result.AmbiguousComponentCount)
            .Append('\n');

        foreach (var decision in result.Decisions)
        {
            builder.Append(decision.Classification)
                .Append('|')
                .Append(decision.Baseline?.FindingKey)
                .Append('|')
                .Append(decision.Candidate?.FindingKey)
                .Append('|')
                .Append(decision.Decision.PrecedenceTier)
                .Append('|')
                .Append(decision.Decision.DisplayConfidence)
                .Append('|')
                .Append(decision.Decision.Ambiguous)
                .Append('|')
                .Append(decision.Decision.MatcherAlgorithmVersion)
                .Append('\n');
        }

        foreach (var diagnostic in result.Diagnostics)
        {
            builder.Append(DiagnosticSignature(diagnostic)).Append('\n');
        }

        return builder.ToString();
    }

    public static string DiagnosticSignature(Diagnostic diagnostic)
    {
        var source = diagnostic.SourceReference;
        return string.Join(
            "|",
            diagnostic.Stage,
            diagnostic.Code,
            diagnostic.Severity,
            source?.Input,
            Invariant(source?.RunIndex),
            Invariant(source?.ResultIndex),
            source?.JsonPointer,
            diagnostic.Message,
            diagnostic.StandardBasis,
            diagnostic.Help);
    }

    public static IReadOnlyList<ImmutableArray<T>> Permutations<T>(
        IReadOnlyList<T> values)
    {
        var permutations = new List<ImmutableArray<T>>();
        var buffer = values.ToArray();
        Generate(index: 0);
        return permutations;

        void Generate(int index)
        {
            if (index == buffer.Length)
            {
                permutations.Add(buffer.ToImmutableArray());
                return;
            }

            for (var swapIndex = index; swapIndex < buffer.Length; swapIndex++)
            {
                (buffer[index], buffer[swapIndex]) =
                    (buffer[swapIndex], buffer[index]);
                Generate(index + 1);
                (buffer[index], buffer[swapIndex]) =
                    (buffer[swapIndex], buffer[index]);
            }
        }
    }

    public static void AssertOneToOne(MatchResult result, string caseId)
    {
        var baselineKeys = result.Decisions
            .Where(decision => decision.Baseline is not null)
            .Select(decision => decision.Baseline!.FindingKey)
            .ToArray();
        var candidateKeys = result.Decisions
            .Where(decision => decision.Candidate is not null)
            .Select(decision => decision.Candidate!.FindingKey)
            .ToArray();

        Assert.True(
            baselineKeys.Length ==
            baselineKeys.Distinct(StringComparer.Ordinal).Count(),
            $"case={caseId}; side=baseline");
        Assert.True(
            candidateKeys.Length ==
            candidateKeys.Distinct(StringComparer.Ordinal).Count(),
            $"case={caseId}; side=candidate");
    }

    private static string Invariant(int? value) =>
        value?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
}

internal sealed class CultureScope : IDisposable
{
    private readonly CultureInfo originalCulture;
    private readonly CultureInfo originalUiCulture;

    public CultureScope(string cultureName)
    {
        originalCulture = CultureInfo.CurrentCulture;
        originalUiCulture = CultureInfo.CurrentUICulture;
        var culture = CultureInfo.GetCultureInfo(cultureName);
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }

    public void Dispose()
    {
        CultureInfo.CurrentCulture = originalCulture;
        CultureInfo.CurrentUICulture = originalUiCulture;
    }
}
