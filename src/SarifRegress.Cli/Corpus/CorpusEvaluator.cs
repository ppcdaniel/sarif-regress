using System.Collections.Immutable;
using SarifRegress.Core.Matching;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Evaluates accepted and refused decisions against a labelled pairing graph.
/// </summary>
public static class CorpusEvaluator
{
    /// <summary>
    /// Evaluates one corpus case.
    /// </summary>
    /// <param name="caseName">The stable repository-relative case name.</param>
    /// <param name="labels">The ground-truth pairing graph.</param>
    /// <param name="decisions">The matcher decisions.</param>
    /// <returns>Exact counts and deterministic decimal metrics.</returns>
    public static CorpusCaseEvaluation Evaluate(
        string caseName,
        CorpusLabels labels,
        IEnumerable<FindingDecision> decisions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caseName);
        ArgumentNullException.ThrowIfNull(labels);
        ArgumentNullException.ThrowIfNull(decisions);

        var expectedPairs = labels.Pairs
            .ToDictionary(
                pair => CreatePairKey(pair.BaselineKey, pair.CandidateKey),
                pair => pair,
                StringComparer.Ordinal);

        FindingDecision[] decisionArray = decisions.ToArray();
        var acceptedDecisions = decisionArray
            .Where(IsAcceptedPair)
            .ToArray();
        var acceptedPairs = acceptedDecisions
            .Select(decision => CreatePairKey(
                decision.Baseline!.FindingKey,
                decision.Candidate!.FindingKey))
            .ToHashSet(StringComparer.Ordinal);

        var truePositives = acceptedPairs.Count(expectedPairs.ContainsKey);
        var falsePositives = acceptedPairs.Count - truePositives;
        var falseNegatives = expectedPairs.Count - truePositives;
        var classificationMismatches = acceptedDecisions.Count(decision =>
        {
            var pairKey = CreatePairKey(
                decision.Baseline!.FindingKey,
                decision.Candidate!.FindingKey);
            return expectedPairs.TryGetValue(pairKey, out var expected)
                && expected.Classification != decision.Classification;
        });

        var silentlyMatchedAmbiguous = acceptedDecisions
            .SelectMany(decision =>
                new[]
                {
                    decision.Baseline!.FindingKey,
                    decision.Candidate!.FindingKey,
                })
            .Distinct(StringComparer.Ordinal)
            .Count(labels.ExpectedAmbiguous.Contains);
        var actualAmbiguous = GetFindingKeys(
            decisionArray,
            FindingClassification.Ambiguous);
        var actualResolved = GetFindingKeys(
            decisionArray,
            FindingClassification.Resolved);
        var actualNew = GetFindingKeys(
            decisionArray,
            FindingClassification.New);

        CorpusMetrics metrics = CreateMetrics(
            expectedPairs.Count,
            truePositives,
            falsePositives,
            falseNegatives,
            labels.ExpectedAmbiguous.Count,
            silentlyMatchedAmbiguous) with
        {
            ClassificationMismatches = classificationMismatches,
            CorrectAmbiguous = IntersectionCount(
                labels.ExpectedAmbiguous,
                actualAmbiguous),
            MissingAmbiguous = ExceptCount(
                labels.ExpectedAmbiguous,
                actualAmbiguous),
            UnexpectedAmbiguous = ExceptCount(
                actualAmbiguous,
                labels.ExpectedAmbiguous),
            ExpectedResolved = labels.ExpectedResolved.Count,
            CorrectResolved = IntersectionCount(
                labels.ExpectedResolved,
                actualResolved),
            MissingResolved = ExceptCount(
                labels.ExpectedResolved,
                actualResolved),
            UnexpectedResolved = ExceptCount(
                actualResolved,
                labels.ExpectedResolved),
            ExpectedNew = labels.ExpectedNew.Count,
            CorrectNew = IntersectionCount(
                labels.ExpectedNew,
                actualNew),
            MissingNew = ExceptCount(
                labels.ExpectedNew,
                actualNew),
            UnexpectedNew = ExceptCount(
                actualNew,
                labels.ExpectedNew),
        };

        return new CorpusCaseEvaluation(caseName, metrics);
    }

    /// <summary>
    /// Aggregates case evaluations without averaging already-rounded ratios.
    /// </summary>
    /// <param name="evaluations">The case evaluations.</param>
    /// <returns>A stable aggregate.</returns>
    public static CorpusEvaluation Aggregate(
        IEnumerable<CorpusCaseEvaluation> evaluations)
    {
        ArgumentNullException.ThrowIfNull(evaluations);
        var cases = evaluations
            .OrderBy(item => item.CaseName, StringComparer.Ordinal)
            .ToImmutableArray();

        var aggregate = CreateMetrics(
            cases.Sum(item => item.Metrics.LabelledPairs),
            cases.Sum(item => item.Metrics.TruePositives),
            cases.Sum(item => item.Metrics.FalsePositives),
            cases.Sum(item => item.Metrics.FalseNegatives),
            cases.Sum(item => item.Metrics.ExpectedAmbiguous),
            cases.Sum(item => item.Metrics.SilentAmbiguousMatches)) with
        {
            ClassificationMismatches =
                cases.Sum(item => item.Metrics.ClassificationMismatches),
            CorrectAmbiguous = cases.Sum(item => item.Metrics.CorrectAmbiguous),
            MissingAmbiguous = cases.Sum(item => item.Metrics.MissingAmbiguous),
            UnexpectedAmbiguous = cases.Sum(item => item.Metrics.UnexpectedAmbiguous),
            ExpectedResolved = cases.Sum(item => item.Metrics.ExpectedResolved),
            CorrectResolved = cases.Sum(item => item.Metrics.CorrectResolved),
            MissingResolved = cases.Sum(item => item.Metrics.MissingResolved),
            UnexpectedResolved = cases.Sum(item => item.Metrics.UnexpectedResolved),
            ExpectedNew = cases.Sum(item => item.Metrics.ExpectedNew),
            CorrectNew = cases.Sum(item => item.Metrics.CorrectNew),
            MissingNew = cases.Sum(item => item.Metrics.MissingNew),
            UnexpectedNew = cases.Sum(item => item.Metrics.UnexpectedNew),
        };

        return new CorpusEvaluation(cases, aggregate);
    }

    private static CorpusMetrics CreateMetrics(
        int labelledPairs,
        int truePositives,
        int falsePositives,
        int falseNegatives,
        int expectedAmbiguous,
        int silentAmbiguousMatches)
    {
        var precision = Divide(
            truePositives,
            truePositives + falsePositives);
        var recall = Divide(
            truePositives,
            truePositives + falseNegatives);
        var f1 = precision + recall == 0
            ? 0
            : Decimal.Round(
                2 * precision * recall / (precision + recall),
                decimals: 6,
                MidpointRounding.ToEven);

        return new CorpusMetrics(
            labelledPairs,
            truePositives,
            falsePositives,
            falseNegatives,
            expectedAmbiguous,
            silentAmbiguousMatches,
            precision,
            recall,
            f1);
    }

    private static decimal Divide(int numerator, int denominator)
    {
        if (denominator == 0)
        {
            return 1;
        }

        return Decimal.Round(
            (decimal)numerator / denominator,
            decimals: 6,
            MidpointRounding.ToEven);
    }

    private static bool IsAcceptedPair(FindingDecision decision)
    {
        return decision.Baseline is not null &&
            decision.Candidate is not null &&
            decision.Classification is not FindingClassification.Ambiguous;
    }

    private static string CreatePairKey(string baselineKey, string candidateKey)
    {
        return $"{baselineKey.Length}:{baselineKey}{candidateKey.Length}:{candidateKey}";
    }

    private static HashSet<string> GetFindingKeys(
        IEnumerable<FindingDecision> decisions,
        FindingClassification classification)
    {
        return decisions
            .Where(item => item.Classification == classification)
            .SelectMany(item => new[]
            {
                item.Baseline?.FindingKey,
                item.Candidate?.FindingKey,
            })
            .Where(item => item is not null)
            .Select(item => item!)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static int IntersectionCount(
        IEnumerable<string> left,
        IReadOnlySet<string> right)
    {
        return left.Count(right.Contains);
    }

    private static int ExceptCount(
        IEnumerable<string> left,
        IReadOnlySet<string> right)
    {
        return left.Count(item => !right.Contains(item));
    }
}
