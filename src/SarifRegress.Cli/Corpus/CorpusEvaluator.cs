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
            .Select(pair => CreatePairKey(pair.BaselineKey, pair.CandidateKey))
            .ToHashSet(StringComparer.Ordinal);

        FindingDecision[] decisionArray = decisions.ToArray();
        var acceptedPairs = decisionArray
            .Where(IsAcceptedPair)
            .Select(decision => CreatePairKey(
                decision.Baseline!.FindingKey,
                decision.Candidate!.FindingKey))
            .ToHashSet(StringComparer.Ordinal);

        var truePositives = acceptedPairs.Count(expectedPairs.Contains);
        var falsePositives = acceptedPairs.Count - truePositives;
        var falseNegatives = expectedPairs.Count - truePositives;

        var silentlyMatchedAmbiguous = decisionArray
            .Where(IsAcceptedPair)
            .SelectMany(decision =>
                new[]
                {
                    decision.Baseline!.FindingKey,
                    decision.Candidate!.FindingKey,
                })
            .Distinct(StringComparer.Ordinal)
            .Count(labels.ExpectedAmbiguous.Contains);

        CorpusMetrics metrics = CreateMetrics(
            expectedPairs.Count,
            truePositives,
            falsePositives,
            falseNegatives,
            labels.ExpectedAmbiguous.Count,
            silentlyMatchedAmbiguous);

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
            cases.Sum(item => item.Metrics.SilentAmbiguousMatches));

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
}
