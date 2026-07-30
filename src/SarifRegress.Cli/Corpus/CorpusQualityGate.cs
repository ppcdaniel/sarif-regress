using System.Collections.Immutable;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Applies the published deterministic corpus quality gates.
/// </summary>
public static class CorpusQualityGate
{
    /// <summary>
    /// Returns stable failure messages for aggregate metrics and case expectations.
    /// </summary>
    /// <param name="cases">The completed case runs.</param>
    /// <param name="aggregate">The aggregate metrics.</param>
    /// <param name="thresholds">The quality thresholds.</param>
    /// <returns>Ordinal-sorted failure messages.</returns>
    public static ImmutableArray<string> Evaluate(
        IEnumerable<CorpusCaseRun> cases,
        CorpusMetrics aggregate,
        CorpusThresholds thresholds)
    {
        ArgumentNullException.ThrowIfNull(cases);
        ArgumentNullException.ThrowIfNull(aggregate);
        ArgumentNullException.ThrowIfNull(thresholds);
        thresholds.Validate();

        var failures = new List<string>();
        foreach (var caseRun in cases.OrderBy(
                     item => item.CaseName,
                     StringComparer.Ordinal))
        {
            if (!caseRun.Passed)
            {
                failures.Add(
                    $"Case '{caseRun.CaseName}' did not satisfy its complete label graph.");
                failures.AddRange(
                    caseRun.ExpectationFailures.Select(
                        failure =>
                            $"Case '{caseRun.CaseName}': {failure}"));
            }
        }

        if (aggregate.Precision < thresholds.MinimumPrecision)
        {
            failures.Add(
                $"Aggregate precision {Format(aggregate.Precision)} is below "
                + $"{Format(thresholds.MinimumPrecision)}.");
        }

        if (aggregate.Recall < thresholds.MinimumRecall)
        {
            failures.Add(
                $"Aggregate recall {Format(aggregate.Recall)} is below "
                + $"{Format(thresholds.MinimumRecall)}.");
        }

        if (aggregate.SilentAmbiguousMatches >
            thresholds.MaximumSilentAmbiguousMatches)
        {
            failures.Add(
                $"Silent ambiguity count {aggregate.SilentAmbiguousMatches} exceeds "
                + $"{thresholds.MaximumSilentAmbiguousMatches}.");
        }

        if (!aggregate.ExpectationsSatisfied)
        {
            failures.Add(
                "Aggregate classifications or expected new, resolved, and ambiguous "
                + "sets differ from the labels.");
        }

        return failures
            .Order(StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static string Format(decimal value) =>
        value.ToString(
            "0.######",
            System.Globalization.CultureInfo.InvariantCulture);
}
