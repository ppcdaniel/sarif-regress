using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Evaluates exact diagnostics and selected structured explanation goldens.
/// </summary>
public static class CorpusExpectationEvaluator
{
    /// <summary>
    /// Compares explicitly initialized expectation arrays with observed
    /// diagnostics and selected structured decisions.
    /// </summary>
    /// <param name="labels">The case ground truth.</param>
    /// <param name="diagnostics">All input, compatibility, and match diagnostics.</param>
    /// <param name="decisions">The complete matcher decision set.</param>
    /// <returns>Stable, ordinal-sorted mismatch descriptions.</returns>
    public static ImmutableArray<string> Evaluate(
        CorpusLabels labels,
        IEnumerable<Diagnostic> diagnostics,
        IEnumerable<FindingDecision> decisions)
    {
        ArgumentNullException.ThrowIfNull(labels);
        ArgumentNullException.ThrowIfNull(diagnostics);
        ArgumentNullException.ThrowIfNull(decisions);

        var failures = new List<string>();
        if (!labels.ExpectedDiagnostics.IsDefault)
        {
            EvaluateDiagnostics(
                labels.ExpectedDiagnostics,
                diagnostics,
                failures);
        }

        if (!labels.ExpectedExplanations.IsDefault)
        {
            EvaluateExplanations(
                labels.ExpectedExplanations,
                decisions,
                failures);
        }

        return failures
            .Order(StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static void EvaluateDiagnostics(
        ImmutableArray<CorpusDiagnosticExpectation> expected,
        IEnumerable<Diagnostic> actual,
        ICollection<string> failures)
    {
        string[] expectedSignatures = expected
            .Select(Signature)
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] actualSignatures = Diagnostic.Sort(actual)
            .Select(Signature)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (expectedSignatures.SequenceEqual(actualSignatures))
        {
            return;
        }

        AddMultisetDifferences(
            expectedSignatures,
            actualSignatures,
            "Missing expected diagnostic",
            "Unexpected diagnostic",
            failures);
    }

    private static void EvaluateExplanations(
        ImmutableArray<CorpusExplanationExpectation> expected,
        IEnumerable<FindingDecision> actual,
        ICollection<string> failures)
    {
        var decisions = IndexDecisions(actual);
        foreach (var expectation in expected.OrderBy(
                     item => ExplanationIdentity(
                         item.BaselineKey,
                         item.CandidateKey,
                         item.Classification),
                     StringComparer.Ordinal))
        {
            var key = new ExplanationDecisionIdentity(
                expectation.Classification,
                expectation.BaselineKey,
                expectation.CandidateKey);
            string identity = ExplanationIdentity(
                expectation.BaselineKey,
                expectation.CandidateKey,
                expectation.Classification);
            if (!decisions.TryGetValue(key, out var matches))
            {
                failures.Add($"Missing expected explanation: {identity}.");
                continue;
            }

            if (matches.Count > 1)
            {
                failures.Add($"Expected explanation is not unique: {identity}.");
                continue;
            }

            var decision = matches[0].Decision;
            if (decision.PrecedenceTier != expectation.PrecedenceTier)
            {
                failures.Add(
                    $"Explanation {identity} expected precedence "
                    + $"'{PrecedenceName(expectation.PrecedenceTier)}' but observed "
                    + $"'{PrecedenceName(decision.PrecedenceTier)}'.");
            }

            if (decision.Ambiguous != expectation.Ambiguous)
            {
                failures.Add(
                    $"Explanation {identity} expected ambiguous="
                    + $"{expectation.Ambiguous.ToString().ToLowerInvariant()} but observed "
                    + $"{decision.Ambiguous.ToString().ToLowerInvariant()}.");
            }

            string[] expectedKinds = expectation.EvidenceKinds
                .Order(StringComparer.Ordinal)
                .ToArray();
            string[] actualKinds = decision.Evidence
                .Select(item => item.Kind)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (!expectedKinds.SequenceEqual(actualKinds))
            {
                failures.Add(
                    $"Explanation {identity} expected evidence kinds "
                    + $"[{string.Join(", ", expectedKinds)}] but observed "
                    + $"[{string.Join(", ", actualKinds)}].");
            }
        }
    }

    private static Dictionary<
        ExplanationDecisionIdentity,
        List<FindingDecision>> IndexDecisions(
        IEnumerable<FindingDecision> decisions)
    {
        var result = new Dictionary<
            ExplanationDecisionIdentity,
            List<FindingDecision>>();
        foreach (var decision in decisions)
        {
            var key = new ExplanationDecisionIdentity(
                decision.Classification,
                decision.Baseline?.FindingKey,
                decision.Candidate?.FindingKey);
            if (!result.TryGetValue(key, out var matches))
            {
                matches = [];
                result.Add(key, matches);
            }

            matches.Add(decision);
        }

        return result;
    }

    private static void AddMultisetDifferences(
        IEnumerable<string> expected,
        IEnumerable<string> actual,
        string missingPrefix,
        string unexpectedPrefix,
        ICollection<string> failures)
    {
        var expectedCounts = Count(expected);
        var actualCounts = Count(actual);
        foreach (var signature in expectedCounts.Keys
                     .Union(actualCounts.Keys, StringComparer.Ordinal)
                     .Order(StringComparer.Ordinal))
        {
            expectedCounts.TryGetValue(signature, out var expectedCount);
            actualCounts.TryGetValue(signature, out var actualCount);
            for (var index = actualCount; index < expectedCount; index++)
            {
                failures.Add($"{missingPrefix}: {signature}.");
            }

            for (var index = expectedCount; index < actualCount; index++)
            {
                failures.Add($"{unexpectedPrefix}: {signature}.");
            }
        }
    }

    private static Dictionary<string, int> Count(IEnumerable<string> values)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            counts.TryGetValue(value, out var count);
            counts[value] = checked(count + 1);
        }

        return counts;
    }

    private static string Signature(CorpusDiagnosticExpectation diagnostic) =>
        Segment(diagnostic.Code)
        + Segment(SeverityName(diagnostic.Severity))
        + Segment(StageName(diagnostic.Stage))
        + Segment(diagnostic.Message)
        + OptionalSegment(
            diagnostic.Input.HasValue
                ? InputName(diagnostic.Input.Value)
                : null)
        + OptionalSegment(Coordinate(diagnostic.RunIndex))
        + OptionalSegment(Coordinate(diagnostic.ResultIndex))
        + OptionalSegment(diagnostic.JsonPointer)
        + OptionalSegment(diagnostic.StandardBasis)
        + OptionalSegment(diagnostic.Help);

    private static string Signature(Diagnostic diagnostic)
    {
        var source = diagnostic.SourceReference;
        return Segment(diagnostic.Code)
            + Segment(SeverityName(diagnostic.Severity))
            + Segment(StageName(diagnostic.Stage))
            + Segment(diagnostic.Message)
            + OptionalSegment(
                source is null ? null : InputName(source.Input))
            + OptionalSegment(Coordinate(source?.RunIndex))
            + OptionalSegment(Coordinate(source?.ResultIndex))
            + OptionalSegment(source?.JsonPointer)
            + OptionalSegment(diagnostic.StandardBasis)
            + OptionalSegment(diagnostic.Help);
    }

    private static string Segment(string value) =>
        $"{value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}:{value}";

    private static string OptionalSegment(string? value) =>
        value is null ? "N" : $"V{Segment(value)}";

    private static string ExplanationIdentity(
        string? baselineKey,
        string? candidateKey,
        FindingClassification classification) =>
        $"{ClassificationName(classification)} "
        + $"{baselineKey ?? "<none>"} -> {candidateKey ?? "<none>"}";

    private static string? Coordinate(int? value) =>
        value?.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static string ClassificationName(FindingClassification value) =>
        value.ToString().ToLowerInvariant();

    private static string InputName(InputKind value) =>
        value.ToString().ToLowerInvariant();

    private static string SeverityName(DiagnosticSeverity value) =>
        value.ToString().ToLowerInvariant();

    private static string StageName(DiagnosticStage value) =>
        value == DiagnosticStage.GithubCompatibility
            ? "github-compat"
            : value.ToString().ToLowerInvariant();

    private static string PrecedenceName(PrecedenceTier value) =>
        value switch
        {
            PrecedenceTier.Refuse => "refuse",
            PrecedenceTier.WeakContextual => "weak-contextual",
            PrecedenceTier.PathProblem => "path-problem",
            PrecedenceTier.StrongMoved => "strong-moved",
            PrecedenceTier.ExactCanonical => "exact-canonical",
            PrecedenceTier.ExactProducer => "exact-producer",
            PrecedenceTier.Override => "override",
            _ => throw new ArgumentOutOfRangeException(
                nameof(value),
                value,
                "Unknown precedence tier."),
        };

    private readonly record struct ExplanationDecisionIdentity(
        FindingClassification Classification,
        string? BaselineKey,
        string? CandidateKey);
}
