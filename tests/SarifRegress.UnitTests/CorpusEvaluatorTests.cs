using System.Collections.Immutable;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;

namespace SarifRegress.UnitTests;

public sealed class CorpusEvaluatorTests
{
    [Fact]
    public void Evaluation_uses_the_pairing_graph_not_summary_counts()
    {
        Finding baselineA = CreateFinding("baseline-a", InputKind.Baseline, 0);
        Finding baselineB = CreateFinding("baseline-b", InputKind.Baseline, 1);
        Finding candidateA = CreateFinding("candidate-a", InputKind.Candidate, 0);
        Finding candidateWrong = CreateFinding("candidate-wrong", InputKind.Candidate, 1);
        CorpusLabels labels = new(
            "1",
            [
                new LabelledPair(
                    baselineA.FindingKey,
                    candidateA.FindingKey,
                    FindingClassification.Unchanged),
                new LabelledPair(
                    baselineB.FindingKey,
                    candidateWrong.FindingKey,
                    FindingClassification.Unchanged),
            ],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        FindingDecision[] decisions =
        [
            CreateAccepted(baselineA, candidateA),
            CreateAccepted(baselineB, candidateA),
        ];

        var evaluation = CorpusEvaluator.Evaluate("pairing-graph", labels, decisions);

        Assert.Equal(1, evaluation.Metrics.TruePositives);
        Assert.Equal(1, evaluation.Metrics.FalsePositives);
        Assert.Equal(1, evaluation.Metrics.FalseNegatives);
        Assert.Equal(0.5m, evaluation.Metrics.Precision);
        Assert.Equal(0.5m, evaluation.Metrics.Recall);
    }

    [Fact]
    public void Accepted_match_for_expected_ambiguity_is_counted_as_silent()
    {
        Finding baseline = CreateFinding("baseline-a", InputKind.Baseline, 0);
        Finding candidate = CreateFinding("candidate-a", InputKind.Candidate, 0);
        CorpusLabels labels = new(
            "1",
            [],
            ImmutableHashSet.Create(StringComparer.Ordinal, baseline.FindingKey),
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);

        var evaluation = CorpusEvaluator.Evaluate(
            "ambiguous",
            labels,
            [CreateAccepted(baseline, candidate)]);

        Assert.Equal(1, evaluation.Metrics.SilentAmbiguousMatches);
    }

    [Fact]
    public void Aggregate_sorts_cases_and_recomputes_ratios_from_counts()
    {
        CorpusCaseEvaluation first = new(
            "z-case",
            new CorpusMetrics(2, 1, 1, 1, 0, 0, 0.5m, 0.5m, 0.5m));
        CorpusCaseEvaluation second = new(
            "a-case",
            new CorpusMetrics(8, 8, 0, 0, 0, 0, 1m, 1m, 1m));

        var aggregate = CorpusEvaluator.Aggregate([first, second]);

        Assert.Equal(["a-case", "z-case"], aggregate.Cases.Select(item => item.CaseName));
        Assert.Equal(0.9m, aggregate.Aggregate.Precision);
        Assert.Equal(0.9m, aggregate.Aggregate.Recall);
    }

    private static FindingDecision CreateAccepted(Finding baseline, Finding candidate)
    {
        DecisionTrace trace = new(
            PrecedenceTier.ExactCanonical,
            DisplayConfidence.High,
            false,
            "test/v1",
            [],
            [],
            [],
            []);
        return new FindingDecision(
            FindingClassification.Unchanged,
            baseline,
            candidate,
            trace);
    }

    private static Finding CreateFinding(
        string key,
        InputKind input,
        int resultIndex)
    {
        return new Finding(
            key,
            new SourceReference(
                input,
                0,
                resultIndex,
                $"/runs/0/results/{resultIndex}"),
            new RunIdentity(0, null, "run:0"),
            new ProducerIdentity(
                "Test",
                "1.0",
                "test",
                AutomationCategory: null,
                AutomaticIdentity: "test"),
            new RuleIdentity("R1", "test/R1", false),
            null,
            new MessageIdentity("Message", "Message", "message", []));
    }
}
