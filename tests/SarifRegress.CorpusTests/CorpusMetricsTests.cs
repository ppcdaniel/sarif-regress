using System.Collections.Immutable;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;

namespace SarifRegress.CorpusTests;

public sealed class CorpusMetricsTests
{
    [Fact]
    public void Evaluator_checks_classification_and_complete_expected_sets()
    {
        Finding baselinePair = CreateFinding(
            "baseline:0:0",
            InputKind.Baseline,
            0);
        Finding baselineResolved = CreateFinding(
            "baseline:0:1",
            InputKind.Baseline,
            1);
        Finding baselineAmbiguous = CreateFinding(
            "baseline:0:2",
            InputKind.Baseline,
            2);
        Finding candidatePair = CreateFinding(
            "candidate:0:0",
            InputKind.Candidate,
            0);
        Finding candidateNew = CreateFinding(
            "candidate:0:1",
            InputKind.Candidate,
            1);
        CorpusLabels labels = new(
            "1",
            [
                new LabelledPair(
                    baselinePair.FindingKey,
                    candidatePair.FindingKey,
                    FindingClassification.Unchanged),
            ],
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                baselineAmbiguous.FindingKey),
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                baselineResolved.FindingKey),
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                candidateNew.FindingKey));
        FindingDecision[] decisions =
        [
            CreateDecision(
                FindingClassification.Moved,
                baselinePair,
                candidatePair,
                ambiguous: false),
            CreateDecision(
                FindingClassification.Resolved,
                baselineResolved,
                candidate: null,
                ambiguous: false),
            CreateDecision(
                FindingClassification.Ambiguous,
                baselineAmbiguous,
                candidate: null,
                ambiguous: true),
            CreateDecision(
                FindingClassification.New,
                baseline: null,
                candidateNew,
                ambiguous: false),
        ];

        var evaluation = CorpusEvaluator.Evaluate(
            "complete-expectations",
            labels,
            decisions);

        Assert.Equal(1, evaluation.Metrics.TruePositives);
        Assert.Equal(1, evaluation.Metrics.ClassificationMismatches);
        Assert.Equal(1, evaluation.Metrics.CorrectAmbiguous);
        Assert.Equal(1, evaluation.Metrics.CorrectResolved);
        Assert.Equal(1, evaluation.Metrics.CorrectNew);
        Assert.False(evaluation.Metrics.ExpectationsSatisfied);
    }

    [Fact]
    public void Quality_gate_fails_published_precision_recall_and_ambiguity_bounds()
    {
        CorpusMetrics metrics = new(
            LabelledPairs: 20,
            TruePositives: 17,
            FalsePositives: 2,
            FalseNegatives: 3,
            ExpectedAmbiguous: 1,
            SilentAmbiguousMatches: 1,
            Precision: 0.894737m,
            Recall: 0.85m,
            F1: 0.871795m);
        CorpusCaseRun caseRun = new(
            "below-threshold",
            [],
            [],
            metrics,
            Passed: true);

        var failures = CorpusQualityGate.Evaluate(
            [caseRun],
            metrics,
            CorpusThresholds.Mvp);

        Assert.Contains(failures, item => item.Contains(
            "precision",
            StringComparison.Ordinal));
        Assert.Contains(failures, item => item.Contains(
            "recall",
            StringComparison.Ordinal));
        Assert.Contains(failures, item => item.Contains(
            "Silent ambiguity",
            StringComparison.Ordinal));
    }

    private static FindingDecision CreateDecision(
        FindingClassification classification,
        Finding? baseline,
        Finding? candidate,
        bool ambiguous)
    {
        DecisionTrace trace = new(
            ambiguous ? PrecedenceTier.Refuse : PrecedenceTier.ExactCanonical,
            ambiguous ? DisplayConfidence.Low : DisplayConfidence.High,
            ambiguous,
            "test/v1",
            [],
            [],
            [],
            []);
        return new FindingDecision(classification, baseline, candidate, trace);
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
            new RunIdentity(0, null, $"{input}:0"),
            new ProducerIdentity("Corpus", "1.0", "corpus", null),
            new RuleIdentity("R1", "corpus/R1", false),
            null,
            new MessageIdentity("Message", "Message", "message", []));
    }
}
