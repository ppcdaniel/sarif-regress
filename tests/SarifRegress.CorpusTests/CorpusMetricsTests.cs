using System.Collections.Immutable;
using System.Text;
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
            new CorpusCaseArtifact(
                "test",
                Encoding.UTF8.GetBytes("{}\n")),
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

    [Fact]
    public void Explicit_diagnostic_and_explanation_expectations_are_enforced()
    {
        Finding baseline = CreateFinding(
            "baseline:0:0",
            InputKind.Baseline,
            0);
        Finding candidate = CreateFinding(
            "candidate:0:0",
            InputKind.Candidate,
            0);
        var source = new SourceReference(
            InputKind.Baseline,
            0,
            0,
            "/runs/0/results/0");
        var expectedDiagnostic = new CorpusDiagnosticExpectation(
            "PARSE0100",
            DiagnosticSeverity.Error,
            DiagnosticStage.Parse,
            "Expected message.",
            Input: InputKind.Baseline,
            RunIndex: 0,
            ResultIndex: 0,
            JsonPointer: "/runs/0/results/0");
        CorpusLabels labels = new(
            "1",
            [],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty)
        {
            ExpectedDiagnostics = [expectedDiagnostic],
            ExpectedExplanations =
            [
                new CorpusExplanationExpectation(
                    baseline.FindingKey,
                    candidate.FindingKey,
                    FindingClassification.Unchanged,
                    PrecedenceTier.ExactProducer,
                    Ambiguous: false,
                    EvidenceKinds: ["producer-fingerprint"]),
            ],
        };
        var actualDiagnostic = new Diagnostic(
            "PARSE0100",
            DiagnosticSeverity.Error,
            DiagnosticStage.Parse,
            "Changed message.",
            source);
        var actualDecision = CreateDecision(
            FindingClassification.Unchanged,
            baseline,
            candidate,
            ambiguous: false);

        var failures = CorpusExpectationEvaluator.Evaluate(
            labels,
            [actualDiagnostic],
            [actualDecision]);

        Assert.Contains(
            failures,
            item => item.StartsWith(
                "Missing expected diagnostic:",
                StringComparison.Ordinal));
        Assert.Contains(
            failures,
            item => item.StartsWith(
                "Unexpected diagnostic:",
                StringComparison.Ordinal));
        Assert.Contains(
            failures,
            item => item.Contains(
                "expected precedence 'exact-producer'",
                StringComparison.Ordinal));
        Assert.Contains(
            failures,
            item => item.Contains(
                "expected evidence kinds [producer-fingerprint]",
                StringComparison.Ordinal));
    }

    [Fact]
    public void Exact_diagnostics_include_source_absence_standard_basis_and_help()
    {
        var expected = new CorpusDiagnosticExpectation(
            "MATCH0001",
            DiagnosticSeverity.Warning,
            DiagnosticStage.Match,
            "Ambiguous assignment.",
            StandardBasis: "matcher-policy-v1",
            Help: "Add stronger evidence.");
        CorpusLabels labels = new(
            "1",
            [],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty)
        {
            ExpectedDiagnostics = [expected],
        };
        var exact = new Diagnostic(
            "MATCH0001",
            DiagnosticSeverity.Warning,
            DiagnosticStage.Match,
            "Ambiguous assignment.",
            standardBasis: "matcher-policy-v1",
            help: "Add stronger evidence.");
        var changedHelp = new Diagnostic(
            "MATCH0001",
            DiagnosticSeverity.Warning,
            DiagnosticStage.Match,
            "Ambiguous assignment.",
            standardBasis: "matcher-policy-v1",
            help: "Different guidance.");

        Assert.Empty(
            CorpusExpectationEvaluator.Evaluate(labels, [exact], []));
        var failures = CorpusExpectationEvaluator.Evaluate(
            labels,
            [changedHelp],
            []);

        Assert.Equal(2, failures.Length);
        Assert.Contains(
            failures,
            item => item.StartsWith(
                "Missing expected diagnostic:",
                StringComparison.Ordinal));
        Assert.Contains(
            failures,
            item => item.StartsWith(
                "Unexpected diagnostic:",
                StringComparison.Ordinal));
    }

    [Fact]
    public void Explanation_lookup_retains_duplicate_decision_multiplicity()
    {
        Finding baseline = CreateFinding(
            "baseline:0:0",
            InputKind.Baseline,
            0);
        Finding candidate = CreateFinding(
            "candidate:0:0",
            InputKind.Candidate,
            0);
        CorpusLabels labels = new(
            "1",
            [],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty)
        {
            ExpectedExplanations =
            [
                new CorpusExplanationExpectation(
                    baseline.FindingKey,
                    candidate.FindingKey,
                    FindingClassification.Unchanged,
                    PrecedenceTier.ExactCanonical,
                    Ambiguous: false,
                    EvidenceKinds: []),
            ],
        };
        var decision = CreateDecision(
            FindingClassification.Unchanged,
            baseline,
            candidate,
            ambiguous: false);

        var failures = CorpusExpectationEvaluator.Evaluate(
            labels,
            [],
            [decision, decision]);

        var failure = Assert.Single(failures);
        Assert.Equal(
            "Expected explanation is not unique: unchanged "
            + "baseline:0:0 -> candidate:0:0.",
            failure);
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
            new ProducerIdentity(
                "Corpus",
                "1.0",
                "corpus",
                AutomationCategory: null,
                AutomaticIdentity: "corpus"),
            new RuleIdentity("R1", "corpus/R1", false),
            null,
            new MessageIdentity("Message", "Message", "message", []));
    }
}
