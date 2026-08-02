using System.Collections.Immutable;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class ComparisonSummaryTests
{
    [Fact]
    public void Aggregate_pass_does_not_hide_per_producer_precision_or_recall_failure()
    {
        CaseDefinition large = Case(
            "large-case",
            "large-producer",
            Enumerable.Range(1, 20)
                .Select(index => Match("large", index, correct: true))
                .ToImmutableArray(),
            Metrics(
                groundTruthUnits: 20,
                labelledRelationships: 20,
                truePositives: 20,
                falsePositives: 0,
                falseNegatives: 0,
                precision: 1m,
                recall: 1m,
                f1: 1m));
        CaseDefinition small = Case(
            "small-case",
            "small-producer",
            [
                Match("small", 1, correct: true),
                Match("small", 2, correct: false),
            ],
            Metrics(
                groundTruthUnits: 2,
                labelledRelationships: 2,
                truePositives: 1,
                falsePositives: 1,
                falseNegatives: 1,
                precision: 0.5m,
                recall: 0.5m,
                f1: 0.5m));

        ComparisonSummaryReport report = Build(
            [small, large],
            new ChangedDecisionExplanationCoverage(
                ChangedDecisionCount: 3,
                ChangedDecisionTraceCount: 3));

        Assert.True(report.ReleaseConditions.PrecisionMet);
        Assert.True(report.ReleaseConditions.RecallMet);
        Assert.False(report.ReleaseConditions.AllProducerPrecisionMet);
        Assert.False(report.ReleaseConditions.AllProducerRecallMet);
        Assert.Equal(0.95m, report.Thresholds.MinimumPerProducerPrecision);
        Assert.Equal(0.80m, report.Thresholds.MinimumPerProducerRecall);
        ProducerComparison smallProducer = Assert.Single(
            report.Producers,
            item => item.ProducerId == "small-producer");
        Assert.Equal(
            new ProducerQualityGates(0.95m, 0.80m, PrecisionMet: false, RecallMet: false),
            smallProducer.QualityGates);
        Assert.Equal(
            [
                "per-producer-precision-below-threshold",
                "per-producer-recall-below-threshold",
                "complete-label-graph-failed",
            ],
            report.RecommendationReasons);
        Assert.Equal("blocked", report.ReleaseRecommendation);
    }

    [Fact]
    public void Missing_changed_decision_trace_blocks_an_otherwise_ready_comparison()
    {
        CaseDefinition value = Case(
            "trace-case",
            "trace-producer",
            [Match("trace", 1, correct: true)],
            Metrics(
                groundTruthUnits: 1,
                labelledRelationships: 1,
                truePositives: 1,
                falsePositives: 0,
                falseNegatives: 0,
                precision: 1m,
                recall: 1m,
                f1: 1m));

        ComparisonSummaryReport report = Build(
            [value],
            new ChangedDecisionExplanationCoverage(
                ChangedDecisionCount: 2,
                ChangedDecisionTraceCount: 1));

        Assert.True(report.Thresholds.RequireChangedDecisionExplanations);
        Assert.False(report.ReleaseConditions.EveryChangedDecisionExplained);
        Assert.Equal(
            ["changed-decision-explanation-missing"],
            report.RecommendationReasons);
        Assert.Equal("blocked", report.ReleaseRecommendation);
    }

    [Fact]
    public void Lifecycle_projection_reports_expected_correct_incorrect_and_accuracy()
    {
        GroundTruthRelationship newTruth = new(
            "new",
            BaselineKey: null,
            CandidateKey: "candidate:new",
            ExpectedClassification: "new");
        GroundTruthRelationship resolvedTruth = new(
            "resolved",
            BaselineKey: "baseline:resolved",
            CandidateKey: null,
            ExpectedClassification: "resolved");
        ImmutableArray<RelationshipResult> relationships =
        [
            Relationship(
                "lifecycle-new-001",
                newTruth,
                new ActualRelationship("new", null, "candidate:new"),
                "correct-new"),
            Relationship(
                "lifecycle-new-002",
                newTruth with { CandidateKey = "candidate:missing" },
                new ActualRelationship("not-reported", null, null),
                "incorrect-new"),
            Relationship(
                "lifecycle-resolved-001",
                resolvedTruth,
                new ActualRelationship("resolved", "baseline:resolved", null),
                "correct-resolved"),
            Relationship(
                "lifecycle-resolved-002",
                resolvedTruth with { BaselineKey = "baseline:missing" },
                new ActualRelationship("not-reported", null, null),
                "incorrect-resolved"),
        ];
        CaseDefinition value = Case(
            "lifecycle-case",
            "lifecycle-producer",
            relationships,
            Metrics(
                groundTruthUnits: 4,
                labelledRelationships: 0,
                truePositives: 0,
                falsePositives: 0,
                falseNegatives: 0,
                precision: 1m,
                recall: 1m,
                f1: 1m,
                newClassifications: 1,
                resolvedClassifications: 1,
                expectedNewClassifications: 2,
                expectedResolvedClassifications: 2,
                correctNewClassifications: 1,
                correctResolvedClassifications: 1));

        ComparisonSummaryReport report = Build(
            [value],
            new ChangedDecisionExplanationCoverage(
                ChangedDecisionCount: 0,
                ChangedDecisionTraceCount: 0));
        SarifRegressComparisonMetrics aggregate = report.SarifRegress.Metrics;

        AssertLifecycleMetrics(aggregate);
        AssertLifecycleMetrics(Assert.Single(report.Producers).SarifRegress);
        Assert.Equal(Hash('5'), report.ReportHashes.MatcherV31ReportSha256);
        Assert.Equal(Hash('6'), report.ReportHashes.V31ToV32DeltaReportSha256);
    }

    [Fact]
    public void Recommendation_reasons_are_stable_across_case_input_order()
    {
        CaseDefinition precisionFailure = Case(
            "precision-case",
            "precision-producer",
            [Match("precision", 1, correct: false)],
            Metrics(
                groundTruthUnits: 1,
                labelledRelationships: 1,
                truePositives: 0,
                falsePositives: 1,
                falseNegatives: 1,
                precision: 0m,
                recall: 0m,
                f1: 0m));
        CaseDefinition passing = Case(
            "passing-case",
            "passing-producer",
            [Match("passing", 1, correct: true)],
            Metrics(
                groundTruthUnits: 1,
                labelledRelationships: 1,
                truePositives: 1,
                falsePositives: 0,
                falseNegatives: 0,
                precision: 1m,
                recall: 1m,
                f1: 1m));
        ChangedDecisionExplanationCoverage coverage = new(1, 0);

        ComparisonSummaryReport first = Build(
            [precisionFailure, passing],
            coverage,
            crossPlatformByteIdentity: false);
        ComparisonSummaryReport second = Build(
            [passing, precisionFailure],
            coverage,
            crossPlatformByteIdentity: false);

        Assert.Equal(first.RecommendationReasons, second.RecommendationReasons);
        Assert.Equal(
            [
                "precision-below-threshold",
                "recall-below-threshold",
                "per-producer-precision-below-threshold",
                "per-producer-recall-below-threshold",
                "complete-label-graph-failed",
                "cross-platform-determinism-failed",
                "changed-decision-explanation-missing",
            ],
            first.RecommendationReasons);
    }

    [Fact]
    public void Comparison_rejects_an_unbound_or_malformed_report_hash()
    {
        CaseDefinition value = Case(
            "hash-case",
            "hash-producer",
            [Match("hash", 1, correct: true)],
            Metrics(
                groundTruthUnits: 1,
                labelledRelationships: 1,
                truePositives: 1,
                falsePositives: 0,
                falseNegatives: 0,
                precision: 1m,
                recall: 1m,
                f1: 1m));
        var invalid = new ComparisonReportHashes(
            Identity().HoldoutManifestSha256,
            Hash('2'),
            Hash('3'),
            Hash('4'),
            Hash('5'),
            "not-a-hash");

        Assert.Throws<InvalidDataException>(() => Build(
            [value],
            new ChangedDecisionExplanationCoverage(0, 0),
            hashesOverride: invalid));
    }

    private static void AssertLifecycleMetrics(SarifRegressComparisonMetrics metrics)
    {
        Assert.Equal(2, metrics.ExpectedNewClassifications);
        Assert.Equal(1, metrics.CorrectNewClassifications);
        Assert.Equal(1, metrics.IncorrectNewClassifications);
        Assert.Equal(0.5m, metrics.NewClassificationAccuracy);
        Assert.Equal(2, metrics.ExpectedResolvedClassifications);
        Assert.Equal(1, metrics.CorrectResolvedClassifications);
        Assert.Equal(1, metrics.IncorrectResolvedClassifications);
        Assert.Equal(0.5m, metrics.ResolvedClassificationAccuracy);
    }

    private static ComparisonSummaryReport Build(
        ImmutableArray<CaseDefinition> definitions,
        ChangedDecisionExplanationCoverage coverage,
        bool crossPlatformByteIdentity = true,
        ComparisonReportHashes? hashesOverride = null)
    {
        EvaluationIdentity identity = Identity();
        ImmutableArray<SarifRegressCaseResult> sarifCases = definitions
            .OrderBy(item => item.CaseId, StringComparer.Ordinal)
            .Select(item => new SarifRegressCaseResult(
                item.CaseId,
                item.ProducerId,
                "evaluated",
                Inputs(),
                Hash('3'),
                item.Metrics,
                item.Relationships,
                new OutcomeDetails([], [], [], [], [], [], []),
                []))
            .ToImmutableArray();
        ImmutableArray<ProducerHoldoutMetrics> sarifProducers = definitions
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerHoldoutMetrics(
                group.Key,
                HoldoutMetricsCalculator.Aggregate(group.Select(item => item.Metrics))))
            .ToImmutableArray();
        SarifRegressHoldoutReport sarifRegress = new(
            identity,
            HoldoutMetricsCalculator.Aggregate(definitions.Select(item => item.Metrics)),
            sarifProducers,
            sarifCases,
            []);

        ImmutableArray<MultitoolCaseResult> multitoolCases = definitions
            .OrderBy(item => item.CaseId, StringComparer.Ordinal)
            .Select(item => MultitoolCase(item))
            .ToImmutableArray();
        ImmutableArray<ProducerMultitoolMetrics> multitoolProducers = definitions
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerMultitoolMetrics(
                group.Key,
                PerfectMultitoolMetrics(group.SelectMany(item => item.Relationships))))
            .ToImmutableArray();
        SarifMultitoolBaselineReport multitool = new(
            identity,
            Tool(),
            PerfectMultitoolMetrics(definitions.SelectMany(item => item.Relationships)),
            multitoolProducers,
            multitoolCases);
        ComparisonReportHashes hashes = hashesOverride ?? new(
            identity.HoldoutManifestSha256,
            Hash('2'),
            Hash('3'),
            Hash('4'),
            Hash('5'),
            Hash('6'));
        return ComparisonSummaryBuilder.Create(
            sarifRegress,
            multitool,
            hashes,
            crossPlatformByteIdentity,
            evaluationCompleted: true,
            changedDecisionExplanations: coverage);
    }

    private static MultitoolCaseResult MultitoolCase(CaseDefinition definition)
    {
        ImmutableArray<MultitoolRelationshipResult> relationships = definition.Relationships
            .Select(item => new MultitoolRelationshipResult(
                item.RelationshipId,
                item.GroundTruth,
                MultitoolState(item.GroundTruth.Kind),
                TaxonomyMapped: true,
                MappedClassification: item.GroundTruth.ExpectedClassification,
                Comparable: true,
                ComparabilityReason: "equivalent-state-semantics",
                Correct: true,
                ErrorOrUnsupportedCode: null))
            .ToImmutableArray();
        return new MultitoolCaseResult(
            definition.CaseId,
            definition.ProducerId,
            Inputs(),
            new NormalizedInvocation(".", "sarif", []),
            $"raw/multitool/{definition.CaseId}.sarif",
            InstrumentationStateMultisetPreserved: true,
            PerfectMultitoolMetrics(definition.Relationships),
            relationships);
    }

    private static MultitoolMetrics PerfectMultitoolMetrics(
        IEnumerable<RelationshipResult> relationships)
    {
        RelationshipResult[] values = relationships.ToArray();
        int labelledRelationships = values.Count(item =>
            item.GroundTruth.Kind == "match");
        return new MultitoolMetrics(
            GroundTruthUnits: values.Length,
            LabelledRelationships: labelledRelationships,
            ComparableRelationships: values.Length,
            NonComparableRelationships: 0,
            TruePositives: labelledRelationships,
            FalsePositives: 0,
            FalseNegatives: 0,
            Errors: 0,
            Unsupported: 0,
            Precision: 1m,
            Recall: 1m,
            F1: 1m,
            States: new MultitoolStateCounts(
                New: values.Count(item => item.GroundTruth.Kind == "new"),
                Absent: values.Count(item => item.GroundTruth.Kind == "resolved"),
                Unchanged: labelledRelationships,
                Updated: 0,
                Error: 0,
                Unsupported: 0));
    }

    private static CaseDefinition Case(
        string caseId,
        string producerId,
        ImmutableArray<RelationshipResult> relationships,
        HoldoutMetrics metrics) => new(caseId, producerId, relationships, metrics);

    private static RelationshipResult Match(string prefix, int index, bool correct)
    {
        string suffix = index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);
        GroundTruthRelationship truth = new(
            "match",
            $"baseline:{prefix}:{suffix}",
            $"candidate:{prefix}:{suffix}",
            "unchanged");
        return Relationship(
            $"{prefix}-match-{suffix}",
            truth,
            new ActualRelationship(
                "unchanged",
                truth.BaselineKey,
                correct ? truth.CandidateKey : $"candidate:{prefix}:wrong-{suffix}"),
            correct ? "true-positive" : "false-match");
    }

    private static RelationshipResult Relationship(
        string id,
        GroundTruthRelationship truth,
        ActualRelationship actual,
        string outcome) => new(id, truth, actual, outcome);

    private static HoldoutMetrics Metrics(
        int groundTruthUnits,
        int labelledRelationships,
        int truePositives,
        int falsePositives,
        int falseNegatives,
        decimal precision,
        decimal recall,
        decimal f1,
        int newClassifications = 0,
        int resolvedClassifications = 0,
        int expectedNewClassifications = 0,
        int expectedResolvedClassifications = 0,
        int correctNewClassifications = 0,
        int correctResolvedClassifications = 0)
    {
        return new HoldoutMetrics(
            GroundTruthUnits: groundTruthUnits,
            LabelledRelationships: labelledRelationships,
            LabelledMatches: truePositives + falsePositives,
            TruePositives: truePositives,
            FalsePositives: falsePositives,
            FalseNegatives: falseNegatives,
            ClassificationMismatches: 0,
            NewClassifications: newClassifications,
            ResolvedClassifications: resolvedClassifications,
            AmbiguousClassifications: 0,
            CorrectNewClassifications: correctNewClassifications,
            CorrectResolvedClassifications: correctResolvedClassifications,
            CorrectAmbiguityRefusals: 0,
            UnexpectedAmbiguityRefusals: 0,
            IncorrectlyAutoMatchedAmbiguousCases: 0,
            IngestionFailures: 0,
            StructuralFailures: 0,
            Precision: precision,
            Recall: recall,
            F1: f1)
        {
            ExpectedNewClassifications = expectedNewClassifications,
            IncorrectNewClassifications = checked(
                expectedNewClassifications - correctNewClassifications),
            NewClassificationAccuracy = Accuracy(
                correctNewClassifications,
                expectedNewClassifications),
            ExpectedResolvedClassifications = expectedResolvedClassifications,
            IncorrectResolvedClassifications = checked(
                expectedResolvedClassifications - correctResolvedClassifications),
            ResolvedClassificationAccuracy = Accuracy(
                correctResolvedClassifications,
                expectedResolvedClassifications),
        };
    }

    private static decimal Accuracy(int correct, int expected) => expected == 0
        ? 1m
        : decimal.Round(
            (decimal)correct / expected,
            6,
            MidpointRounding.ToEven);

    private static EvaluationIdentity Identity() => new(
        new string('a', 40),
        Hash('a'),
        "0.1.0",
        "sarifregress/matcher/v3",
        [new NamedAlgorithmVersion("derived-fingerprint", "v2")],
        "1",
        "1",
        Hash('b'));

    private static CaseInputHashes Inputs() => new(
        Hash('a'),
        Hash('b'),
        Hash('c'),
        Hash('d'),
        Hash('e'),
        Hash('f'));

    private static MultitoolToolEvidence Tool() => new(
        "Microsoft SARIF Multitool",
        "Microsoft.CodeAnalysis.Sarif.Multitool",
        "5.5.0",
        "https://github.com/microsoft/sarif-sdk",
        new string('a', 40),
        "https://api.nuget.org/v3-flatcontainer/package.nupkg",
        Hash('7'),
        1,
        "MIT",
        Hash('8'),
        Hash('9'));

    private static string MultitoolState(string kind) => kind switch
    {
        "new" => "new",
        "resolved" => "absent",
        _ => "unchanged",
    };

    private static string Hash(char value) => new(value, 64);

    private sealed record CaseDefinition(
        string CaseId,
        string ProducerId,
        ImmutableArray<RelationshipResult> Relationships,
        HoldoutMetrics Metrics);
}
