using System.Collections.Immutable;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class HoldoutEvaluationTests
{
    [Fact]
    public void Aggregate_metrics_recompute_precision_recall_and_f1_from_counts()
    {
        HoldoutMetrics first = CreateMetrics(
            labelledRelationships: 10,
            truePositives: 8,
            falsePositives: 2,
            falseNegatives: 2);
        HoldoutMetrics second = CreateMetrics(
            labelledRelationships: 4,
            truePositives: 1,
            falsePositives: 0,
            falseNegatives: 3);

        HoldoutMetrics aggregate = HoldoutMetricsCalculator.Aggregate(
            [first, second]);

        Assert.Equal(14, aggregate.LabelledRelationships);
        Assert.Equal(9, aggregate.TruePositives);
        Assert.Equal(2, aggregate.FalsePositives);
        Assert.Equal(5, aggregate.FalseNegatives);
        Assert.Equal(0.818182m, aggregate.Precision);
        Assert.Equal(0.642857m, aggregate.Recall);
        Assert.Equal(0.72m, aggregate.F1);
    }

    [Fact]
    public void Zero_denominators_have_explicit_perfect_metrics()
    {
        HoldoutMetrics aggregate = HoldoutMetricsCalculator.Aggregate(
            [CreateMetrics(0, 0, 0, 0)]);

        Assert.Equal(1m, aggregate.Precision);
        Assert.Equal(1m, aggregate.Recall);
        Assert.Equal(1m, aggregate.F1);
    }

    [Fact]
    public void Classifier_separates_false_match_miss_mismatch_and_ambiguity()
    {
        CorpusLabels labels = new(
            "1",
            [
                Pair("baseline:0:0", "candidate:0:0"),
                Pair("baseline:0:1", "candidate:0:1"),
                Pair("baseline:0:2", "candidate:0:2"),
                Pair("baseline:0:3", "candidate:0:3"),
            ],
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                "baseline:0:4",
                "candidate:0:4"),
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        CorpusCaseRun caseRun = CreateCaseRun(
            "taxonomy",
            """
            {
              "findings": [
                {
                  "classification": "unchanged",
                  "baseline": { "findingKey": "baseline:0:0" },
                  "candidate": { "findingKey": "candidate:0:99" }
                },
                {
                  "classification": "moved",
                  "baseline": { "findingKey": "baseline:0:2" },
                  "candidate": { "findingKey": "candidate:0:2" }
                },
                {
                  "classification": "ambiguous",
                  "baseline": { "findingKey": "baseline:0:3" },
                  "candidate": null
                },
                {
                  "classification": "unchanged",
                  "baseline": { "findingKey": "baseline:0:4" },
                  "candidate": { "findingKey": "candidate:0:4" }
                }
              ],
              "diagnostics": []
            }
            """,
            new CorpusMetrics(4, 0, 1, 3, 2, 1, 0m, 0m, 0m)
            {
                ClassificationMismatches = 1,
                UnexpectedAmbiguous = 1,
            });

        SarifRegressCaseResult result = HoldoutOutcomeClassifier.Classify(
            CreateHoldoutCase("taxonomy", labels),
            caseRun);

        Assert.Equal(
            ["taxonomy-match-001"],
            RelationshipIds(result.Outcomes.FalseMatches));
        Assert.Equal(
            ["taxonomy-match-002"],
            RelationshipIds(result.Outcomes.MissedMatches));
        Assert.Equal(
            ["taxonomy-match-003"],
            RelationshipIds(result.Outcomes.ClassificationMismatches));
        AmbiguityRefusal refusal = Assert.Single(result.Outcomes.AmbiguityRefusals);
        Assert.Equal("taxonomy-match-004", refusal.RelationshipId);
        Assert.False(refusal.Expected);
        Assert.Equal(
            ["taxonomy-ambiguous-001"],
            RelationshipIds(result.Outcomes.IncorrectAmbiguityMatches));
        Assert.Equal(1, result.Metrics.UnexpectedAmbiguityRefusals);
        Assert.Equal(1, result.Metrics.IncorrectlyAutoMatchedAmbiguousCases);
        Assert.Empty(result.Outcomes.IngestionFailures);
        Assert.Empty(result.Outcomes.StructuralFailures);
    }

    [Fact]
    public void Ingestion_failure_is_not_collapsed_into_match_failures()
    {
        CorpusLabels labels = new(
            "1",
            [Pair("baseline:0:0", "candidate:0:0")],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        CorpusCaseRun run = CreateCaseRun(
            "ingestion",
            """
            {
              "inputs": [
                {
                  "input": "baseline",
                  "valid": false,
                  "diagnostics": [{
                    "code": "PARSE0100",
                    "severity": "error",
                    "stage": "parse"
                  }]
                },
                {
                  "input": "candidate",
                  "valid": true,
                  "diagnostics": []
                }
              ]
            }
            """,
            new CorpusMetrics(1, 0, 0, 1, 0, 0, 1m, 0m, 0m),
            observedInvalidInputs: [InputKind.Baseline],
            artifactKind: "invalid-input-diagnostics");

        SarifRegressCaseResult result = HoldoutOutcomeClassifier.Classify(
            CreateHoldoutCase("ingestion", labels),
            run);

        Assert.Equal("ingestion-failure", result.Status);
        IngestionFailure failure = Assert.Single(result.Outcomes.IngestionFailures);
        Assert.Equal("baseline", failure.Input);
        Assert.Equal("PARSE0100", failure.DiagnosticCode);
        Assert.Empty(result.Outcomes.FalseMatches);
        Assert.Empty(result.Outcomes.MissedMatches);
        Assert.Empty(result.Outcomes.ClassificationMismatches);
        Assert.Empty(result.Outcomes.AmbiguityRefusals);
        Assert.Empty(result.Outcomes.IncorrectAmbiguityMatches);
        Assert.All(
            result.RelationshipResults,
            relationship => Assert.Equal("ingestion-failure", relationship.Outcome));
    }

    [Fact]
    public void Unknown_corpus_artifact_kind_is_rejected()
    {
        CorpusLabels labels = new(
            "1",
            [Pair("baseline:0:0", "candidate:0:0")],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        CorpusCaseRun run = CreateCaseRun(
            "unknown-artifact",
            """{ "findings": [] }""",
            new CorpusMetrics(1, 0, 0, 1, 0, 0, 1m, 0m, 0m),
            artifactKind: "unknown");

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
            HoldoutOutcomeClassifier.Classify(
                CreateHoldoutCase("unknown-artifact", labels),
                run));

        Assert.Contains(
            "unsupported artifact kind",
            exception.Message,
            StringComparison.Ordinal);
    }

    private static LabelledPair Pair(string baseline, string candidate) => new(
        baseline,
        candidate,
        FindingClassification.Unchanged);

    private static CorpusCaseRun CreateCaseRun(
        string caseId,
        string artifactJson,
        CorpusMetrics metrics,
        ImmutableArray<InputKind> observedInvalidInputs = default,
        string artifactKind = "comparison") => new(
        caseId,
        [],
        observedInvalidInputs.IsDefault ? [] : observedInvalidInputs,
        new CorpusCaseArtifact(
            artifactKind,
            ValidationTestRepository.Utf8(artifactJson + "\n")),
        metrics,
        Passed: false);

    private static ValidatedHoldoutCase CreateHoldoutCase(
        string caseId,
        CorpusLabels labels) => new(
        new HoldoutCasePlan(
            caseId,
            "producer",
            new HoldoutCasePaths(
                $"validation/holdout/cases/{caseId}",
                $"validation/holdout/cases/{caseId}/baseline.sarif",
                $"validation/holdout/cases/{caseId}/candidate.sarif",
                $"validation/holdout/cases/{caseId}/labels.json",
                $"validation/holdout/cases/{caseId}/notes.md",
                $"validation/holdout/cases/{caseId}/producer-input",
                Config: null),
            [],
            new HoldoutCaseCounts(
                BaselineFindings: 0,
                CandidateFindings: 0,
                GroundTruthUnits: labels.Pairs.Length
                    + labels.ExpectedNew.Count
                    + labels.ExpectedResolved.Count
                    + labels.ExpectedAmbiguous.Count / 2,
                LabelledRelationships: labels.Pairs.Length,
                SameFindingRelationships: labels.Pairs.Length,
                NewFindings: labels.ExpectedNew.Count,
                ResolvedFindings: labels.ExpectedResolved.Count,
                NewOrResolvedFindings: labels.ExpectedNew.Count
                    + labels.ExpectedResolved.Count,
                AmbiguousOrNearCollisionRelationships:
                    labels.ExpectedAmbiguous.Count / 2)),
        labels,
        new CaseInputHashes(
            Hash('a'),
            Hash('b'),
            Hash('c'),
            Hash('d'),
            Hash('e'),
            ConfigSha256: null));

    private static HoldoutMetrics CreateMetrics(
        int labelledRelationships,
        int truePositives,
        int falsePositives,
        int falseNegatives) => new(
        GroundTruthUnits: labelledRelationships,
        LabelledRelationships: labelledRelationships,
        LabelledMatches: truePositives + falsePositives,
        TruePositives: truePositives,
        FalsePositives: falsePositives,
        FalseNegatives: falseNegatives,
        ClassificationMismatches: 0,
        NewClassifications: 0,
        ResolvedClassifications: 0,
        AmbiguousClassifications: 0,
        CorrectNewClassifications: 0,
        CorrectResolvedClassifications: 0,
        CorrectAmbiguityRefusals: 0,
        UnexpectedAmbiguityRefusals: 0,
        IncorrectlyAutoMatchedAmbiguousCases: 0,
        IngestionFailures: 0,
        StructuralFailures: 0,
        Precision: 0,
        Recall: 0,
        F1: 0);

    private static string[] RelationshipIds(
        IEnumerable<RelationshipReference> relationships) => relationships
        .Select(item => item.RelationshipId)
        .ToArray();

    private static string Hash(char value) => new string(value, 64);
}
