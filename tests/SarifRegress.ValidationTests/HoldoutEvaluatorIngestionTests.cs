using System.Collections.Immutable;
using System.Text;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class HoldoutEvaluatorIngestionTests
{
    [Theory]
    [InlineData(true, false, "baseline")]
    [InlineData(false, true, "candidate")]
    [InlineData(true, true, "baseline,candidate")]
    public async Task Labelled_ingestion_failures_are_normalized_by_input(
        bool invalidBaseline,
        bool invalidCandidate,
        string expectedInputs)
    {
        string repositoryRoot = CreateRepository(
            invalidBaseline,
            invalidCandidate);
        try
        {
            string labelsPath = Path.Combine(
                repositoryRoot,
                "validation",
                "holdout",
                "cases",
                CaseId,
                "labels.json");
            byte[] labelsBefore = File.ReadAllBytes(labelsPath);
            ValidatedHoldout holdout = CreateHoldout(CaseId);
            SarifRegressHoldoutReport report = await new SarifRegressHoldoutEvaluator()
                .EvaluateAsync(
                    repositoryRoot,
                    holdout,
                    CreateIdentity(),
                    TestContext.Current.CancellationToken);

            SarifRegressCaseResult result = Assert.Single(report.Cases);
            Assert.Equal("ingestion-failure", result.Status);
            Assert.Equal(
                expectedInputs.Split(','),
                result.Outcomes.IngestionFailures
                    .Select(item => item.Input)
                    .ToArray());
            Assert.All(
                result.Outcomes.IngestionFailures,
                failure => Assert.Equal("PARSE0100", failure.DiagnosticCode));
            RelationshipResult relationship = Assert.Single(
                result.RelationshipResults);
            Assert.Equal("baseline:0:0", relationship.GroundTruth.BaselineKey);
            Assert.Equal("candidate:0:0", relationship.GroundTruth.CandidateKey);
            Assert.Equal("ingestion-failure", relationship.Actual.State);
            Assert.Equal("ingestion-failure", relationship.Outcome);
            Assert.Empty(result.Outcomes.FalseMatches);
            Assert.Empty(result.Outcomes.MissedMatches);
            Assert.Equal(1, result.Metrics.LabelledRelationships);
            Assert.Equal(0, result.Metrics.TruePositives);
            Assert.Equal(0, result.Metrics.FalsePositives);
            Assert.Equal(1, result.Metrics.FalseNegatives);
            Assert.Equal(
                expectedInputs.Split(',').Length,
                result.Metrics.IngestionFailures);
            Assert.Equal(1, report.Aggregate.LabelledRelationships);
            Assert.Equal(1, report.Aggregate.FalseNegatives);
            Assert.Equal(
                expectedInputs.Split(',').Length,
                report.Aggregate.IngestionFailures);
            DiagnosticCount diagnostic = Assert.Single(report.DiagnosticCounts);
            Assert.Equal("PARSE0100", diagnostic.Code);
            Assert.Equal(expectedInputs.Split(',').Length, diagnostic.Count);
            Assert.Equal(
                ValidationExitCodes.Success,
                ValidationApplication.DetermineEvaluationExitCode(
                    report,
                    externalReproducibilityFailed: false,
                    crossPlatformByteIdentity: true));
            Assert.Equal(
                ValidationExitCodes.ValidationFailure,
                ValidationApplication.DetermineEvaluationExitCode(
                    report with
                    {
                        Aggregate = report.Aggregate with
                        {
                            StructuralFailures = 1,
                        },
                    },
                    externalReproducibilityFailed: false,
                    crossPlatformByteIdentity: true));
            Assert.Equal(labelsBefore, File.ReadAllBytes(labelsPath));
        }
        finally
        {
            Directory.Delete(repositoryRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Valid_case_retains_the_frozen_corpus_runner_artifact()
    {
        string repositoryRoot = CreateRepository(
            invalidBaseline: false,
            invalidCandidate: false);
        try
        {
            string holdoutRoot = Path.Combine(
                repositoryRoot,
                "validation",
                "holdout");
            CorpusRunResult direct = await new CorpusRunner().RunAsync(
                new CorpusRunRequest(
                    holdoutRoot,
                    CorpusThresholds.Mvp,
                    ResourceLimits.Default),
                TestContext.Current.CancellationToken);
            SarifRegressHoldoutReport report = await new SarifRegressHoldoutEvaluator()
                .EvaluateAsync(
                    repositoryRoot,
                    CreateHoldout(CaseId),
                    CreateIdentity(),
                    TestContext.Current.CancellationToken);

            CorpusCaseRun directCase = Assert.Single(direct.Cases);
            SarifRegressCaseResult result = Assert.Single(report.Cases);
            Assert.Equal("evaluated", result.Status);
            Assert.Equal(directCase.Artifact.Sha256, result.EngineReportSha256);
            Assert.Equal(
                "true-positive",
                Assert.Single(result.RelationshipResults).Outcome);
            Assert.Equal(1, result.Metrics.TruePositives);
            Assert.Empty(result.Outcomes.IngestionFailures);
        }
        finally
        {
            Directory.Delete(repositoryRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Fallback_retains_every_valid_neighbor_case_unchanged()
    {
        string repositoryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        string validOnlyRoot = CreateRepository(
            ValidCaseId,
            invalidBaseline: false,
            invalidCandidate: false);
        CreateCase(
            repositoryRoot,
            CaseId,
            invalidBaseline: true,
            invalidCandidate: false);
        CreateCase(
            repositoryRoot,
            ValidCaseId,
            invalidBaseline: false,
            invalidCandidate: false);
        try
        {
            CorpusRunResult direct = await new CorpusRunner().RunAsync(
                new CorpusRunRequest(
                    Path.Combine(validOnlyRoot, "validation", "holdout"),
                    CorpusThresholds.Mvp,
                    ResourceLimits.Default),
                TestContext.Current.CancellationToken);
            SarifRegressHoldoutReport report = await new SarifRegressHoldoutEvaluator()
                .EvaluateAsync(
                    repositoryRoot,
                    CreateHoldout(CaseId, ValidCaseId),
                    CreateIdentity(),
                    TestContext.Current.CancellationToken);

            Assert.Equal(
                [CaseId, ValidCaseId],
                report.Cases.Select(item => item.CaseId).ToArray());
            Assert.Equal(
                "ingestion-failure",
                report.Cases.Single(item => item.CaseId == CaseId).Status);
            SarifRegressCaseResult valid = report.Cases.Single(
                item => item.CaseId == ValidCaseId);
            Assert.Equal("evaluated", valid.Status);
            Assert.Equal(
                Assert.Single(direct.Cases).Artifact.Sha256,
                valid.EngineReportSha256);
            Assert.Equal(
                "true-positive",
                Assert.Single(valid.RelationshipResults).Outcome);
            Assert.Equal(2, report.Aggregate.LabelledRelationships);
            Assert.Equal(1, report.Aggregate.TruePositives);
            Assert.Equal(1, report.Aggregate.FalseNegatives);
            Assert.Equal(1, report.Aggregate.IngestionFailures);
        }
        finally
        {
            Directory.Delete(repositoryRoot, recursive: true);
            Directory.Delete(validOnlyRoot, recursive: true);
        }
    }

    private static string CreateRepository(
        bool invalidBaseline,
        bool invalidCandidate) => CreateRepository(
            CaseId,
            invalidBaseline,
            invalidCandidate);

    private static string CreateRepository(
        string caseId,
        bool invalidBaseline,
        bool invalidCandidate)
    {
        string root = ValidationTestRepository.CreateTemporaryDirectory();
        CreateCase(root, caseId, invalidBaseline, invalidCandidate);
        return root;
    }

    private static void CreateCase(
        string root,
        string caseId,
        bool invalidBaseline,
        bool invalidCandidate)
    {
        string caseDirectory = Path.Combine(
            root,
            "validation",
            "holdout",
            "cases",
            caseId);
        Directory.CreateDirectory(Path.Combine(caseDirectory, "producer-input"));
        File.WriteAllText(
            Path.Combine(caseDirectory, "baseline.sarif"),
            invalidBaseline ? InvalidSarif : ValidSarif,
            Utf8);
        File.WriteAllText(
            Path.Combine(caseDirectory, "candidate.sarif"),
            invalidCandidate ? InvalidSarif : ValidSarif,
            Utf8);
        File.WriteAllText(
            Path.Combine(caseDirectory, "labels.json"),
            Labels,
            Utf8);
    }

    private static ValidatedHoldout CreateHoldout(params string[] caseIds)
    {
        CorpusLabels labels = new(
            "1",
            [new LabelledPair(
                "baseline:0:0",
                "candidate:0:0",
                FindingClassification.Unchanged)],
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        var counts = new HoldoutCaseCounts(
            BaselineFindings: 1,
            CandidateFindings: 1,
            GroundTruthUnits: 1,
            LabelledRelationships: 1,
            SameFindingRelationships: 1,
            NewFindings: 0,
            ResolvedFindings: 0,
            NewOrResolvedFindings: 0,
            AmbiguousOrNearCollisionRelationships: 0);
        HoldoutCasePlan[] plans = caseIds
            .Order(StringComparer.Ordinal)
            .Select(caseId => new HoldoutCasePlan(
                caseId,
                "test-producer",
                new HoldoutCasePaths(
                    $"validation/holdout/cases/{caseId}",
                    $"validation/holdout/cases/{caseId}/baseline.sarif",
                    $"validation/holdout/cases/{caseId}/candidate.sarif",
                    $"validation/holdout/cases/{caseId}/labels.json",
                    $"validation/holdout/cases/{caseId}/notes.md",
                    $"validation/holdout/cases/{caseId}/producer-input",
                    Config: null),
                [],
                counts))
            .ToArray();
        HoldoutCaseCounts aggregateCounts = counts with
        {
            BaselineFindings = counts.BaselineFindings * plans.Length,
            CandidateFindings = counts.CandidateFindings * plans.Length,
            GroundTruthUnits = counts.GroundTruthUnits * plans.Length,
            LabelledRelationships = counts.LabelledRelationships * plans.Length,
            SameFindingRelationships =
                counts.SameFindingRelationships * plans.Length,
        };
        return new ValidatedHoldout(
            new HoldoutManifest(
                "1",
                "ingestion-test",
                [new HoldoutProducer(
                    "test-producer",
                    "test-family",
                    "Test Producer",
                    "1.0.0")],
                [.. plans],
                aggregateCounts),
            Hash('f'),
            [.. plans.Select(plan => new ValidatedHoldoutCase(
                plan,
                labels,
                new CaseInputHashes(
                    Hash('a'),
                    Hash('b'),
                    Hash('c'),
                    Hash('d'),
                    Hash('e'),
                    ConfigSha256: null)))]);
    }

    private static EvaluationIdentity CreateIdentity() => new(
        Hash('1'),
        Hash('2'),
        "0.1.0",
        "test-matcher/v1",
        [],
        "1",
        "1",
        Hash('f'));

    private static string Hash(char value) => new(value, 64);

    private const string CaseId = "labelled-invalid";
    private const string ValidCaseId = "valid-neighbor";
    private const string InvalidSarif = "{ this is not valid JSON }";
    private static readonly UTF8Encoding Utf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private const string Labels = """
        {
          "schemaVersion": "1",
          "pairs": [
            {
              "baselineKey": "baseline:0:0",
              "candidateKey": "candidate:0:0",
              "classification": "unchanged"
            }
          ],
          "expectedAmbiguous": [],
          "expectedResolved": [],
          "expectedNew": [],
          "expectedInvalidInputs": []
        }
        """;
    private const string ValidSarif = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": {
                "driver": {
                  "name": "Validation Test Producer",
                  "version": "1.0.0"
                }
              },
              "results": [
                {
                  "ruleId": "TEST001",
                  "message": { "text": "Controlled finding" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/example.cs" },
                        "region": {
                          "startLine": 4,
                          "startColumn": 3,
                          "snippet": { "text": "dangerous();" }
                        }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }
        """;
}
