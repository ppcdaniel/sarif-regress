using System.Collections.Immutable;
using System.Text;
using System.Text.Json.Nodes;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class StableReportSerializerTests
{
    [Fact]
    public void All_normalized_reports_are_repeatedly_byte_stable()
    {
        (SarifRegressHoldoutReport sarifRegress,
            SarifMultitoolBaselineReport multitool) = CreateReports();
        ComparisonSummaryReport comparison = ComparisonSummaryBuilder.Create(
            sarifRegress,
            multitool,
            new ComparisonReportHashes(
                sarifRegress.Evaluation.HoldoutManifestSha256,
                Hash('b'),
                Hash('c'),
                Hash('d'),
                Hash('e'),
                Hash('f')),
            crossPlatformByteIdentity: true);

        AssertStable(() => StableReportSerializer.Serialize(sarifRegress));
        AssertStable(() => StableReportSerializer.Serialize(multitool));
        AssertStable(() => StableReportSerializer.Serialize(comparison));

        string comparisonJson = Encoding.UTF8.GetString(
            StableReportSerializer.Serialize(comparison));
        Assert.Contains(
            "\"schemaVersion\": \"3\"",
            comparisonJson,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"matcherV3ReportSha256\"",
            comparisonJson,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"v3ToV31DeltaReportSha256\"",
            comparisonJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "matcherV2ReportSha256",
            comparisonJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "v2ToV3DeltaReportSha256",
            comparisonJson,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Normalized_multitool_report_uses_only_portable_path_spelling()
    {
        var (_, multitool) = CreateReports();

        byte[] bytes = StableReportSerializer.Serialize(multitool);
        string text = System.Text.Encoding.UTF8.GetString(bytes);

        Assert.Contains(
            "validation/holdout/cases/test/candidate.sarif",
            text,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"instrumentationStateMultisetPreserved\": true",
            text,
            StringComparison.Ordinal);
        Assert.DoesNotContain('\\', text);
        AmbientDataGuard.Validate(bytes, ValidationTestRepository.FindRoot());
    }

    [Fact]
    public void Matcher_v31_delta_is_byte_stable_schema_valid_and_semantically_sorted()
    {
        (SarifRegressHoldoutReport sarifRegress, _) = CreateReports();
        EvaluationIdentity matcherV3Identity = sarifRegress.Evaluation with
        {
            MatcherAlgorithmVersion = "sarifregress/matcher/v3",
        };
        EvaluationIdentity matcherV31Identity = matcherV3Identity with
        {
            MatcherAlgorithmVersion = "sarifregress/matcher/v3.1",
        };
        var matcherV3 = new MatcherMetricsSnapshot(
            matcherV3Identity,
            sarifRegress.Aggregate,
            sarifRegress.Producers);
        var matcherV31 = new MatcherMetricsSnapshot(
            matcherV31Identity,
            sarifRegress.Aggregate,
            sarifRegress.Producers);
        var first = new MatcherV3ToV31RelationshipReference(
            "test",
            "producer",
            "relationship-a",
            "classification-mismatch",
            "true-positive",
            "modified",
            "moved");
        var second = first with { RelationshipId = "relationship-b" };
        var report = new MatcherV3ToV31DeltaReport(
            new MatcherV3ToV31InputHashes(
                Hash('a'),
                Hash('b'),
                Hash('c'),
                matcherV31Identity.HoldoutManifestSha256),
            matcherV3,
            matcherV31,
            [
                new MatcherV3ToV31AlgorithmVersionChange(
                    "matcher",
                    matcherV3Identity.MatcherAlgorithmVersion,
                    matcherV31Identity.MatcherAlgorithmVersion,
                    Changed: true),
            ],
            new MatcherCorrespondenceIdentityDelta(
                new MatcherCorrespondenceIdentity(1, 0, 0),
                new MatcherCorrespondenceIdentity(1, 0, 0),
                Unchanged: true),
            new MatcherV3ToV31ClassificationMismatchDelta(
                MatcherV3Count: 2,
                MatcherV31Count: 0,
                Fixed: [second, first],
                Introduced: []),
            new MatcherV3ToV31CaseDelta(
                Fixed: [new MatcherDeltaCaseReference("test", "producer")],
                Regressed: [],
                StillFailing: []),
            new MatcherV3ToV31RelationshipDelta(
                Fixed: [second, first],
                Regressed: [],
                StillFailing: []),
            NewlyIntroducedFalseMatches: [],
            AmbiguityChanges: new MatcherV3ToV31AmbiguityDelta(
                MatcherV3CorrectRefusals: 0,
                MatcherV31CorrectRefusals: 0,
                MatcherV3UnexpectedRefusals: 0,
                MatcherV31UnexpectedRefusals: 0,
                MatcherV3IncorrectAutoMatches: 0,
                MatcherV31IncorrectAutoMatches: 0,
                Fixed: [],
                Regressed: [],
                StillFailing: [],
                UnexpectedRefusalsResolved: [],
                UnexpectedRefusalsIntroduced: []),
            IngestionSuccessChanges: new MatcherV3ToV31IngestionDelta(
                MatcherV3Failures: 0,
                MatcherV31Failures: 0,
                NewlySuccessful: [],
                NewlyFailed: [],
                StillFailing: []),
            RemainingFailures: [],
            ChangedDecisionCount: 2,
            ChangedDecisionTraceCount: 2,
            ChangedDecisionWithoutTraceCount: 0,
            ChangedDecisionsWithoutTrace: [],
            EveryChangedDecisionHasTrace: true);
        MatcherV3ToV31DeltaReport permuted = report with
        {
            ClassificationMismatchChanges =
                report.ClassificationMismatchChanges with
                {
                    Fixed = [first, second],
                },
            Relationships = report.Relationships with
            {
                Fixed = [first, second],
            },
        };

        byte[] bytes = StableReportSerializer.Serialize(report);

        AssertStable(() => StableReportSerializer.Serialize(report));
        Assert.Equal(bytes, StableReportSerializer.Serialize(permuted));
        JsonNode node = JsonNode.Parse(bytes)
            ?? throw new InvalidDataException("The serialized delta is null.");
        string root = ValidationTestRepository.FindRoot();
        _ = new JsonSchemaValidator().ValidateNode(
            Path.Combine(
                root,
                "validation",
                "schemas",
                "v3-to-v3.1-delta.schema.json"),
            node,
            "v3-to-v3.1-delta.json",
            root);
        string text = Encoding.UTF8.GetString(bytes);
        Assert.True(
            text.IndexOf("\"relationshipId\": \"relationship-a\"", StringComparison.Ordinal)
            < text.IndexOf("\"relationshipId\": \"relationship-b\"", StringComparison.Ordinal));
        Assert.Contains(
            "\"correspondenceIdentity\"",
            text,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"classificationMismatchChanges\"",
            text,
            StringComparison.Ordinal);
        AmbientDataGuard.Validate(bytes, root);
    }

    [Fact]
    public void Comparison_builder_requires_complete_classification_for_release_readiness()
    {
        (SarifRegressHoldoutReport sarifRegress,
            SarifMultitoolBaselineReport multitool) = CreateReports();
        SarifRegressCaseResult original = Assert.Single(sarifRegress.Cases);
        RelationshipResult relationship = Assert.Single(
            original.RelationshipResults);
        SarifRegressCaseResult mismatchedCase = original with
        {
            RelationshipResults =
            [relationship with { Outcome = "classification-mismatch" }],
        };
        SarifRegressHoldoutReport mismatchedReport = sarifRegress with
        {
            Cases = [mismatchedCase],
        };

        ComparisonSummaryReport comparison = ComparisonSummaryBuilder.Create(
            mismatchedReport,
            multitool,
            new ComparisonReportHashes(
                mismatchedReport.Evaluation.HoldoutManifestSha256,
                Hash('b'),
                Hash('c'),
                Hash('d'),
                Hash('e'),
                Hash('f')),
            crossPlatformByteIdentity: true);

        Assert.Equal("blocked", comparison.ReleaseRecommendation);
        Assert.False(comparison.ReleaseConditions.CompleteLabelGraphSatisfied);
        Assert.Contains(
            "complete-label-graph-failed",
            comparison.RecommendationReasons);
    }

    private static void AssertStable(Func<byte[]> serialize)
    {
        byte[] first = serialize();
        byte[] second = serialize();

        Assert.True(first.AsSpan().SequenceEqual(second));
        Assert.Equal((byte)'\n', first[^1]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.NotEqual(0xEF, first[0]);
    }

    private static (
        SarifRegressHoldoutReport SarifRegress,
        SarifMultitoolBaselineReport Multitool) CreateReports()
    {
        EvaluationIdentity identity = new(
            new string('a', 40),
            Hash('b'),
            "0.1.0",
            "sarifregress/matcher/v2",
            [new NamedAlgorithmVersion("derived-fingerprint", "v2")],
            "1",
            "1",
            Hash('c'));
        CaseInputHashes inputHashes = new(
            Hash('d'),
            Hash('e'),
            Hash('f'),
            Hash('0'),
            Hash('1'),
            Hash('2'));
        HoldoutMetrics sarifMetrics = CreateHoldoutMetrics();
        GroundTruthRelationship groundTruth = new(
            "match",
            "baseline:0:0",
            "candidate:0:0",
            "unchanged");
        RelationshipResult sarifRelationship = new(
            "test-match-001",
            groundTruth,
            new ActualRelationship(
                "unchanged",
                "baseline:0:0",
                "candidate:0:0"),
            "true-positive");
        SarifRegressCaseResult sarifCase = new(
            "test",
            "producer",
            "evaluated",
            inputHashes,
            Hash('3'),
            sarifMetrics,
            [sarifRelationship],
            new OutcomeDetails([], [], [], [], [], [], []),
            []);
        SarifRegressHoldoutReport sarifRegress = new(
            identity,
            sarifMetrics,
            [new ProducerHoldoutMetrics("producer", sarifMetrics)],
            [sarifCase],
            []);

        MultitoolMetrics multitoolMetrics = new(
            GroundTruthUnits: 1,
            LabelledRelationships: 1,
            ComparableRelationships: 1,
            NonComparableRelationships: 0,
            TruePositives: 1,
            FalsePositives: 0,
            FalseNegatives: 0,
            Errors: 0,
            Unsupported: 0,
            Precision: 1m,
            Recall: 1m,
            F1: 1m,
            States: new MultitoolStateCounts(
                New: 0,
                Absent: 0,
                Unchanged: 1,
                Updated: 0,
                Error: 0,
                Unsupported: 0));
        MultitoolRelationshipResult multitoolRelationship = new(
            "test-match-001",
            groundTruth,
            "unchanged",
            TaxonomyMapped: true,
            MappedClassification: "unchanged",
            Comparable: true,
            ComparabilityReason: "equivalent-state-semantics",
            Correct: true,
            ErrorOrUnsupportedCode: null);
        MultitoolCaseResult multitoolCase = new(
            "test",
            "producer",
            inputHashes,
            new NormalizedInvocation(
                ".",
                "sarif",
                [
                    "match-results-forward",
                    "validation/holdout/cases/test/candidate.sarif",
                    "--previous",
                    "validation/holdout/cases/test/baseline.sarif",
                    "--output-file-path",
                    "raw/multitool/test.sarif",
                ]),
            "raw/multitool/test.sarif",
            InstrumentationStateMultisetPreserved: true,
            Metrics: multitoolMetrics,
            RelationshipResults: [multitoolRelationship]);
        SarifMultitoolBaselineReport multitool = new(
            identity,
            new MultitoolToolEvidence(
                "Microsoft SARIF Multitool",
                MultitoolRunner.PackageId,
                "5.5.0",
                MultitoolRunner.ProjectUrl,
                MultitoolRunner.SourceCommitSha,
                MultitoolRunner.PackageUrl,
                MultitoolRunner.PackageSha256,
                MultitoolRunner.PackageSizeBytes,
                "MIT",
                Hash('4'),
                Hash('5')),
            multitoolMetrics,
            [new ProducerMultitoolMetrics("producer", multitoolMetrics)],
            [multitoolCase]);
        return (sarifRegress, multitool);
    }

    private static HoldoutMetrics CreateHoldoutMetrics() => new(
        GroundTruthUnits: 1,
        LabelledRelationships: 1,
        LabelledMatches: 1,
        TruePositives: 1,
        FalsePositives: 0,
        FalseNegatives: 0,
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
        Precision: 1m,
        Recall: 1m,
        F1: 1m);

    private static string Hash(char value) => new string(value, 64);
}
