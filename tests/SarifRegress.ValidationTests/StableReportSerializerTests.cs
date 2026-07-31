using System.Collections.Immutable;
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
                Hash('a'),
                Hash('b'),
                Hash('c'),
                Hash('d')),
            crossPlatformByteIdentity: true);

        AssertStable(() => StableReportSerializer.Serialize(sarifRegress));
        AssertStable(() => StableReportSerializer.Serialize(multitool));
        AssertStable(() => StableReportSerializer.Serialize(comparison));
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
                Hash('a'),
                Hash('b'),
                Hash('c'),
                Hash('d')),
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
