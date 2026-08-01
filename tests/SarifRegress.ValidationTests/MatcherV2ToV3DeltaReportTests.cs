using System.Collections.Immutable;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class MatcherV2ToV3DeltaReportTests
{
    private const string HoldoutManifestSha256 =
        "b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379";

    [Fact]
    public void Reader_verifies_and_enriches_the_immutable_matcher_v2_history()
    {
        MatcherV2HistorySnapshot snapshot = new MatcherV2HistoryReader().Read(
            ValidationTestRepository.FindRoot());

        Assert.Equal(
            MatcherV2HistoryReader.MatcherV2AlgorithmVersion,
            snapshot.Report.Evaluation.MatcherAlgorithmVersion);
        Assert.Equal(99, snapshot.Report.Aggregate.GroundTruthUnits);
        Assert.Equal(9, snapshot.Report.Aggregate.ExpectedNewClassifications);
        Assert.Equal(6, snapshot.Report.Aggregate.IncorrectNewClassifications);
        Assert.Equal(0.333333m, snapshot.Report.Aggregate.NewClassificationAccuracy);
        Assert.Equal(9, snapshot.Report.Aggregate.ExpectedResolvedClassifications);
        Assert.Equal(6, snapshot.Report.Aggregate.IncorrectResolvedClassifications);
        Assert.Equal(
            MatcherV2HistoryReader.MatcherV2HistoryChecksumManifestSha256,
            snapshot.HistoryChecksumManifestSha256);
        Assert.Equal(
            "d53225fbafeda78048726d201b230c6c24f0f8f68348e827b096f754406110cf",
            snapshot.ReportSha256);
        Assert.All(
            snapshot.Report.Cases.SelectMany(item => item.RelationshipResults),
            item => Assert.Empty(item.Actual.DecisionTraces));
    }

    [Fact]
    public void Reader_rejects_report_tampering_and_duplicate_json_properties()
    {
        string root = CopyHistory();
        try
        {
            string reportPath = Path.Combine(
                root,
                "validation",
                "history",
                "matcher-v2",
                "sarif-regress-holdout.json");
            string text = File.ReadAllText(reportPath);
            File.WriteAllText(
                reportPath,
                text.Replace(
                    "\"schemaVersion\": \"1\",",
                    "\"schemaVersion\": \"1\",\n  \"schemaVersion\": \"1\",",
                    StringComparison.Ordinal));

            InvalidDataException exception = Assert.Throws<InvalidDataException>(
                () => new MatcherV2HistoryReader().Read(root));

            Assert.Contains("repeats object property", exception.Message);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Reader_rejects_a_rewritten_checksum_manifest_even_when_well_formed()
    {
        string root = CopyHistory();
        try
        {
            string path = Path.Combine(
                root,
                "validation",
                "history",
                "matcher-v2",
                "checksums.sha256");
            string text = File.ReadAllText(path);
            char replacement = text[0] == '0' ? '1' : '0';
            File.WriteAllText(path, replacement + text[1..]);

            InvalidDataException exception = Assert.Throws<InvalidDataException>(
                () => new MatcherV2HistoryReader().Read(root));

            Assert.Contains("immutable anchor", exception.Message);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Builder_categorizes_exact_outcomes_in_ordinal_order()
    {
        CasePair[] cases =
        [
            Pair(
                "z-still",
                [
                    Versions("z-false", "match", "missed-match", "not-reported",
                        "false-match", "moved", trace: true),
                    Versions("a-ambiguous", "ambiguous", "missed-match", "not-reported",
                        "incorrect-ambiguity-match", "unchanged", trace: false),
                ]),
            Pair(
                "a-fixed",
                [Versions("fixed", "match", "classification-mismatch", "modified",
                    "true-positive", "unchanged", trace: true)]),
            Pair(
                "m-regressed",
                [Versions("regressed", "match", "true-positive", "unchanged",
                    "classification-mismatch", "modified", trace: false)]),
            Pair(
                "b-ambiguity-fixed",
                [Versions("ambiguous-fixed", "ambiguous", "missed-match", "not-reported",
                    "correct-ambiguity-refusal", "ambiguous", trace: true)]),
        ];
        MatcherV2HistorySnapshot v2 = Snapshot(
            CreateReport(
                MatcherV2HistoryReader.MatcherV2AlgorithmVersion,
                "sarifregress/derived-fingerprint-compare/v1",
                cases.Reverse().Select(item => item.MatcherV2)));
        SarifRegressHoldoutReport v3 = CreateReport(
            MatcherV2HistoryReader.MatcherV3AlgorithmVersion,
            "sarifregress/derived-fingerprint-compare/v2",
            cases.Select(item => item.MatcherV3));

        MatcherV2ToV3DeltaReport delta = MatcherV2ToV3DeltaBuilder.Create(
            v2,
            v3,
            InputHashes(v2, v3));

        Assert.Equal(
            ["a-fixed", "b-ambiguity-fixed"],
            delta.Cases.Fixed.Select(item => item.CaseId));
        Assert.Equal(["m-regressed"], delta.Cases.Regressed.Select(item => item.CaseId));
        Assert.Equal(["z-still"], delta.Cases.StillFailing.Select(item => item.CaseId));
        Assert.Equal(
            ["fixed", "ambiguous-fixed"],
            delta.Relationships.Fixed.Select(item => item.RelationshipId));
        Assert.Equal(
            ["regressed"],
            delta.Relationships.Regressed.Select(item => item.RelationshipId));
        Assert.Equal(
            ["a-ambiguous", "z-false"],
            delta.Relationships.StillFailing.Select(item => item.RelationshipId));
        Assert.Equal(
            ["a-ambiguous", "z-false"],
            delta.NewlyIntroducedFalseMatches.Select(item => item.RelationshipId));
        Assert.Equal(
            ["regressed", "a-ambiguous", "z-false"],
            delta.RemainingFailures.Select(item => item.RelationshipId));
        Assert.Equal(5, delta.ChangedDecisionCount);
        Assert.Equal(3, delta.ChangedDecisionTraceCount);
        Assert.Equal(2, delta.ChangedDecisionWithoutTraceCount);
        Assert.False(delta.EveryChangedDecisionHasTrace);
        Assert.Equal(
            ["regressed", "a-ambiguous"],
            delta.ChangedDecisionsWithoutTrace.Select(item => item.RelationshipId));
        Assert.Contains(
            delta.AlgorithmVersionChanges,
            item => item.Name == "matcher"
                && item.MatcherV2Version == "sarifregress/matcher/v2"
                && item.MatcherV3Version == "sarifregress/matcher/v3"
                && item.Changed);
        Assert.Contains(
            delta.AlgorithmVersionChanges,
            item => item.Name == "embedded-snippet" && !item.Changed);
        Assert.Single(delta.AmbiguityChanges.Fixed);
        Assert.Single(delta.AmbiguityChanges.StillFailing);
        Assert.True(
            StableReportSerializer.Serialize(delta).AsSpan().SequenceEqual(
                StableReportSerializer.Serialize(delta)));
        string json = System.Text.Encoding.UTF8.GetString(
            StableReportSerializer.Serialize(delta));
        Assert.DoesNotContain("baselineKey", json, StringComparison.Ordinal);
        Assert.DoesNotContain("candidateKey", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"message\":", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"path\":", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Builder_reports_ingestion_transitions_and_complete_trace_coverage()
    {
        CasePair newlySuccessful = Pair(
            "c-success",
            [Versions("success", "match", "ingestion-failure", "ingestion-failure",
                "true-positive", "unchanged", trace: true)],
            matcherV2IngestionFailures: 1);
        CasePair newlyFailed = Pair(
            "a-failed",
            [Versions("failed", "match", "true-positive", "unchanged",
                "ingestion-failure", "ingestion-failure", trace: true)],
            matcherV3IngestionFailures: 1);
        CasePair stillFailed = Pair(
            "b-still",
            [Versions("still", "match", "ingestion-failure", "ingestion-failure",
                "ingestion-failure", "ingestion-failure", trace: false)],
            matcherV2IngestionFailures: 1,
            matcherV3IngestionFailures: 1);
        CasePair[] pairs = [newlySuccessful, newlyFailed, stillFailed];
        MatcherV2HistorySnapshot v2 = Snapshot(CreateReport(
            MatcherV2HistoryReader.MatcherV2AlgorithmVersion,
            "v1",
            pairs.Select(item => item.MatcherV2)));
        SarifRegressHoldoutReport v3 = CreateReport(
            MatcherV2HistoryReader.MatcherV3AlgorithmVersion,
            "v2",
            pairs.Reverse().Select(item => item.MatcherV3));

        MatcherV2ToV3DeltaReport delta = MatcherV2ToV3DeltaBuilder.Create(
            v2,
            v3,
            InputHashes(v2, v3));

        Assert.Equal(["c-success"], delta.IngestionSuccessChanges.NewlySuccessful
            .Select(item => item.CaseId));
        Assert.Equal(["a-failed"], delta.IngestionSuccessChanges.NewlyFailed
            .Select(item => item.CaseId));
        Assert.Equal(["b-still"], delta.IngestionSuccessChanges.StillFailing
            .Select(item => item.CaseId));
        Assert.Equal(2, delta.IngestionSuccessChanges.MatcherV2Failures);
        Assert.Equal(2, delta.IngestionSuccessChanges.MatcherV3Failures);
        Assert.Equal(2, delta.ChangedDecisionCount);
        Assert.True(delta.EveryChangedDecisionHasTrace);
    }

    [Fact]
    public void Builder_allows_input_hash_changes_but_rejects_label_graph_changes()
    {
        CasePair pair = Pair(
            "case",
            [Versions("relationship", "match", "missed-match", "not-reported",
                "true-positive", "unchanged", trace: true)]);
        MatcherV2HistorySnapshot v2 = Snapshot(CreateReport(
            MatcherV2HistoryReader.MatcherV2AlgorithmVersion,
            "v1",
            [pair.MatcherV2]));
        SarifRegressCaseResult changedInputs = pair.MatcherV3 with
        {
            InputHashes = Hashes('9'),
        };
        SarifRegressHoldoutReport v3 = CreateReport(
            MatcherV2HistoryReader.MatcherV3AlgorithmVersion,
            "v2",
            [changedInputs]);

        MatcherV2ToV3DeltaReport delta = MatcherV2ToV3DeltaBuilder.Create(
            v2,
            v3,
            InputHashes(v2, v3));
        Assert.Single(delta.Relationships.Fixed);

        RelationshipResult relationship = Assert.Single(
            Assert.Single(v3.Cases).RelationshipResults);
        SarifRegressHoldoutReport changedGraph = ReplaceOnlyRelationship(
            v3,
            relationship with
            {
                GroundTruth = relationship.GroundTruth with
                {
                    ExpectedClassification = "moved",
                },
            });
        Assert.Throws<InvalidDataException>(() =>
            MatcherV2ToV3DeltaBuilder.Create(
                v2,
                changedGraph,
                InputHashes(v2, changedGraph)));
    }

    [Fact]
    public void Builder_rejects_duplicate_relationships_and_unbound_input_hashes()
    {
        CasePair pair = Pair(
            "case",
            [Versions("relationship", "match", "missed-match", "not-reported",
                "true-positive", "unchanged", trace: true)]);
        MatcherV2HistorySnapshot v2 = Snapshot(CreateReport(
            MatcherV2HistoryReader.MatcherV2AlgorithmVersion,
            "v1",
            [pair.MatcherV2]));
        SarifRegressHoldoutReport v3 = CreateReport(
            MatcherV2HistoryReader.MatcherV3AlgorithmVersion,
            "v2",
            [pair.MatcherV3]);
        SarifRegressCaseResult original = Assert.Single(v3.Cases);
        SarifRegressHoldoutReport duplicate = v3 with
        {
            Cases =
            [
                original with
                {
                    RelationshipResults =
                    [original.RelationshipResults[0], original.RelationshipResults[0]],
                    Metrics = original.Metrics with { GroundTruthUnits = 2 },
                },
            ],
            Aggregate = v3.Aggregate with { GroundTruthUnits = 2 },
            Producers =
            [
                v3.Producers[0] with
                {
                    Metrics = v3.Producers[0].Metrics with { GroundTruthUnits = 2 },
                },
            ],
        };

        Assert.Throws<InvalidDataException>(() =>
            MatcherV2ToV3DeltaBuilder.Create(
                v2,
                duplicate,
                InputHashes(v2, duplicate)));
        MatcherDeltaInputHashes wrong = InputHashes(v2, v3) with
        {
            MatcherV3ReportSha256 = Hash('f'),
        };
        Assert.Throws<InvalidDataException>(() =>
            MatcherV2ToV3DeltaBuilder.Create(v2, v3, wrong));
    }

    private static MatcherV2HistorySnapshot Snapshot(SarifRegressHoldoutReport report) =>
        new(
            report,
            MatcherV2HistoryReader.MatcherV2HistoryChecksumManifestSha256,
            Hash('b'));

    private static MatcherDeltaInputHashes InputHashes(
        MatcherV2HistorySnapshot snapshot,
        SarifRegressHoldoutReport matcherV3) => new(
        snapshot.HistoryChecksumManifestSha256,
        snapshot.ReportSha256,
        Sha256(StableReportSerializer.Serialize(matcherV3)),
        HoldoutManifestSha256);

    private static SarifRegressHoldoutReport ReplaceOnlyRelationship(
        SarifRegressHoldoutReport report,
        RelationshipResult relationship)
    {
        SarifRegressCaseResult item = Assert.Single(report.Cases);
        return report with
        {
            Cases = [item with { RelationshipResults = [relationship] }],
        };
    }

    private static CasePair Pair(
        string caseId,
        IEnumerable<RelationshipVersions> relationships,
        int matcherV2IngestionFailures = 0,
        int matcherV3IngestionFailures = 0)
    {
        RelationshipVersions[] values = relationships.ToArray();
        return new CasePair(
            CreateCase(
                caseId,
                values.Select(item => item.MatcherV2),
                matcherV2IngestionFailures),
            CreateCase(
                caseId,
                values.Reverse().Select(item => item.MatcherV3),
                matcherV3IngestionFailures));
    }

    private static RelationshipVersions Versions(
        string id,
        string kind,
        string oldOutcome,
        string oldState,
        string newOutcome,
        string newState,
        bool trace)
    {
        GroundTruthRelationship groundTruth = new(
            kind,
            kind == "new" ? null : "baseline:" + id,
            kind == "resolved" ? null : "candidate:" + id,
            kind switch
            {
                "ambiguous" => "ambiguous",
                "new" => "new",
                "resolved" => "resolved",
                _ => "unchanged",
            });
        return new RelationshipVersions(
            Relationship(id, groundTruth, oldOutcome, oldState, trace: false),
            Relationship(id, groundTruth, newOutcome, newState, trace));
    }

    private static RelationshipResult Relationship(
        string id,
        GroundTruthRelationship groundTruth,
        string outcome,
        string state,
        bool trace)
    {
        ActualRelationship actual = new(
            state,
            state == "not-reported" ? null : groundTruth.BaselineKey,
            state == "not-reported" ? null : groundTruth.CandidateKey)
        {
            DecisionTraces = trace ? [Trace()] : [],
        };
        return new RelationshipResult(id, groundTruth, actual, outcome);
    }

    private static DecisionTraceProjection Trace() => new(
        "candidate",
        "unchanged",
        "exact-producer",
        "high",
        Ambiguous: false,
        MatcherV2HistoryReader.MatcherV3AlgorithmVersion,
        [],
        [],
        [],
        []);

    private static SarifRegressCaseResult CreateCase(
        string id,
        IEnumerable<RelationshipResult> relationships,
        int ingestionFailures)
    {
        ImmutableArray<RelationshipResult> values = relationships.ToImmutableArray();
        return new SarifRegressCaseResult(
            id,
            "producer",
            ingestionFailures == 0 ? "evaluated" : "ingestion-failure",
            Hashes('1'),
            Hash('2'),
            Metrics(values, ingestionFailures),
            values,
            new OutcomeDetails([], [], [], [], [], [], []),
            []);
    }

    private static SarifRegressHoldoutReport CreateReport(
        string matcherVersion,
        string compareVersion,
        IEnumerable<SarifRegressCaseResult> cases)
    {
        ImmutableArray<SarifRegressCaseResult> values = cases.ToImmutableArray();
        ImmutableArray<ProducerHoldoutMetrics> producers = values
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerHoldoutMetrics(
                group.Key,
                HoldoutMetricsCalculator.Aggregate(group.Select(item => item.Metrics))))
            .ToImmutableArray();
        return new SarifRegressHoldoutReport(
            new EvaluationIdentity(
                new string(matcherVersion.EndsWith("v2", StringComparison.Ordinal)
                    ? '2'
                    : '3', 40),
                Hash('4'),
                "0.1.0",
                matcherVersion,
                [
                    new NamedAlgorithmVersion("embedded-snippet", "embedded-snippet/v1"),
                    new NamedAlgorithmVersion("derived-fingerprint-compare", compareVersion),
                ],
                "1",
                "1",
                HoldoutManifestSha256),
            HoldoutMetricsCalculator.Aggregate(values.Select(item => item.Metrics)),
            producers,
            values,
            []);
    }

    private static HoldoutMetrics Metrics(
        ImmutableArray<RelationshipResult> relationships,
        int ingestionFailures)
    {
        int truePositives = relationships.Count(item => item.Outcome == "true-positive");
        int falsePositives = relationships.Count(item => item.Outcome == "false-match");
        int falseNegatives = relationships.Count(item =>
            item.GroundTruth.Kind == "match" && item.Outcome != "true-positive");
        int expectedNew = relationships.Count(item => item.GroundTruth.Kind == "new");
        int correctNew = relationships.Count(item => item.Outcome == "correct-new");
        int expectedResolved = relationships.Count(item =>
            item.GroundTruth.Kind == "resolved");
        int correctResolved = relationships.Count(item =>
            item.Outcome == "correct-resolved");
        decimal precision = Divide(truePositives, truePositives + falsePositives);
        decimal recall = Divide(truePositives, truePositives + falseNegatives);
        var result = new HoldoutMetrics(
            relationships.Length,
            relationships.Count(item => item.GroundTruth.Kind == "match"),
            truePositives + falsePositives,
            truePositives,
            falsePositives,
            falseNegatives,
            relationships.Count(item => item.Outcome == "classification-mismatch"),
            correctNew,
            correctResolved,
            relationships.Count(item => item.Actual.State == "ambiguous"),
            correctNew,
            correctResolved,
            relationships.Count(item => item.Outcome == "correct-ambiguity-refusal"),
            relationships.Count(item => item.Outcome == "unexpected-ambiguity-refusal"),
            relationships.Count(item => item.Outcome == "incorrect-ambiguity-match"),
            ingestionFailures,
            0,
            precision,
            recall,
            precision + recall == 0
                ? 0
                : decimal.Round(
                    2 * precision * recall / (precision + recall),
                    6,
                    MidpointRounding.ToEven))
        {
            ExpectedNewClassifications = expectedNew,
            IncorrectNewClassifications = expectedNew - correctNew,
            NewClassificationAccuracy = Divide(correctNew, expectedNew),
            ExpectedResolvedClassifications = expectedResolved,
            IncorrectResolvedClassifications = expectedResolved - correctResolved,
            ResolvedClassificationAccuracy = Divide(correctResolved, expectedResolved),
        };
        return result;
    }

    private static decimal Divide(int numerator, int denominator) => denominator == 0
        ? 1m
        : decimal.Round((decimal)numerator / denominator, 6, MidpointRounding.ToEven);

    private static CaseInputHashes Hashes(char value) => new(
        Hash(value),
        Hash(value),
        Hash(value),
        Hash(value),
        Hash(value),
        Hash(value));

    private static string Hash(char value) => new(value, 64);

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))
            .ToLowerInvariant();

    private static string CopyHistory()
    {
        string sourceRoot = ValidationTestRepository.FindRoot();
        string destinationRoot = ValidationTestRepository.CreateTemporaryDirectory();
        CopyDirectory(
            Path.Combine(sourceRoot, "validation", "history", "matcher-v2"),
            Path.Combine(destinationRoot, "validation", "history", "matcher-v2"));
        string destinationManifest = Path.Combine(
            destinationRoot,
            "validation",
            "holdout",
            "manifest.json");
        Directory.CreateDirectory(Path.GetDirectoryName(destinationManifest)!);
        File.Copy(
            Path.Combine(sourceRoot, "validation", "holdout", "manifest.json"),
            destinationManifest);
        return destinationRoot;
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string path in Directory.EnumerateFiles(source))
        {
            File.Copy(path, Path.Combine(destination, Path.GetFileName(path)));
        }
    }

    private sealed record RelationshipVersions(
        RelationshipResult MatcherV2,
        RelationshipResult MatcherV3);

    private sealed record CasePair(
        SarifRegressCaseResult MatcherV2,
        SarifRegressCaseResult MatcherV3);
}
