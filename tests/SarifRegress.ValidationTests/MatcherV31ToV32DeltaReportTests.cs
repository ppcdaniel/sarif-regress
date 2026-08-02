using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class MatcherV31ToV32DeltaReportTests
{
    [Fact]
    public void Archived_matcher_v31_report_is_checksum_anchored_and_canonical()
    {
        MatcherV31HistorySnapshot snapshot = new MatcherV31HistoryReader().Read(
            ValidationTestRepository.FindRoot());

        Assert.Equal(
            MatcherV31HistoryReader.MatcherV31AlgorithmVersion,
            snapshot.Report.Evaluation.MatcherAlgorithmVersion);
        Assert.Equal(
            MatcherV31HistoryReader.MatcherV31HistoryChecksumManifestSha256,
            snapshot.HistoryChecksumManifestSha256);
        Assert.Equal(
            MatcherV31HistoryReader.MatcherV31ReportSha256,
            snapshot.ReportSha256);
        Assert.Equal(
            snapshot.ReportSha256,
            Hash(StableReportSerializer.Serialize(snapshot.Report)));
    }

    [Fact]
    public void Delta_builder_and_serializer_are_deterministic_without_fabricated_metrics()
    {
        string root = ValidationTestRepository.FindRoot();
        MatcherV31HistorySnapshot history = new MatcherV31HistoryReader().Read(root);
        SarifRegressHoldoutReport candidate = history.Report with
        {
            Evaluation = history.Report.Evaluation with
            {
                MatcherAlgorithmVersion =
                    MatcherV31HistoryReader.MatcherV32AlgorithmVersion,
            },
        };
        var inputHashes = new MatcherV31ToV32InputHashes(
            history.HistoryChecksumManifestSha256,
            history.ReportSha256,
            Hash(StableReportSerializer.Serialize(candidate)),
            candidate.Evaluation.HoldoutManifestSha256);
        string candidateJson = Encoding.UTF8.GetString(
            StableReportSerializer.Serialize(candidate));
        Assert.Contains(
            "\"reportKind\": \"sarif-regress-exposed-holdout-regression\"",
            candidateJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "sarif-regress-independent-holdout",
            candidateJson,
            StringComparison.Ordinal);

        MatcherV31ToV32DeltaReport first = MatcherV31ToV32DeltaBuilder.Create(
            history,
            candidate,
            inputHashes);
        MatcherV31ToV32DeltaReport second = MatcherV31ToV32DeltaBuilder.Create(
            history,
            candidate,
            inputHashes);
        byte[] firstBytes = StableReportSerializer.Serialize(first);
        byte[] secondBytes = StableReportSerializer.Serialize(second);

        Assert.Equal(firstBytes, secondBytes);
        Assert.True(first.CorrespondenceIdentity.Unchanged);
        Assert.Equal(0, first.ChangedDecisionCount);
        Assert.True(first.EveryChangedDecisionHasTrace);
        MatcherV31ToV32AlgorithmVersionChange matcher = Assert.Single(
            first.AlgorithmVersionChanges,
            item => item.Name == "matcher");
        Assert.Equal("sarifregress/matcher/v3.1", matcher.MatcherV31Version);
        Assert.Equal("sarifregress/matcher/v3.2", matcher.MatcherV32Version);
        Assert.True(matcher.Changed);

        JsonNode node = JsonNode.Parse(firstBytes)
            ?? throw new InvalidDataException("The generated delta is null.");
        _ = new JsonSchemaValidator().ValidateNode(
            Path.Combine(
                root,
                "validation",
                "schemas",
                "v3.1-to-v3.2-delta.schema.json"),
            node,
            "v3.1-to-v3.2-delta.json",
            root);
    }

    [Fact]
    public void Delta_builder_rejects_a_snapshot_without_the_immutable_anchor()
    {
        MatcherV31HistorySnapshot history = new MatcherV31HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        SarifRegressHoldoutReport candidate = history.Report with
        {
            Evaluation = history.Report.Evaluation with
            {
                MatcherAlgorithmVersion =
                    MatcherV31HistoryReader.MatcherV32AlgorithmVersion,
            },
        };
        MatcherV31HistorySnapshot unanchored = history with
        {
            HistoryChecksumManifestSha256 = new string('0', 64),
        };
        var inputHashes = new MatcherV31ToV32InputHashes(
            unanchored.HistoryChecksumManifestSha256,
            unanchored.ReportSha256,
            Hash(StableReportSerializer.Serialize(candidate)),
            candidate.Evaluation.HoldoutManifestSha256);

        _ = Assert.Throws<InvalidDataException>(() =>
            MatcherV31ToV32DeltaBuilder.Create(
                unanchored,
                candidate,
                inputHashes));
    }

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
