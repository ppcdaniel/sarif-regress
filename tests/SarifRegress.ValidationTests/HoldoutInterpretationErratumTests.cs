using System.Text.Json;
using System.Text.Json.Nodes;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class HoldoutInterpretationErratumTests
{
    [Fact]
    public void Tracked_erratum_is_strict_hash_bound_and_canonical()
    {
        string root = ValidationTestRepository.FindRoot();
        string erratumPath = Path.Combine(
            root,
            "validation",
            "holdout",
            "interpretation-erratum.json");
        string checksumPath = Path.Combine(
            root,
            "validation",
            "holdout",
            "interpretation-erratum.checksums.sha256");
        byte[] erratumBytes = File.ReadAllBytes(erratumPath);
        byte[] checksumBytes = File.ReadAllBytes(checksumPath);

        string[] erratumChecksumPaths =
            ChecksumManifest.Parse(checksumBytes).Keys.ToArray();
        ChecksumManifest.VerifyFiles(root, checksumBytes, erratumChecksumPaths);
        Assert.Contains(
            "validation/history/matcher-v3.1/sarif-regress-holdout.json",
            erratumChecksumPaths);
        HoldoutInterpretationErratumSnapshot snapshot =
            new HoldoutInterpretationErratumReader().Read(root);
        byte[] currentReportBytes = File.ReadAllBytes(Path.Combine(
            root,
            "validation",
            "expected",
            "sarif-regress-holdout.json"));

        Assert.Equal("sarifregress/matcher/v3.2", snapshot.CurrentMatcherAlgorithmVersion);
        if (snapshot.IsCurrentReportUnbound)
        {
            Assert.Null(snapshot.CurrentReportSha256);
            Assert.False(snapshot.ValidateCurrentReport(
                "sarifregress/matcher/v3.2",
                currentReportBytes));
        }
        else
        {
            Assert.Equal("bound", snapshot.CurrentReportBindingStatus);
            Assert.NotNull(snapshot.CurrentReportSha256);
            Assert.True(snapshot.ValidateCurrentReport(
                "sarifregress/matcher/v3.2",
                currentReportBytes));
        }
        Assert.Equal((byte)'\n', erratumBytes[^1]);
        Assert.DoesNotContain((byte)'\r', erratumBytes);
        Assert.NotEqual(0xEF, erratumBytes[0]);
        AmbientDataGuard.Validate(erratumBytes, root);

        using JsonDocument document = JsonDocument.Parse(erratumBytes);
        JsonElement rootElement = document.RootElement;
        Assert.Equal(
            "matcher-v2-first-evaluation-only",
            rootElement.GetProperty("interpretationPolicy")
                .GetProperty("independentClaimScope")
                .GetString());
        JsonElement[] corrections = rootElement.GetProperty("corrections")
            .EnumerateArray()
            .ToArray();
        string?[] expectedMatcherVersions =
        [
            "sarifregress/matcher/v3",
            "sarifregress/matcher/v3.1",
        ];
        Assert.Equal(
            expectedMatcherVersions,
            corrections
                .Select(item => item.GetProperty("matcherAlgorithmVersion").GetString())
                .ToArray());
        Assert.All(
            corrections,
            correction =>
            {
                Assert.Equal(
                    "exposed-holdout-regression-evidence",
                    correction.GetProperty("correctedInterpretation").GetString());
                Assert.False(correction.GetProperty("metricsChanged").GetBoolean());
            });
    }

    [Theory]
    [InlineData("candidate-unbound", true)]
    [InlineData("refresh-unbound", false)]
    public void Unbound_current_report_is_never_treated_as_hash_bound(
        string bindingStatus,
        bool usesArchivedMatcherV31Outputs)
    {
        string root = ValidationTestRepository.FindRoot();
        var snapshot = new HoldoutInterpretationErratumSnapshot(
            "sarifregress/matcher/v3.2",
            bindingStatus,
            CurrentReportSha256: null);
        byte[] reportBytes = File.ReadAllBytes(Path.Combine(
            root,
            "validation",
            "expected",
            "sarif-regress-holdout.json"));
        byte[] changedBytes = new byte[reportBytes.Length + 1];
        reportBytes.CopyTo(changedBytes, 0);
        changedBytes[^1] = (byte)'\n';

        Assert.True(snapshot.IsCurrentReportUnbound);
        Assert.Equal(
            usesArchivedMatcherV31Outputs,
            snapshot.UsesArchivedMatcherV31Outputs);
        _ = Assert.Throws<InvalidDataException>(() =>
            snapshot.ValidateCurrentReport("sarifregress/matcher/v4", reportBytes));
        Assert.False(snapshot.ValidateCurrentReport(
            "sarifregress/matcher/v3.2",
            reportBytes));
        Assert.False(snapshot.ValidateCurrentReport(
            "sarifregress/matcher/v3.2",
            changedBytes));

        string reportSha256 = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(reportBytes))
            .ToLowerInvariant();
        var bound = new HoldoutInterpretationErratumSnapshot(
            "sarifregress/matcher/v3.2",
            "bound",
            reportSha256);
        Assert.True(bound.ValidateCurrentReport(
            "sarifregress/matcher/v3.2",
            reportBytes));
        _ = Assert.Throws<InvalidDataException>(() =>
            bound.ValidateCurrentReport(
                "sarifregress/matcher/v3.2",
                changedBytes));
    }

    [Fact]
    public void Erratum_schema_accepts_only_artifact_free_refresh_state()
    {
        string root = ValidationTestRepository.FindRoot();
        string schemaPath = Path.Combine(
            root,
            "validation",
            "schemas",
            "interpretation-erratum.schema.json");
        JsonObject node = JsonNode.Parse(File.ReadAllBytes(Path.Combine(
                root,
                "validation",
                "holdout",
                "interpretation-erratum.json")))
            ?.AsObject()
            ?? throw new InvalidDataException("The tracked interpretation erratum is null.");
        JsonObject binding = node["currentReportBinding"]?.AsObject()
            ?? throw new InvalidDataException("The tracked report binding is null.");
        binding["status"] = "refresh-unbound";
        _ = binding.Remove("artifact");

        _ = new JsonSchemaValidator().ValidateNode(
            schemaPath,
            node,
            "interpretation-erratum.json",
            root);

        binding["artifact"] = new JsonObject
        {
            ["path"] = "validation/expected/sarif-regress-holdout.json",
            ["sha256"] = new string('a', 64),
        };
        _ = Assert.Throws<InvalidDataException>(() =>
            new JsonSchemaValidator().ValidateNode(
                schemaPath,
                node,
                "interpretation-erratum.json",
                root));
    }

    [Fact]
    public void Erratum_schema_rejects_unrecognized_properties()
    {
        string root = ValidationTestRepository.FindRoot();
        JsonObject node = JsonNode.Parse(File.ReadAllBytes(Path.Combine(
                root,
                "validation",
                "holdout",
                "interpretation-erratum.json")))
            ?.AsObject()
            ?? throw new InvalidDataException("The tracked interpretation erratum is null.");
        node["unrecognized"] = true;

        _ = Assert.Throws<InvalidDataException>(() =>
            new JsonSchemaValidator().ValidateNode(
                Path.Combine(
                    root,
                    "validation",
                    "schemas",
                    "interpretation-erratum.schema.json"),
                node,
                "interpretation-erratum.json",
                root));
    }
}
