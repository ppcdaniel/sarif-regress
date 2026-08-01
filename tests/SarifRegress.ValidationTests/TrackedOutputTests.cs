using System.Security.Cryptography;
using System.Text.Json;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class TrackedOutputTests
{
    private static readonly string[] ExpectedInputHashFields =
    [
        "baselineSarifSha256",
        "candidateSarifSha256",
        "configSha256",
        "labelsSha256",
        "notesSha256",
        "producerInputTreeSha256",
    ];

    [Theory]
    [InlineData(
        "sarif-regress-holdout.json",
        "sarif-regress-holdout-report.schema.json")]
    [InlineData(
        "sarif-multitool-baseline.json",
        "sarif-multitool-baseline-report.schema.json")]
    [InlineData(
        "comparison-summary.json",
        "comparison-summary.schema.json")]
    [InlineData(
        "v2-to-v3-delta.json",
        "v2-to-v3-delta.schema.json")]
    public void Tracked_normalized_output_is_schema_valid_and_free_of_ambient_data(
        string reportName,
        string schemaName)
    {
        string root = ValidationTestRepository.FindRoot();
        string reportPath = Path.Combine(
            root,
            "validation",
            "expected",
            reportName);
        byte[] bytes = File.ReadAllBytes(reportPath);

        _ = new JsonSchemaValidator().ValidateFile(
            Path.Combine(root, "validation", "schemas", schemaName),
            reportPath,
            ValidationLimits.Default.MaximumSarifBytes);
        AmbientDataGuard.Validate(bytes, root);
        Assert.Equal((byte)'\n', bytes[^1]);
        Assert.DoesNotContain((byte)'\r', bytes);
        Assert.NotEqual(0xEF, bytes[0]);
    }

    [Fact]
    public void Both_matcher_reports_retain_all_six_case_input_hash_fields()
    {
        string expectedRoot = Path.Combine(
            ValidationTestRepository.FindRoot(),
            "validation",
            "expected");
        foreach (string reportName in new[]
                 {
                     "sarif-regress-holdout.json",
                     "sarif-multitool-baseline.json",
                 })
        {
            using JsonDocument report = JsonDocument.Parse(File.ReadAllBytes(
                Path.Combine(expectedRoot, reportName)));
            JsonElement[] cases = report.RootElement
                .GetProperty("cases")
                .EnumerateArray()
                .ToArray();
            Assert.Equal(3, cases.Length);
            Assert.All(
                cases,
                item => Assert.Equal(
                    ExpectedInputHashFields,
                    item.GetProperty("inputHashes")
                        .EnumerateObject()
                        .Select(property => property.Name)
                        .Order(StringComparer.Ordinal)));
        }
    }

    [Fact]
    public void Tracked_multitool_report_identifies_the_verified_exact_package()
    {
        string path = Path.Combine(
            ValidationTestRepository.FindRoot(),
            "validation",
            "expected",
            "sarif-multitool-baseline.json");
        using JsonDocument report = JsonDocument.Parse(File.ReadAllBytes(path));
        JsonElement tool = report.RootElement.GetProperty("tool");

        Assert.Equal("Sarif.Multitool", tool.GetProperty("packageId").GetString());
        Assert.Equal("5.5.0", tool.GetProperty("exactVersion").GetString());
        Assert.Equal(
            MultitoolRunner.PackageSha256,
            tool.GetProperty("packageSha256").GetString());
        Assert.Equal(
            MultitoolRunner.PackageSizeBytes,
            tool.GetProperty("packageSizeBytes").GetInt64());
        Assert.Matches(
            "^[0-9a-f]{64}$",
            tool.GetProperty("helpOutputSha256").GetString()!);
        Assert.Matches(
            "^[0-9a-f]{64}$",
            tool.GetProperty("versionOutputSha256").GetString()!);
    }

    [Fact]
    public void Comparison_categories_partition_all_99_ground_truth_units()
    {
        string path = Path.Combine(
            ValidationTestRepository.FindRoot(),
            "validation",
            "expected",
            "comparison-summary.json");
        using JsonDocument report = JsonDocument.Parse(File.ReadAllBytes(path));
        JsonElement root = report.RootElement;
        JsonElement aggregate = root.GetProperty("aggregate");
        JsonElement[] relationships = root.GetProperty("relationships")
            .EnumerateArray()
            .ToArray();

        Assert.Equal(99, aggregate.GetProperty("groundTruthUnits").GetInt32());
        Assert.Equal(99, relationships.Length);
        Assert.Equal(
            99,
            relationships
                .Select(item => item.GetProperty("relationshipId").GetString())
                .Distinct(StringComparer.Ordinal)
                .Count());
        int categorized = aggregate.GetProperty("bothToolsCorrect").GetInt32()
            + aggregate.GetProperty("sarifRegressOnlyCorrect").GetInt32()
            + aggregate.GetProperty("multitoolOnlyCorrect").GetInt32()
            + aggregate.GetProperty("bothIncorrect").GetInt32()
            + aggregate.GetProperty("nonComparable").GetInt32();
        Assert.Equal(99, categorized);
        Assert.Equal(
            aggregate.GetProperty("nonComparable").GetInt32(),
            root.GetProperty("nonComparableRelationships").GetArrayLength());
        Assert.All(
            root.GetProperty("producers").EnumerateArray(),
            producer => Assert.Equal(
                33,
                producer.GetProperty("comparison")
                    .GetProperty("groundTruthUnits")
                    .GetInt32()));
    }

    [Fact]
    public void Tracked_checksum_manifest_verifies_the_exact_input_and_report_set()
    {
        string root = ValidationTestRepository.FindRoot();
        string expectedRoot = Path.Combine(
            root,
            "validation",
            "expected");
        string[] checksummedPaths =
        [
            "validation/expected/comparison-summary.json",
            "validation/expected/sarif-multitool-baseline.json",
            "validation/expected/sarif-regress-holdout.json",
            "validation/expected/v2-to-v3-delta.json",
            "validation/history/matcher-v2/checksums.sha256",
            "validation/history/matcher-v2/sarif-regress-holdout.json",
            "validation/holdout/cross-platform-attestation.json",
            "validation/holdout/evaluation-metadata.json",
            "validation/holdout/manifest.json",
        ];
        byte[] manifest = File.ReadAllBytes(Path.Combine(
            expectedRoot,
            "checksums.sha256"));

        ChecksumManifest.VerifyFiles(root, manifest, checksummedPaths);
    }

    [Fact]
    public void Matcher_v3_history_is_immutable_schema_valid_and_exact()
    {
        const string expectedManifestSha256 =
            "1e99493b52780109d230ce91d8d7f23eb9b128e35c25c4b474d2b1b7681dac4f";
        string root = ValidationTestRepository.FindRoot();
        string historyRoot = Path.Combine(
            root,
            "validation",
            "history",
            "matcher-v3");
        string manifestPath = Path.Combine(historyRoot, "checksums.sha256");
        byte[] manifest = File.ReadAllBytes(manifestPath);
        string[] checksummedPaths =
        [
            "validation/history/matcher-v3/comparison-summary.json",
            "validation/history/matcher-v3/cross-platform-attestation.json",
            "validation/history/matcher-v3/evaluation-metadata.json",
            "validation/history/matcher-v3/metadata.json",
            "validation/history/matcher-v3/original-checksums.sha256",
            "validation/history/matcher-v3/sarif-multitool-baseline.json",
            "validation/history/matcher-v3/sarif-regress-holdout.json",
            "validation/history/matcher-v3/schemas/comparison-summary.schema.json",
            "validation/history/matcher-v3/schemas/cross-platform-attestation.schema.json",
            "validation/history/matcher-v3/schemas/evaluation-metadata.schema.json",
            "validation/history/matcher-v3/schemas/history-metadata.schema.json",
            "validation/history/matcher-v3/schemas/sarif-multitool-baseline-report.schema.json",
            "validation/history/matcher-v3/schemas/sarif-regress-holdout-report.schema.json",
            "validation/history/matcher-v3/schemas/v2-to-v3-delta.schema.json",
            "validation/history/v2-to-v3-delta.json",
        ];

        ChecksumManifest.VerifyFiles(root, manifest, checksummedPaths);
        Assert.Equal(
            expectedManifestSha256,
            Convert.ToHexString(SHA256.HashData(manifest)).ToLowerInvariant());

        (string Instance, string Schema)[] schemaChecks =
        [
            ("metadata.json", "history-metadata.schema.json"),
            ("evaluation-metadata.json", "evaluation-metadata.schema.json"),
            (
                "cross-platform-attestation.json",
                "cross-platform-attestation.schema.json"),
            (
                "sarif-regress-holdout.json",
                "sarif-regress-holdout-report.schema.json"),
            (
                "sarif-multitool-baseline.json",
                "sarif-multitool-baseline-report.schema.json"),
            ("comparison-summary.json", "comparison-summary.schema.json"),
        ];
        foreach ((string instance, string schema) in schemaChecks)
        {
            string instancePath = Path.Combine(historyRoot, instance);
            _ = new JsonSchemaValidator().ValidateFile(
                Path.Combine(historyRoot, "schemas", schema),
                instancePath,
                ValidationLimits.Default.MaximumSarifBytes);
            AmbientDataGuard.Validate(File.ReadAllBytes(instancePath), root);
        }
        _ = new JsonSchemaValidator().ValidateFile(
            Path.Combine(historyRoot, "schemas", "v2-to-v3-delta.schema.json"),
            Path.Combine(root, "validation", "history", "v2-to-v3-delta.json"),
            ValidationLimits.Default.MaximumSarifBytes);

        Assert.Equal(
            File.ReadAllBytes(Path.Combine(
                root,
                "validation",
                "expected",
                "checksums.sha256")),
            File.ReadAllBytes(Path.Combine(
                historyRoot,
                "original-checksums.sha256")));
        foreach (string reportName in new[]
                 {
                     "comparison-summary.json",
                     "sarif-multitool-baseline.json",
                     "sarif-regress-holdout.json",
                 })
        {
            Assert.Equal(
                File.ReadAllBytes(Path.Combine(
                    root,
                    "validation",
                    "expected",
                    reportName)),
                File.ReadAllBytes(Path.Combine(historyRoot, reportName)));
        }
        Assert.Equal(
            File.ReadAllBytes(Path.Combine(
                root,
                "validation",
                "expected",
                "v2-to-v3-delta.json")),
            File.ReadAllBytes(Path.Combine(
                root,
                "validation",
                "history",
                "v2-to-v3-delta.json")));
    }
}
