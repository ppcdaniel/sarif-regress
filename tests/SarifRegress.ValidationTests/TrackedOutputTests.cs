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
}
