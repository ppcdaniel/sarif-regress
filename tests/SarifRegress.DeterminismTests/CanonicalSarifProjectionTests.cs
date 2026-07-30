using System.Text.Json;
using SarifRegress.Core.Findings;
using SarifRegress.Report;

namespace SarifRegress.DeterminismTests;

public sealed class CanonicalSarifProjectionTests
{
    [Fact]
    public void Project_RepeatedAndAcrossCultures_ProducesIdenticalBytes()
    {
        var stableJson = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());
        var first = CanonicalSarifExporter.Project(stableJson);
        var second = CanonicalSarifExporter.Project(stableJson);

        byte[] cultureSpecific;
        using (new CultureScope("ar-SA"))
        {
            cultureSpecific = CanonicalSarifExporter.Project(stableJson);
        }

        Assert.Equal(first, second);
        Assert.Equal(first, cultureSpecific);
        Assert.Equal((byte)'\n', first[^1]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.False(
            first.Length >= 3
            && first[0] == 0xEF
            && first[1] == 0xBB
            && first[2] == 0xBF);
    }

    [Fact]
    public void Project_RepresentativeReport_EmitsCanonicalSarifAndFingerprints()
    {
        var stableJson = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());

        using var document = JsonDocument.Parse(
            CanonicalSarifExporter.Project(stableJson));
        var root = document.RootElement;
        var run = root.GetProperty("runs")[0];
        var results = run.GetProperty("results");

        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.Equal(2, results.GetArrayLength());
        Assert.Equal(
            "test-scanner/RULE-001",
            results[0].GetProperty("ruleId").GetString());
        Assert.Equal(
            "new",
            results[0].GetProperty("baselineState").GetString());
        Assert.Equal(
            ReportTestData.NewDerivedFingerprintValue,
            results[0]
                .GetProperty("partialFingerprints")
                .GetProperty(ReportContractVersions.SarifFingerprint)
                .GetString());
        Assert.Equal(
            "updated",
            results[1].GetProperty("baselineState").GetString());
        Assert.Equal(
            "modified",
            results[1]
                .GetProperty("properties")
                .GetProperty("sarifregress/classification")
                .GetString());
    }

    [Fact]
    public void Project_FindingWithoutDerivedFingerprint_OmitsPartialFingerprints()
    {
        var report = ReportTestData.CreateSingleCandidateReport(
            "repo://src/plain.cs",
            new Region(1, 1, 1, 2),
            includeDerivedFingerprint: false);
        var stableJson = StableJsonReportSerializer.Serialize(report);

        using var document = JsonDocument.Parse(
            CanonicalSarifExporter.Project(stableJson));
        var result = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("results")[0];

        Assert.False(result.TryGetProperty("partialFingerprints", out _));
    }

    [Fact]
    public void Project_FilePathUri_EncodesReservedAndNonAsciiPathCharacters()
    {
        var report = ReportTestData.CreateSingleCandidateReport(
            "repo://src/My file#中?.cs",
            new Region(1, 1, 1, 2),
            includeDerivedFingerprint: true);
        var stableJson = StableJsonReportSerializer.Serialize(report);

        using var document = JsonDocument.Parse(
            CanonicalSarifExporter.Project(stableJson));
        var artifactUri = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("results")[0]
            .GetProperty("locations")[0]
            .GetProperty("physicalLocation")
            .GetProperty("artifactLocation")
            .GetProperty("uri")
            .GetString();

        Assert.Equal(
            "repo://src/My%20file%23%E4%B8%AD%3F.cs",
            artifactUri);
    }

    [Fact]
    public void Project_RegionWithoutStartLine_OmitsInvalidSarifRegion()
    {
        var report = ReportTestData.CreateSingleCandidateReport(
            "repo://src/plain.cs",
            new Region(
                startLine: null,
                startColumn: 4,
                endLine: null,
                endColumn: null),
            includeDerivedFingerprint: true);
        var stableJson = StableJsonReportSerializer.Serialize(report);

        using var document = JsonDocument.Parse(
            CanonicalSarifExporter.Project(stableJson));
        var physicalLocation = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("results")[0]
            .GetProperty("locations")[0]
            .GetProperty("physicalLocation");

        Assert.False(physicalLocation.TryGetProperty("region", out _));
    }
}
