using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Report;

namespace SarifRegress.DeterminismTests;

public sealed class StableJsonReportTests
{
    [Fact]
    public void Serialize_EmptyReport_MatchesByteGolden()
    {
        var expectedJson = """
            {
              "outputSchemaVersion": "1",
              "tool": {
                "name": "sarif-regress",
                "version": "0.1.0-test"
              },
              "inputs": {
                "baseline": "baseline.sarif",
                "candidate": "candidate.sarif"
              },
              "summary": {
                "baselineCount": 0,
                "candidateCount": 0,
                "new": 0,
                "unchanged": 0,
                "moved": 0,
                "modified": 0,
                "resolved": 0,
                "ambiguous": 0
              },
              "findings": [],
              "diagnostics": [],
              "metrics": {
                "candidateEdges": 0,
                "assignmentComponents": 0,
                "ambiguousComponents": 0,
                "diagnostics": 0
              },
              "determinism": {
                "jsonCanonicalisation": "schema-order-v1",
                "crossPlatformNormalisation": "approved-path-normalisation-v1",
                "matcherAlgorithm": "matcher-v1"
              }
            }
            """;
        var expectedBytes = Encoding.UTF8.GetBytes(expectedJson + "\n");

        var actualBytes = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateEmptyReport());

        Assert.Equal(expectedBytes, actualBytes);
    }

    [Fact]
    public void Serialize_RepeatedAndRoundTripped_ProducesIdenticalBytes()
    {
        var report = ReportTestData.CreateRepresentativeReport();

        var first = StableJsonReportSerializer.Serialize(report);
        var second = StableJsonReportSerializer.Serialize(report);
        var roundTripped = StableJsonReportSerializer.Serialize(
            StableJsonReportSerializer.Deserialize(first));

        Assert.Equal(first, second);
        Assert.Equal(first, roundTripped);
        Assert.Equal((byte)'\n', first[^1]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.False(
            first.Length >= 3
            && first[0] == 0xEF
            && first[1] == 0xBB
            && first[2] == 0xBF);
    }

    [Fact]
    public void Serialize_FindingSnapshot_UsesVersionOnePropertyOrder()
    {
        var bytes = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());
        using var document = JsonDocument.Parse(bytes);
        var snapshot = document.RootElement
            .GetProperty("findings")[0]
            .GetProperty("candidate");

        Assert.Equal(
            [
                "findingKey",
                "producerFamily",
                "canonicalRule",
                "canonicalUri",
                "region",
                "canonicalMessage",
                "derivedFingerprints",
            ],
            snapshot.EnumerateObject().Select(item => item.Name));
        Assert.Equal(
            ReportTestData.DerivedFingerprintValue,
            snapshot
                .GetProperty("derivedFingerprints")[0]
                .GetProperty("value")
                .GetString());
    }

    [Fact]
    public void Serialize_AcrossCultures_ProducesIdenticalBytes()
    {
        var report = ReportTestData.CreateRepresentativeReport();
        var invariantBytes = StableJsonReportSerializer.Serialize(report);

        byte[] turkishBytes;
        using (new CultureScope("tr-TR"))
        {
            turkishBytes = StableJsonReportSerializer.Serialize(report);
        }

        byte[] arabicBytes;
        using (new CultureScope("ar-SA"))
        {
            arabicBytes = StableJsonReportSerializer.Serialize(report);
        }

        Assert.Equal(invariantBytes, turkishBytes);
        Assert.Equal(invariantBytes, arabicBytes);
    }

    [Fact]
    public void Serialize_UnorderedArrays_CanonicalizesEveryReportLevel()
    {
        var report = ReportTestData.CreateRepresentativeReport();
        var reversedFindings = report.Findings
            .Reverse()
            .Select(
                finding => finding with
                {
                    Decision = finding.Decision with
                    {
                        Evidence = finding.Decision.Evidence
                            .Reverse()
                            .ToImmutableArray(),
                        RejectedAlternatives = finding.Decision.RejectedAlternatives
                            .Reverse()
                            .ToImmutableArray(),
                        Transformations = finding.Decision.Transformations
                            .Reverse()
                            .ToImmutableArray(),
                        Diagnostics = finding.Decision.Diagnostics
                            .Reverse()
                            .ToImmutableArray(),
                    },
                })
            .ToImmutableArray();
        var unordered = report with
        {
            Findings = reversedFindings,
            Diagnostics = report.Diagnostics.Reverse().ToImmutableArray(),
        };

        Assert.Equal(
            StableJsonReportSerializer.Serialize(report),
            StableJsonReportSerializer.Serialize(unordered));
    }

    [Fact]
    public void Serialize_InconsistentSummaryOrFindingSides_RejectsReport()
    {
        var report = ReportTestData.CreateRepresentativeReport();
        var inconsistentSummary = report with
        {
            Summary = report.Summary with { New = report.Summary.New + 1 },
        };
        var modifiedFinding = report.Findings[0];
        var invalidSides = report with
        {
            Findings = report.Findings.SetItem(
                0,
                modifiedFinding with
                {
                    Classification = FindingClassification.New,
                }),
        };

        Assert.Throws<ArgumentException>(
            () => StableJsonReportSerializer.Serialize(inconsistentSummary));
        Assert.Throws<ArgumentException>(
            () => StableJsonReportSerializer.Serialize(invalidSides));
    }

    [Fact]
    public void Serialize_DuplicateSideOrAmbiguityMismatch_RejectsReport()
    {
        var report = ReportTestData.CreateRepresentativeReport();
        var duplicateCandidate = report with
        {
            Findings = report.Findings.Add(report.Findings[^1]),
        };
        var modifiedFinding = report.Findings[0];
        var ambiguityMismatch = report with
        {
            Findings = report.Findings.SetItem(
                0,
                modifiedFinding with
                {
                    Decision = modifiedFinding.Decision with
                    {
                        Ambiguous = true,
                    },
                }),
        };

        Assert.Throws<ArgumentException>(
            () => StableJsonReportSerializer.Serialize(duplicateCandidate));
        Assert.Throws<ArgumentException>(
            () => StableJsonReportSerializer.Serialize(ambiguityMismatch));
    }

    [Fact]
    public void Deserialize_InvalidConstantsAndDecisionRanges_RejectsJson()
    {
        var wrongTool = ParseRepresentativeJson();
        wrongTool["tool"]!["name"] = "another-tool";

        var negativeDecisionVector = ParseRepresentativeJson();
        negativeDecisionVector["findings"]![0]!["rejectedAlternatives"]![0]!
            ["decisionVector"]!["producerFingerprintStrength"] = -1;

        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(ToBytes(wrongTool)));
        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(
                ToBytes(negativeDecisionVector)));
    }

    [Fact]
    public void Deserialize_BlankInputsAndInvalidFindingSides_RejectsJson()
    {
        var blankInput = ParseRepresentativeJson();
        blankInput["inputs"]!["baseline"] = string.Empty;

        var missingSides = ParseRepresentativeJson();
        var finding = missingSides["findings"]![0]!;
        finding["classification"] = "ambiguous";
        finding["baselineRef"] = null;
        finding["candidateRef"] = null;
        finding["baseline"] = null;
        finding["candidate"] = null;
        finding["decision"]!["ambiguous"] = true;

        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(ToBytes(blankInput)));
        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(ToBytes(missingSides)));
    }

    [Fact]
    public void Deserialize_ResourceBounds_RejectOversizedReports()
    {
        var bytes = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());
        var byteLimit = ResourceLimits.Default with
        {
            MaximumInputBytes = bytes.Length - 1,
        };
        var stringLimit = ResourceLimits.Default with
        {
            MaximumStringCharacters = 3,
        };
        var collectionLimit = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 1,
        };

        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(bytes, byteLimit));
        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(bytes, stringLimit));
        Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(bytes, collectionLimit));
    }

    [Fact]
    public void Deserialize_LegacySnapshotWithoutDerivedFingerprints_DefaultsEmpty()
    {
        var document = ParseRepresentativeJson();
        foreach (var finding in document["findings"]!.AsArray())
        {
            finding?["baseline"]?.AsObject().Remove("derivedFingerprints");
            finding?["candidate"]?.AsObject().Remove("derivedFingerprints");
        }

        var report = StableJsonReportSerializer.Deserialize(ToBytes(document));

        Assert.All(
            report.Findings,
            finding =>
            {
                if (finding.Baseline is not null)
                {
                    Assert.Empty(finding.Baseline.DerivedFingerprints);
                }

                if (finding.Candidate is not null)
                {
                    Assert.Empty(finding.Candidate.DerivedFingerprints);
                }
            });
    }

    [Fact]
    public void Deserialize_ByteOrderMark_RejectsNonCanonicalEncoding()
    {
        var stableBytes = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateEmptyReport());
        var bytesWithBom = new byte[stableBytes.Length + 3];
        bytesWithBom[0] = 0xEF;
        bytesWithBom[1] = 0xBB;
        bytesWithBom[2] = 0xBF;
        stableBytes.CopyTo(bytesWithBom, 3);

        var exception = Assert.Throws<JsonException>(
            () => StableJsonReportSerializer.Deserialize(bytesWithBom));

        Assert.Contains(
            "without a byte-order mark",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void WriteFile_ThenReadFile_PreservesExactCanonicalBytes()
    {
        var report = ReportTestData.CreateRepresentativeReport();
        var expected = StableJsonReportSerializer.Serialize(report);
        var path = Path.Combine(
            Path.GetTempPath(),
            $"sarifregress-report-{Guid.NewGuid():N}.json");

        try
        {
            StableJsonReportSerializer.WriteFile(path, report);

            Assert.Equal(expected, File.ReadAllBytes(path));
            Assert.Equal(
                expected,
                StableJsonReportSerializer.Serialize(
                    StableJsonReportSerializer.ReadFile(path)));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static JsonObject ParseRepresentativeJson()
    {
        var bytes = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());
        return JsonNode.Parse(bytes)!.AsObject();
    }

    private static byte[] ToBytes(JsonNode document) =>
        Encoding.UTF8.GetBytes(document.ToJsonString());
}
