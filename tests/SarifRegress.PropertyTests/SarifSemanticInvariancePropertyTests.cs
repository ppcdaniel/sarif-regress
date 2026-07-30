using System.Text;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Match;
using SarifRegress.Report;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.PropertyTests;

public sealed class SarifSemanticInvariancePropertyTests
{
    private const string BaseSarif =
        """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": {
                "driver": {
                  "name": "Property scanner",
                  "semanticVersion": "1.2.3",
                  "rules": [
                    { "id": "RULE-UNUSED" },
                    { "id": "RULE-001" }
                  ]
                }
              },
              "artifacts": [
                { "location": { "uri": "src/unused.cs" } },
                { "location": { "uri": "src/shared.cs" } }
              ],
              "results": [
                {
                  "ruleIndex": 1,
                  "message": { "text": "Shared property message." },
                  "partialFingerprints": {
                    "secondary/v1": "secondary-001",
                    "primary/v1": "primary-001"
                  },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "index": 1 },
                        "region": {
                          "startLine": 7,
                          "startColumn": 1,
                          "endLine": 7,
                          "endColumn": 8
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

    private const string PropertyReorderedSarif =
        """
        {
          "runs": [
            {
              "results": [
                {
                  "locations": [
                    {
                      "physicalLocation": {
                        "region": {
                          "endColumn": 8,
                          "endLine": 7,
                          "startColumn": 1,
                          "startLine": 7
                        },
                        "artifactLocation": { "index": 1 }
                      }
                    }
                  ],
                  "partialFingerprints": {
                    "primary/v1": "primary-001",
                    "secondary/v1": "secondary-001"
                  },
                  "message": { "text": "Shared property message." },
                  "ruleIndex": 1
                }
              ],
              "artifacts": [
                { "location": { "uri": "src/unused.cs" } },
                { "location": { "uri": "src/shared.cs" } }
              ],
              "tool": {
                "driver": {
                  "rules": [
                    { "id": "RULE-UNUSED" },
                    { "id": "RULE-001" }
                  ],
                  "semanticVersion": "1.2.3",
                  "name": "Property scanner"
                }
              }
            }
          ],
          "version": "2.1.0"
        }
        """;

    private const string ReferencePreservingArrayReorderedSarif =
        """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": {
                "driver": {
                  "name": "Property scanner",
                  "semanticVersion": "1.2.3",
                  "rules": [
                    { "id": "RULE-001" },
                    { "id": "RULE-UNUSED" }
                  ]
                }
              },
              "artifacts": [
                { "location": { "uri": "src/shared.cs" } },
                { "location": { "uri": "src/unused.cs" } }
              ],
              "results": [
                {
                  "ruleIndex": 0,
                  "message": { "text": "Shared property message." },
                  "partialFingerprints": {
                    "secondary/v1": "secondary-001",
                    "primary/v1": "primary-001"
                  },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "index": 0 },
                        "region": {
                          "startLine": 7,
                          "startColumn": 1,
                          "endLine": 7,
                          "endColumn": 8
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

    private const string IgnoredOptionalPropertiesSarif =
        """
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "properties": { "root-note": "ignored" },
          "inlineExternalProperties": [],
          "runs": [
            {
              "language": "en-US",
              "newlineSequences": ["\r\n", "\n"],
              "columnKind": "utf16CodeUnits",
              "properties": { "run-note": "ignored" },
              "tool": {
                "driver": {
                  "name": "Property scanner",
                  "semanticVersion": "1.2.3",
                  "fullName": "Property scanner full name",
                  "informationUri": "https://example.invalid/scanner",
                  "organization": "Example",
                  "properties": { "driver-note": "ignored" },
                  "rules": [
                    { "id": "RULE-UNUSED" },
                    { "id": "RULE-001" }
                  ]
                }
              },
              "artifacts": [
                {
                  "location": {
                    "uri": "src/unused.cs",
                    "description": { "text": "Unused source file" },
                    "properties": { "artifact-location-note": "ignored" }
                  },
                  "properties": { "artifact-note": "ignored" }
                },
                { "location": { "uri": "src/shared.cs" } }
              ],
              "results": [
                {
                  "ruleIndex": 1,
                  "guid": "11111111-1111-1111-1111-111111111111",
                  "correlationGuid": "22222222-2222-2222-2222-222222222222",
                  "rank": 42.0,
                  "hostedViewerUri": "https://example.invalid/result/1",
                  "occurrenceCount": 3,
                  "provenance": { "firstDetectionTimeUtc": "2024-01-01T00:00:00Z" },
                  "properties": { "result-note": "ignored" },
                  "message": {
                    "text": "Shared property message.",
                    "id": "message-id",
                    "arguments": ["ignored"],
                    "properties": { "message-note": "ignored" }
                  },
                  "partialFingerprints": {
                    "secondary/v1": "secondary-001",
                    "primary/v1": "primary-001"
                  },
                  "locations": [
                    {
                      "id": 17,
                      "annotations": [],
                      "relationships": [],
                      "properties": { "location-note": "ignored" },
                      "physicalLocation": {
                        "artifactLocation": {
                          "index": 1,
                          "description": { "text": "Primary source file" },
                          "properties": { "primary-artifact-note": "ignored" }
                        },
                        "contextRegion": {
                          "startLine": 6,
                          "endLine": 8
                        },
                        "address": { "absoluteAddress": 1234 },
                        "properties": { "physical-location-note": "ignored" },
                        "region": {
                          "startLine": 7,
                          "startColumn": 1,
                          "endLine": 7,
                          "endColumn": 8,
                          "message": { "text": "Ignored region message" },
                          "sourceLanguage": "csharp",
                          "properties": { "region-note": "ignored" }
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

    [Fact]
    public async Task Json_object_property_reordering_preserves_stable_output()
    {
        await AssertCandidateTransformationIsInvariantAsync(
            "json-property-order",
            PropertyReorderedSarif);
    }

    [Fact]
    public async Task Reference_preserving_array_reordering_preserves_stable_output()
    {
        await AssertCandidateTransformationIsInvariantAsync(
            "reference-preserving-array-order",
            ReferencePreservingArrayReorderedSarif);
    }

    [Fact]
    public async Task Ignored_optional_properties_preserve_decisions_and_output()
    {
        await AssertCandidateTransformationIsInvariantAsync(
            "ignored-optional-properties",
            IgnoredOptionalPropertiesSarif);
    }

    private static async Task AssertCandidateTransformationIsInvariantAsync(
        string caseId,
        string transformedCandidate)
    {
        var expected = await CompareAsync(BaseSarif, BaseSarif);
        var actual = await CompareAsync(BaseSarif, transformedCandidate);

        Assert.True(
            expected.DecisionSignature == actual.DecisionSignature,
            $"case={caseId}; field=decisions");
        Assert.True(
            expected.StableJson.SequenceEqual(actual.StableJson),
            $"case={caseId}; field=stable-json");
    }

    private static async Task<ComparisonProjection> CompareAsync(
        string baselineJson,
        string candidateJson)
    {
        var ingestor = new SarifIngestor();
        var baseline = await IngestAsync(
            ingestor,
            InputKind.Baseline,
            "baseline.sarif",
            baselineJson);
        var candidate = await IngestAsync(
            ingestor,
            InputKind.Candidate,
            "candidate.sarif",
            candidateJson);

        Assert.True(
            baseline.IsValid,
            $"side=baseline; diagnostics={Diagnostics(baseline)}");
        Assert.True(
            candidate.IsValid,
            $"side=candidate; diagnostics={Diagnostics(candidate)}");

        var result = new FindingMatcher().Match(
            baseline.ComparisonInput,
            candidate.ComparisonInput);
        Assert.True(
            result.Decisions.Length == 1
            && result.Decisions[0].Classification
                == FindingClassification.Unchanged,
            "field=expected-unchanged-decision");

        return new ComparisonProjection(
            PropertyTestData.MatchSignature(result),
            StableJsonReportSerializer.Serialize(
                PropertyTestData.Report(result)));
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        SarifIngestor ingestor,
        InputKind input,
        string logicalName,
        string json)
    {
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(json),
            writable: false);
        return await ingestor.IngestAsync(
            stream,
            new SarifIngestionRequest(
                input,
                logicalName,
                PropertyTestData.BoundedConfiguration(
                    maximumRunCollectionItems: 32)),
            TestContext.Current.CancellationToken);
    }

    private static string Diagnostics(SarifIngestionResult result) =>
        string.Join(
            "; ",
            result.ComparisonInput.Diagnostics.Select(
                PropertyTestData.DiagnosticSignature));

    private sealed record ComparisonProjection(
        string DecisionSignature,
        byte[] StableJson);
}
