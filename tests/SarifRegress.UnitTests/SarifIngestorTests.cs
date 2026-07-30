using System.Collections.Immutable;
using System.Text;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Paths;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.UnitTests;

public sealed class SarifIngestorTests
{
    [Fact]
    public async Task Supported_subset_maps_to_a_canonical_finding()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [
                {
                  "tool": {
                    "driver": {
                      "name": "CodeQL command-line toolchain",
                      "semanticVersion": "2.20.0",
                      "rules": [
                        { "id": "cpp/test", "properties": { "tags": ["security"] } }
                      ]
                    }
                  },
                  "automationDetails": { "id": "nightly/" },
                  "originalUriBaseIds": {
                    "SRCROOT": { "uri": "file:///repo/" }
                  },
                  "artifacts": [
                    {
                      "location": {
                        "uri": "src/a.cpp",
                        "uriBaseId": "SRCROOT"
                      }
                    }
                  ],
                  "results": [
                    {
                      "ruleIndex": 0,
                      "message": { "text": "  Unsafe   value. " },
                      "partialFingerprints": {
                        "primaryLocationLineHash/v1": "producer-value"
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "index": 0 },
                            "region": {
                              "startLine": 10,
                              "startColumn": 2,
                              "endLine": 10,
                              "endColumn": 8,
                              "snippet": { "text": "unsafe(source);" }
                            }
                          }
                        },
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/z.cpp" },
                            "region": { "startLine": 2 }
                          }
                        }
                      ],
                      "relatedLocations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/b.cpp" },
                            "region": { "startLine": 3 }
                          }
                        }
                      ],
                      "codeFlows": [
                        {
                          "threadFlows": [
                            {
                              "locations": [
                                {
                                  "location": {
                                    "physicalLocation": {
                                      "artifactLocation": { "uri": "src/z.cpp" },
                                      "region": {
                                        "startLine": 9,
                                        "snippet": { "text": "z();" }
                                      }
                                    }
                                  }
                                },
                                {
                                  "location": {
                                    "physicalLocation": {
                                      "artifactLocation": { "uri": "src/b.cpp" },
                                      "region": {
                                        "startLine": 3,
                                        "snippet": { "text": "b();" }
                                      }
                                    }
                                  }
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
            """;
        var request = new SarifIngestionRequest(
            InputKind.Baseline,
            "baseline.sarif",
            CreateConfiguration("/repo"),
            compressedUploadBytes: 512);

        var result = await IngestAsync(sarif, request);

        Assert.True(result.IsValid);
        var finding = Assert.Single(result.ComparisonInput.Findings);
        Assert.Equal("baseline:0:0", finding.FindingKey);
        Assert.Equal("/runs/0/results/0", finding.SourceReference.JsonPointer);
        Assert.Equal("codeql", finding.Producer.Family);
        Assert.Equal("2.20.0", finding.Producer.ToolVersion);
        Assert.Equal("nightly/", finding.Run.AutomationCategory);
        Assert.Equal("cpp/test", finding.Rule.OriginalId);
        Assert.Equal("codeql/cpp/test", finding.Rule.CanonicalId);
        Assert.Equal(
            "repo://src/a.cpp",
            finding.PrimaryLocation?.Path.CanonicalUri);
        Assert.Equal(
            "file:///repo/src/a.cpp",
            finding.PrimaryLocation?.Path.ResolvedValue);
        Assert.Equal("Unsafe value.", finding.Message.CanonicalText);
        Assert.Equal("unsafe value.", finding.Message.ComparisonText);
        Assert.Equal(
            FingerprintReliability.High,
            Assert.Single(finding.ProducerFingerprints).Reliability);
        Assert.Single(finding.DerivedFingerprints);
        Assert.Collection(
            finding.RelatedLocations,
            item => Assert.NotNull(item.Path),
            item => Assert.NotNull(item.Path));
        Assert.Equal(
            finding.RelatedLocations
                .OrderBy(item => item.StableKey, StringComparer.Ordinal)
                .Select(item => item.StableKey),
            finding.RelatedLocations.Select(item => item.StableKey));
        var codeFlow = Assert.IsType<CodeFlowEvidence>(finding.CodeFlow);
        Assert.Equal(
            ["repo://src/b.cpp", "repo://src/z.cpp"],
            codeFlow.Anchors.Select(item => item.CanonicalPath));
        Assert.Equal([0, 1], codeFlow.Anchors.Select(item => item.Ordinal));
        Assert.Equal("2.1.0", result.Summary.Version);
        Assert.Equal(512L, result.Summary.CompressedUploadBytes);
        Assert.Empty(result.ComparisonInput.Diagnostics);
    }

    [Fact]
    public async Task Rule_aliases_map_both_sides_to_the_same_canonical_identity()
    {
        const string baselineSarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "CodeQL" } },
                "results": [{
                  "ruleId": "old/rule",
                  "message": { "text": "message" }
                }]
              }]
            }
            """;
        const string candidateSarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Internal Scanner" } },
                "results": [{
                  "ruleId": "new/rule",
                  "message": { "text": "message" }
                }]
              }]
            }
            """;
        var configuration = CreateConfiguration(
            repositoryRoot: null,
            ruleAliases:
            [
                new RuleAlias(
                    "CodeQL",
                    "old/rule",
                    "Internal Scanner",
                    "new/rule"),
            ]);

        var baseline = await IngestAsync(
            baselineSarif,
            new SarifIngestionRequest(
                InputKind.Baseline,
                "baseline",
                configuration));
        var candidate = await IngestAsync(
            candidateSarif,
            new SarifIngestionRequest(
                InputKind.Candidate,
                "candidate",
                configuration));

        var baselineRule =
            Assert.Single(baseline.ComparisonInput.Findings).Rule;
        var candidateRule =
            Assert.Single(candidate.ComparisonInput.Findings).Rule;
        Assert.True(baselineRule.AliasApplied);
        Assert.True(candidateRule.AliasApplied);
        Assert.Equal(baselineRule.CanonicalId, candidateRule.CanonicalId);
        Assert.StartsWith(
            "alias/",
            baselineRule.CanonicalId,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Duplicate_producer_fingerprints_are_not_treated_as_unique()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [
                  {
                    "ruleId": "R1",
                    "message": { "text": "first" },
                    "partialFingerprints": { "stable/v1": "duplicate" }
                  },
                  {
                    "ruleId": "R1",
                    "message": { "text": "second" },
                    "partialFingerprints": { "stable/v1": "duplicate" }
                  }
                ]
              }]
            }
            """;

        var result = await IngestAsync(
            sarif,
            new SarifIngestionRequest(InputKind.Baseline, "baseline"));

        Assert.Collection(
            result.ComparisonInput.Findings,
            finding => Assert.Equal(
                FingerprintReliability.Degraded,
                Assert.Single(finding.ProducerFingerprints).Reliability),
            finding => Assert.Equal(
                FingerprintReliability.Degraded,
                Assert.Single(finding.ProducerFingerprints).Reliability));
    }

    [Fact]
    public async Task Repeated_ingestion_has_identical_findings_and_diagnostics()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "Message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "uri": "src/a.cs" },
                      "region": {
                        "startLine": 5,
                        "snippet": { "text": "value();" }
                      }
                    }
                  }]
                }]
              }]
            }
            """;
        var request = new SarifIngestionRequest(
            InputKind.Candidate,
            "candidate");

        var first = await IngestAsync(sarif, request);
        var second = await IngestAsync(sarif, request);

        Assert.Equal(
            first.ComparisonInput.Findings.Select(ToStableFindingTuple),
            second.ComparisonInput.Findings.Select(ToStableFindingTuple));
        Assert.Equal(
            first.ComparisonInput.Diagnostics.Select(ToStableDiagnosticTuple),
            second.ComparisonInput.Diagnostics.Select(ToStableDiagnosticTuple));
        Assert.Equal(
            first.Summary.Runs.Select(item => item),
            second.Summary.Runs.Select(item => item));
        Assert.Equal(first.Summary.Version, second.Summary.Version);
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        string sarif,
        SarifIngestionRequest request)
    {
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(sarif),
            writable: false);
        return await new SarifIngestor().IngestAsync(stream, request);
    }

    private static SarifRegressConfiguration CreateConfiguration(
        string? repositoryRoot,
        IEnumerable<RuleAlias>? ruleAliases = null)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            repositoryRoot,
            defaults.PathRebases,
            defaults.PathAliases,
            ruleAliases ?? defaults.RuleAliases,
            defaults.Matching,
            defaults.Policy,
            defaults.Reporting,
            defaults.Limits);
    }

    private static (
        string Key,
        string Rule,
        string? Path,
        string Message,
        string? DerivedFingerprint)
        ToStableFindingTuple(Finding finding) =>
        (
            finding.FindingKey,
            finding.Rule.CanonicalId,
            finding.PrimaryLocation?.Path.CanonicalUri,
            finding.Message.ComparisonText,
            finding.DerivedFingerprints.FirstOrDefault()?.Value
        );

    private static (string Code, string Pointer, string Message)
        ToStableDiagnosticTuple(Diagnostic diagnostic) =>
        (
            diagnostic.Code,
            diagnostic.SourceReference?.JsonPointer ?? string.Empty,
            diagnostic.Message
        );
}
