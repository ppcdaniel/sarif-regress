using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
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
                      "level": "warning",
                      "kind": "fail",
                      "baselineState": "unchanged",
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
        Assert.Equal("warning", finding.Metadata.Level);
        Assert.Equal("fail", finding.Metadata.Kind);
        Assert.Equal("unchanged", finding.Metadata.BaselineState);
        Assert.Equal(
            [
                "trimmed-whitespace",
                "collapsed-whitespace",
                "invariant-case-fold",
            ],
            finding.Message.NormalisationFlags);
        Assert.Equal(
            [
                "collapsed-whitespace",
                "invariant-case-fold",
                "producer-family-allowlist",
                "trimmed-whitespace",
            ],
            finding.Lossiness);
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

    [Theory]
    [InlineData("Scanner.A", "Scanner A")]
    [InlineData("Scanner", "scanner")]
    [InlineData("掃描器甲", "掃描器乙")]
    [InlineData("CodeQL-Evil", "CodeQL")]
    [InlineData("CodeQL Scanner", "CodeQL")]
    [InlineData("CodeQLicious", "CodeQL")]
    [InlineData("Semgrep CLI", "Semgrep")]
    [InlineData("Semgrepper", "Semgrep")]
    public async Task Distinct_tool_names_have_distinct_automatic_identities(
        string baselineToolName,
        string candidateToolName)
    {
        var baseline = await IngestSingleFindingAsync(
            baselineToolName,
            "1.0.0",
            InputKind.Baseline);
        var candidate = await IngestSingleFindingAsync(
            candidateToolName,
            "1.0.0",
            InputKind.Candidate);

        Assert.NotEqual(
            baseline.Producer.AutomaticIdentity,
            candidate.Producer.AutomaticIdentity);
        Assert.NotEqual(
            Assert.Single(baseline.DerivedFingerprints).Value,
            Assert.Single(candidate.DerivedFingerprints).Value);
    }

    [Theory]
    [InlineData(
        "CodeQL",
        "CodeQL command-line toolchain",
        "codeql")]
    [InlineData("semgrep", "Semgrep", "semgrep")]
    public async Task Allowlisted_family_names_share_identity_across_versions(
        string baselineToolName,
        string candidateToolName,
        string expectedFamily)
    {
        var baseline = await IngestSingleFindingAsync(
            baselineToolName,
            "1.0.0",
            InputKind.Baseline);
        var candidate = await IngestSingleFindingAsync(
            candidateToolName,
            "2.0.0",
            InputKind.Candidate);

        Assert.Equal(expectedFamily, baseline.Producer.Family);
        Assert.Equal(expectedFamily, candidate.Producer.Family);
        Assert.Equal(
            baseline.Producer.AutomaticIdentity,
            candidate.Producer.AutomaticIdentity);
        Assert.Equal(
            Assert.Single(baseline.DerivedFingerprints).Value,
            Assert.Single(candidate.DerivedFingerprints).Value);
        Assert.Equal("1.0.0", baseline.Producer.ToolVersion);
        Assert.Equal("2.0.0", candidate.Producer.ToolVersion);
        Assert.Contains(
            ProducerIdentityResolver.AllowlistLossinessIdentifier,
            baseline.Lossiness);
        Assert.Contains(
            ProducerIdentityResolver.AllowlistLossinessIdentifier,
            candidate.Lossiness);
    }

    [Fact]
    public async Task Exact_tool_name_identity_excludes_tool_version()
    {
        var baseline = await IngestSingleFindingAsync(
            "Custom Scanner",
            "1.0.0",
            InputKind.Baseline);
        var candidate = await IngestSingleFindingAsync(
            "Custom Scanner",
            "2.0.0",
            InputKind.Candidate);

        Assert.Equal(
            baseline.Producer.AutomaticIdentity,
            candidate.Producer.AutomaticIdentity);
        Assert.StartsWith(
            "producer-tool-name/v1/",
            baseline.Producer.AutomaticIdentity,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            ProducerIdentityResolver.AllowlistLossinessIdentifier,
            baseline.Lossiness);
        Assert.DoesNotContain(
            ProducerIdentityResolver.AllowlistLossinessIdentifier,
            candidate.Lossiness);
    }

    [Theory]
    [InlineData("CodeQL", "CodeQL-Evil")]
    [InlineData("Scanner.A", "Scanner A")]
    public async Task Rule_alias_producer_names_use_collision_safe_identity(
        string configuredProducer,
        string actualProducer)
    {
        var configuration = CreateConfiguration(
            repositoryRoot: null,
            ruleAliases:
            [
                new RuleAlias(
                    configuredProducer,
                    "R1",
                    "Other Scanner",
                    "R2"),
            ]);

        var finding = await IngestSingleFindingAsync(
            actualProducer,
            "1.0.0",
            InputKind.Baseline,
            configuration);

        Assert.False(finding.Rule.AliasApplied);
    }

    [Fact]
    public async Task Representation_changes_are_retained_as_deterministic_lossiness()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "\r\n  Mixed   CASE \t" },
                  "level": "error",
                  "kind": "review",
                  "baselineState": "updated",
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "uri": "src\\./A%2Ecs" },
                      "region": { "startLine": 5 }
                    }
                  }]
                }]
              }]
            }
            """;
        var request = new SarifIngestionRequest(
            InputKind.Candidate,
            "candidate.sarif");

        var result = await IngestAsync(sarif, request);

        Assert.True(result.IsValid);
        var finding = Assert.Single(result.ComparisonInput.Findings);
        Assert.Equal(
            new FindingMetadata("error", "review", "updated"),
            finding.Metadata);
        Assert.Equal("repo://src/A.cs", finding.PrimaryLocation?.Path.CanonicalUri);
        Assert.All(
            finding.PrimaryLocation!.Path.Transformations,
            transformation => Assert.True(transformation.IsLossy));
        Assert.Equal(
            [
                "canonical-separators",
                "collapsed-rooted-segments",
                "collapsed-whitespace",
                "invariant-case-fold",
                "normalised-line-endings",
                "safe-percent-decode",
                "trimmed-whitespace",
            ],
            finding.Lossiness);
    }

    [Fact]
    public async Task Rule_aliases_map_both_sides_to_the_same_canonical_identity()
    {
        const string baselineSarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": {
                  "driver": { "name": "CodeQL command-line toolchain" }
                },
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
            first.Summary.Runs.Select(ToStableRunSummaryTuple),
            second.Summary.Runs.Select(ToStableRunSummaryTuple));
        Assert.Equal(first.Summary.Version, second.Summary.Version);
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        string sarif,
        SarifIngestionRequest request)
    {
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(sarif),
            writable: false);
        return await new SarifIngestor().IngestAsync(
            stream,
            request,
            TestContext.Current.CancellationToken);
    }

    private static async Task<Finding> IngestSingleFindingAsync(
        string toolName,
        string toolVersion,
        InputKind input,
        SarifRegressConfiguration? configuration = null)
    {
        var sarif = JsonSerializer.Serialize(
            new
            {
                version = "2.1.0",
                runs = new[]
                {
                    new
                    {
                        tool = new
                        {
                            driver = new
                            {
                                name = toolName,
                                semanticVersion = toolVersion,
                            },
                        },
                        results = new[]
                        {
                            new
                            {
                                ruleId = "R1",
                                message = new { text = "message" },
                                locations = new[]
                                {
                                    new
                                    {
                                        physicalLocation = new
                                        {
                                            artifactLocation = new
                                            {
                                                uri = "src/example.cs",
                                            },
                                            region = new
                                            {
                                                startLine = 1,
                                                snippet = new
                                                {
                                                    text = "example();",
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            });
        var result = await IngestAsync(
            sarif,
            new SarifIngestionRequest(
                input,
                input.ToString(),
                configuration ?? SarifRegressConfiguration.Default));

        Assert.True(result.IsValid);
        return Assert.Single(result.ComparisonInput.Findings);
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
        string? Level,
        string? Kind,
        string? BaselineState,
        string MessageFlags,
        string Lossiness,
        string? DerivedFingerprint)
        ToStableFindingTuple(Finding finding) =>
        (
            finding.FindingKey,
            finding.Rule.CanonicalId,
            finding.PrimaryLocation?.Path.CanonicalUri,
            finding.Message.ComparisonText,
            finding.Metadata.Level,
            finding.Metadata.Kind,
            finding.Metadata.BaselineState,
            string.Join("|", finding.Message.NormalisationFlags),
            string.Join("|", finding.Lossiness),
            finding.DerivedFingerprints.FirstOrDefault()?.Value
        );

    private static (string Code, string Pointer, string Message)
        ToStableDiagnosticTuple(Diagnostic diagnostic) =>
        (
            diagnostic.Code,
            diagnostic.SourceReference?.JsonPointer ?? string.Empty,
            diagnostic.Message
        );

    private static (SarifRunSummary Summary, string IgnoredProperties)
        ToStableRunSummaryTuple(SarifRunSummary summary) =>
        (
            summary with
            {
                IgnoredProperties =
                    ImmutableArray<GithubIgnoredPropertyFact>.Empty,
            },
            string.Join(
                "|",
                summary.IgnoredProperties.Select(
                    item => $"{item.PropertyPath}:{item.Occurrences}"))
        );
}
