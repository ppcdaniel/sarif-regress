using System.Globalization;
using System.Text;
using System.Text.Json;
using SarifRegress.Cli;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Compatibility;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.UnitTests;

public sealed class GithubCompatibilityProjectionTests
{
    [Fact]
    public async Task Ingestion_retains_bounded_driver_extension_and_source_root_facts()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": {
                  "driver": {
                    "name": "Analyzer",
                    "rules": [
                      { "id": "R1", "properties": { "tags": ["a"] } },
                      { "id": "R2", "properties": { "tags": ["a", "b"] } }
                    ]
                  },
                  "extensions": [{
                    "name": "Plugin",
                    "rules": [{
                      "id": "E1",
                      "properties": { "tags": ["a", "b", "c", "d"] }
                    }]
                  }]
                },
                "invocations": [
                  { "workingDirectory": { "uri": "file:///repo/" } },
                  { "workingDirectory": { "uri": "file:///ignored/" } }
                ],
                "automationDetails": { "id": "category/run-123" },
                "graphs": {},
                "results": [
                  {
                    "ruleId": "R1",
                    "message": { "text": "relative" },
                    "partialFingerprints": {
                      "primaryLocationLineHash/v1": "relative"
                    },
                    "locations": [{
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/a.cs" },
                        "region": { "startLine": 1 }
                      }
                    }]
                  },
                  {
                    "ruleId": "R1",
                    "message": { "text": "convertible" },
                    "partialFingerprints": {
                      "primaryLocationLineHash/v1": "convertible"
                    },
                    "locations": [{
                      "physicalLocation": {
                        "artifactLocation": {
                          "uri": "file:///repo/src/b.cs"
                        },
                        "region": { "startLine": 1 }
                      }
                    }]
                  },
                  {
                    "ruleId": "R1",
                    "message": { "text": "outside root" },
                    "partialFingerprints": {
                      "primaryLocationLineHash/v1": "outside"
                    },
                    "locations": [{
                      "physicalLocation": {
                        "artifactLocation": {
                          "uri": "file:///outside/c.cs"
                        },
                        "region": { "startLine": 1 }
                      }
                    }]
                  },
                  {
                    "ruleId": "R2",
                    "message": { "text": "scheme mismatch" },
                    "partialFingerprints": {
                      "primaryLocationLineHash/v1": "mismatch"
                    },
                    "locations": [{
                      "physicalLocation": {
                        "artifactLocation": {
                          "uri": "https://example.invalid/d.cs"
                        },
                        "region": { "startLine": 1 }
                      }
                    }]
                  },
                  {
                    "ruleId": "R2",
                    "message": {
                      "text": "not displayed",
                      "markdown": "**not displayed**"
                    },
                    "kind": "fail",
                    "baselineState": "new",
                    "fingerprints": { "producer": "value" },
                    "stacks": []
                  }
                ]
              }]
            }
            """;

        var ingestion = await IngestAsync(sarif);

        var run = Assert.Single(ingestion.Summary.Runs);
        Assert.Equal(3, run.RuleCount);
        Assert.Equal(2, run.DriverRuleCount);
        Assert.Equal(1, run.ExtensionRuleCount);
        Assert.Equal(4, run.MaximumTagsPerRule);
        Assert.Equal(1, run.MaximumPartialFingerprintsPerResult);
        Assert.Equal(1, run.ResultsWithoutDisplayLocation);
        var sourceRoot = Assert.IsType<GithubSourceRootFacts>(
            run.SourceRootFacts);
        Assert.Equal(2, sourceRoot.InvocationCount);
        Assert.Equal(
            GithubWorkingDirectoryUriKind.AbsoluteUri,
            sourceRoot.WorkingDirectoryUriKind);
        Assert.Equal(1, sourceRoot.LaterInvocationsWithWorkingDirectory);
        Assert.Equal(3, sourceRoot.AbsoluteUriPrimaryLocations);
        Assert.Equal(0, sourceRoot.AbsolutePathPrimaryLocations);
        Assert.Equal(1, sourceRoot.ConvertibleAbsoluteUriPrimaryLocations);
        Assert.Equal(
            1,
            sourceRoot.OutsideSourceRootAbsoluteUriPrimaryLocations);
        Assert.Equal(
            1,
            sourceRoot.SourceRootSchemeMismatchPrimaryLocations);
        Assert.Equal(
            [
                "automationDetails.id.runId",
                "result.baselineState",
                "result.fingerprints",
                "result.kind",
                "result.message.markdown",
                "result.stacks",
                "run.graphs",
            ],
            run.IgnoredProperties.Select(item => item.PropertyPath));

        var advisories = new GithubCompatibilityChecker().Check(
            ingestion.Summary);
        Assert.Contains(advisories, item => item.Code == "GHCS0018");
        Assert.Contains(advisories, item => item.Code == "GHCS0020");
        Assert.Contains(advisories, item => item.Code == "GHCS0021");
        Assert.Contains(advisories, item => item.Code == "GHCS0022");
        Assert.Equal(
            7,
            advisories.Count(item => item.Code == "GHCS0023"));
        Assert.DoesNotContain(advisories, item => item.Code == "GHCS0017");
        Assert.All(
            advisories,
            item => Assert.DoesNotContain(
                "/repo/",
                item.Message + item.Help,
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task Relative_working_directory_is_not_claimed_as_absolute_source_root()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Analyzer" } },
                "invocations": [{
                  "workingDirectory": { "uri": "workspace/" }
                }],
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "file:///repo/a.cs"
                      },
                      "region": { "startLine": 1 }
                    }
                  }]
                }]
              }]
            }
            """;

        var ingestion = await IngestAsync(sarif);
        var run = Assert.Single(ingestion.Summary.Runs);
        Assert.Equal(
            GithubWorkingDirectoryUriKind.RelativeReference,
            Assert.IsType<GithubSourceRootFacts>(run.SourceRootFacts)
                .WorkingDirectoryUriKind);

        var diagnostics = new GithubCompatibilityChecker().Check(
            ingestion.Summary);

        Assert.Contains(diagnostics, item => item.Code == "GHCS0019");
        Assert.DoesNotContain(diagnostics, item => item.Code == "GHCS0020");
    }

    [Fact]
    public async Task Indexed_artifact_is_not_claimed_as_documented_display_location()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Analyzer" } },
                "artifacts": [{
                  "location": { "uri": "src/a.cs" }
                }],
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "index": 0 },
                      "region": { "startLine": 1 }
                    }
                  }]
                }]
              }]
            }
            """;

        var ingestion = await IngestAsync(sarif);
        var run = Assert.Single(ingestion.Summary.Runs);

        Assert.Equal(1, run.ResultsWithoutDisplayLocation);
        Assert.Equal(
            ["artifactLocation.index", "run.artifacts"],
            run.IgnoredProperties.Select(item => item.PropertyPath));
        var diagnostics = new GithubCompatibilityChecker().Check(
            ingestion.Summary);
        Assert.Contains(diagnostics, item => item.Code == "GHCS0018");
        Assert.Equal(
            2,
            diagnostics.Count(item => item.Code == "GHCS0023"));
    }

    [Fact]
    public async Task Category_only_automation_id_has_no_ignored_run_component()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Analyzer" } },
                "automationDetails": { "id": "category" },
                "results": []
              }]
            }
            """;

        var ingestion = await IngestAsync(sarif);
        var run = Assert.Single(ingestion.Summary.Runs);

        Assert.DoesNotContain(
            run.IgnoredProperties,
            item => item.PropertyPath == "automationDetails.id.runId");
    }

    [Fact]
    public void Unknown_compressed_payload_size_does_not_claim_limit_compliance()
    {
        var summary = new SarifDocumentSummary(
            InputKind.Candidate,
            "2.1.0",
            InputBytes: 50_000_000,
            CompressedUploadBytes: null,
            Runs: []);

        var diagnostics = new GithubCompatibilityChecker().Check(summary);

        Assert.DoesNotContain(diagnostics, item => item.Code == "GHCS0002");
        Assert.Null(summary.CompressedUploadBytes);
    }

    [Fact]
    public void Validate_reports_raw_file_compression_as_not_evaluated()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "sarif-regress-github-profile-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(
                Path.Combine(directory, "input.sarif"),
                """
                {
                  "version": "2.1.0",
                  "runs": [{
                    "tool": { "driver": { "name": "Analyzer" } },
                    "results": [{
                      "ruleId": "R1",
                      "message": { "text": "message" },
                      "partialFingerprints": {
                        "primaryLocationLineHash/v1": "stable"
                      },
                      "locations": [{
                        "physicalLocation": {
                          "artifactLocation": { "uri": "src/a.cs" },
                          "region": { "startLine": 1 }
                        }
                      }]
                    }]
                  }]
                }
                """);
            using var output =
                new StringWriter(CultureInfo.InvariantCulture);
            using var error =
                new StringWriter(CultureInfo.InvariantCulture);

            var exitCode = CliApplication.Run(
                ["validate", "--input", "input.sarif"],
                output,
                error,
                directory);

            Assert.Equal(0, exitCode);
            Assert.Equal(string.Empty, error.ToString());
            using var json = JsonDocument.Parse(output.ToString());
            var input = json.RootElement.GetProperty("input");
            Assert.Equal(
                "not-evaluated",
                input
                    .GetProperty("compressedUploadSizeEvaluation")
                    .GetString());
            Assert.Equal(
                JsonValueKind.Null,
                input.GetProperty("compressedUploadBytes").ValueKind);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        string sarif)
    {
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(sarif),
            writable: false);
        return await new SarifIngestor().IngestAsync(
            stream,
            new SarifIngestionRequest(
                InputKind.Candidate,
                "candidate.sarif"),
            TestContext.Current.CancellationToken);
    }
}
