using System.Collections.Immutable;
using System.Text;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.UnitTests;

public sealed class SarifValidationTests
{
    [Fact]
    public async Task Malformed_json_produces_a_stable_parse_diagnostic()
    {
        var result = await IngestAsync(
            """{ "version": "2.1.0", "runs": [""");

        Assert.False(result.IsValid);
        var diagnostic = Assert.Single(result.ComparisonInput.Diagnostics);
        Assert.Equal("PARSE0100", diagnostic.Code);
        Assert.Equal(DiagnosticStage.Parse, diagnostic.Stage);
        Assert.Equal(string.Empty, diagnostic.SourceReference?.JsonPointer);
        Assert.Empty(result.ComparisonInput.Findings);
    }

    [Fact]
    public async Task Unsupported_version_fails_before_result_mapping()
    {
        var result = await IngestAsync(
            """
            {
              "version": "2.0.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" }
                }]
              }]
            }
            """);

        Assert.False(result.IsValid);
        Assert.Empty(result.ComparisonInput.Findings);
        var diagnostic = Assert.Single(result.ComparisonInput.Diagnostics);
        Assert.Equal("SCHEMA0101", diagnostic.Code);
        Assert.Equal("/version", diagnostic.SourceReference?.JsonPointer);
        Assert.Equal("2.0.0", result.Summary.Version);
    }

    [Fact]
    public async Task Invalid_artifact_index_fails_closed_for_the_location()
    {
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "artifacts": [],
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "index": 2 }
                    }
                  }]
                }]
              }]
            }
            """);

        var finding = Assert.Single(result.ComparisonInput.Findings);
        Assert.Null(finding.PrimaryLocation);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item =>
                item.Code == "SCHEMA0122" &&
                item.SourceReference?.JsonPointer.EndsWith(
                    "/artifactLocation/index",
                    StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task Uri_base_cycle_is_detected_with_a_result_pointer()
    {
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "originalUriBaseIds": {
                  "A": { "uri": "a/", "uriBaseId": "B" },
                  "B": { "uri": "b/", "uriBaseId": "A" }
                },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "src/a.cs",
                        "uriBaseId": "A"
                      }
                    }
                  }]
                }]
              }]
            }
            """);

        var finding = Assert.Single(result.ComparisonInput.Findings);
        Assert.Null(finding.PrimaryLocation);
        var diagnostic = Assert.Single(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0031");
        Assert.Equal(0, diagnostic.SourceReference?.ResultIndex);
        Assert.Equal(
            "/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uriBaseId",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public async Task Configured_input_limit_is_enforced()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumInputBytes = 20,
        };
        var configuration = CreateConfiguration(limits);
        var result = await IngestAsync(
            """{ "version": "2.1.0", "runs": [] }""",
            configuration);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
                item => item.Code == "SECURITY0100");
    }

    [Fact]
    public async Task Empty_and_reversed_line_regions_are_rejected()
    {
        var empty = await IngestAsync(
            CreateSingleResultSarif("""{ }"""));
        var reversed = await IngestAsync(
            CreateSingleResultSarif(
                """
                {
                  "startLine": 3,
                  "startColumn": 5,
                  "endLine": 3,
                  "endColumn": 4
                }
                """));

        Assert.False(empty.IsValid);
        Assert.False(reversed.IsValid);
        Assert.Contains(
            empty.ComparisonInput.Diagnostics,
            item => item.Code == "SCHEMA0123");
        Assert.Contains(
            reversed.ComparisonInput.Diagnostics,
            item => item.Code == "SCHEMA0123");
    }

    [Fact]
    public async Task Offset_only_region_is_explicitly_diagnosed_as_unsupported()
    {
        var result = await IngestAsync(
            CreateSingleResultSarif(
                """
                {
                  "charOffset": 0,
                  "charLength": 4
                }
                """));

        Assert.True(result.IsValid);
        Assert.Null(
            Assert.Single(result.ComparisonInput.Findings)
                .PrimaryLocation?.Region);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item =>
                item.Code == "UNSUPPORTED0101" &&
                item.Severity == DiagnosticSeverity.Warning);
    }

    [Fact]
    public async Task Conflicting_artifact_uri_and_index_fail_closed()
    {
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "artifacts": [{
                  "location": { "uri": "src/indexed.cs" }
                }],
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "src/explicit.cs",
                        "index": 0
                      }
                    }
                  }]
                }]
              }]
            }
            """);

        Assert.False(result.IsValid);
        Assert.Null(
            Assert.Single(result.ComparisonInput.Findings).PrimaryLocation);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SCHEMA0124");
    }

    [Fact]
    public async Task Uri_base_composition_cannot_exceed_the_string_budget()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumStringCharacters = 24,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "originalUriBaseIds": {
                  "ROOT": { "uri": "repo:/1234567890/" }
                },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "abcdefghij.cs",
                        "uriBaseId": "ROOT"
                      }
                    }
                  }]
                }]
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SECURITY0103");
    }

    [Fact]
    public async Task Per_result_thread_flow_budget_is_enforced_while_reading()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumThreadFlowLocationsPerResult = 1,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "codeFlows": [{
                    "threadFlows": [
                      { "locations": [{ "location": {} }] },
                      { "locations": [{ "location": {} }] }
                    ]
                  }]
                }]
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Empty(result.ComparisonInput.Findings);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SECURITY0102");
    }

    [Fact]
    public async Task String_budget_is_enforced_while_reading()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumStringCharacters = 5,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "ToolXX" } },
                "results": []
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SECURITY0103");
    }

    [Fact]
    public async Task Unsupported_subtrees_cannot_bypass_collection_budget()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 4,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "graphs": [1, 2, 3, 4, 5],
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" }
                }]
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Empty(result.ComparisonInput.Findings);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SECURITY0102");
    }

    [Fact]
    public async Task Unsupported_subtrees_cannot_bypass_string_budget()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumStringCharacters = 12,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "graphs": [{ "value": "1234567890123" }],
                "results": []
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Empty(result.ComparisonInput.Findings);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SECURITY0103");
    }

    [Fact]
    public async Task Unknown_subtrees_cannot_bypass_object_budget()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 2,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "future": { "first": 1, "second": 2, "third": 3 }
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Empty(result.ComparisonInput.Findings);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "SECURITY0102");
    }

    [Fact]
    public async Task Unknown_nested_subtrees_cannot_bypass_depth_budget()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumJsonDepth = 4,
        };
        var result = await IngestAsync(
            """
            {
              "version": "2.1.0",
              "runs": [{
                "future": { "one": { "two": { "three": true } } }
              }]
            }
            """,
            CreateConfiguration(limits));

        Assert.False(result.IsValid);
        Assert.Empty(result.ComparisonInput.Findings);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "PARSE0100");
    }

    [Fact]
    public void Bounded_stream_read_byte_fails_on_the_first_excess_byte()
    {
        var streamType = typeof(SarifIngestor).Assembly.GetType(
            "SarifRegress.Sarif.Ingestion.BoundedReadStream",
            throwOnError: true)!;
        using var inner = new MemoryStream([1, 2], writable: false);
        using var bounded = Assert.IsAssignableFrom<Stream>(
            Activator.CreateInstance(streamType, inner, 1L));

        Assert.Equal(1, bounded.ReadByte());
        Assert.ThrowsAny<IOException>(() => bounded.ReadByte());
    }

    [Fact]
    public async Task Repository_context_is_requested_only_for_a_canonical_repo_path()
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "uri": "src/a.cs" },
                      "region": { "startLine": 2 }
                    }
                  }]
                }]
              }]
            }
            """;
        var repository = new RecordingRepositoryContext();
        await using var stream = CreateStream(sarif);

        var result = await new SarifIngestor(repository).IngestAsync(
            stream,
            new SarifIngestionRequest(InputKind.Candidate, "candidate"),
            TestContext.Current.CancellationToken);

        Assert.Equal("src/a.cs", repository.RequestedPath);
        Assert.Equal(3, repository.RequestedRadius);
        Assert.False(repository.RequestedTokenWindow);
        Assert.Equal(
            "repository-hash",
            Assert.Single(result.ComparisonInput.Findings).Context?.SnippetHash);
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        string sarif,
        SarifRegressConfiguration? configuration = null)
    {
        await using var stream = CreateStream(sarif);
        return await new SarifIngestor().IngestAsync(
            stream,
            new SarifIngestionRequest(
                InputKind.Baseline,
                "baseline",
                configuration),
            TestContext.Current.CancellationToken);
    }

    private static MemoryStream CreateStream(string value) =>
        new(Encoding.UTF8.GetBytes(value), writable: false);

    private static string CreateSingleResultSarif(string region) =>
        $$"""
          {
            "version": "2.1.0",
            "runs": [{
              "tool": { "driver": { "name": "Tool" } },
              "results": [{
                "ruleId": "R1",
                "message": { "text": "message" },
                "locations": [{
                  "physicalLocation": {
                    "artifactLocation": { "uri": "src/a.cs" },
                    "region": {{region}}
                  }
                }]
              }]
            }]
          }
          """;

    private static SarifRegressConfiguration CreateConfiguration(
        ResourceLimits limits)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            defaults.RepositoryRoot,
            defaults.PathRebases,
            defaults.PathAliases,
            defaults.RuleAliases,
            defaults.Matching,
            defaults.Policy,
            defaults.Reporting,
            limits);
    }

    private sealed class RecordingRepositoryContext : IRepositoryContext
    {
        public string? RequestedPath { get; private set; }

        public int? RequestedRadius { get; private set; }

        public bool RequestedTokenWindow { get; private set; }

        public ValueTask<RepositoryContextResult> ReadAsync(
            string repositoryRelativePath,
            SarifRegress.Core.Findings.Region? region,
            int lineRadius,
            SourceReference? sourceReference = null,
            CancellationToken cancellationToken = default,
            bool includeTokenWindow = false)
        {
            RequestedPath = repositoryRelativePath;
            RequestedRadius = lineRadius;
            RequestedTokenWindow = includeTokenWindow;
            return ValueTask.FromResult(
                new RepositoryContextResult(
                    Exists: true,
                    Snippet: "source",
                    new SarifRegress.Core.Findings.ContextEvidence(
                        "repository-hash",
                        null,
                        null,
                        region?.StartLine,
                        region?.EndLine ?? region?.StartLine),
                    ImmutableArray<Diagnostic>.Empty));
        }
    }
}
