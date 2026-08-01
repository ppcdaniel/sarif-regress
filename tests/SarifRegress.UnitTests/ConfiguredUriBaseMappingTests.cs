using System.Text;
using System.Text.Json;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.UnitTests;

public sealed class ConfiguredUriBaseMappingTests
{
    private const string ArtifactLocationPointer =
        "/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uriBaseId";

    private static readonly JsonSerializerOptions SarifJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    [Fact]
    public async Task Missing_external_base_remains_rejected_without_configuration()
    {
        var result = await IngestAsync("MISSING_ROOT");

        Assert.False(result.IsValid);
        Assert.Null(Assert.Single(result.ComparisonInput.Findings).PrimaryLocation);
        var diagnostic = Assert.Single(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0032");
        Assert.Equal(ArtifactLocationPointer, diagnostic.SourceReference?.JsonPointer);
        Assert.DoesNotContain(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0033");
    }

    [Theory]
    [InlineData("%SRCROOT%")]
    [InlineData("UNRELATED_LOGICAL_ROOT")]
    public async Task Any_explicit_identifier_uses_the_same_general_mapping(
        string uriBaseId)
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping(uriBaseId, "repo:/")]);

        var result = await IngestAsync(uriBaseId, configuration);

        Assert.True(result.IsValid);
        var finding = Assert.Single(result.ComparisonInput.Findings);
        Assert.Equal(
            "repo://src/example.cs",
            finding.PrimaryLocation?.Path.CanonicalUri);
        Assert.DoesNotContain(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0032");
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item =>
                item.Code == "CANON0033" &&
                item.Severity == DiagnosticSeverity.Note &&
                item.SourceReference?.JsonPointer == ArtifactLocationPointer);
    }

    [Theory]
    [InlineData("baseline.sarif", InputKind.Baseline)]
    [InlineData("candidate.sarif", InputKind.Candidate)]
    public async Task Authentic_semgrep_external_base_shape_ingests(
        string fileName,
        InputKind input)
    {
        var path = Path.Combine(
            RepositoryLayout.Root,
            "validation",
            "holdout",
            "cases",
            "semgrep",
            fileName);
        await using var stream = File.OpenRead(path);
        var configuration = CreateConfiguration(
            [new UriBaseMapping("%SRCROOT%", "repo:/")]);

        var result = await new SarifIngestor().IngestAsync(
            stream,
            new SarifIngestionRequest(input, fileName, configuration),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
        Assert.Equal(30, result.ComparisonInput.Findings.Length);
        Assert.DoesNotContain(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0032");
        Assert.All(
            result.ComparisonInput.Findings,
            finding => Assert.Contains(
                finding.PrimaryLocation!.Path.Transformations,
                item => item.Kind == "configured-uri-base"));
    }

    [Fact]
    public async Task Sarif_defined_base_takes_precedence_over_configuration()
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "repo:/configured/")]);
        var sarifBases = new Dictionary<string, UriBaseDefinition?>
        {
            ["ROOT"] = new("repo:/sarif/"),
        };

        var result = await IngestAsync("ROOT", configuration, sarifBases);

        Assert.True(result.IsValid);
        var path = Assert.IsType<CanonicalPath>(
            Assert.Single(result.ComparisonInput.Findings).PrimaryLocation?.Path);
        Assert.Equal("repo://sarif/src/example.cs", path.CanonicalUri);
        Assert.DoesNotContain(
            path.Transformations,
            item => item.Kind == "configured-uri-base");
        Assert.DoesNotContain(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0033");
    }

    [Fact]
    public async Task Invalid_Sarif_definition_is_not_masked_by_configuration()
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "repo:/configured/")]);
        var sarifBases = new Dictionary<string, UriBaseDefinition?>
        {
            ["ROOT"] = new(Uri: null),
        };

        var result = await IngestAsync("ROOT", configuration, sarifBases);

        Assert.False(result.IsValid);
        Assert.Null(Assert.Single(result.ComparisonInput.Findings).PrimaryLocation);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item =>
                item.Code == "CANON0032" &&
                item.Message.Contains("SARIF-defined", StringComparison.Ordinal));
        Assert.DoesNotContain(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0033");
    }

    [Fact]
    public async Task Configured_and_Sarif_base_cycle_is_rejected()
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("CONFIGURED", "configured/", "SARIF")]);
        var sarifBases = new Dictionary<string, UriBaseDefinition?>
        {
            ["SARIF"] = new("sarif/", "CONFIGURED"),
        };

        var result = await IngestAsync(
            "CONFIGURED",
            configuration,
            sarifBases);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0031");
    }

    [Fact]
    public async Task Configuration_only_base_cycle_is_rejected()
    {
        var configuration = CreateConfiguration(
            [
                new UriBaseMapping("A", "a/", "B"),
                new UriBaseMapping("B", "b/", "A"),
            ]);

        var result = await IngestAsync("A", configuration);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0031");
    }

    [Fact]
    public async Task Configured_chain_obeys_the_existing_depth_limit()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumUriBaseDepth = 2,
        };
        var configuration = CreateConfiguration(
            [
                new UriBaseMapping("A", "a/", "B"),
                new UriBaseMapping("B", "b/", "C"),
                new UriBaseMapping("C", "repo:/"),
            ],
            limits);

        var result = await IngestAsync("A", configuration);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0030");
    }

    [Theory]
    [InlineData("https://example.invalid/source/")]
    [InlineData(@"\\server\share\")]
    [InlineData(@"/\server\share\")]
    [InlineData(@"repo:/\server\share\")]
    public async Task Programmatic_network_mapping_fails_closed_without_a_location(
        string target)
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("ROOT", target)]);

        var result = await IngestAsync("ROOT", configuration);

        Assert.False(result.IsValid);
        Assert.Null(Assert.Single(result.ComparisonInput.Findings).PrimaryLocation);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item =>
                item.Code == "CANON0032" &&
                item.Message.Contains("unsafe", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("../outside.cs")]
    [InlineData("%2e%2e/outside.cs")]
    [InlineData(".%2E\\outside.cs")]
    [InlineData("%2e%2e%2foutside.cs")]
    public async Task Configured_root_rejects_parent_traversing_artifact_reference(
        string artifactUri)
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "repo:/")]);

        var result = await IngestAsync(
            "ROOT",
            configuration,
            artifactUri: artifactUri);

        Assert.False(result.IsValid);
        Assert.Null(Assert.Single(result.ComparisonInput.Findings).PrimaryLocation);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item =>
                item.Code == "CANON0032" &&
                item.Message.Contains("parent-traversing", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("file:///elsewhere/")]
    [InlineData("../../outside/")]
    [InlineData("%2e%2e/outside/")]
    public async Task Sarif_child_cannot_replace_or_escape_a_configured_parent(
        string childUri)
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "repo:/approved/")]);
        var sarifBases = new Dictionary<string, UriBaseDefinition?>
        {
            ["CHILD"] = new(childUri, "ROOT"),
        };

        var result = await IngestAsync(
            "CHILD",
            configuration,
            sarifBases);

        Assert.False(result.IsValid);
        Assert.Null(Assert.Single(result.ComparisonInput.Findings).PrimaryLocation);
        Assert.Contains(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0032");
    }

    [Fact]
    public async Task Posix_and_Windows_local_roots_produce_the_same_canonical_path()
    {
        var posixConfiguration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "file:///workspace/")],
            repositoryRoot: "/workspace");
        var windowsConfiguration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "file:///C:/workspace/")],
            repositoryRoot: "C:/workspace");

        var posix = await IngestAsync("ROOT", posixConfiguration);
        var windows = await IngestAsync("ROOT", windowsConfiguration);

        Assert.True(posix.IsValid);
        Assert.True(windows.IsValid);
        Assert.Equal(
            Assert.Single(posix.ComparisonInput.Findings)
                .PrimaryLocation?.Path.CanonicalUri,
            Assert.Single(windows.ComparisonInput.Findings)
                .PrimaryLocation?.Path.CanonicalUri);
        Assert.Equal(
            "repo://src/example.cs",
            Assert.Single(posix.ComparisonInput.Findings)
                .PrimaryLocation?.Path.CanonicalUri);
    }

    [Fact]
    public async Task Mapping_order_does_not_change_resolution_or_provenance()
    {
        UriBaseMapping root = new("ROOT", "repo:/");
        UriBaseMapping child = new("CHILD", "source/", "ROOT");
        var firstConfiguration = CreateConfiguration([root, child]);
        var secondConfiguration = CreateConfiguration([child, root]);

        var first = await IngestAsync("CHILD", firstConfiguration);
        var second = await IngestAsync("CHILD", secondConfiguration);

        Assert.True(first.IsValid);
        Assert.True(second.IsValid);
        var firstSnapshot = Snapshot(first);
        var secondSnapshot = Snapshot(second);
        Assert.Equal(firstSnapshot.CanonicalUri, secondSnapshot.CanonicalUri);
        Assert.Equal(
            firstSnapshot.Transformations,
            secondSnapshot.Transformations);
        Assert.Equal(firstSnapshot.Diagnostics, secondSnapshot.Diagnostics);
    }

    [Fact]
    public async Task Configured_mapping_records_bounded_explanation_provenance()
    {
        var configuration = CreateConfiguration(
            [new UriBaseMapping("ROOT", "repo:/")]);

        var result = await IngestAsync("ROOT", configuration);

        var path = Assert.IsType<CanonicalPath>(
            Assert.Single(result.ComparisonInput.Findings).PrimaryLocation?.Path);
        var transformation = Assert.Single(
            path.Transformations,
            item => item.Kind == "configured-uri-base");
        Assert.Equal("ROOT", transformation.OriginalValue);
        Assert.Equal("repo:/", transformation.TransformedValue);
        Assert.False(transformation.IsLossy);
        Assert.Equal(
            SarifIngestor.ConfiguredUriBaseAlgorithmVersion,
            transformation.AlgorithmVersion);
        Assert.Single(
            result.ComparisonInput.Diagnostics,
            item => item.Code == "CANON0033");
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        string uriBaseId,
        SarifRegressConfiguration? configuration = null,
        IReadOnlyDictionary<string, UriBaseDefinition?>? sarifUriBases = null,
        string artifactUri = "src/example.cs")
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
                                name = "URI Base Test Analyzer",
                            },
                        },
                        originalUriBaseIds = sarifUriBases,
                        results = new[]
                        {
                            new
                            {
                                ruleId = "TEST001",
                                message = new
                                {
                                    text = "Controlled finding",
                                },
                                locations = new[]
                                {
                                    new
                                    {
                                        physicalLocation = new
                                        {
                                            artifactLocation = new
                                            {
                                                uri = artifactUri,
                                                uriBaseId,
                                            },
                                            region = new
                                            {
                                                startLine = 4,
                                                startColumn = 3,
                                                snippet = new
                                                {
                                                    text = "dangerous();",
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            SarifJsonOptions);
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(sarif),
            writable: false);
        return await new SarifIngestor().IngestAsync(
            stream,
            new SarifIngestionRequest(
                InputKind.Baseline,
                "baseline.sarif",
                configuration ?? SarifRegressConfiguration.Default),
            TestContext.Current.CancellationToken);
    }

    private static SarifRegressConfiguration CreateConfiguration(
        IEnumerable<UriBaseMapping> mappings,
        ResourceLimits? limits = null,
        string? repositoryRoot = null)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            repositoryRoot,
            defaults.PathRebases,
            defaults.PathAliases,
            defaults.RuleAliases,
            defaults.Matching,
            defaults.Policy,
            defaults.Reporting,
            limits ?? defaults.Limits,
            mappings);
    }

    private static UriBaseResolutionSnapshot Snapshot(
        SarifIngestionResult result)
    {
        var finding = Assert.Single(result.ComparisonInput.Findings);
        var path = Assert.IsType<CanonicalPath>(finding.PrimaryLocation?.Path);
        return new UriBaseResolutionSnapshot(
            path.CanonicalUri,
            path.Transformations
                .Select(item => new TransformationSnapshot(
                    item.Kind,
                    item.OriginalValue,
                    item.TransformedValue,
                    item.IsLossy,
                    item.AlgorithmVersion))
                .ToArray(),
            result.ComparisonInput.Diagnostics
                .Select(item => new DiagnosticSnapshot(
                    item.Code,
                    item.Severity,
                    item.Stage,
                    item.Message,
                    item.SourceReference?.JsonPointer))
                .ToArray());
    }

    private sealed record UriBaseDefinition(
        string? Uri,
        string? UriBaseId = null);

    private sealed record UriBaseResolutionSnapshot(
        string CanonicalUri,
        TransformationSnapshot[] Transformations,
        DiagnosticSnapshot[] Diagnostics);

    private sealed record TransformationSnapshot(
        string Kind,
        string? OriginalValue,
        string? TransformedValue,
        bool IsLossy,
        string AlgorithmVersion);

    private sealed record DiagnosticSnapshot(
        string Code,
        DiagnosticSeverity Severity,
        DiagnosticStage Stage,
        string Message,
        string? Pointer);
}
