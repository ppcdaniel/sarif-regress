using System.Text;
using System.Text.Json;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Configuration;

namespace SarifRegress.UnitTests;

public sealed class ConfigurationReaderTests
{
    [Fact]
    public async Task Valid_configuration_maps_all_mvp_sections()
    {
        const string json =
            """
            {
              "schemaVersion": "1",
              "repoRoot": ".",
              "uriBaseMappings": [
                { "id": "CHILD", "uri": "src/", "uriBaseId": "ROOT" },
                { "id": "ROOT", "uri": "repo:/" }
              ],
              "pathRebases": [
                { "from": "file:///agent/", "to": "repo:/" }
              ],
              "pathAliases": [
                { "baseline": "src-old/", "candidate": "src/" }
              ],
              "ruleAliases": [
                {
                  "baselineProducer": "CodeQL",
                  "baselineRule": "old/rule",
                  "candidateProducer": "Scanner",
                  "candidateRule": "new/rule"
                }
              ],
              "matching": {
                "enableRepoContext": false,
                "snippetLinesRadius": 2,
                "enableTokenWindows": true,
                "allowWeakMessageSimilarity": true,
                "pathCaseSensitivity": "ascii-insensitive"
              },
              "policy": {
                "failOn": ["new", "ambiguous"],
                "treatGithubIncompatibilityAsError": true
              },
              "reporting": {
                "emitCanonicalSarif": true,
                "emitHtml": true
              }
            }
            """;

        var result = await ReadAsync(json);

        Assert.True(result.IsValid);
        Assert.Empty(result.Diagnostics);
        var configuration = Assert.IsType<
            SarifRegress.Core.Configuration.SarifRegressConfiguration>(
                result.Configuration);
        Assert.Equal(".", configuration.RepositoryRoot);
        Assert.Equal(["CHILD", "ROOT"], configuration.UriBaseMappings.Select(
            item => item.Id));
        Assert.Equal("ROOT", configuration.UriBaseMappings[0].UriBaseId);
        Assert.Single(configuration.PathRebases);
        Assert.Single(configuration.PathAliases);
        Assert.Single(configuration.RuleAliases);
        Assert.False(configuration.Matching.EnableRepositoryContext);
        Assert.True(configuration.Matching.EnableTokenWindows);
        Assert.Equal(2, configuration.Matching.SnippetLinesRadius);
        Assert.Equal(
            PathCaseSensitivity.AsciiInsensitive,
            configuration.Matching.PathCaseSensitivity);
        Assert.Equal(
            [FindingClassification.New, FindingClassification.Ambiguous],
            configuration.Policy.FailOn);
        Assert.True(configuration.Policy.TreatGithubIncompatibilityAsError);
        Assert.True(configuration.Reporting.EmitCanonicalSarif);
        Assert.True(configuration.Reporting.EmitHtml);
    }

    [Fact]
    public async Task Unsupported_schema_version_is_rejected_at_a_stable_pointer()
    {
        var result = await ReadAsync("""{ "schemaVersion": "2" }""");

        Assert.False(result.IsValid);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal("SCHEMA0002", diagnostic.Code);
        Assert.Equal("/schemaVersion", diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public async Task Conflicting_rebases_are_rejected_deterministically()
    {
        const string json =
            """
            {
              "schemaVersion": "1",
              "pathRebases": [
                { "from": "file:///agent/", "to": "repo:/" },
                { "from": "file:///agent/", "to": "external:/" }
              ]
            }
            """;

        var first = await ReadAsync(json);
        var second = await ReadAsync(json);

        Assert.False(first.IsValid);
        Assert.Equal(
            first.Diagnostics.Select(item => (item.Code, item.Message, item.SourceReference?.JsonPointer)),
            second.Diagnostics.Select(item => (item.Code, item.Message, item.SourceReference?.JsonPointer)));
        Assert.Contains(first.Diagnostics, item => item.Code == "SCHEMA0003");
    }

    [Fact]
    public async Task Unknown_property_is_advisory_and_source_addressable()
    {
        var result = await ReadAsync(
            """{ "schemaVersion": "1", "future/property": true }""");

        Assert.True(result.IsValid);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal("UNSUPPORTED0001", diagnostic.Code);
        Assert.Equal(
            "/future~1property",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public async Task Bootstrap_input_limit_is_enforced_before_configuration_limits()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumInputBytes = 16,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """{ "schemaVersion": "1", "repoRoot": "." }""");

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item =>
                item.Code == "SECURITY0010" &&
                item.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public async Task Configuration_can_only_tighten_every_runtime_limit()
    {
        const string json =
            """
            {
              "schemaVersion": "1",
              "limits": {
                "maximumInputBytes": 1024,
                "maximumJsonDepth": 16,
                "maximumRuns": 2,
                "maximumRunCollectionItems": 10,
                "maximumLocationsPerResult": 4,
                "maximumCodeFlowsPerResult": 2,
                "maximumThreadFlowLocationsPerResult": 5,
                "maximumStringCharacters": 100,
                "maximumUriBaseDepth": 4,
                "maximumRepositoryFileBytes": 100,
                "maximumSnippetRadius": 4,
                "maximumTokenWindowTerms": 10,
                "maximumCandidateEdgesPerFinding": 2,
                "maximumCandidatePairEvaluationsPerFinding": 4,
                "maximumCandidatePairEvaluations": 20,
                "maximumRejectedAlternatives": 3,
                "maximumAssignmentSideSize": 2
              }
            }
            """;

        var result = await ReadAsync(json);

        Assert.True(result.IsValid);
        var limits = Assert.IsType<
            SarifRegress.Core.Configuration.SarifRegressConfiguration>(
                result.Configuration).Limits;
        Assert.Equal(1024L, limits.MaximumInputBytes);
        Assert.Equal(16, limits.MaximumJsonDepth);
        Assert.Equal(2, limits.MaximumRuns);
        Assert.Equal(10, limits.MaximumRunCollectionItems);
        Assert.Equal(4, limits.MaximumLocationsPerResult);
        Assert.Equal(2, limits.MaximumCodeFlowsPerResult);
        Assert.Equal(5, limits.MaximumThreadFlowLocationsPerResult);
        Assert.Equal(100, limits.MaximumStringCharacters);
        Assert.Equal(4, limits.MaximumUriBaseDepth);
        Assert.Equal(100L, limits.MaximumRepositoryFileBytes);
        Assert.Equal(4, limits.MaximumSnippetRadius);
        Assert.Equal(10, limits.MaximumTokenWindowTerms);
        Assert.Equal(2, limits.MaximumCandidateEdgesPerFinding);
        Assert.Equal(4, limits.MaximumCandidatePairEvaluationsPerFinding);
        Assert.Equal(20L, limits.MaximumCandidatePairEvaluations);
        Assert.Equal(3, limits.MaximumRejectedAlternatives);
        Assert.Equal(2, limits.MaximumAssignmentSideSize);
    }

    [Fact]
    public async Task Untrusted_configuration_cannot_raise_a_bootstrap_ceiling()
    {
        var attemptedLimit = ResourceLimits.Default.MaximumInputBytes + 1;
        var result = await ReadAsync(
            $$"""
              {
                "schemaVersion": "1",
                "limits": { "maximumInputBytes": {{attemptedLimit}} }
              }
              """);

        Assert.False(result.IsValid);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == "SECURITY0013");
        Assert.Equal(
            "/limits/maximumInputBytes",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public async Task Unknown_nested_properties_are_discarded_and_diagnosed()
    {
        const string json =
            """
            {
              "schemaVersion": "1",
              "matching": {
                "enableRepoContext": true,
                "future": { "large": [1, 2, 3, 4] }
              }
            }
            """;

        var result = await ReadAsync(json);

        Assert.True(result.IsValid);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == "UNSUPPORTED0001");
        Assert.Equal(
            "/matching/future",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public async Task String_limit_is_enforced_during_configuration_read()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumStringCharacters = 4,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """{ "schemaVersion": "12345" }""");

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item => item.Code == "SECURITY0011");
    }

    [Fact]
    public async Task Collection_limit_is_enforced_during_configuration_read()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 1,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """
            {
              "schemaVersion": "1",
              "pathRebases": [
                { "from": "a/", "to": "repo:/" },
                { "from": "b/", "to": "repo:/" }
              ]
            }
            """);

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item => item.Code == "SECURITY0012");
    }

    [Fact]
    public async Task Unknown_configuration_subtrees_cannot_bypass_collection_limit()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 3,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """
            {
              "schemaVersion": "1",
              "matching": {
                "enableRepoContext": false,
                "future": [1, 2, 3, 4]
              }
            }
            """);

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item => item.Code == "SECURITY0012");
    }

    [Fact]
    public async Task Unknown_configuration_subtrees_cannot_bypass_string_limit()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumStringCharacters = 16,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """
            {
              "schemaVersion": "1",
              "future": { "value": "12345678901234567" }
            }
            """);

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item => item.Code == "SECURITY0011");
    }

    [Fact]
    public async Task Configuration_extension_dictionary_is_bounded_before_materialisation()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 3,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """
            {
              "schemaVersion": "1",
              "futureA": true,
              "futureB": true,
              "futureC": true
            }
            """);

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item => item.Code == "SECURITY0012");
    }

    [Fact]
    public async Task Unknown_configuration_subtrees_cannot_bypass_depth_limit()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumJsonDepth = 3,
        };
        var reader = new SarifConfigurationReader(limits);
        await using var input = CreateStream(
            """
            {
              "schemaVersion": "1",
              "matching": {
                "future": { "one": { "two": true } }
              }
            }
            """);

        var result = await reader.ReadAsync(
            input,
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Diagnostics,
            item => item.Code == "PARSE0001");
    }

    [Fact]
    public async Task Input_io_failure_returns_a_deterministic_diagnostic()
    {
        await using var input = new ThrowingReadStream();
        await using var secondInput = new ThrowingReadStream();

        var first = await new SarifConfigurationReader().ReadAsync(
            input,
            TestContext.Current.CancellationToken);
        var second = await new SarifConfigurationReader()
            .ReadAsync(
                secondInput,
                TestContext.Current.CancellationToken);

        Assert.False(first.IsValid);
        var diagnostic = Assert.Single(first.Diagnostics);
        Assert.Equal("IO0010", diagnostic.Code);
        Assert.Equal(DiagnosticStage.Io, diagnostic.Stage);
        Assert.Equal(first.Diagnostics, second.Diagnostics);
    }

    [Fact]
    public async Task Cancellation_is_not_converted_to_an_io_diagnostic()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await using var input = CreateStream("""{ "schemaVersion": "1" }""");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new SarifConfigurationReader()
                .ReadAsync(input, cancellation.Token)
                .AsTask());
    }

    [Fact]
    public async Task Uri_base_mappings_are_parsed_and_sorted_deterministically()
    {
        const string firstJson =
            """
            {
              "schemaVersion": "1",
              "uriBaseMappings": [
                { "id": "ROOT", "uri": "repo:/" },
                { "id": "CHILD", "uri": "source/", "uriBaseId": "ROOT" }
              ]
            }
            """;
        const string secondJson =
            """
            {
              "schemaVersion": "1",
              "uriBaseMappings": [
                { "id": "CHILD", "uri": "source/", "uriBaseId": "ROOT" },
                { "id": "ROOT", "uri": "repo:/" }
              ]
            }
            """;

        var first = await ReadAsync(firstJson);
        var second = await ReadAsync(secondJson);

        Assert.True(first.IsValid);
        Assert.True(second.IsValid);
        var firstConfiguration = Assert.IsType<SarifRegressConfiguration>(
            first.Configuration);
        var secondConfiguration = Assert.IsType<SarifRegressConfiguration>(
            second.Configuration);
        Assert.Equal(
            [
                new UriBaseMapping("CHILD", "source/", "ROOT"),
                new UriBaseMapping("ROOT", "repo:/"),
            ],
            firstConfiguration.UriBaseMappings);
        Assert.Equal(
            firstConfiguration.UriBaseMappings.ToArray(),
            secondConfiguration.UriBaseMappings.ToArray());
        Assert.Equal(
            first.Diagnostics.ToArray(),
            second.Diagnostics.ToArray());
    }

    [Fact]
    public async Task Conflicting_uri_base_mapping_ids_are_rejected()
    {
        const string json =
            """
            {
              "schemaVersion": "1",
              "uriBaseMappings": [
                { "id": "ROOT", "uri": "repo:/one/" },
                { "id": "ROOT", "uri": "repo:/two/" }
              ]
            }
            """;

        var result = await ReadAsync(json);

        Assert.False(result.IsValid);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == "SCHEMA0011");
        Assert.Equal(
            "/uriBaseMappings/1",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Theory]
    [InlineData("https://example.invalid/source/")]
    [InlineData("file://server/share/")]
    [InlineData(@"\\server\share\")]
    [InlineData(@"/\server\share\")]
    [InlineData(@"repo:/\server\share\")]
    [InlineData("relative/")]
    [InlineData("repo:/../outside/")]
    [InlineData("repo:/%2e%2e/outside/")]
    [InlineData("repo:/.%2E/outside/")]
    [InlineData("repo:/source/?query=true")]
    [InlineData("repo:/directory-without-trailing-slash")]
    public async Task Unsafe_uri_base_mapping_targets_are_rejected(
        string target)
    {
        var json = JsonSerializer.Serialize(
            new
            {
                schemaVersion = "1",
                uriBaseMappings = new[]
                {
                    new
                    {
                        id = "ROOT",
                        uri = target,
                    },
                },
            });

        var result = await ReadAsync(json);

        Assert.False(result.IsValid);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == "SCHEMA0012");
        Assert.Equal(
            "/uriBaseMappings/0/uri",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public async Task Relative_uri_base_mapping_requires_directory_form()
    {
        var result = await ReadAsync(
            """
            {
              "schemaVersion": "1",
              "uriBaseMappings": [
                { "id": "ROOT", "uri": "repo:/" },
                { "id": "CHILD", "uri": "directory", "uriBaseId": "ROOT" }
              ]
            }
            """);

        Assert.False(result.IsValid);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == "SCHEMA0012");
        Assert.Equal(
            "/uriBaseMappings/1/uri",
            diagnostic.SourceReference?.JsonPointer);
    }

    [Fact]
    public void Published_schema_defines_the_bounded_uri_base_mapping_shape()
    {
        var schemaPath = Path.Combine(
            RepositoryLayout.Root,
            "schemas",
            "config.schema.json");
        using var schema = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        var root = schema.RootElement;
        var mappings = root
            .GetProperty("properties")
            .GetProperty("uriBaseMappings");
        var definition = root
            .GetProperty("$defs")
            .GetProperty("uriBaseMapping");

        Assert.Equal(
            ResourceLimits.Default.MaximumRunCollectionItems,
            mappings.GetProperty("maxItems").GetInt32());
        Assert.Equal(
            "#/$defs/uriBaseMapping",
            mappings.GetProperty("items").GetProperty("$ref").GetString());
        Assert.False(definition.GetProperty("additionalProperties").GetBoolean());
        Assert.Equal(
            ["id", "uri"],
            definition
                .GetProperty("required")
                .EnumerateArray()
                .Select(item => item.GetString())
                .ToArray());
        Assert.Equal(
            ["id", "uri", "uriBaseId"],
            definition
                .GetProperty("properties")
                .EnumerateObject()
                .Select(item => item.Name)
                .ToArray());
    }

    [Fact]
    public void Published_schema_exposes_every_runtime_limit_at_its_trusted_ceiling()
    {
        var schemaPath = Path.Combine(
            RepositoryLayout.Root,
            "schemas",
            "config.schema.json");
        using var schema = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        var schemaLimits = schema.RootElement
            .GetProperty("$defs")
            .GetProperty("limits")
            .GetProperty("properties");
        var runtimeLimits = typeof(ResourceLimits)
            .GetProperties()
            .Where(property => property.Name.StartsWith(
                "Maximum",
                StringComparison.Ordinal))
            .OrderBy(property => property.Name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(runtimeLimits.Length, schemaLimits.EnumerateObject().Count());
        foreach (var property in runtimeLimits)
        {
            var jsonName = char.ToLowerInvariant(property.Name[0]) +
                property.Name[1..];
            var schemaMaximum = schemaLimits
                .GetProperty(jsonName)
                .GetProperty("maximum")
                .GetInt64();
            var runtimeMaximum = Convert.ToInt64(
                property.GetValue(ResourceLimits.Default),
                System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(runtimeMaximum, schemaMaximum);
        }
    }

    private static async Task<ConfigurationReadResult> ReadAsync(string json)
    {
        await using var input = CreateStream(json);
        return await new SarifConfigurationReader().ReadAsync(
            input,
            TestContext.Current.CancellationToken);
    }

    private static MemoryStream CreateStream(string value) =>
        new(Encoding.UTF8.GetBytes(value), writable: false);

    private sealed class ThrowingReadStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new IOException("Test read failure.");

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(
                new IOException("Test read failure."));

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
