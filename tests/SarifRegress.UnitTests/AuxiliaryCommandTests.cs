using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using SarifRegress.Cli.Benchmarking;
using SarifRegress.Cli.CommandLine;
using SarifRegress.Core.Security;

namespace SarifRegress.UnitTests;

public sealed class AuxiliaryCommandTests
{
    private const string ValidSarif =
        """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "Example Analyzer", "version": "1.0" } },
            "results": [{
              "ruleId": "EXAMPLE001",
              "message": { "text": "  Stable   message  " },
              "partialFingerprints": {
                "primaryLocationLineHash/v1": "stable-fingerprint"
              },
              "locations": [{
                "physicalLocation": {
                  "artifactLocation": { "uri": "src/example file.cs" },
                  "region": { "startLine": 2, "startColumn": 1 }
                }
              }]
            }]
          }]
        }
        """;

    [Fact]
    public void Auxiliary_command_shapes_expose_bounded_options()
    {
        var validate = ValidateCommandFactory.Create();
        var canonicalise = CanonicaliseCommandFactory.Create();
        var bench = BenchCommandFactory.Create();

        Assert.Equal(
            ["--config", "--input", "--json-out", "--repo"],
            OptionNames(validate));
        Assert.Equal(
            ["--config", "--input", "--repo", "--sarif-out"],
            OptionNames(canonicalise));
        Assert.Equal(
            ["--dataset", "--enforce-budgets", "--json-out", "--size"],
            OptionNames(bench));
        Assert.True(
            Assert.Single(
                validate.Options,
                item => item.Name == "--input").Required);
        Assert.True(
            Assert.Single(
                canonicalise.Options,
                item => item.Name == "--input").Required);
    }

    [Fact]
    public async Task Validate_emits_a_stable_summary_for_valid_input()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("input.sarif", ValidSarif);

        var invocation = await InvokeAsync(
            ValidateCommandFactory.Create(workspace.Root),
            TestContext.Current.CancellationToken,
            "validate",
            "--input",
            "input.sarif");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardError);
        using var summary = JsonDocument.Parse(invocation.StandardOutput);
        Assert.Equal(
            "1",
            summary.RootElement
                .GetProperty("validationSchemaVersion")
                .GetString());
        Assert.True(summary.RootElement.GetProperty("valid").GetBoolean());
        Assert.True(
            summary.RootElement.GetProperty("policyPassed").GetBoolean());
        Assert.Equal(
            1,
            summary.RootElement
                .GetProperty("input")
                .GetProperty("findingCount")
                .GetInt32());
        Assert.DoesNotContain(
            workspace.Root,
            invocation.StandardOutput,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Validate_reports_malformed_input_and_returns_one()
    {
        using var workspace = new TestWorkspace();
        workspace.Write(
            "input.sarif",
            """{ "version": "2.1.0", "runs": [""");

        var invocation = await InvokeAsync(
            ValidateCommandFactory.Create(workspace.Root),
            TestContext.Current.CancellationToken,
            "validate",
            "--input",
            "input.sarif");

        Assert.Equal(1, invocation.ExitCode);
        Assert.Contains(
            "PARSE0100 error:",
            invocation.StandardError,
            StringComparison.Ordinal);
        using var summary = JsonDocument.Parse(invocation.StandardOutput);
        Assert.False(summary.RootElement.GetProperty("valid").GetBoolean());
        Assert.False(
            summary.RootElement.GetProperty("policyPassed").GetBoolean());
        Assert.Contains(
            summary.RootElement.GetProperty("diagnostics").EnumerateArray(),
            item => item.GetProperty("code").GetString() == "PARSE0100");
    }

    [Fact]
    public async Task Canonicalise_emits_project_owned_sarif_without_match_state()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("input.sarif", ValidSarif);

        var invocation = await InvokeAsync(
            CanonicaliseCommandFactory.Create(workspace.Root),
            TestContext.Current.CancellationToken,
            "canonicalise",
            "--input",
            "input.sarif");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardError);
        Assert.DoesNotContain(
            "baselineState",
            invocation.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "classification",
            invocation.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            workspace.Root,
            invocation.StandardOutput,
            StringComparison.Ordinal);
        using var sarif = JsonDocument.Parse(invocation.StandardOutput);
        var result = sarif.RootElement
            .GetProperty("runs")[0]
            .GetProperty("results")[0];
        Assert.Equal(
            "example-analyzer/EXAMPLE001",
            result.GetProperty("ruleId").GetString());
        Assert.Equal(
            "Stable message",
            result.GetProperty("message").GetProperty("text").GetString());
        Assert.Equal(
            "repo://src/example%20file.cs",
            result.GetProperty("locations")[0]
                .GetProperty("physicalLocation")
                .GetProperty("artifactLocation")
                .GetProperty("uri")
                .GetString());
    }

    [Fact]
    public async Task Canonicalise_refuses_to_overwrite_its_input()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("input.sarif", ValidSarif);

        var invocation = await InvokeAsync(
            CanonicaliseCommandFactory.Create(workspace.Root),
            TestContext.Current.CancellationToken,
            "canonicalise",
            "--input",
            "input.sarif",
            "--sarif-out",
            "input.sarif");

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Contains(
            "CLI0011 error:",
            invocation.StandardError,
            StringComparison.Ordinal);
        Assert.Equal(ValidSarif, workspace.Read("input.sarif"));
    }

    [Theory]
    [InlineData("--size", "999")]
    [InlineData("--dataset", "unknown")]
    public async Task Bench_rejects_unbounded_or_unknown_selections(
        string option,
        string value)
    {
        var invocation = await InvokeAsync(
            BenchCommandFactory.Create(),
            TestContext.Current.CancellationToken,
            "bench",
            option,
            value);

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Contains(
            "CLI0030 error:",
            invocation.StandardError,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Benchmark_generator_is_bounded_and_byte_deterministic()
    {
        var first = BenchmarkDatasetGenerator.Generate(
            1_000,
            BenchmarkDatasetKind.UniqueFingerprints);
        var second = BenchmarkDatasetGenerator.Generate(
            1_000,
            BenchmarkDatasetKind.UniqueFingerprints);

        Assert.Equal(1_000, first.FindingCount);
        Assert.Equal(first.BaselineSarif, first.CandidateSarif);
        Assert.Equal(first.BaselineSarif, second.BaselineSarif);
        using var document = JsonDocument.Parse(first.BaselineSarif);
        Assert.Equal(
            1_000,
            document.RootElement
                .GetProperty("runs")[0]
                .GetProperty("results")
                .GetArrayLength());
        Assert.Throws<ArgumentOutOfRangeException>(
            () => BenchmarkDatasetGenerator.Generate(
                999,
                BenchmarkDatasetKind.UniqueFingerprints));
    }

    [Fact]
    public async Task Bench_default_smoke_emits_expected_counts_and_hash()
    {
        var invocation = await InvokeAsync(
            BenchCommandFactory.Create(),
            TestContext.Current.CancellationToken,
            "bench");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardError);
        using var report = JsonDocument.Parse(invocation.StandardOutput);
        var operations = report.RootElement.GetProperty("operations");
        Assert.Equal(
            2_000,
            operations.GetProperty("canonicalFindingCount").GetInt32());
        Assert.Equal(
            1_000,
            operations.GetProperty("candidateEdgeCount").GetInt32());
        Assert.Equal(
            1_000,
            operations.GetProperty("componentCount").GetInt32());
        Assert.Equal(
            0,
            operations.GetProperty("ambiguousComponentCount").GetInt32());
        Assert.Equal(
            1_000,
            operations.GetProperty("classifications")
                .GetProperty("unchanged")
                .GetInt32());
        Assert.True(
            operations.GetProperty("explanationOutputBytes").GetInt32() > 0);
        Assert.Equal(
            1_000,
            operations.GetProperty("candidateBucketSizeDistribution")[0]
                .GetProperty("count")
                .GetInt32());
        Assert.Equal(
            1_000,
            operations.GetProperty("componentSizeDistribution")[0]
                .GetProperty("count")
                .GetInt32());
        Assert.Equal(
            64,
            operations.GetProperty("comparisonOutputSha256")
                .GetString()!
                .Length);
        Assert.True(
            operations.GetProperty("comparisonOutputBytes").GetInt32() > 0);
        Assert.True(
            report.RootElement
                .GetProperty("observations")
                .TryGetProperty("parseLatencyMilliseconds", out _));
        Assert.True(
            report.RootElement
                .GetProperty("budget")
                .TryGetProperty("passed", out _));
    }

    [Fact]
    public async Task Benchmark_pathological_bucket_honours_pair_bounds()
    {
        var report = await new BenchmarkRunner().RunAsync(
            1_000,
            BenchmarkDatasetKind.PathologicalBucket,
            TestContext.Current.CancellationToken);

        Assert.Equal(0, report.Operations.CandidateEdgeCount);
        Assert.Equal(1, report.Operations.ComponentCount);
        Assert.Equal(
            1_000,
            report.Operations.MaximumCandidateBucketSize);
        Assert.Equal(
            2_000,
            report.Operations.MaximumComponentFindingCount);
        Assert.Equal(1, report.Operations.AmbiguousComponentCount);
        Assert.Equal(
            2_000,
            report.Operations.Classifications.Ambiguous);
        Assert.Equal(
            [new BenchmarkSizeDistributionEntry(1_000, 1)],
            report.Operations.CandidateBucketSizeDistribution);
        Assert.Equal(
            [new BenchmarkSizeDistributionEntry(2_000, 1)],
            report.Operations.ComponentSizeDistribution);
        Assert.Contains("MATCH0007", report.Operations.DiagnosticCodes);
        Assert.Equal(
            ResourceLimits.DefaultMaximumCandidatePairEvaluationsPerFinding,
            report.MaximumCandidatePairsPerFinding);
    }

    private static string[] OptionNames(Command command) =>
        command.Options
            .Select(item => item.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

    private static async Task<InvocationResult> InvokeAsync(
        Command command,
        CancellationToken cancellationToken,
        params string[] arguments)
    {
        RootCommand root = new("Auxiliary command test root.");
        root.Subcommands.Add(command);
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        InvocationConfiguration configuration = new()
        {
            Output = output,
            Error = error,
        };
        var exitCode = await root
            .Parse(arguments)
            .InvokeAsync(configuration, cancellationToken);
        return new InvocationResult(
            exitCode,
            output.ToString(),
            error.ToString());
    }

    private sealed record InvocationResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private sealed class TestWorkspace : IDisposable
    {
        public TestWorkspace()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "sarif-regress-auxiliary-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Write(string relativePath, string contents)
        {
            var path = Path.Combine(Root, relativePath);
            Directory.CreateDirectory(
                Path.GetDirectoryName(path)
                    ?? throw new InvalidOperationException(
                        "The test path has no containing directory."));
            File.WriteAllText(path, contents);
        }

        public string Read(string relativePath) =>
            File.ReadAllText(Path.Combine(Root, relativePath));

        public void Dispose()
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
