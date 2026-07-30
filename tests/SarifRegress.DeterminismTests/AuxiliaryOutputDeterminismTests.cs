using System.Collections.Immutable;
using System.CommandLine;
using System.Globalization;
using System.Text;
using System.Text.Json;
using SarifRegress.Cli.Benchmarking;
using SarifRegress.Cli.CommandLine;

namespace SarifRegress.DeterminismTests;

public sealed class AuxiliaryOutputDeterminismTests
{
    private const string ValidSarif =
        """
        {
          "runs": [{
            "results": [{
              "locations": [{
                "physicalLocation": {
                  "region": { "startColumn": 2, "startLine": 7 },
                  "artifactLocation": { "uri": "src/deterministic.cs" }
                }
              }],
              "message": { "text": "Deterministic finding." },
              "partialFingerprints": {
                "primaryLocationLineHash/v1": "deterministic"
              },
              "ruleId": "DET001"
            }],
            "tool": { "driver": { "name": "Deterministic Analyzer" } }
          }],
          "version": "2.1.0"
        }
        """;

    [Fact]
    public async Task Validate_and_canonicalise_are_byte_stable_across_directories()
    {
        using var first = new TestWorkspace();
        using var second = new TestWorkspace();
        first.Write(ValidSarif);
        second.Write(ValidSarif);

        var firstValidation = await InvokeAsync(
            ValidateCommandFactory.Create(first.Root),
            TestContext.Current.CancellationToken,
            "validate",
            "--input",
            "input.sarif");
        var secondValidation = await InvokeAsync(
            ValidateCommandFactory.Create(second.Root),
            TestContext.Current.CancellationToken,
            "validate",
            "--input",
            "input.sarif");
        var firstCanonical = await InvokeAsync(
            CanonicaliseCommandFactory.Create(first.Root),
            TestContext.Current.CancellationToken,
            "canonicalise",
            "--input",
            "input.sarif");
        var secondCanonical = await InvokeAsync(
            CanonicaliseCommandFactory.Create(second.Root),
            TestContext.Current.CancellationToken,
            "canonicalise",
            "--input",
            "input.sarif");

        Assert.Equal(0, firstValidation.ExitCode);
        Assert.Equal(0, secondValidation.ExitCode);
        Assert.Equal(0, firstCanonical.ExitCode);
        Assert.Equal(0, secondCanonical.ExitCode);
        Assert.Equal(firstValidation.StandardOutput, secondValidation.StandardOutput);
        Assert.Equal(firstCanonical.StandardOutput, secondCanonical.StandardOutput);
        Assert.DoesNotContain(
            first.Root,
            firstValidation.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            second.Root,
            secondCanonical.StandardOutput,
            StringComparison.Ordinal);
        Assert.Equal(string.Empty, firstValidation.StandardError);
        Assert.Equal(string.Empty, secondValidation.StandardError);
        Assert.Equal(string.Empty, firstCanonical.StandardError);
        Assert.Equal(string.Empty, secondCanonical.StandardError);
    }

    [Fact]
    public void Benchmark_deterministic_fields_do_not_depend_on_observations()
    {
        var operations = new BenchmarkOperations(
            ParsedDocumentCount: 2,
            CanonicalFindingCount: 2_000,
            MaximumCandidateBucketSize: 1,
            CandidateBucketSizeDistribution:
                [new BenchmarkSizeDistributionEntry(1, 1_000)],
            CandidateEdgeCount: 1_000,
            ComponentCount: 1_000,
            MaximumComponentFindingCount: 2,
            ComponentSizeDistribution:
                [new BenchmarkSizeDistributionEntry(2, 1_000)],
            AmbiguousComponentCount: 0,
            Classifications: new BenchmarkClassificationCounts(
                New: 0,
                Unchanged: 1_000,
                Moved: 0,
                Modified: 0,
                Resolved: 0,
                Ambiguous: 0),
            DiagnosticCount: 0,
            ExplanationOutputBytes: 100,
            ComparisonOutputBytes: 123,
            ComparisonOutputSha256: new string('a', 64),
            DiagnosticCodes: ImmutableArray<string>.Empty);
        var first = new BenchmarkReport(
            BenchmarkDatasetKind.UniqueFingerprints,
            FindingCount: 1_000,
            BaselineBytes: 10,
            CandidateBytes: 10,
            MaximumCandidatePairsPerFinding: 256,
            MaximumCandidatePairs: 1_000_000,
            operations,
            new BenchmarkObservations(
                ParseLatencyMilliseconds: 1,
                ParseThroughputBytesPerSecond: 2,
                CanonicaliseLatencyMilliseconds: 3,
                CanonicaliseThroughputFindingsPerSecond: 4,
                CompareLatencyMilliseconds: 5,
                SerializeLatencyMilliseconds: 6,
                AllocatedBytesProxy: 7,
                WorkingSetBytes: 8,
                PeakWorkingSetBytes: 9),
            new BenchmarkBudgetEvaluation(
                MaximumPipelineLatencyMilliseconds: 10_000,
                MaximumPeakWorkingSetBytes: 512L * 1024 * 1024,
                Passed: true,
                FailureCodes: ImmutableArray<string>.Empty));
        var second = first with
        {
            Observations = new BenchmarkObservations(
                ParseLatencyMilliseconds: 11,
                ParseThroughputBytesPerSecond: 12,
                CanonicaliseLatencyMilliseconds: 13,
                CanonicaliseThroughputFindingsPerSecond: 14,
                CompareLatencyMilliseconds: 15,
                SerializeLatencyMilliseconds: 16,
                AllocatedBytesProxy: 17,
                WorkingSetBytes: 18,
                PeakWorkingSetBytes: 19),
            Budget = new BenchmarkBudgetEvaluation(
                MaximumPipelineLatencyMilliseconds: 10_000,
                MaximumPeakWorkingSetBytes: 512L * 1024 * 1024,
                Passed: false,
                FailureCodes: ["latency-budget-exceeded"]),
        };

        var firstJson = BenchmarkReportSerializer.Serialize(first);
        var secondJson = BenchmarkReportSerializer.Serialize(second);
        var firstProjection =
            BenchmarkReportSerializer.SerializeDeterministicProjection(first);
        var secondProjection =
            BenchmarkReportSerializer.SerializeDeterministicProjection(second);
        using var firstDocument = JsonDocument.Parse(firstJson);
        using var secondDocument = JsonDocument.Parse(secondJson);
        AssertStablePropertyEqual(firstDocument, secondDocument, "tool");
        AssertStablePropertyEqual(firstDocument, secondDocument, "dataset");
        AssertStablePropertyEqual(firstDocument, secondDocument, "limits");
        AssertStablePropertyEqual(firstDocument, secondDocument, "operations");
        AssertStablePropertyEqual(firstDocument, secondDocument, "determinism");
        Assert.NotEqual(
            firstDocument.RootElement
                .GetProperty("observations")
                .GetRawText(),
            secondDocument.RootElement
                .GetProperty("observations")
                .GetRawText());
        Assert.NotEqual(
            firstDocument.RootElement
                .GetProperty("budget")
                .GetRawText(),
            secondDocument.RootElement
                .GetProperty("budget")
                .GetRawText());
        Assert.Equal(firstProjection, secondProjection);
        using var projectionDocument = JsonDocument.Parse(firstProjection);
        Assert.False(
            projectionDocument.RootElement.TryGetProperty(
                "observations",
                out _));
        Assert.False(
            projectionDocument.RootElement
                .GetProperty("budgetLimits")
                .TryGetProperty("passed", out _));

        var text = Encoding.UTF8.GetString(firstJson);
        Assert.True(
            text.IndexOf("\"dataset\"", StringComparison.Ordinal) <
            text.IndexOf("\"limits\"", StringComparison.Ordinal));
        Assert.True(
            text.IndexOf("\"limits\"", StringComparison.Ordinal) <
            text.IndexOf("\"operations\"", StringComparison.Ordinal));
        Assert.EndsWith("\n", text, StringComparison.Ordinal);
        Assert.Equal((byte)'\n', firstProjection[^1]);
        Assert.DoesNotContain((byte)'\r', firstProjection);
        Assert.False(
            firstProjection.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }));
    }

    private static void AssertStablePropertyEqual(
        JsonDocument first,
        JsonDocument second,
        string propertyName)
    {
        Assert.Equal(
            first.RootElement.GetProperty(propertyName).GetRawText(),
            second.RootElement.GetProperty(propertyName).GetRawText());
    }

    private static async Task<InvocationResult> InvokeAsync(
        Command command,
        CancellationToken cancellationToken,
        params string[] arguments)
    {
        RootCommand root = new("Auxiliary determinism test root.");
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
                "sarif-regress-aux-determinism",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Write(string contents)
        {
            File.WriteAllText(Path.Combine(Root, "input.sarif"), contents);
        }

        public void Dispose()
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
