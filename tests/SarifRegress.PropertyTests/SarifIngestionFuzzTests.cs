using System.Text;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.PropertyTests;

public sealed class SarifIngestionFuzzTests
{
    private static readonly UTF8Encoding Utf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    [Fact]
    public async Task Bounded_ingestion_never_throws_and_diagnostics_are_stable()
    {
        var cases = CreateCases();
        var configuration = PropertyTestData.BoundedConfiguration();
        var request = new SarifIngestionRequest(
            InputKind.Baseline,
            "fuzz-input",
            configuration);
        var ingestor = new SarifIngestor();

        foreach (var testCase in cases)
        {
            var first = await CaptureAsync(ingestor, request, testCase.Bytes);
            var second = await CaptureAsync(ingestor, request, testCase.Bytes);

            Assert.True(
                first.ExceptionType is null,
                $"case={testCase.Id}; pass=first; exception={first.ExceptionType}");
            Assert.True(
                second.ExceptionType is null,
                $"case={testCase.Id}; pass=second; exception={second.ExceptionType}");
            if (first.Result is null || second.Result is null)
            {
                continue;
            }

            var firstDiagnostics = ProjectDiagnostics(first.Result);
            var secondDiagnostics = ProjectDiagnostics(second.Result);
            Assert.True(
                firstDiagnostics.Count > 0,
                $"case={testCase.Id}; field=diagnostics");
            Assert.True(
                firstDiagnostics.SequenceEqual(
                    secondDiagnostics,
                    StringComparer.Ordinal),
                $"case={testCase.Id}; field=diagnostic-stability");
            if (testCase.ExpectedDiagnosticCode is not null)
            {
                Assert.Contains(
                    first.Result.ComparisonInput.Diagnostics,
                    diagnostic =>
                        diagnostic.Code == testCase.ExpectedDiagnosticCode);
            }

            Assert.True(
                first.Result.ComparisonInput.Findings.Length ==
                second.Result.ComparisonInput.Findings.Length,
                $"case={testCase.Id}; field=finding-count");
            Assert.True(
                first.Result.Summary.InputBytes == second.Result.Summary.InputBytes,
                $"case={testCase.Id}; field=input-bytes");
        }
    }

    private static IReadOnlyList<FuzzCase> CreateCases()
    {
        const string validSarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Property scanner" } },
                "results": [{
                  "ruleId": "RULE-001",
                  "message": { "text": "Property message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "uri": "src/file.cs" },
                      "region": { "startLine": 7, "startColumn": 1 }
                    }
                  }]
                }]
              }]
            }
            """;
        var validBytes = Utf8.GetBytes(validSarif);
        var cases = new List<FuzzCase>
        {
            new("empty", []),
            new("whitespace", Utf8.GetBytes(" \t\r\n")),
            new("null-root", Utf8.GetBytes("null")),
            new("array-root", Utf8.GetBytes("[]")),
            new("number-root", Utf8.GetBytes("42")),
            new("string-root", Utf8.GetBytes("\"sarif\"")),
            new("invalid-byte", [0xFF]),
            new("truncated-utf8", [0x7B, 0x22, 0xE2, 0x82]),
            new("object-empty", Utf8.GetBytes("{}")),
            new(
                "missing-version",
                Utf8.GetBytes("""{"runs":[]}""")),
            new(
                "unsupported-version",
                Utf8.GetBytes("""{"version":"2.0.0","runs":[]}""")),
            new(
                "runs-object",
                Utf8.GetBytes("""{"version":"2.1.0","runs":{}}""")),
            new(
                "run-number",
                Utf8.GetBytes("""{"version":"2.1.0","runs":[1]}""")),
            new(
                "run-null",
                Utf8.GetBytes("""{"version":"2.1.0","runs":[null]}""")),
            new(
                "tool-string",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[{"tool":"bad","results":[]}]}""")),
            new(
                "driver-array",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[{"tool":{"driver":[]},"results":[]}]}""")),
            new(
                "results-object",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":{}}]}""")),
            new(
                "result-number",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[1]}]}""")),
            new(
                "message-string",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[{"ruleId":"R","message":"bad"}]}]}""")),
            new(
                "locations-object",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[{"ruleId":"R","message":{"text":"m"},"locations":{}}]}]}""")),
            new(
                "too-many-runs",
                Utf8.GetBytes(
                    """{"version":"2.1.0","runs":[null,null,null]}""")),
            new(
                "too-many-results",
                Utf8.GetBytes(CreateRunWithResults(resultCount: 9))),
            new(
                "too-many-locations",
                Utf8.GetBytes(CreateResultWithLocations(locationCount: 5))),
            new(
                "aggregate-thread-flows",
                Utf8.GetBytes(
                    CreateResultWithThreadFlows(
                        codeFlowCount: 2,
                        threadFlowsPerCodeFlow: 5)),
                ExpectedDiagnosticCode: "SECURITY0102"),
            new(
                "overlong-string",
                Utf8.GetBytes(
                    $$"""{"version":"{{new string('v', 129)}}","runs":[]}""")),
            new(
                "excessive-depth",
                Utf8.GetBytes(CreateDeepDocument(depth: 24))),
            new(
                "input-limit",
                Enumerable.Repeat((byte)' ', 4_097).ToArray()),
        };

        var truncationOffsets = Enumerable.Range(0, validBytes.Length)
            .Where(index => index % 17 == 0)
            .Append(validBytes.Length - 1)
            .Distinct()
            .Order()
            .ToArray();
        for (var index = 0; index < truncationOffsets.Length; index++)
        {
            var length = truncationOffsets[index];
            cases.Add(
                new FuzzCase(
                    $"truncate-{index:D2}",
                    validBytes[..length]));
        }

        return cases;
    }

    private static string CreateRunWithResults(int resultCount)
    {
        var results = string.Join(
            ",",
            Enumerable.Range(0, resultCount)
                .Select(_ => "null"));
        return string.Concat(
            """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[""",
            results,
            "]}]}");
    }

    private static string CreateResultWithLocations(int locationCount)
    {
        var locations = string.Join(
            ",",
            Enumerable.Range(0, locationCount)
                .Select(_ => "null"));
        return string.Concat(
            """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[{"ruleId":"R","message":{"text":"m"},"locations":[""",
            locations,
            "]}]}]}");
    }

    private static string CreateResultWithThreadFlows(
        int codeFlowCount,
        int threadFlowsPerCodeFlow)
    {
        var threadFlows = string.Join(
            ",",
            Enumerable.Repeat("{}", threadFlowsPerCodeFlow));
        var codeFlows = string.Join(
            ",",
            Enumerable.Repeat(
                $$"""{"threadFlows":[{{threadFlows}}]}""",
                codeFlowCount));
        return string.Concat(
            """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[{"ruleId":"R","message":{"text":"m"},"codeFlows":[""",
            codeFlows,
            "]}]}]}");
    }

    private static string CreateDeepDocument(int depth) =>
        """{"version":"2.1.0","runs":[],"extension":"""
        + new string('[', depth)
        + "0"
        + new string(']', depth)
        + "}";

    private static async Task<IngestionCapture> CaptureAsync(
        SarifIngestor ingestor,
        SarifIngestionRequest request,
        byte[] input)
    {
        try
        {
            await using var stream = new MemoryStream(input, writable: false);
            var result = await ingestor.IngestAsync(
                stream,
                request,
                TestContext.Current.CancellationToken);
            return new IngestionCapture(result, ExceptionType: null);
        }
        catch (Exception exception)
        {
            return new IngestionCapture(
                Result: null,
                exception.GetType().FullName ?? exception.GetType().Name);
        }
    }

    private static IReadOnlyList<string> ProjectDiagnostics(
        SarifIngestionResult result) =>
        result.ComparisonInput.Diagnostics
            .Select(PropertyTestData.DiagnosticSignature)
            .ToArray();

    private sealed record FuzzCase(
        string Id,
        byte[] Bytes,
        string? ExpectedDiagnosticCode = null);

    private sealed record IngestionCapture(
        SarifIngestionResult? Result,
        string? ExceptionType);
}
