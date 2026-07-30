using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core;

namespace SarifRegress.Cli.Benchmarking;

/// <summary>
/// Serializes benchmark results with a stable schema and property order.
/// </summary>
public static class BenchmarkReportSerializer
{
    private const byte LineFeed = (byte)'\n';
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = true,
        IndentCharacter = ' ',
        IndentSize = 2,
        MaxDepth = 32,
        NewLine = "\n",
        SkipValidation = false,
    };

    /// <summary>
    /// Serializes deterministic fields and explicit benchmark observations.
    /// </summary>
    /// <param name="report">The completed benchmark report.</param>
    /// <returns>UTF-8 JSON without a BOM and with a final LF.</returns>
    public static byte[] Serialize(BenchmarkReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("benchmarkSchemaVersion", "1");
            writer.WriteStartObject("tool");
            writer.WriteString("name", ProductInformation.Name);
            writer.WriteString("version", ProductInformation.Version);
            writer.WriteEndObject();
            WriteDataset(writer, report);
            WriteLimits(writer, report);
            WriteOperations(writer, report.Operations);
            WriteObservations(writer, report.Observations);
            WriteBudget(writer, report.Budget);
            writer.WriteStartObject("determinism");
            writer.WriteString(
                "datasetGenerator",
                "sarifregress/benchmark-dataset/v1");
            writer.WriteString(
                "comparisonOutputHash",
                "sha256");
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.Flush();
        }

        stream.WriteByte(LineFeed);
        return stream.ToArray();
    }

    private static void WriteDataset(
        Utf8JsonWriter writer,
        BenchmarkReport report)
    {
        writer.WriteStartObject("dataset");
        writer.WriteString("kind", DatasetKindName(report.DatasetKind));
        writer.WriteNumber("findingCountPerSide", report.FindingCount);
        writer.WriteNumber("baselineBytes", report.BaselineBytes);
        writer.WriteNumber("candidateBytes", report.CandidateBytes);
        writer.WriteEndObject();
    }

    private static void WriteLimits(
        Utf8JsonWriter writer,
        BenchmarkReport report)
    {
        writer.WriteStartObject("limits");
        writer.WriteNumber(
            "maximumCandidatePairsPerFinding",
            report.MaximumCandidatePairsPerFinding);
        writer.WriteNumber(
            "maximumCandidatePairs",
            report.MaximumCandidatePairs);
        writer.WriteEndObject();
    }

    private static void WriteOperations(
        Utf8JsonWriter writer,
        BenchmarkOperations operations)
    {
        writer.WriteStartObject("operations");
        writer.WriteNumber(
            "parsedDocumentCount",
            operations.ParsedDocumentCount);
        writer.WriteNumber(
            "canonicalFindingCount",
            operations.CanonicalFindingCount);
        writer.WriteNumber(
            "maximumCandidateBucketSize",
            operations.MaximumCandidateBucketSize);
        WriteDistribution(
            writer,
            "candidateBucketSizeDistribution",
            operations.CandidateBucketSizeDistribution);
        writer.WriteNumber(
            "candidateEdgeCount",
            operations.CandidateEdgeCount);
        writer.WriteNumber("componentCount", operations.ComponentCount);
        writer.WriteNumber(
            "maximumComponentFindingCount",
            operations.MaximumComponentFindingCount);
        WriteDistribution(
            writer,
            "componentSizeDistribution",
            operations.ComponentSizeDistribution);
        writer.WriteNumber(
            "ambiguousComponentCount",
            operations.AmbiguousComponentCount);
        WriteClassifications(writer, operations.Classifications);
        writer.WriteNumber("diagnosticCount", operations.DiagnosticCount);
        writer.WriteNumber(
            "explanationOutputBytes",
            operations.ExplanationOutputBytes);
        writer.WriteNumber(
            "comparisonOutputBytes",
            operations.ComparisonOutputBytes);
        writer.WriteString(
            "comparisonOutputSha256",
            operations.ComparisonOutputSha256);
        writer.WriteStartArray("diagnosticCodes");
        foreach (var code in operations.DiagnosticCodes
                     .Distinct(StringComparer.Ordinal)
                     .Order(StringComparer.Ordinal))
        {
            writer.WriteStringValue(code);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteDistribution(
        Utf8JsonWriter writer,
        string propertyName,
        IEnumerable<BenchmarkSizeDistributionEntry> distribution)
    {
        writer.WriteStartArray(propertyName);
        foreach (var entry in distribution
                     .OrderBy(item => item.Size)
                     .ThenBy(item => item.Count))
        {
            writer.WriteStartObject();
            writer.WriteNumber("size", entry.Size);
            writer.WriteNumber("count", entry.Count);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteClassifications(
        Utf8JsonWriter writer,
        BenchmarkClassificationCounts counts)
    {
        writer.WriteStartObject("classifications");
        writer.WriteNumber("new", counts.New);
        writer.WriteNumber("unchanged", counts.Unchanged);
        writer.WriteNumber("moved", counts.Moved);
        writer.WriteNumber("modified", counts.Modified);
        writer.WriteNumber("resolved", counts.Resolved);
        writer.WriteNumber("ambiguous", counts.Ambiguous);
        writer.WriteEndObject();
    }

    private static void WriteObservations(
        Utf8JsonWriter writer,
        BenchmarkObservations observations)
    {
        writer.WriteStartObject("observations");
        writer.WriteNumber(
            "parseLatencyMilliseconds",
            observations.ParseLatencyMilliseconds);
        writer.WriteNumber(
            "parseThroughputBytesPerSecond",
            observations.ParseThroughputBytesPerSecond);
        writer.WriteNumber(
            "canonicaliseLatencyMilliseconds",
            observations.CanonicaliseLatencyMilliseconds);
        writer.WriteNumber(
            "canonicaliseThroughputFindingsPerSecond",
            observations.CanonicaliseThroughputFindingsPerSecond);
        writer.WriteNumber(
            "compareLatencyMilliseconds",
            observations.CompareLatencyMilliseconds);
        writer.WriteNumber(
            "serializeLatencyMilliseconds",
            observations.SerializeLatencyMilliseconds);
        writer.WriteNumber(
            "allocatedBytesProxy",
            observations.AllocatedBytesProxy);
        writer.WriteNumber("workingSetBytes", observations.WorkingSetBytes);
        writer.WriteNumber(
            "peakWorkingSetBytes",
            observations.PeakWorkingSetBytes);
        writer.WriteEndObject();
    }

    private static void WriteBudget(
        Utf8JsonWriter writer,
        BenchmarkBudgetEvaluation budget)
    {
        writer.WriteStartObject("budget");
        writer.WriteNumber(
            "maximumPipelineLatencyMilliseconds",
            budget.MaximumPipelineLatencyMilliseconds);
        writer.WriteNumber(
            "maximumPeakWorkingSetBytes",
            budget.MaximumPeakWorkingSetBytes);
        writer.WriteBoolean("passed", budget.Passed);
        writer.WriteStartArray("failureCodes");
        foreach (var failure in budget.FailureCodes
                     .Distinct(StringComparer.Ordinal)
                     .Order(StringComparer.Ordinal))
        {
            writer.WriteStringValue(failure);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static string DatasetKindName(BenchmarkDatasetKind kind) =>
        kind switch
        {
            BenchmarkDatasetKind.UniqueFingerprints => "unique-fingerprints",
            BenchmarkDatasetKind.PathologicalBucket => "pathological-bucket",
            _ => throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                "Unknown benchmark dataset kind."),
        };
}
