using System.Collections.Immutable;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace SarifRegress.Cli.Benchmarking;

/// <summary>
/// Generates deterministic dependency-free SARIF benchmark fixtures.
/// </summary>
public static class BenchmarkDatasetGenerator
{
    private const byte LineFeed = (byte)'\n';
    private static readonly ImmutableArray<int> Sizes = [1_000, 10_000, 100_000];
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = false,
        MaxDepth = 32,
        SkipValidation = false,
    };

    /// <summary>
    /// Gets the only accepted benchmark sizes.
    /// </summary>
    public static ImmutableArray<int> SupportedSizes => Sizes;

    /// <summary>
    /// Generates byte-identical baseline and candidate SARIF fixtures.
    /// </summary>
    /// <param name="findingCount">One of 1,000, 10,000, or 100,000.</param>
    /// <param name="kind">The requested deterministic dataset shape.</param>
    /// <returns>The generated in-memory fixture pair.</returns>
    public static BenchmarkDataset Generate(
        int findingCount,
        BenchmarkDatasetKind kind)
    {
        if (!Sizes.Contains(findingCount))
        {
            throw new ArgumentOutOfRangeException(
                nameof(findingCount),
                findingCount,
                "Benchmark size must be 1000, 10000, or 100000.");
        }

        if (kind is not BenchmarkDatasetKind.UniqueFingerprints and
            not BenchmarkDatasetKind.PathologicalBucket)
        {
            throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                "Unknown benchmark dataset kind.");
        }

        var sarif = CreateSarif(findingCount, kind);
        return new BenchmarkDataset(
            kind,
            findingCount,
            sarif,
            (byte[])sarif.Clone());
    }

    private static byte[] CreateSarif(
        int findingCount,
        BenchmarkDatasetKind kind)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("version", "2.1.0");
            writer.WriteStartArray("runs");
            writer.WriteStartObject();
            writer.WriteStartObject("tool");
            writer.WriteStartObject("driver");
            writer.WriteString("name", "SarifRegress Benchmark Producer");
            writer.WriteString("version", "1.0.0");
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WriteStartArray("results");
            for (var index = 0; index < findingCount; index++)
            {
                WriteFinding(writer, index, kind);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        stream.WriteByte(LineFeed);
        return stream.ToArray();
    }

    private static void WriteFinding(
        Utf8JsonWriter writer,
        int index,
        BenchmarkDatasetKind kind)
    {
        var ordinal = index.ToString("D6", CultureInfo.InvariantCulture);
        var unique = kind == BenchmarkDatasetKind.UniqueFingerprints;
        var ruleId = unique ? $"BENCH/{ordinal}" : "BENCH/PATHOLOGICAL";
        var path = unique
            ? $"src/generated/file-{ordinal}.cs"
            : "src/generated/shared.cs";

        writer.WriteStartObject();
        writer.WriteString("ruleId", ruleId);
        writer.WriteStartObject("message");
        writer.WriteString(
            "text",
            unique ? $"Generated finding {ordinal}." : "Shared benchmark finding.");
        writer.WriteEndObject();
        writer.WriteStartObject("partialFingerprints");
        writer.WriteString(
            "primaryLocationLineHash/v1",
            $"benchmark-fingerprint-{ordinal}");
        writer.WriteEndObject();
        writer.WriteStartArray("locations");
        writer.WriteStartObject();
        writer.WriteStartObject("physicalLocation");
        writer.WriteStartObject("artifactLocation");
        writer.WriteString("uri", path);
        writer.WriteEndObject();
        writer.WriteStartObject("region");
        writer.WriteNumber("startLine", unique ? 1 : index + 1);
        writer.WriteNumber("startColumn", 1);
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
    }
}
