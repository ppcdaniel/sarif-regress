using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core.Diagnostics;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Serializes corpus metrics with explicit property order and stable UTF-8 bytes.
/// </summary>
public static class CorpusRunReportSerializer
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = true,
        MaxDepth = 16,
        SkipValidation = false,
    };

    /// <summary>
    /// Serializes one corpus run as UTF-8 without a byte-order mark and with a final LF.
    /// </summary>
    /// <param name="result">The completed corpus result.</param>
    /// <returns>Stable JSON bytes.</returns>
    public static byte[] Serialize(CorpusRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", result.SchemaVersion);
            WriteThresholds(writer, result.Thresholds);
            writer.WriteBoolean("passed", result.Passed);
            WriteMetrics(writer, "aggregate", result.Aggregate);
            writer.WritePropertyName("cases");
            writer.WriteStartArray();
            foreach (var caseRun in result.Cases.OrderBy(
                         item => item.CaseName,
                         StringComparer.Ordinal))
            {
                WriteCase(writer, caseRun);
            }

            writer.WriteEndArray();
            writer.WritePropertyName("failures");
            writer.WriteStartArray();
            foreach (var failure in result.Failures.Order(StringComparer.Ordinal))
            {
                writer.WriteStringValue(failure);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        byte[] json = stream.ToArray();
        var resultBytes = GC.AllocateUninitializedArray<byte>(json.Length + 1);
        json.CopyTo(resultBytes, 0);
        resultBytes[^1] = (byte)'\n';
        return resultBytes;
    }

    /// <summary>
    /// Decodes stable report bytes for console output.
    /// </summary>
    /// <param name="bytes">Stable UTF-8 report bytes.</param>
    /// <returns>The decoded report.</returns>
    public static string Decode(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetString(bytes);
    }

    private static void WriteThresholds(
        Utf8JsonWriter writer,
        CorpusThresholds thresholds)
    {
        writer.WritePropertyName("thresholds");
        writer.WriteStartObject();
        writer.WriteNumber("minimumPrecision", thresholds.MinimumPrecision);
        writer.WriteNumber("minimumRecall", thresholds.MinimumRecall);
        writer.WriteNumber(
            "maximumSilentAmbiguousMatches",
            thresholds.MaximumSilentAmbiguousMatches);
        writer.WriteEndObject();
    }

    private static void WriteCase(Utf8JsonWriter writer, CorpusCaseRun caseRun)
    {
        writer.WriteStartObject();
        writer.WriteString("caseName", caseRun.CaseName);
        WriteInputs(writer, "expectedInvalidInputs", caseRun.ExpectedInvalidInputs);
        WriteInputs(writer, "observedInvalidInputs", caseRun.ObservedInvalidInputs);
        writer.WriteBoolean("passed", caseRun.Passed);
        writer.WriteString("artifactKind", caseRun.Artifact.Kind);
        writer.WriteString("artifactSha256", caseRun.Artifact.Sha256);
        writer.WritePropertyName("artifact");
        using (var artifact = JsonDocument.Parse(caseRun.Artifact.Json.ToArray()))
        {
            artifact.RootElement.WriteTo(writer);
        }

        WriteMetrics(writer, "metrics", caseRun.Metrics);
        writer.WriteEndObject();
    }

    private static void WriteInputs(
        Utf8JsonWriter writer,
        string propertyName,
        IEnumerable<InputKind> inputs)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartArray();
        foreach (var input in inputs.Order())
        {
            writer.WriteStringValue(input.ToString().ToLowerInvariant());
        }

        writer.WriteEndArray();
    }

    private static void WriteMetrics(
        Utf8JsonWriter writer,
        string propertyName,
        CorpusMetrics metrics)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartObject();
        writer.WriteNumber("labelledPairs", metrics.LabelledPairs);
        writer.WriteNumber("truePositives", metrics.TruePositives);
        writer.WriteNumber("falsePositives", metrics.FalsePositives);
        writer.WriteNumber("falseNegatives", metrics.FalseNegatives);
        writer.WriteNumber(
            "classificationMismatches",
            metrics.ClassificationMismatches);
        writer.WriteNumber("expectedAmbiguous", metrics.ExpectedAmbiguous);
        writer.WriteNumber("correctAmbiguous", metrics.CorrectAmbiguous);
        writer.WriteNumber("missingAmbiguous", metrics.MissingAmbiguous);
        writer.WriteNumber("unexpectedAmbiguous", metrics.UnexpectedAmbiguous);
        writer.WriteNumber(
            "silentAmbiguousMatches",
            metrics.SilentAmbiguousMatches);
        writer.WriteNumber("expectedResolved", metrics.ExpectedResolved);
        writer.WriteNumber("correctResolved", metrics.CorrectResolved);
        writer.WriteNumber("missingResolved", metrics.MissingResolved);
        writer.WriteNumber("unexpectedResolved", metrics.UnexpectedResolved);
        writer.WriteNumber("expectedNew", metrics.ExpectedNew);
        writer.WriteNumber("correctNew", metrics.CorrectNew);
        writer.WriteNumber("missingNew", metrics.MissingNew);
        writer.WriteNumber("unexpectedNew", metrics.UnexpectedNew);
        writer.WriteNumber("precision", metrics.Precision);
        writer.WriteNumber("recall", metrics.Recall);
        writer.WriteNumber("f1", metrics.F1);
        writer.WriteEndObject();
    }
}
