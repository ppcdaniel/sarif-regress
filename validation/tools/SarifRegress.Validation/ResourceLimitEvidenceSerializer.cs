using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core.Security;

namespace SarifRegress.Validation;

/// <summary>Serializes the exact default matcher limits used by hosted evidence.</summary>
public static class ResourceLimitEvidenceSerializer
{
    public const string OutputFileName = "resource-limits.json";

    private const byte LineFeed = (byte)'\n';
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = true,
        IndentCharacter = ' ',
        IndentSize = 2,
        MaxDepth = 8,
        NewLine = "\n",
        SkipValidation = false,
    };

    /// <summary>Returns stable UTF-8 JSON with a final line feed.</summary>
    public static byte[] Serialize()
    {
        ResourceLimits limits = ResourceLimits.Default;
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "1");
            writer.WriteString("kind", "sarifregress-resource-limits/v1");
            writer.WriteNumber(
                "maximumCandidatePairsPerFinding",
                limits.MaximumCandidatePairEvaluationsPerFinding);
            writer.WriteNumber(
                "maximumCandidatePairs",
                limits.MaximumCandidatePairEvaluations);
            writer.WriteNumber(
                "maximumAssignmentSideSize",
                limits.MaximumAssignmentSideSize);
            writer.WriteEndObject();
            writer.Flush();
        }

        stream.WriteByte(LineFeed);
        return stream.ToArray();
    }
}
