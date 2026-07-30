using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Report;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Produces the exact comparison or invalid-input artifact retained by a corpus run.
/// </summary>
public static class CorpusCaseArtifactSerializer
{
    private const string ComparisonKind = "comparison";
    private const string DiagnosticsKind = "invalid-input-diagnostics";
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
    /// Creates the complete stable comparison JSON for a valid corpus case.
    /// </summary>
    public static CorpusCaseArtifact CreateComparison(
        string caseName,
        MatchResult matchResult)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caseName);
        ArgumentNullException.ThrowIfNull(matchResult);
        var report = ComparisonReportFactory.Create(
            matchResult,
            new ComparisonReportMetadata(
                ProductInformation.Version,
                $"{caseName}/baseline.sarif",
                $"{caseName}/candidate.sarif",
                ProductInformation.MatcherAlgorithmVersion));
        return new CorpusCaseArtifact(
            ComparisonKind,
            StableJsonReportSerializer.Serialize(report));
    }

    /// <summary>
    /// Creates a stable diagnostic bundle when either case input is invalid.
    /// </summary>
    public static CorpusCaseArtifact CreateInvalidInputDiagnostics(
        string caseName,
        SarifIngestionResult baseline,
        SarifIngestionResult candidate,
        IEnumerable<Diagnostic> configurationDiagnostics)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caseName);
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(configurationDiagnostics);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("artifactSchemaVersion", "1");
            writer.WriteString("kind", DiagnosticsKind);
            writer.WriteString("caseName", caseName);
            writer.WriteStartArray("configurationDiagnostics");
            foreach (var diagnostic in Diagnostic.Sort(
                         configurationDiagnostics))
            {
                WriteDiagnostic(writer, diagnostic);
            }

            writer.WriteEndArray();
            writer.WriteStartArray("inputs");
            WriteInput(writer, InputKind.Baseline, baseline);
            WriteInput(writer, InputKind.Candidate, candidate);
            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        stream.WriteByte(LineFeed);
        return new CorpusCaseArtifact(DiagnosticsKind, stream.ToArray());
    }

    private static void WriteInput(
        Utf8JsonWriter writer,
        InputKind input,
        SarifIngestionResult ingestion)
    {
        writer.WriteStartObject();
        writer.WriteString("input", input.ToString().ToLowerInvariant());
        writer.WriteString("logicalName", ingestion.ComparisonInput.LogicalName);
        writer.WriteBoolean("valid", ingestion.IsValid);
        writer.WriteNumber(
            "findingCount",
            ingestion.ComparisonInput.Findings.Length);
        writer.WriteStartArray("diagnostics");
        foreach (var diagnostic in Diagnostic.Sort(
                     ingestion.ComparisonInput.Diagnostics))
        {
            WriteDiagnostic(writer, diagnostic);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteDiagnostic(
        Utf8JsonWriter writer,
        Diagnostic diagnostic)
    {
        writer.WriteStartObject();
        writer.WriteString("code", diagnostic.Code);
        writer.WriteString(
            "severity",
            diagnostic.Severity.ToString().ToLowerInvariant());
        writer.WriteString(
            "stage",
            diagnostic.Stage.ToString().ToLowerInvariant());
        writer.WriteString("message", diagnostic.Message);
        WriteOptionalString(writer, "standardBasis", diagnostic.StandardBasis);
        WriteOptionalString(writer, "help", diagnostic.Help);
        if (diagnostic.SourceReference is not null)
        {
            writer.WriteStartObject("source");
            writer.WriteString(
                "input",
                diagnostic.SourceReference.Input.ToString().ToLowerInvariant());
            WriteOptionalNumber(
                writer,
                "runIndex",
                diagnostic.SourceReference.RunIndex);
            WriteOptionalNumber(
                writer,
                "resultIndex",
                diagnostic.SourceReference.ResultIndex);
            writer.WriteString(
                "jsonPointer",
                diagnostic.SourceReference.JsonPointer);
            writer.WriteEndObject();
        }

        writer.WriteEndObject();
    }

    private static void WriteOptionalString(
        Utf8JsonWriter writer,
        string propertyName,
        string? value)
    {
        if (value is not null)
        {
            writer.WriteString(propertyName, value);
        }
    }

    private static void WriteOptionalNumber(
        Utf8JsonWriter writer,
        string propertyName,
        int? value)
    {
        if (value.HasValue)
        {
            writer.WriteNumber(propertyName, value.Value);
        }
    }
}
