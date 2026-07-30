using System.Collections.Immutable;
using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Serializes the stable single-input validation contract.
/// </summary>
internal static class ValidateSummarySerializer
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

    public static byte[] Serialize(
        string logicalInputName,
        SarifIngestionResult ingestion,
        IEnumerable<Diagnostic> diagnostics,
        bool policyPassed)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalInputName);
        ArgumentNullException.ThrowIfNull(ingestion);
        var orderedDiagnostics = Diagnostic.Sort(diagnostics);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("validationSchemaVersion", "1");
            writer.WriteStartObject("tool");
            writer.WriteString("name", ProductInformation.Name);
            writer.WriteString("version", ProductInformation.Version);
            writer.WriteEndObject();
            writer.WriteStartObject("input");
            writer.WriteString("name", logicalInputName);
            writer.WriteNumber("inputBytes", ingestion.Summary.InputBytes);
            WriteNullableString(
                writer,
                "sarifVersion",
                ingestion.Summary.Version);
            writer.WriteNumber("runCount", ingestion.Summary.Runs.Length);
            writer.WriteNumber(
                "findingCount",
                ingestion.ComparisonInput.Findings.Length);
            writer.WriteEndObject();
            writer.WriteBoolean("valid", ingestion.IsValid);
            writer.WriteBoolean("policyPassed", policyPassed);
            WriteDiagnosticCounts(writer, orderedDiagnostics);
            WriteDiagnostics(writer, orderedDiagnostics);
            writer.WriteEndObject();
            writer.Flush();
        }

        stream.WriteByte(LineFeed);
        return stream.ToArray();
    }

    private static void WriteDiagnosticCounts(
        Utf8JsonWriter writer,
        ImmutableArray<Diagnostic> diagnostics)
    {
        writer.WriteStartObject("diagnosticCounts");
        writer.WriteNumber(
            "note",
            diagnostics.Count(item => item.Severity == DiagnosticSeverity.Note));
        writer.WriteNumber(
            "warning",
            diagnostics.Count(item => item.Severity == DiagnosticSeverity.Warning));
        writer.WriteNumber(
            "error",
            diagnostics.Count(item => item.Severity == DiagnosticSeverity.Error));
        writer.WriteEndObject();
    }

    private static void WriteDiagnostics(
        Utf8JsonWriter writer,
        ImmutableArray<Diagnostic> diagnostics)
    {
        writer.WriteStartArray("diagnostics");
        foreach (var diagnostic in diagnostics)
        {
            writer.WriteStartObject();
            writer.WriteString("code", diagnostic.Code);
            writer.WriteString("severity", SeverityName(diagnostic.Severity));
            writer.WriteString("stage", StageName(diagnostic.Stage));
            writer.WriteString("message", diagnostic.Message);
            WriteSourceReference(writer, diagnostic.SourceReference);
            WriteNullableString(
                writer,
                "standardBasis",
                diagnostic.StandardBasis);
            WriteNullableString(writer, "help", diagnostic.Help);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteSourceReference(
        Utf8JsonWriter writer,
        SourceReference? sourceReference)
    {
        if (sourceReference is null)
        {
            writer.WriteNull("sourceRef");
            return;
        }

        writer.WriteStartObject("sourceRef");
        writer.WriteString("input", InputName(sourceReference.Input));
        WriteNullableNumber(writer, "runIndex", sourceReference.RunIndex);
        WriteNullableNumber(writer, "resultIndex", sourceReference.ResultIndex);
        writer.WriteString("jsonPointer", sourceReference.JsonPointer);
        writer.WriteEndObject();
    }

    private static void WriteNullableString(
        Utf8JsonWriter writer,
        string propertyName,
        string? value)
    {
        if (value is null)
        {
            writer.WriteNull(propertyName);
        }
        else
        {
            writer.WriteString(propertyName, value);
        }
    }

    private static void WriteNullableNumber(
        Utf8JsonWriter writer,
        string propertyName,
        int? value)
    {
        if (value.HasValue)
        {
            writer.WriteNumber(propertyName, value.Value);
        }
        else
        {
            writer.WriteNull(propertyName);
        }
    }

    private static string SeverityName(DiagnosticSeverity severity) =>
        severity switch
        {
            DiagnosticSeverity.Note => "note",
            DiagnosticSeverity.Warning => "warning",
            DiagnosticSeverity.Error => "error",
            _ => throw new ArgumentOutOfRangeException(
                nameof(severity),
                severity,
                "Unknown diagnostic severity."),
        };

    private static string StageName(DiagnosticStage stage) =>
        stage switch
        {
            DiagnosticStage.Io => "io",
            DiagnosticStage.Parse => "parse",
            DiagnosticStage.Schema => "schema",
            DiagnosticStage.Unsupported => "unsupported",
            DiagnosticStage.Canonicalisation => "canonicalisation",
            DiagnosticStage.Repository => "repository",
            DiagnosticStage.Fingerprint => "fingerprint",
            DiagnosticStage.Match => "match",
            DiagnosticStage.GithubCompatibility => "github-compat",
            DiagnosticStage.Security => "security",
            DiagnosticStage.Report => "report",
            DiagnosticStage.Internal => "internal",
            _ => throw new ArgumentOutOfRangeException(
                nameof(stage),
                stage,
                "Unknown diagnostic stage."),
        };

    private static string InputName(InputKind input) =>
        input switch
        {
            InputKind.Baseline => "baseline",
            InputKind.Candidate => "candidate",
            InputKind.Configuration => "configuration",
            InputKind.Corpus => "corpus",
            _ => throw new ArgumentOutOfRangeException(
                nameof(input),
                input,
                "Unknown input kind."),
        };
}
