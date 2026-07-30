using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Reporting;

namespace SarifRegress.Report;

internal readonly record struct StableJsonWriteResult(
    long OutputBytes,
    long ExplanationBytes);

internal static class StableJsonReportWriter
{
    private const byte LineFeed = (byte)'\n';
    private const int MaximumDepth = 64;

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = true,
        IndentCharacter = ' ',
        IndentSize = 2,
        MaxDepth = MaximumDepth,
        NewLine = "\n",
        SkipValidation = false,
    };

    public static StableJsonWriteResult Write(
        Stream destination,
        ComparisonReport report)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(report);
        if (!destination.CanWrite)
        {
            throw new ArgumentException(
                "The stable report destination must be writable.",
                nameof(destination));
        }

        using var writer = new Utf8JsonWriter(destination, WriterOptions);
        writer.WriteStartObject();
        writer.WriteString("outputSchemaVersion", report.OutputSchemaVersion);
        WriteTool(writer, report);
        WriteInputs(writer, report);
        WriteSummary(writer, report.Summary);

        long explanationBytes = 0;
        writer.WriteStartArray("findings");
        foreach (var finding in report.Findings)
        {
            explanationBytes = checked(
                explanationBytes + WriteFinding(writer, finding));
        }

        writer.WriteEndArray();
        WriteDiagnostics(writer, "diagnostics", report.Diagnostics);
        WriteMetrics(writer, report.Metrics);
        WriteDeterminism(writer, report.Determinism);
        writer.WriteEndObject();
        writer.Flush();

        var outputBytes = checked(writer.BytesCommitted + 1);
        destination.WriteByte(LineFeed);
        return new StableJsonWriteResult(outputBytes, explanationBytes);
    }

    private static void WriteTool(
        Utf8JsonWriter writer,
        ComparisonReport report)
    {
        writer.WriteStartObject("tool");
        writer.WriteString("name", report.ToolName);
        writer.WriteString("version", report.ToolVersion);
        writer.WriteEndObject();
    }

    private static void WriteInputs(
        Utf8JsonWriter writer,
        ComparisonReport report)
    {
        writer.WriteStartObject("inputs");
        writer.WriteString("baseline", report.BaselineInputName);
        writer.WriteString("candidate", report.CandidateInputName);
        writer.WriteEndObject();
    }

    private static void WriteSummary(
        Utf8JsonWriter writer,
        ComparisonSummary summary)
    {
        writer.WriteStartObject("summary");
        writer.WriteNumber("baselineCount", summary.BaselineCount);
        writer.WriteNumber("candidateCount", summary.CandidateCount);
        writer.WriteNumber("new", summary.New);
        writer.WriteNumber("unchanged", summary.Unchanged);
        writer.WriteNumber("moved", summary.Moved);
        writer.WriteNumber("modified", summary.Modified);
        writer.WriteNumber("resolved", summary.Resolved);
        writer.WriteNumber("ambiguous", summary.Ambiguous);
        writer.WriteEndObject();
    }

    private static long WriteFinding(
        Utf8JsonWriter writer,
        FindingReport finding)
    {
        writer.WriteStartObject();
        writer.WriteString(
            "classification",
            StableJsonNames.Classification(finding.Classification));
        WriteSourceReference(
            writer,
            "baselineRef",
            finding.BaselineReference);
        WriteSourceReference(
            writer,
            "candidateRef",
            finding.CandidateReference);
        WriteSnapshot(writer, "baseline", finding.Baseline);
        WriteSnapshot(writer, "candidate", finding.Candidate);

        long explanationBytes = 0;
        writer.WritePropertyName("decision");
        var valueStart = Position(writer);
        WriteDecision(writer, finding.Decision);
        explanationBytes = checked(
            explanationBytes + Position(writer) - valueStart);

        writer.WritePropertyName("evidence");
        valueStart = Position(writer);
        WriteEvidence(writer, finding.Decision.Evidence);
        explanationBytes = checked(
            explanationBytes + Position(writer) - valueStart);

        writer.WritePropertyName("rejectedAlternatives");
        valueStart = Position(writer);
        WriteRejectedAlternatives(
            writer,
            finding.Decision.RejectedAlternatives);
        explanationBytes = checked(
            explanationBytes + Position(writer) - valueStart);

        writer.WritePropertyName("transforms");
        valueStart = Position(writer);
        WriteTransformations(writer, finding.Decision.Transformations);
        explanationBytes = checked(
            explanationBytes + Position(writer) - valueStart);

        writer.WritePropertyName("diagnostics");
        valueStart = Position(writer);
        WriteDiagnostics(writer, finding.Decision.Diagnostics);
        explanationBytes = checked(
            explanationBytes + Position(writer) - valueStart);

        writer.WriteEndObject();
        return explanationBytes;
    }

    private static void WriteSourceReference(
        Utf8JsonWriter writer,
        string propertyName,
        SourceReference? sourceReference)
    {
        if (sourceReference is null)
        {
            writer.WriteNull(propertyName);
            return;
        }

        writer.WriteStartObject(propertyName);
        writer.WriteString(
            "input",
            StableJsonNames.Input(sourceReference.Input));
        WriteNullableNumber(writer, "runIndex", sourceReference.RunIndex);
        WriteNullableNumber(
            writer,
            "resultIndex",
            sourceReference.ResultIndex);
        writer.WriteString("jsonPointer", sourceReference.JsonPointer);
        writer.WriteEndObject();
    }

    private static void WriteSnapshot(
        Utf8JsonWriter writer,
        string propertyName,
        FindingSnapshot? snapshot)
    {
        if (snapshot is null)
        {
            writer.WriteNull(propertyName);
            return;
        }

        writer.WriteStartObject(propertyName);
        writer.WriteString("findingKey", snapshot.FindingKey);
        writer.WriteString("producerFamily", snapshot.ProducerFamily);
        writer.WriteString("canonicalRule", snapshot.CanonicalRule);
        WriteNullableString(
            writer,
            "canonicalUri",
            snapshot.CanonicalUri);
        WriteRegion(writer, snapshot.Region);
        writer.WriteString("canonicalMessage", snapshot.CanonicalMessage);
        WriteSourceMetadata(writer, snapshot.SourceMetadata);
        WriteStrings(
            writer,
            "messageNormalisationFlags",
            snapshot.MessageNormalisationFlags);
        WriteStrings(writer, "lossiness", snapshot.Lossiness);
        WriteDerivedFingerprints(writer, snapshot.DerivedFingerprints);
        writer.WriteEndObject();
    }

    private static void WriteRegion(
        Utf8JsonWriter writer,
        Region? region)
    {
        if (region is null)
        {
            writer.WriteNull("region");
            return;
        }

        writer.WriteStartObject("region");
        WriteNullableNumber(writer, "startLine", region.StartLine);
        WriteNullableNumber(writer, "startColumn", region.StartColumn);
        WriteNullableNumber(writer, "endLine", region.EndLine);
        WriteNullableNumber(writer, "endColumn", region.EndColumn);
        writer.WriteEndObject();
    }

    private static void WriteSourceMetadata(
        Utf8JsonWriter writer,
        FindingMetadata metadata)
    {
        writer.WriteStartObject("sourceMetadata");
        WriteNullableString(writer, "level", metadata.Level);
        WriteNullableString(writer, "kind", metadata.Kind);
        WriteNullableString(
            writer,
            "baselineState",
            metadata.BaselineState);
        writer.WriteEndObject();
    }

    private static void WriteStrings(
        Utf8JsonWriter writer,
        string propertyName,
        IEnumerable<string> values)
    {
        writer.WriteStartArray(propertyName);
        foreach (var value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

    private static void WriteDerivedFingerprints(
        Utf8JsonWriter writer,
        IEnumerable<DerivedFingerprint> fingerprints)
    {
        writer.WriteStartArray("derivedFingerprints");
        foreach (var fingerprint in fingerprints)
        {
            writer.WriteStartObject();
            writer.WriteString("name", fingerprint.Name);
            writer.WriteString("value", fingerprint.Value);
            writer.WriteString(
                "algorithmVersion",
                fingerprint.AlgorithmVersion);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteDecision(
        Utf8JsonWriter writer,
        DecisionTrace decision)
    {
        writer.WriteStartObject();
        writer.WriteString(
            "precedenceTier",
            StableJsonNames.Precedence(decision.PrecedenceTier));
        writer.WriteString(
            "displayConfidence",
            StableJsonNames.Confidence(decision.DisplayConfidence));
        writer.WriteBoolean("ambiguous", decision.Ambiguous);
        writer.WriteString(
            "matcherAlgorithmVersion",
            decision.MatcherAlgorithmVersion);
        writer.WriteEndObject();
    }

    private static void WriteEvidence(
        Utf8JsonWriter writer,
        IEnumerable<EvidenceRecord> evidence)
    {
        writer.WriteStartArray();
        foreach (var item in evidence)
        {
            writer.WriteStartObject();
            writer.WriteString("kind", item.Kind);
            WriteNullableString(
                writer,
                "baselineValue",
                item.BaselineValue);
            WriteNullableString(
                writer,
                "candidateValue",
                item.CandidateValue);
            writer.WriteString(
                "origin",
                StableJsonNames.Origin(item.Origin));
            writer.WriteString(
                "precedenceTier",
                StableJsonNames.Precedence(item.PrecedenceTier));
            writer.WriteBoolean("lossy", item.Lossy);
            writer.WriteString(
                "algorithmVersion",
                item.AlgorithmVersion);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteRejectedAlternatives(
        Utf8JsonWriter writer,
        IEnumerable<RejectedAlternative> alternatives)
    {
        writer.WriteStartArray();
        foreach (var alternative in alternatives)
        {
            writer.WriteStartObject();
            writer.WriteString("findingKey", alternative.FindingKey);
            writer.WriteString("reason", alternative.Reason);
            writer.WriteString(
                "precedenceTier",
                StableJsonNames.Precedence(
                    alternative.PrecedenceTier));
            WriteDecisionVector(
                writer,
                alternative.DecisionVector);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteDecisionVector(
        Utf8JsonWriter writer,
        DecisionVector vector)
    {
        writer.WriteStartObject("decisionVector");
        writer.WriteString(
            "precedenceTier",
            StableJsonNames.Precedence(vector.PrecedenceTier));
        writer.WriteNumber(
            "producerFingerprintStrength",
            vector.ProducerFingerprintStrength);
        writer.WriteString(
            "pathMatchKind",
            StableJsonNames.PathMatch(vector.PathMatchKind));
        writer.WriteString(
            "contextAgreement",
            StableJsonNames.Agreement(vector.ContextAgreement));
        writer.WriteString(
            "codeFlowAgreement",
            StableJsonNames.Agreement(vector.CodeFlowAgreement));
        writer.WriteString(
            "messageAgreement",
            StableJsonNames.Agreement(vector.MessageAgreement));
        writer.WriteNumber("regionDriftBand", vector.RegionDriftBand);
        writer.WriteEndObject();
    }

    private static void WriteTransformations(
        Utf8JsonWriter writer,
        IEnumerable<TransformationRecord> transformations)
    {
        writer.WriteStartArray();
        foreach (var transformation in transformations)
        {
            writer.WriteStartObject();
            writer.WriteString("kind", transformation.Kind);
            WriteNullableString(
                writer,
                "originalValue",
                transformation.OriginalValue);
            WriteNullableString(
                writer,
                "transformedValue",
                transformation.TransformedValue);
            writer.WriteBoolean("lossy", transformation.IsLossy);
            writer.WriteString(
                "algorithmVersion",
                transformation.AlgorithmVersion);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteDiagnostics(
        Utf8JsonWriter writer,
        string propertyName,
        IEnumerable<Diagnostic> diagnostics)
    {
        writer.WritePropertyName(propertyName);
        WriteDiagnostics(writer, diagnostics);
    }

    private static void WriteDiagnostics(
        Utf8JsonWriter writer,
        IEnumerable<Diagnostic> diagnostics)
    {
        writer.WriteStartArray();
        foreach (var diagnostic in diagnostics)
        {
            writer.WriteStartObject();
            writer.WriteString("code", diagnostic.Code);
            writer.WriteString(
                "severity",
                StableJsonNames.Severity(diagnostic.Severity));
            writer.WriteString(
                "stage",
                StableJsonNames.Stage(diagnostic.Stage));
            writer.WriteString("message", diagnostic.Message);
            WriteSourceReference(
                writer,
                "sourceRef",
                diagnostic.SourceReference);
            WriteNullableString(
                writer,
                "standardBasis",
                diagnostic.StandardBasis);
            WriteNullableString(writer, "help", diagnostic.Help);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteMetrics(
        Utf8JsonWriter writer,
        ComparisonMetrics metrics)
    {
        writer.WriteStartObject("metrics");
        writer.WriteNumber("candidateEdges", metrics.CandidateEdges);
        writer.WriteNumber(
            "assignmentComponents",
            metrics.AssignmentComponents);
        writer.WriteNumber(
            "ambiguousComponents",
            metrics.AmbiguousComponents);
        writer.WriteNumber("diagnostics", metrics.Diagnostics);
        writer.WriteEndObject();
    }

    private static void WriteDeterminism(
        Utf8JsonWriter writer,
        DeterminismDescriptor determinism)
    {
        writer.WriteStartObject("determinism");
        writer.WriteString(
            "jsonCanonicalisation",
            determinism.JsonCanonicalisation);
        writer.WriteString(
            "crossPlatformNormalisation",
            determinism.CrossPlatformNormalisation);
        writer.WriteString(
            "matcherAlgorithm",
            determinism.MatcherAlgorithm);
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
            return;
        }

        writer.WriteString(propertyName, value);
    }

    private static void WriteNullableNumber(
        Utf8JsonWriter writer,
        string propertyName,
        int? value)
    {
        if (value.HasValue)
        {
            writer.WriteNumber(propertyName, value.Value);
            return;
        }

        writer.WriteNull(propertyName);
    }

    private static long Position(Utf8JsonWriter writer) =>
        checked(writer.BytesCommitted + writer.BytesPending);
}
