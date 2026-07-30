using System.Buffers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Reporting;

namespace SarifRegress.Report;

/// <summary>
/// Projects the stable comparison contract into deterministic SARIF 2.1.0.
/// </summary>
public static class CanonicalSarifExporter
{
    private const string SarifSchema =
        "https://json.schemastore.org/sarif-2.1.0.json";
    private const string SarifVersion = "2.1.0";
    private const string ProjectInformationUri =
        "https://github.com/ppcdaniel/sarif-regress";
    private const string ClassificationProperty =
        "sarifregress/classification";
    private const string FindingKeyProperty = "sarifregress/findingKey";
    private const string UpperHexDigits = "0123456789ABCDEF";
    private const byte LineFeed = (byte)'\n';

    private static readonly HashSet<string> FilePathSchemes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "file",
            "relative",
            "repo",
            "unc",
            "unresolved",
            "win-device",
            "win-device-unc",
            "win-drive",
            "win-drive-relative",
            "win-root",
        };

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = true,
        IndentCharacter = ' ',
        IndentSize = 2,
        MaxDepth = 64,
        NewLine = "\n",
        SkipValidation = false,
    };

    /// <summary>
    /// Deserializes stable JSON and emits a canonical SARIF 2.1.0 projection.
    /// </summary>
    /// <param name="stableJson">Canonical comparison-report JSON.</param>
    /// <returns>UTF-8 SARIF bytes without a byte-order mark and with a final LF.</returns>
    public static byte[] Project(ReadOnlySpan<byte> stableJson)
    {
        var report = StableJsonReportSerializer.Deserialize(stableJson);
        return ProjectReport(report);
    }

    /// <summary>
    /// Projects stable JSON into a canonical SARIF file.
    /// </summary>
    /// <param name="path">The destination file path.</param>
    /// <param name="stableJson">Canonical comparison-report JSON.</param>
    public static void WriteFile(string path, ReadOnlySpan<byte> stableJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        File.WriteAllBytes(path, Project(stableJson));
    }

    // Time: O(n log n), Space: O(n), for n report findings.
    private static byte[] ProjectReport(ComparisonReport report)
    {
        var projections = report.Findings
            .Select(CreateProjection)
            .Where(item => item is not null)
            .Cast<SarifResultProjection>()
            .OrderBy(item => item.Snapshot.CanonicalRule, StringComparer.Ordinal)
            .ThenBy(
                item => item.Snapshot.CanonicalUri ?? string.Empty,
                StringComparer.Ordinal)
            .ThenBy(item => item.Snapshot.FindingKey, StringComparer.Ordinal)
            .ThenBy(
                item => StableJsonNames.Classification(item.Classification),
                StringComparer.Ordinal)
            .ToArray();
        var ruleIds = projections
            .Select(item => item.Snapshot.CanonicalRule)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("$schema", SarifSchema);
            writer.WriteString("version", SarifVersion);
            writer.WriteStartArray("runs");
            writer.WriteStartObject();
            WriteTool(writer, report, ruleIds);
            writer.WriteStartArray("results");
            foreach (var projection in projections)
            {
                WriteResult(writer, projection);
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

    private static SarifResultProjection? CreateProjection(FindingReport finding)
    {
        var snapshot = finding.Candidate ?? finding.Baseline;
        return snapshot is null
            ? null
            : new SarifResultProjection(finding.Classification, snapshot);
    }

    private static void WriteTool(
        Utf8JsonWriter writer,
        ComparisonReport report,
        IEnumerable<string> ruleIds)
    {
        writer.WriteStartObject("tool");
        writer.WriteStartObject("driver");
        writer.WriteString("name", report.ToolName);
        writer.WriteString("version", report.ToolVersion);
        writer.WriteString("informationUri", ProjectInformationUri);
        writer.WriteStartArray("rules");
        foreach (var ruleId in ruleIds)
        {
            writer.WriteStartObject();
            writer.WriteString("id", ruleId);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteResult(
        Utf8JsonWriter writer,
        SarifResultProjection projection)
    {
        var snapshot = projection.Snapshot;
        writer.WriteStartObject();
        writer.WriteString("ruleId", snapshot.CanonicalRule);
        writer.WriteStartObject("message");
        writer.WriteString("text", snapshot.CanonicalMessage);
        writer.WriteEndObject();
        WriteLocations(writer, snapshot);

        var baselineState = BaselineState(projection.Classification);
        if (baselineState is not null)
        {
            writer.WriteString("baselineState", baselineState);
        }

        WritePartialFingerprints(writer, snapshot);
        writer.WriteStartObject("properties");
        writer.WriteString(
            ClassificationProperty,
            StableJsonNames.Classification(projection.Classification));
        writer.WriteString(FindingKeyProperty, snapshot.FindingKey);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteLocations(
        Utf8JsonWriter writer,
        FindingSnapshot snapshot)
    {
        var artifactUri = EncodeArtifactUri(snapshot.CanonicalUri);
        if (artifactUri is null)
        {
            return;
        }

        writer.WriteStartArray("locations");
        writer.WriteStartObject();
        writer.WriteStartObject("physicalLocation");
        writer.WriteStartObject("artifactLocation");
        writer.WriteString("uri", artifactUri);
        writer.WriteEndObject();
        if (snapshot.Region is { StartLine: not null })
        {
            WriteRegion(writer, snapshot.Region);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.WriteEndArray();
    }

    private static void WriteRegion(Utf8JsonWriter writer, Region region)
    {
        writer.WriteStartObject("region");
        WriteOptionalNumber(writer, "startLine", region.StartLine);
        WriteOptionalNumber(writer, "startColumn", region.StartColumn);
        WriteOptionalNumber(writer, "endLine", region.EndLine);
        WriteOptionalNumber(writer, "endColumn", region.EndColumn);
        writer.WriteEndObject();
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

    private static void WritePartialFingerprints(
        Utf8JsonWriter writer,
        FindingSnapshot snapshot)
    {
        var fingerprint = snapshot.DerivedFingerprints
            .SingleOrDefault(item => string.Equals(
                item.Name,
                ReportContractVersions.SarifFingerprint,
                StringComparison.Ordinal));
        if (fingerprint is null)
        {
            return;
        }

        writer.WriteStartObject("partialFingerprints");
        writer.WriteString(fingerprint.Name, fingerprint.Value);
        writer.WriteEndObject();
    }

    private static string? BaselineState(FindingClassification classification) =>
        classification switch
        {
            FindingClassification.New => "new",
            FindingClassification.Unchanged => "unchanged",
            FindingClassification.Moved => "updated",
            FindingClassification.Modified => "updated",
            FindingClassification.Resolved => "absent",
            FindingClassification.Ambiguous => null,
            _ => throw new ArgumentOutOfRangeException(
                nameof(classification),
                classification,
                "Unknown finding classification."),
        };

    private static string? EncodeArtifactUri(string? canonicalUri)
    {
        if (canonicalUri is null)
        {
            return null;
        }

        var separatorIndex = canonicalUri.IndexOf(':');
        string encoded;
        if (separatorIndex > 0
            && FilePathSchemes.Contains(canonicalUri[..separatorIndex]))
        {
            var encodedBody = EncodeFilePathUriBody(
                canonicalUri.AsSpan(separatorIndex + 1));
            if (encodedBody is null)
            {
                return null;
            }

            encoded = canonicalUri[..(separatorIndex + 1)] + encodedBody;
        }
        else if (Uri.TryCreate(
                     canonicalUri,
                     UriKind.Absolute,
                     out var absoluteUri))
        {
            encoded = absoluteUri.AbsoluteUri;
        }
        else
        {
            encoded = EncodeFilePathUriBody(canonicalUri.AsSpan())
                ?? string.Empty;
        }

        return encoded.Length > 0
            && Uri.TryCreate(encoded, UriKind.RelativeOrAbsolute, out _)
                ? encoded
                : null;
    }

    private static string? EncodeFilePathUriBody(ReadOnlySpan<char> value)
    {
        var encoded = new StringBuilder(value.Length);
        Span<byte> utf8Bytes = stackalloc byte[4];
        for (var index = 0; index < value.Length;)
        {
            var current = value[index];
            if (current == '%'
                && index + 2 < value.Length
                && IsHexDigit(value[index + 1])
                && IsHexDigit(value[index + 2]))
            {
                encoded.Append('%');
                encoded.Append(char.ToUpperInvariant(value[index + 1]));
                encoded.Append(char.ToUpperInvariant(value[index + 2]));
                index += 3;
                continue;
            }

            if (IsUnreservedAscii(current) || current is '/' or ':')
            {
                encoded.Append(current);
                index++;
                continue;
            }

            if (Rune.DecodeFromUtf16(
                    value[index..],
                    out var rune,
                    out var charactersConsumed) != OperationStatus.Done)
            {
                return null;
            }

            var bytesWritten = rune.EncodeToUtf8(utf8Bytes);
            for (var byteIndex = 0; byteIndex < bytesWritten; byteIndex++)
            {
                var currentByte = utf8Bytes[byteIndex];
                encoded.Append('%');
                encoded.Append(UpperHexDigits[currentByte >> 4]);
                encoded.Append(UpperHexDigits[currentByte & 0x0F]);
            }

            index += charactersConsumed;
        }

        return encoded.ToString();
    }

    private static bool IsUnreservedAscii(char value) =>
        value is >= 'A' and <= 'Z'
        || value is >= 'a' and <= 'z'
        || value is >= '0' and <= '9'
        || value is '-' or '.' or '_' or '~';

    private static bool IsHexDigit(char value) =>
        value is >= '0' and <= '9'
        || value is >= 'A' and <= 'F'
        || value is >= 'a' and <= 'f';

    private sealed record SarifResultProjection(
        FindingClassification Classification,
        FindingSnapshot Snapshot);
}
