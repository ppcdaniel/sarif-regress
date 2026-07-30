using System.Buffers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using SarifRegress.Core;
using SarifRegress.Core.Findings;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Emits the project-owned deterministic canonical SARIF projection.
/// </summary>
internal static class CanonicaliseSarifSerializer
{
    private const string SarifSchema =
        "https://json.schemastore.org/sarif-2.1.0.json";
    private const string InformationUri =
        "https://github.com/ppcdaniel/sarif-regress";
    private const string FindingKeyProperty = "sarifregress/findingKey";
    private const string SourceProducerFamilyProperty =
        "sarifregress/sourceProducerFamily";
    private const string SourceToolNameProperty =
        "sarifregress/sourceToolName";
    private const string SourceToolVersionProperty =
        "sarifregress/sourceToolVersion";
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

    public static byte[] Serialize(SarifIngestionResult ingestion)
    {
        ArgumentNullException.ThrowIfNull(ingestion);
        var findingsByRun = ingestion.ComparisonInput.Findings
            .GroupBy(item => item.Run.RunIndex)
            .ToDictionary(
                group => group.Key,
                group => OrderFindings(group).ToArray());
        var runIndexes = ingestion.Summary.Runs
            .Select(item => item.RunIndex)
            .Concat(findingsByRun.Keys)
            .Distinct()
            .Order()
            .ToArray();

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("$schema", SarifSchema);
            writer.WriteString("version", "2.1.0");
            writer.WriteStartArray("runs");
            foreach (var runIndex in runIndexes)
            {
                findingsByRun.TryGetValue(runIndex, out var findings);
                WriteRun(writer, findings ?? []);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        stream.WriteByte(LineFeed);
        return stream.ToArray();
    }

    private static IOrderedEnumerable<Finding> OrderFindings(
        IEnumerable<Finding> findings) =>
        findings
            .OrderBy(item => item.Rule.CanonicalId, StringComparer.Ordinal)
            .ThenBy(
                item => item.PrimaryLocation?.Path.CanonicalUri ?? string.Empty,
                StringComparer.Ordinal)
            .ThenBy(item => item.PrimaryLocation?.Region?.StartLine)
            .ThenBy(item => item.PrimaryLocation?.Region?.StartColumn)
            .ThenBy(item => item.FindingKey, StringComparer.Ordinal);

    private static void WriteRun(
        Utf8JsonWriter writer,
        IReadOnlyCollection<Finding> findings)
    {
        writer.WriteStartObject();
        WriteTool(writer, findings);
        var automationCategory = findings
            .Select(item => item.Run.AutomationCategory)
            .Where(item => item is not null)
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .FirstOrDefault();
        if (automationCategory is not null)
        {
            writer.WriteStartObject("automationDetails");
            writer.WriteString("id", automationCategory);
            writer.WriteEndObject();
        }

        WriteSourceProducerProperties(writer, findings);
        writer.WriteStartArray("results");
        foreach (var finding in findings)
        {
            WriteResult(writer, finding);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteTool(
        Utf8JsonWriter writer,
        IReadOnlyCollection<Finding> findings)
    {
        var ruleIds = findings
            .Select(item => item.Rule.CanonicalId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);

        writer.WriteStartObject("tool");
        writer.WriteStartObject("driver");
        writer.WriteString("name", ProductInformation.Name);
        writer.WriteString("version", ProductInformation.Version);
        writer.WriteString("informationUri", InformationUri);
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

    private static void WriteSourceProducerProperties(
        Utf8JsonWriter writer,
        IReadOnlyCollection<Finding> findings)
    {
        var producer = findings
            .Select(item => item.Producer)
            .OrderBy(item => item.Family, StringComparer.Ordinal)
            .ThenBy(item => item.ToolName, StringComparer.Ordinal)
            .ThenBy(
                item => item.ToolVersion ?? string.Empty,
                StringComparer.Ordinal)
            .FirstOrDefault();
        if (producer is null)
        {
            return;
        }

        writer.WriteStartObject("properties");
        writer.WriteString(SourceProducerFamilyProperty, producer.Family);
        writer.WriteString(SourceToolNameProperty, producer.ToolName);
        if (producer.ToolVersion is not null)
        {
            writer.WriteString(
                SourceToolVersionProperty,
                producer.ToolVersion);
        }

        writer.WriteEndObject();
    }

    private static void WriteResult(Utf8JsonWriter writer, Finding finding)
    {
        writer.WriteStartObject();
        writer.WriteString("ruleId", finding.Rule.CanonicalId);
        writer.WriteStartObject("message");
        writer.WriteString("text", finding.Message.CanonicalText);
        writer.WriteEndObject();
        WriteLocation(writer, finding.PrimaryLocation);
        WriteProjectFingerprints(writer, finding);
        writer.WriteStartObject("properties");
        writer.WriteString(FindingKeyProperty, finding.FindingKey);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteLocation(
        Utf8JsonWriter writer,
        PrimaryLocation? location)
    {
        var artifactUri = EncodeArtifactUri(location?.Path.CanonicalUri);
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
        if (location?.Region is not null)
        {
            WriteRegion(writer, location.Region);
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

    private static void WriteProjectFingerprints(
        Utf8JsonWriter writer,
        Finding finding)
    {
        var fingerprints = finding.DerivedFingerprints
            .Where(item => item.Name.StartsWith(
                "sarifregress/",
                StringComparison.Ordinal))
            .GroupBy(item => item.Name, StringComparer.Ordinal)
            .Select(group => group
                .OrderBy(item => item.Value, StringComparer.Ordinal)
                .First())
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ToArray();
        if (fingerprints.Length == 0)
        {
            return;
        }

        writer.WriteStartObject("partialFingerprints");
        foreach (var fingerprint in fingerprints)
        {
            writer.WriteString(fingerprint.Name, fingerprint.Value);
        }

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

    private static string? EncodeArtifactUri(string? canonicalUri)
    {
        if (canonicalUri is null)
        {
            return null;
        }

        var separatorIndex = canonicalUri.IndexOf(':');
        string encoded;
        if (separatorIndex > 0 &&
            FilePathSchemes.Contains(canonicalUri[..separatorIndex]))
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

        return encoded.Length > 0 &&
            Uri.TryCreate(encoded, UriKind.RelativeOrAbsolute, out _)
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
            if (current == '%' &&
                index + 2 < value.Length &&
                IsHexDigit(value[index + 1]) &&
                IsHexDigit(value[index + 2]))
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
        value is >= 'A' and <= 'Z' ||
        value is >= 'a' and <= 'z' ||
        value is >= '0' and <= '9' ||
        value is '-' or '.' or '_' or '~';

    private static bool IsHexDigit(char value) =>
        value is >= '0' and <= '9' ||
        value is >= 'A' and <= 'F' ||
        value is >= 'a' and <= 'f';
}
