using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using SarifRegress.Core.Reporting;
using SarifRegress.Core.Security;

namespace SarifRegress.Report;

/// <summary>
/// Serializes the versioned comparison contract as canonical UTF-8 JSON.
/// </summary>
public static class StableJsonReportSerializer
{
    private const int MaximumDepth = 64;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        AllowTrailingCommas = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        DictionaryKeyPolicy = null,
        Encoder = JavaScriptEncoder.Default,
        IndentCharacter = ' ',
        IndentSize = 2,
        MaxDepth = MaximumDepth,
        NewLine = "\n",
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = null,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
        WriteIndented = true,
    };

    /// <summary>
    /// Serializes a report as UTF-8 without a byte-order mark and with a final LF.
    /// </summary>
    /// <param name="report">The stable comparison report.</param>
    /// <returns>The canonical JSON bytes.</returns>
    public static byte[] Serialize(ComparisonReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var canonicalReport = StableComparisonReport.NormalizeAndValidate(
            report,
            ResourceLimits.Default);
        using var stream = new MemoryStream();
        StableJsonReportWriter.Write(stream, canonicalReport);
        return stream.ToArray();
    }

    /// <summary>
    /// Streams the canonical report through a bounded-memory hash sink.
    /// </summary>
    /// <param name="report">The stable comparison report.</param>
    /// <returns>Exact output size, explanation size, and SHA-256.</returns>
    public static StableJsonSerializationMeasurement Measure(
        ComparisonReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var canonicalReport = StableComparisonReport.NormalizeAndValidate(
            report,
            ResourceLimits.Default);
        return MeasureCanonical(canonicalReport);
    }

    internal static StableJsonSerializationMeasurement MeasureCanonical(
        ComparisonReport canonicalReport)
    {
        ArgumentNullException.ThrowIfNull(canonicalReport);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stream = new HashingWriteStream(hash);
        var result = StableJsonReportWriter.Write(stream, canonicalReport);
        return new StableJsonSerializationMeasurement(
            checked((int)result.OutputBytes),
            checked((int)result.ExplanationBytes),
            Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    /// <summary>
    /// Deserializes a stable comparison report from UTF-8 JSON bytes.
    /// </summary>
    /// <param name="utf8Json">The report bytes.</param>
    /// <returns>The validated comparison report.</returns>
    /// <exception cref="JsonException">
    /// The document is malformed or violates the supported wire contract.
    /// </exception>
    public static ComparisonReport Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        return Deserialize(utf8Json, ResourceLimits.Default);
    }

    /// <summary>
    /// Deserializes a stable comparison report using explicit resource bounds.
    /// </summary>
    /// <param name="utf8Json">The report bytes.</param>
    /// <param name="limits">Resource bounds for untrusted report content.</param>
    /// <returns>The validated, canonically ordered comparison report.</returns>
    /// <exception cref="JsonException">
    /// The document is malformed, exceeds a resource bound, or violates the wire contract.
    /// </exception>
    public static ComparisonReport Deserialize(
        ReadOnlySpan<byte> utf8Json,
        ResourceLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        if (utf8Json.IsEmpty)
        {
            throw new JsonException("A stable comparison report cannot be empty.");
        }

        if (utf8Json.Length > limits.MaximumInputBytes)
        {
            throw new JsonException(
                $"The stable comparison report exceeds the configured "
                + $"{limits.MaximumInputBytes}-byte limit.");
        }

        if (utf8Json.Length >= 3
            && utf8Json[0] == 0xEF
            && utf8Json[1] == 0xBB
            && utf8Json[2] == 0xBF)
        {
            throw new JsonException(
                "Stable comparison JSON must use UTF-8 without a byte-order mark.");
        }

        var document = JsonSerializer.Deserialize<ReportDocumentDto>(
            utf8Json,
            CreateReaderOptions(limits));
        if (document is null)
        {
            throw new JsonException(
                "The stable comparison report must be a JSON object.");
        }

        try
        {
            return StableComparisonReport.NormalizeAndValidate(
                StableJsonWireMapper.FromDto(document),
                limits);
        }
        catch (ArgumentException exception)
        {
            throw new JsonException(
                "The stable comparison report violates a domain constraint.",
                exception);
        }
    }

    /// <summary>
    /// Writes canonical report bytes to a file.
    /// </summary>
    /// <param name="path">The destination file path.</param>
    /// <param name="report">The stable comparison report.</param>
    public static void WriteFile(string path, ComparisonReport report)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(report);
        File.WriteAllBytes(path, Serialize(report));
    }

    /// <summary>
    /// Reads and validates a stable report file.
    /// </summary>
    /// <param name="path">The report file path.</param>
    /// <returns>The deserialized comparison report.</returns>
    public static ComparisonReport ReadFile(string path)
    {
        return ReadFile(path, ResourceLimits.Default);
    }

    /// <summary>
    /// Reads and validates a stable report file using explicit resource bounds.
    /// </summary>
    /// <param name="path">The report file path.</param>
    /// <param name="limits">Resource bounds for untrusted report content.</param>
    /// <returns>The deserialized comparison report.</returns>
    public static ComparisonReport ReadFile(
        string path,
        ResourceLimits limits)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();

        var file = new FileInfo(path);
        if (file.Length > limits.MaximumInputBytes)
        {
            throw new JsonException(
                $"The stable comparison report exceeds the configured "
                + $"{limits.MaximumInputBytes}-byte limit.");
        }

        return Deserialize(File.ReadAllBytes(path), limits);
    }

    private static JsonSerializerOptions CreateReaderOptions(
        ResourceLimits limits)
    {
        var maximumDepth = Math.Min(MaximumDepth, limits.MaximumJsonDepth);
        return maximumDepth == MaximumDepth
            ? SerializerOptions
            : new JsonSerializerOptions(SerializerOptions)
            {
                MaxDepth = maximumDepth,
            };
    }

    private sealed class HashingWriteStream(IncrementalHash hash) : Stream
    {
        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            hash.AppendData(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            hash.AppendData(buffer);
        }

        public override void WriteByte(byte value)
        {
            Span<byte> buffer = [value];
            hash.AppendData(buffer);
        }
    }
}
