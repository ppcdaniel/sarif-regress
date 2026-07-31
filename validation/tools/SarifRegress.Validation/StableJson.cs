using System.Text.Encodings.Web;
using System.Text.Json;

namespace SarifRegress.Validation;

/// <summary>
/// Produces explicit-order UTF-8 JSON with no BOM, LF newlines, and a final LF.
/// </summary>
public static class StableJson
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        Indented = true,
        IndentCharacter = ' ',
        IndentSize = 2,
        MaxDepth = 128,
        NewLine = "\n",
        SkipValidation = false,
    };

    /// <summary>Serializes one JSON document through a caller-controlled property order.</summary>
    public static byte[] Serialize(Action<Utf8JsonWriter> writeDocument)
    {
        ArgumentNullException.ThrowIfNull(writeDocument);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writeDocument(writer);
            writer.Flush();
        }

        stream.WriteByte((byte)'\n');
        return stream.ToArray();
    }

    /// <summary>Writes exact bytes after ensuring the destination parent exists.</summary>
    public static void WriteFile(string path, ReadOnlySpan<byte> bytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (bytes.IsEmpty || bytes[^1] != (byte)'\n')
        {
            throw new InvalidDataException(
                "Stable JSON must be non-empty and end with one LF.");
        }

        string? parent = Path.GetDirectoryName(Path.GetFullPath(path));
        if (parent is null)
        {
            throw new InvalidDataException("A stable-output path must have a parent directory.");
        }

        Directory.CreateDirectory(parent);
        string temporaryPath = Path.Combine(
            parent,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }
}
