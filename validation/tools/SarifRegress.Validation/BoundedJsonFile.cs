using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.Validation;

/// <summary>
/// Reads repository JSON through one bounded, non-link file handle.
/// </summary>
public static class BoundedJsonFile
{
    private const int ReadBufferBytes = 64 * 1024;

    /// <summary>Reads at most <paramref name="maximumBytes"/> from a regular file.</summary>
    public static byte[] ReadBytes(string path, long maximumBytes)
    {
        string fullPath = Path.GetFullPath(path);
        string approvedRoot = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("A bounded input path must have a parent directory.");
        return ReadBytes(path, maximumBytes, approvedRoot);
    }

    /// <summary>
    /// Reads a file through a fixed handle anchored below an approved non-link root.
    /// </summary>
    public static byte[] ReadBytes(
        string path,
        long maximumBytes,
        string approvedRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(approvedRoot);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(approvedRoot));
        string fullPath = Path.GetFullPath(path);
        string relativePath = Path.GetRelativePath(root, fullPath)
            .Replace(Path.DirectorySeparatorChar, '/');
        StablePath.RequireRepositoryRelative(relativePath, "bounded input path");
        RepositoryFileOpenResult openResult = RepositoryFileHandleOpener.Open(
            root,
            relativePath);
        using FileStream stream = openResult.Stream ?? throw CreateOpenFailure(
            path,
            openResult.Failure);
        if (stream.Length > maximumBytes)
        {
            throw new InvalidDataException(
                $"JSON file '{Path.GetFileName(path)}' exceeds its {maximumBytes}-byte limit.");
        }

        int capacity = checked((int)Math.Min(stream.Length, maximumBytes));
        using var destination = new MemoryStream(capacity);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ReadBufferBytes);
        try
        {
            long total = 0;
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                total = checked(total + bytesRead);
                if (total > maximumBytes)
                {
                    throw new InvalidDataException(
                        $"JSON file '{Path.GetFileName(path)}' exceeds its {maximumBytes}-byte limit.");
                }

                destination.Write(buffer, 0, bytesRead);
            }

            return destination.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>Parses bounded UTF-8 JSON with comments and trailing commas disabled.</summary>
    public static JsonNode ReadNode(
        string path,
        long maximumBytes,
        int maximumDepth,
        int maximumStringCharacters = 64 * 1024,
        string? approvedRoot = null)
    {
        byte[] bytes = approvedRoot is null
            ? ReadBytes(path, maximumBytes)
            : ReadBytes(path, maximumBytes, approvedRoot);
        return ParseNode(
            bytes,
            maximumDepth,
            maximumStringCharacters,
            Path.GetFileName(path));
    }

    /// <summary>Parses already-read bounded bytes without reopening their source.</summary>
    public static JsonNode ParseNode(
        ReadOnlySpan<byte> bytes,
        int maximumDepth,
        int maximumStringCharacters,
        string logicalName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalName);
        EnsureTokenBoundsAndUniqueProperties(
            bytes,
            maximumDepth,
            maximumStringCharacters);
        JsonNode? node = JsonNode.Parse(
            bytes,
            documentOptions: new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = maximumDepth,
            });
        JsonNode value = node ?? throw new InvalidDataException(
            $"JSON file '{logicalName}' contains only null.");
        EnsureStringBounds(value, maximumStringCharacters);
        return value;
    }

    /// <summary>Rejects duplicate object keys and oversized decoded JSON strings.</summary>
    public static void EnsureTokenBoundsAndUniqueProperties(
        ReadOnlySpan<byte> bytes,
        int maximumDepth,
        int maximumStringCharacters)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumDepth);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumStringCharacters);
        var reader = new Utf8JsonReader(
            bytes,
            new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = maximumDepth,
            });
        var objectProperties = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                objectProperties.Push(new HashSet<string>(StringComparer.Ordinal));
            }
            else if (reader.TokenType == JsonTokenType.EndObject)
            {
                if (objectProperties.Count == 0)
                {
                    throw new InvalidDataException("JSON object nesting is invalid.");
                }

                objectProperties.Pop();
            }
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString()
                    ?? throw new InvalidDataException("A JSON property name is null.");
                if (name.Length > maximumStringCharacters)
                {
                    throw new InvalidDataException(
                        "A JSON property name exceeds the configured string limit.");
                }

                if (objectProperties.Count == 0
                    || !objectProperties.Peek().Add(name))
                {
                    throw new InvalidDataException(
                        $"JSON repeats object property '{name}'.");
                }
            }
            else if (reader.TokenType == JsonTokenType.String
                && (reader.GetString()?.Length ?? 0) > maximumStringCharacters)
            {
                throw new InvalidDataException(
                    "A JSON string value exceeds the configured string limit.");
            }
        }

        if (objectProperties.Count != 0)
        {
            throw new InvalidDataException("JSON object nesting is incomplete.");
        }
    }

    /// <summary>Rejects oversized JSON property names and string values.</summary>
    public static void EnsureStringBounds(JsonNode node, int maximumCharacters)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumCharacters);
        Visit(node);

        void Visit(JsonNode current)
        {
            if (current is JsonObject objectValue)
            {
                foreach ((string name, JsonNode? child) in objectValue)
                {
                    if (name.Length > maximumCharacters)
                    {
                        throw new InvalidDataException(
                            "A JSON property name exceeds the configured string limit.");
                    }

                    if (child is not null)
                    {
                        Visit(child);
                    }
                }
            }
            else if (current is JsonArray arrayValue)
            {
                foreach (JsonNode? child in arrayValue)
                {
                    if (child is not null)
                    {
                        Visit(child);
                    }
                }
            }
            else if (current.GetValueKind() == JsonValueKind.String
                && current.GetValue<string>().Length > maximumCharacters)
            {
                throw new InvalidDataException(
                    "A JSON string value exceeds the configured string limit.");
            }
        }
    }

    /// <summary>Rejects oversized strings in an already parsed JSON document.</summary>
    public static void EnsureStringBounds(JsonElement element, int maximumCharacters)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumCharacters);
        Visit(element);

        void Visit(JsonElement current)
        {
            if (current.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty property in current.EnumerateObject())
                {
                    if (property.Name.Length > maximumCharacters)
                    {
                        throw new InvalidDataException(
                            "A JSON property name exceeds the configured string limit.");
                    }

                    Visit(property.Value);
                }
            }
            else if (current.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement child in current.EnumerateArray())
                {
                    Visit(child);
                }
            }
            else if (current.ValueKind == JsonValueKind.String
                && (current.GetString()?.Length ?? 0) > maximumCharacters)
            {
                throw new InvalidDataException(
                    "A JSON string value exceeds the configured string limit.");
            }
        }
    }

    /// <summary>Returns the lowercase SHA-256 digest of the exact file bytes.</summary>
    public static string ComputeSha256(string path, long maximumBytes) =>
        Convert.ToHexString(SHA256.HashData(ReadBytes(path, maximumBytes)))
            .ToLowerInvariant();

    /// <summary>Returns the lowercase digest after an anchored safe open.</summary>
    public static string ComputeSha256(
        string path,
        long maximumBytes,
        string approvedRoot) => Convert.ToHexString(
            SHA256.HashData(ReadBytes(path, maximumBytes, approvedRoot)))
        .ToLowerInvariant();

    /// <summary>Rejects absent, directory, and symbolic-link inputs.</summary>
    public static void EnsureRegularFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"Required file '{Path.GetFileName(path)}' does not exist.",
                path);
        }

        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException(
                $"Required file '{Path.GetFileName(path)}' must be a regular non-link file.");
        }
    }

    private static Exception CreateOpenFailure(
        string path,
        RepositoryFileOpenFailure failure) => failure switch
        {
            RepositoryFileOpenFailure.NotFound => new FileNotFoundException(
                $"Required file '{Path.GetFileName(path)}' does not exist.",
                path),
            RepositoryFileOpenFailure.UnsafePath => new InvalidDataException(
                $"Required file '{Path.GetFileName(path)}' traverses a symbolic link or reparse point."),
            RepositoryFileOpenFailure.UnsupportedFileType => new InvalidDataException(
                $"Required file '{Path.GetFileName(path)}' is not a regular file."),
            RepositoryFileOpenFailure.AccessDenied => new UnauthorizedAccessException(
                $"Required file '{Path.GetFileName(path)}' cannot be read."),
            RepositoryFileOpenFailure.SafetyUnavailable => new PlatformNotSupportedException(
                "The platform cannot provide race-free validation input containment."),
            _ => new IOException(
                $"Required file '{Path.GetFileName(path)}' could not be opened safely."),
        };
}
