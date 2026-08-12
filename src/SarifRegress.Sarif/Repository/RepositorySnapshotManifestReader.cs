using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Security;

namespace SarifRegress.Sarif.Repository;

/// <summary>
/// Returns a trusted repository snapshot manifest or deterministic refusal diagnostics.
/// </summary>
public sealed record RepositorySnapshotManifestReadResult(
    RepositorySnapshotManifest? Manifest,
    ImmutableArray<Diagnostic> Diagnostics);

/// <summary>
/// Reads an independently supplied, bounded raw-byte SHA-256 source manifest.
/// </summary>
public static class RepositorySnapshotManifestReader
{
    private const string SupportedSchemaVersion = "1";
    private const int Sha256HexCharacters = 64;
    private const int ReadBufferBytes = 16 * 1024;
    private static readonly byte[] Utf8ByteOrderMark = [0xEF, 0xBB, 0xBF];

    /// <summary>
    /// Reads a fully qualified manifest without following links in its physical ancestry.
    /// </summary>
    /// <param name="manifestPath">
    /// A fully qualified path resolved by the caller. Relative paths are rejected so the
    /// trust anchor never depends on the process working directory.
    /// </param>
    /// <param name="limits">Bounds applied to the untrusted manifest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The parsed manifest, or a stable fail-closed diagnostic.</returns>
    public static async ValueTask<RepositorySnapshotManifestReadResult> ReadAsync(
        string manifestPath,
        ResourceLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        var effectiveLimits = limits ?? ResourceLimits.Default;
        effectiveLimits.Validate();

        if (!Path.IsPathFullyQualified(manifestPath))
        {
            return Failure(
                "SECURITY0006",
                DiagnosticStage.Security,
                "The repository snapshot manifest path must be fully qualified.");
        }

        string fullManifestPath;
        try
        {
            fullManifestPath = Path.GetFullPath(manifestPath);
        }
        catch (Exception exception)
            when (exception is ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            return Failure(
                "SECURITY0006",
                DiagnosticStage.Security,
                "The repository snapshot manifest path is invalid.");
        }

        var manifestDirectory = Path.GetDirectoryName(fullManifestPath);
        var manifestFileName = Path.GetFileName(fullManifestPath);
        if (string.IsNullOrEmpty(manifestDirectory) ||
            string.IsNullOrEmpty(manifestFileName))
        {
            return Failure(
                "SECURITY0006",
                DiagnosticStage.Security,
                "The repository snapshot manifest path is invalid.");
        }

        using var directoryHandle = RepositoryFileHandleOpener.OpenRoot(
            manifestDirectory);
        var openResult = directoryHandle.Open(manifestFileName);
        if (openResult.Stream is not FileStream manifestStream)
        {
            return CreateOpenFailure(openResult.Failure);
        }

        byte[] manifestBytes;
        try
        {
            await using (manifestStream.ConfigureAwait(false))
            {
                manifestBytes = await ReadBoundedAsync(
                        manifestStream,
                        effectiveLimits.MaximumInputBytes,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (ManifestLimitExceededException)
        {
            return Failure(
                "SECURITY0007",
                DiagnosticStage.Security,
                $"The repository snapshot manifest exceeds the configured {effectiveLimits.MaximumInputBytes}-byte input limit.");
        }
        catch (IOException)
        {
            return Failure(
                "IO0006",
                DiagnosticStage.Io,
                "The repository snapshot manifest could not be read.");
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(
                "IO0007",
                DiagnosticStage.Io,
                "Access to the repository snapshot manifest was denied.");
        }

        try
        {
            return Success(Parse(manifestBytes, effectiveLimits));
        }
        catch (JsonException)
        {
            return Failure(
                "PARSE0020",
                DiagnosticStage.Parse,
                "The repository snapshot manifest is not valid bounded UTF-8 JSON.");
        }
        catch (ManifestSchemaException exception)
        {
            return Failure(
                exception.Code,
                DiagnosticStage.Schema,
                exception.Message);
        }
    }

    private static RepositorySnapshotManifest Parse(
        ReadOnlySpan<byte> manifestBytes,
        ResourceLimits limits)
    {
        var reader = new Utf8JsonReader(
            RemoveOptionalByteOrderMark(manifestBytes),
            new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = limits.MaximumJsonDepth,
            });
        RequireToken(ref reader, JsonTokenType.StartObject);

        string? schemaVersion = null;
        ImmutableDictionary<string, string>? expectedDigests = null;
        var rootProperties = new HashSet<string>(StringComparer.Ordinal);
        while (ReadNext(ref reader) != JsonTokenType.EndObject)
        {
            RequireCurrentToken(reader, JsonTokenType.PropertyName);
            var propertyName = ReadBoundedString(reader, limits);
            if (!rootProperties.Add(propertyName))
            {
                throw new ManifestSchemaException(
                    "SCHEMA0021",
                    $"The repository snapshot manifest contains duplicate property \"{propertyName}\".");
            }

            ReadNext(ref reader);
            switch (propertyName)
            {
                case "schemaVersion":
                    RequireCurrentToken(reader, JsonTokenType.String);
                    schemaVersion = ReadBoundedString(reader, limits);
                    break;
                case "files":
                    RequireCurrentToken(reader, JsonTokenType.StartObject);
                    expectedDigests = ReadFiles(ref reader, limits);
                    break;
                default:
                    throw new ManifestSchemaException(
                        "SCHEMA0020",
                        $"The repository snapshot manifest contains unsupported property \"{propertyName}\".");
            }
        }

        if (reader.Read())
        {
            throw new JsonException("Trailing JSON content is not permitted.");
        }

        if (!string.Equals(
                schemaVersion,
                SupportedSchemaVersion,
                StringComparison.Ordinal))
        {
            throw new ManifestSchemaException(
                "SCHEMA0020",
                $"The repository snapshot manifest schemaVersion must be \"{SupportedSchemaVersion}\".");
        }

        if (expectedDigests is null)
        {
            throw new ManifestSchemaException(
                "SCHEMA0020",
                "The repository snapshot manifest must contain a files object.");
        }

        return new RepositorySnapshotManifest(expectedDigests);
    }

    private static ImmutableDictionary<string, string> ReadFiles(
        ref Utf8JsonReader reader,
        ResourceLimits limits)
    {
        var entries = ImmutableDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        while (ReadNext(ref reader) != JsonTokenType.EndObject)
        {
            RequireCurrentToken(reader, JsonTokenType.PropertyName);
            var repositoryRelativePath = ReadBoundedString(reader, limits);
            if (!RepositorySnapshotPath.IsCanonicalAsciiRelativePath(
                    repositoryRelativePath))
            {
                throw new ManifestSchemaException(
                    "SCHEMA0022",
                    "A repository snapshot manifest path is not a canonical ASCII repository-relative path.");
            }

            if (entries.ContainsKey(repositoryRelativePath))
            {
                throw new ManifestSchemaException(
                    "SCHEMA0021",
                    $"The repository snapshot manifest contains duplicate path \"{repositoryRelativePath}\".");
            }

            RequireToken(ref reader, JsonTokenType.String);
            var digest = ReadBoundedString(reader, limits);
            if (!IsCanonicalSha256(digest))
            {
                throw new ManifestSchemaException(
                    "SCHEMA0023",
                    $"The repository snapshot digest for \"{repositoryRelativePath}\" must be 64 lowercase hexadecimal characters.");
            }

            entries.Add(repositoryRelativePath, digest);
            if (entries.Count > limits.MaximumRunCollectionItems)
            {
                throw new ManifestSchemaException(
                    "SCHEMA0024",
                    $"The repository snapshot manifest files object exceeds the configured {limits.MaximumRunCollectionItems}-item collection limit.");
            }
        }

        return entries.ToImmutable();
    }

    private static JsonTokenType ReadNext(ref Utf8JsonReader reader)
    {
        if (!reader.Read())
        {
            throw new JsonException("The JSON document ended unexpectedly.");
        }

        return reader.TokenType;
    }

    private static void RequireToken(
        ref Utf8JsonReader reader,
        JsonTokenType expected)
    {
        ReadNext(ref reader);
        RequireCurrentToken(reader, expected);
    }

    private static void RequireCurrentToken(
        Utf8JsonReader reader,
        JsonTokenType expected)
    {
        if (reader.TokenType != expected)
        {
            throw new JsonException(
                $"Expected {expected} but observed {reader.TokenType}.");
        }
    }

    private static string ReadBoundedString(
        Utf8JsonReader reader,
        ResourceLimits limits)
    {
        var value = reader.GetString()
            ?? throw new JsonException("A JSON string value was null.");
        if (value.Length > limits.MaximumStringCharacters)
        {
            throw new ManifestSchemaException(
                "SCHEMA0024",
                $"A repository snapshot manifest string exceeds the configured {limits.MaximumStringCharacters}-character limit.");
        }

        return value;
    }

    private static bool IsCanonicalSha256(string digest)
    {
        if (digest.Length != Sha256HexCharacters)
        {
            return false;
        }

        foreach (var character in digest)
        {
            if (character is not (>= '0' and <= '9') and
                not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static ReadOnlySpan<byte> RemoveOptionalByteOrderMark(
        ReadOnlySpan<byte> bytes) =>
        bytes.StartsWith(Utf8ByteOrderMark)
            ? bytes[Utf8ByteOrderMark.Length..]
            : bytes;

    // Time: O(manifest bytes). Space: O(manifest bytes).
    private static async Task<byte[]> ReadBoundedAsync(
        FileStream stream,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        if (stream.Length > maximumBytes)
        {
            throw new ManifestLimitExceededException();
        }

        var initialCapacity = (int)Math.Min(
            Math.Min(stream.Length, ReadBufferBytes),
            int.MaxValue);
        using var content = new MemoryStream(capacity: initialCapacity);
        var buffer = ArrayPool<byte>.Shared.Rent(ReadBufferBytes);
        try
        {
            long totalBytes = 0;
            while (true)
            {
                var bytesRead = await stream
                    .ReadAsync(
                        buffer.AsMemory(0, ReadBufferBytes),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    return content.ToArray();
                }

                totalBytes += bytesRead;
                if (totalBytes > maximumBytes)
                {
                    throw new ManifestLimitExceededException();
                }

                await content
                    .WriteAsync(
                        buffer.AsMemory(0, bytesRead),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static RepositorySnapshotManifestReadResult Success(
        RepositorySnapshotManifest manifest) =>
        new(manifest, ImmutableArray<Diagnostic>.Empty);

    private static RepositorySnapshotManifestReadResult CreateOpenFailure(
        RepositoryFileOpenFailure failure) =>
        failure switch
        {
            RepositoryFileOpenFailure.NotFound => Failure(
                "IO0005",
                DiagnosticStage.Io,
                "The repository snapshot manifest does not exist."),
            RepositoryFileOpenFailure.AccessDenied => Failure(
                "IO0007",
                DiagnosticStage.Io,
                "Access to the repository snapshot manifest was denied."),
            RepositoryFileOpenFailure.UnsafePath => Failure(
                "SECURITY0006",
                DiagnosticStage.Security,
                "The repository snapshot manifest path contains a symbolic link or reparse point."),
            RepositoryFileOpenFailure.UnsupportedFileType => Failure(
                "SECURITY0006",
                DiagnosticStage.Security,
                "The repository snapshot manifest is not a regular file."),
            RepositoryFileOpenFailure.SafetyUnavailable => Failure(
                "SECURITY0006",
                DiagnosticStage.Security,
                "The repository snapshot manifest could not be opened with physical no-follow containment."),
            _ => Failure(
                "IO0006",
                DiagnosticStage.Io,
                "The repository snapshot manifest could not be read."),
        };

    private static RepositorySnapshotManifestReadResult Failure(
        string code,
        DiagnosticStage stage,
        string message) =>
        new(
            Manifest: null,
            [
                new Diagnostic(
                    code,
                    DiagnosticSeverity.Error,
                    stage,
                    message),
            ]);

    private sealed class ManifestLimitExceededException : IOException
    {
    }

    private sealed class ManifestSchemaException(
        string code,
        string message) : Exception(message)
    {
        public string Code { get; } = code;
    }
}

internal static class RepositorySnapshotPath
{
    public static bool IsCanonicalAsciiRelativePath(string path)
    {
        if (string.IsNullOrEmpty(path) ||
            path[0] == '/' ||
            path[^1] == '/')
        {
            return false;
        }

        var segmentStart = 0;
        for (var index = 0; index <= path.Length; index++)
        {
            if (index < path.Length)
            {
                var character = path[index];
                if (character >= '\x7f' ||
                    character < '\x20' ||
                    character is '\\' or ':')
                {
                    return false;
                }

                if (character != '/')
                {
                    continue;
                }
            }

            var segment = path.AsSpan(segmentStart, index - segmentStart);
            if (segment.IsEmpty ||
                segment.SequenceEqual(".") ||
                segment.SequenceEqual(".."))
            {
                return false;
            }

            segmentStart = index + 1;
        }

        return true;
    }
}
