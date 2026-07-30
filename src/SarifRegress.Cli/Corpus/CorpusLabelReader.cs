using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Reads and validates the versioned corpus label contract.
/// </summary>
public static class CorpusLabelReader
{
    private const string SupportedSchemaVersion = "1";
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>
    /// Reads one bounded corpus label file.
    /// </summary>
    /// <param name="path">The label file path.</param>
    /// <param name="limits">The untrusted-input limits.</param>
    /// <returns>The validated immutable labels.</returns>
    public static CorpusLabels Read(string path, ResourceLimits limits)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();

        FileInfo file = new(path);
        if (!file.Exists)
        {
            throw new FileNotFoundException(
                "The corpus label file does not exist.",
                path);
        }

        if (file.Length > limits.MaximumInputBytes)
        {
            throw CreateByteLimitException(limits);
        }

        LabelDocument document;
        try
        {
            var input = ReadBoundedBytes(file, limits);
            document = ParseDocument(input, limits);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "The corpus label file is not valid label JSON.",
                exception);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException(
                "The corpus label file is not valid label JSON.",
                exception);
        }

        if (!string.Equals(
            document.SchemaVersion,
            SupportedSchemaVersion,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Unsupported corpus label schema version "
                + $"'{document.SchemaVersion ?? "<null>"}'.");
        }

        LabelledPair[] pairs = document.Pairs
            .Select(MapPair)
            .OrderBy(item => item.BaselineKey, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey, StringComparer.Ordinal)
            .ToArray();

        EnsureUniquePairs(pairs);
        ValidateStringLengths(pairs, document, limits);

        return new CorpusLabels(
            SupportedSchemaVersion,
            pairs.ToImmutableArray(),
            ToSet(document.ExpectedAmbiguous),
            ToSet(document.ExpectedResolved),
            ToSet(document.ExpectedNew))
        {
            ExpectedInvalidInputs = ToInputSet(
                document.ExpectedInvalidInputs),
        };
    }

    private static byte[] ReadBoundedBytes(
        FileInfo file,
        ResourceLimits limits)
    {
        using FileStream stream = file.OpenRead();
        var initialCapacity = (int)Math.Min(
            Math.Min(file.Length, limits.MaximumInputBytes),
            1024L * 1024L);
        using var buffer = new MemoryStream(initialCapacity);
        var rented = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long totalBytes = 0;
            int bytesRead;
            while ((bytesRead = stream.Read(rented, 0, rented.Length)) != 0)
            {
                totalBytes = checked(totalBytes + bytesRead);
                if (totalBytes > limits.MaximumInputBytes)
                {
                    throw CreateByteLimitException(limits);
                }

                buffer.Write(rented, 0, bytesRead);
            }

            return buffer.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    private static LabelDocument ParseDocument(
        ReadOnlySpan<byte> input,
        ResourceLimits limits)
    {
        if (input.Length >= 3 &&
            input[0] == 0xEF &&
            input[1] == 0xBB &&
            input[2] == 0xBF)
        {
            input = input[3..];
        }

        if (input.IsEmpty)
        {
            throw new InvalidDataException(
                "The corpus label file is empty.");
        }

        var reader = new Utf8JsonReader(
            input,
            new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = limits.MaximumJsonDepth,
            });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException(
                "The corpus label root must be a JSON object.");
        }

        string? schemaVersion = null;
        LabelPairDocument[]? pairs = null;
        string[]? expectedAmbiguous = null;
        string[]? expectedResolved = null;
        string[]? expectedNew = null;
        string[]? expectedInvalidInputs = null;
        var seenProperties = new HashSet<string>(StringComparer.Ordinal);
        var propertyCount = 0;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var propertyName = ReadPropertyName(
                ref reader,
                limits,
                ref propertyCount,
                seenProperties,
                "root object");
            ReadNextValue(ref reader);
            switch (propertyName)
            {
                case "schemaVersion":
                    schemaVersion = ReadRequiredString(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                case "pairs":
                    pairs = ReadPairs(ref reader, limits);
                    break;

                case "expectedAmbiguous":
                    expectedAmbiguous = ReadStringArray(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                case "expectedResolved":
                    expectedResolved = ReadStringArray(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                case "expectedNew":
                    expectedNew = ReadStringArray(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                case "expectedInvalidInputs":
                    expectedInvalidInputs = ReadStringArray(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                default:
                    throw new JsonException(
                        $"The corpus label property \"{propertyName}\" is not supported.");
            }
        }

        if (reader.TokenType != JsonTokenType.EndObject)
        {
            throw new JsonException(
                "The corpus label root object was not terminated.");
        }

        if (reader.Read())
        {
            throw new JsonException(
                "The corpus label file contains trailing JSON.");
        }

        if (schemaVersion is null ||
            pairs is null ||
            expectedAmbiguous is null)
        {
            throw new JsonException(
                "Corpus labels require schemaVersion, pairs, and expectedAmbiguous.");
        }

        return new LabelDocument(
            schemaVersion,
            pairs,
            expectedAmbiguous,
            expectedResolved ?? [],
            expectedNew ?? [],
            expectedInvalidInputs ?? []);
    }

    private static LabelPairDocument[] ReadPairs(
        ref Utf8JsonReader reader,
        ResourceLimits limits)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException(
                "The corpus label property \"pairs\" must be an array.");
        }

        var values = new List<LabelPairDocument>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            EnsureCanAdd(values.Count, "pairs", limits);
            values.Add(ReadPair(ref reader, limits));
        }

        if (reader.TokenType != JsonTokenType.EndArray)
        {
            throw new JsonException(
                "The corpus label pair array was not terminated.");
        }

        return values.ToArray();
    }

    private static LabelPairDocument ReadPair(
        ref Utf8JsonReader reader,
        ResourceLimits limits)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException(
                "A corpus labelled pair must be an object.");
        }

        string? baselineKey = null;
        string? candidateKey = null;
        string? classification = null;
        var seenProperties = new HashSet<string>(StringComparer.Ordinal);
        var propertyCount = 0;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var propertyName = ReadPropertyName(
                ref reader,
                limits,
                ref propertyCount,
                seenProperties,
                "pair object");
            ReadNextValue(ref reader);
            switch (propertyName)
            {
                case "baselineKey":
                    baselineKey = ReadRequiredString(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                case "candidateKey":
                    candidateKey = ReadRequiredString(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                case "classification":
                    classification = ReadRequiredString(
                        ref reader,
                        limits,
                        propertyName);
                    break;

                default:
                    throw new JsonException(
                        $"The corpus pair property \"{propertyName}\" is not supported.");
            }
        }

        if (reader.TokenType != JsonTokenType.EndObject)
        {
            throw new JsonException(
                "A corpus labelled pair object was not terminated.");
        }

        if (baselineKey is null ||
            candidateKey is null ||
            classification is null)
        {
            throw new JsonException(
                "A labelled pair requires baselineKey, candidateKey, and classification.");
        }

        return new LabelPairDocument(
            baselineKey,
            candidateKey,
            classification);
    }

    private static string[] ReadStringArray(
        ref Utf8JsonReader reader,
        ResourceLimits limits,
        string propertyName)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException(
                $"The corpus label property \"{propertyName}\" must be an array.");
        }

        var values = new List<string>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            EnsureCanAdd(values.Count, propertyName, limits);
            values.Add(ReadRequiredString(
                ref reader,
                limits,
                propertyName));
        }

        if (reader.TokenType != JsonTokenType.EndArray)
        {
            throw new JsonException(
                $"The corpus label array \"{propertyName}\" was not terminated.");
        }

        return values.ToArray();
    }

    private static string ReadPropertyName(
        ref Utf8JsonReader reader,
        ResourceLimits limits,
        ref int propertyCount,
        ISet<string> seenProperties,
        string collectionName)
    {
        if (reader.TokenType != JsonTokenType.PropertyName)
        {
            throw new JsonException(
                "A corpus label property name was expected.");
        }

        EnsureCanAdd(propertyCount, collectionName, limits);
        propertyCount++;
        var propertyName = ReadBoundedString(ref reader, limits);
        if (!seenProperties.Add(propertyName))
        {
            throw new JsonException(
                $"The corpus label object contains duplicate property "
                + $"\"{propertyName}\".");
        }

        return propertyName;
    }

    private static void ReadNextValue(ref Utf8JsonReader reader)
    {
        if (!reader.Read())
        {
            throw new JsonException(
                "A corpus label property value is missing.");
        }
    }

    private static string ReadRequiredString(
        ref Utf8JsonReader reader,
        ResourceLimits limits,
        string propertyName)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException(
                $"The corpus label value \"{propertyName}\" must be a string.");
        }

        return ReadBoundedString(ref reader, limits);
    }

    private static string ReadBoundedString(
        ref Utf8JsonReader reader,
        ResourceLimits limits)
    {
        var rawValue = reader.ValueSpan;
        var maximumRawLength = checked(
            (long)limits.MaximumStringCharacters * 6);
        if (rawValue.Length > maximumRawLength)
        {
            throw CreateStringLimitException();
        }

        var decodedCharacters = reader.ValueIsEscaped
            ? CountEscapedUtf16Characters(rawValue)
            : StrictUtf8.GetCharCount(rawValue);
        if (decodedCharacters > limits.MaximumStringCharacters)
        {
            throw CreateStringLimitException();
        }

        var value = reader.GetString()
            ?? throw new JsonException(
                "A corpus label string cannot be null.");
        if (value.Length > limits.MaximumStringCharacters)
        {
            throw CreateStringLimitException();
        }

        return value;
    }

    private static int CountEscapedUtf16Characters(
        ReadOnlySpan<byte> value)
    {
        var characters = 0;
        var segmentStart = 0;
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != (byte)'\\')
            {
                continue;
            }

            characters = checked(
                characters +
                StrictUtf8.GetCharCount(value[segmentStart..index]));
            if (index + 1 >= value.Length)
            {
                throw new JsonException(
                    "A JSON escape sequence is incomplete.");
            }

            characters = checked(characters + 1);
            index += value[index + 1] == (byte)'u' ? 5 : 1;
            segmentStart = index + 1;
        }

        return checked(
            characters +
            StrictUtf8.GetCharCount(value[segmentStart..]));
    }

    private static LabelledPair MapPair(LabelPairDocument pair)
    {
        if (string.IsNullOrWhiteSpace(pair.BaselineKey)
            || string.IsNullOrWhiteSpace(pair.CandidateKey))
        {
            throw new InvalidDataException(
                "A labelled pair requires baselineKey and candidateKey.");
        }

        if (!Enum.TryParse<FindingClassification>(
            pair.Classification,
            ignoreCase: true,
            out var classification) ||
            classification is FindingClassification.New or
                FindingClassification.Resolved or
                FindingClassification.Ambiguous)
        {
            throw new InvalidDataException(
                $"Invalid labelled pair classification "
                + $"'{pair.Classification}'.");
        }

        return new LabelledPair(
            pair.BaselineKey,
            pair.CandidateKey,
            classification);
    }

    private static void EnsureUniquePairs(IEnumerable<LabelledPair> pairs)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in pairs)
        {
            var key = $"{pair.BaselineKey.Length}:{pair.BaselineKey}" +
                $"{pair.CandidateKey.Length}:{pair.CandidateKey}";
            if (!keys.Add(key))
            {
                throw new InvalidDataException(
                    $"Duplicate labelled pair '{pair.BaselineKey}' "
                    + $"-> '{pair.CandidateKey}'.");
            }
        }
    }

    private static ImmutableHashSet<string> ToSet(
        IEnumerable<string> values)
    {
        var result = ImmutableHashSet.CreateBuilder<string>(
            StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidDataException(
                    "An expected finding identity cannot be empty.");
            }

            if (!result.Add(value))
            {
                throw new InvalidDataException(
                    $"Duplicate expected finding identity '{value}'.");
            }
        }

        return result.ToImmutable();
    }

    private static ImmutableHashSet<InputKind> ToInputSet(
        IEnumerable<string> values)
    {
        var result = ImmutableHashSet.CreateBuilder<InputKind>();
        foreach (var value in values)
        {
            if (!Enum.TryParse<InputKind>(
                    value,
                    ignoreCase: true,
                    out var input)
                || input is not InputKind.Baseline and not InputKind.Candidate)
            {
                throw new InvalidDataException(
                    $"Invalid expected input-error side '{value}'.");
            }

            if (!result.Add(input))
            {
                throw new InvalidDataException(
                    $"Duplicate expected input-error side '{value}'.");
            }
        }

        return result.ToImmutable();
    }

    private static void EnsureCanAdd(
        int count,
        string collectionName,
        ResourceLimits limits)
    {
        if (count >= limits.MaximumRunCollectionItems)
        {
            throw new InvalidDataException(
                $"Corpus label collection '{collectionName}' exceeds the "
                + $"{limits.MaximumRunCollectionItems}-item limit.");
        }
    }

    private static void ValidateStringLengths(
        IEnumerable<LabelledPair> pairs,
        LabelDocument document,
        ResourceLimits limits)
    {
        var values = pairs
            .SelectMany(item => new[]
            {
                item.BaselineKey,
                item.CandidateKey,
            })
            .Concat(document.ExpectedAmbiguous)
            .Concat(document.ExpectedResolved)
            .Concat(document.ExpectedNew)
            .Concat(document.ExpectedInvalidInputs);
        if (values.Any(value =>
                value.Length > limits.MaximumStringCharacters))
        {
            throw CreateStringLimitException();
        }
    }

    private static InvalidDataException CreateByteLimitException(
        ResourceLimits limits) =>
        new(
            $"The corpus label file exceeds the "
            + $"{limits.MaximumInputBytes} byte limit.");

    private static InvalidDataException CreateStringLimitException() =>
        new(
            "A corpus label string exceeds the configured character limit.");

    private sealed record LabelDocument(
        string SchemaVersion,
        LabelPairDocument[] Pairs,
        string[] ExpectedAmbiguous,
        string[] ExpectedResolved,
        string[] ExpectedNew,
        string[] ExpectedInvalidInputs);

    private sealed record LabelPairDocument(
        string BaselineKey,
        string CandidateKey,
        string Classification);
}
