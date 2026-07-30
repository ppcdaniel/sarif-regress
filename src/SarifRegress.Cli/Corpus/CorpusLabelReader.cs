using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
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
            throw new FileNotFoundException("The corpus label file does not exist.", path);
        }

        if (file.Length > limits.MaximumInputBytes)
        {
            throw new InvalidDataException(
                $"The corpus label file exceeds the {limits.MaximumInputBytes} byte limit.");
        }

        using FileStream stream = file.OpenRead();
        LabelDocument document;
        try
        {
            document = JsonSerializer.Deserialize<LabelDocument>(
                stream,
                CreateSerializerOptions(limits))
                ?? throw new InvalidDataException(
                    "The corpus label file is empty.");
        }
        catch (JsonException exception)
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
                $"Unsupported corpus label schema version '{document.SchemaVersion ?? "<null>"}'.");
        }

        EnsureCollectionBound(
            document.Pairs?.Length ?? 0,
            "pairs",
            limits);
        EnsureCollectionBound(
            document.ExpectedAmbiguous?.Length ?? 0,
            "expectedAmbiguous",
            limits);
        EnsureCollectionBound(
            document.ExpectedResolved?.Length ?? 0,
            "expectedResolved",
            limits);
        EnsureCollectionBound(
            document.ExpectedNew?.Length ?? 0,
            "expectedNew",
            limits);
        EnsureCollectionBound(
            document.ExpectedInvalidInputs?.Length ?? 0,
            "expectedInvalidInputs",
            limits);
        LabelledPair[] pairs = (document.Pairs ?? [])
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
            ExpectedInvalidInputs = ToInputSet(document.ExpectedInvalidInputs),
        };
    }

    private static LabelledPair MapPair(LabelPairDocument pair)
    {
        if (pair is null
            || string.IsNullOrWhiteSpace(pair.BaselineKey)
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
                $"Invalid labelled pair classification '{pair.Classification ?? "<null>"}'.");
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
                    $"Duplicate labelled pair '{pair.BaselineKey}' -> '{pair.CandidateKey}'.");
            }
        }
    }

    private static ImmutableHashSet<string> ToSet(IEnumerable<string>? values)
    {
        var result = ImmutableHashSet.CreateBuilder<string>(
            StringComparer.Ordinal);
        foreach (var value in values ?? [])
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
        IEnumerable<string>? values)
    {
        var result = ImmutableHashSet.CreateBuilder<InputKind>();
        foreach (var value in values ?? [])
        {
            if (!Enum.TryParse<InputKind>(
                    value,
                    ignoreCase: true,
                    out var input)
                || input is not InputKind.Baseline and not InputKind.Candidate)
            {
                throw new InvalidDataException(
                    $"Invalid expected input-error side '{value ?? "<null>"}'.");
            }

            if (!result.Add(input))
            {
                throw new InvalidDataException(
                    $"Duplicate expected input-error side '{value}'.");
            }
        }

        return result.ToImmutable();
    }

    private static void EnsureCollectionBound(
        int count,
        string collectionName,
        ResourceLimits limits)
    {
        if (count > limits.MaximumRunCollectionItems)
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
            .Concat(document.ExpectedAmbiguous ?? [])
            .Concat(document.ExpectedResolved ?? [])
            .Concat(document.ExpectedNew ?? [])
            .Concat(document.ExpectedInvalidInputs ?? []);
        if (values.Any(value =>
                value is not null
                && value.Length > limits.MaximumStringCharacters))
        {
            throw new InvalidDataException(
                "A corpus label string exceeds the configured character limit.");
        }
    }

    private static JsonSerializerOptions CreateSerializerOptions(
        ResourceLimits limits) =>
        new()
        {
            MaxDepth = Math.Min(
                ResourceLimits.DefaultMaximumJsonDepth,
                limits.MaximumJsonDepth),
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

    private sealed record LabelDocument
    {
        [JsonPropertyName("schemaVersion")]
        public string? SchemaVersion { get; init; }

        [JsonPropertyName("pairs")]
        public LabelPairDocument[]? Pairs { get; init; }

        [JsonPropertyName("expectedAmbiguous")]
        public string[]? ExpectedAmbiguous { get; init; }

        [JsonPropertyName("expectedResolved")]
        public string[]? ExpectedResolved { get; init; }

        [JsonPropertyName("expectedNew")]
        public string[]? ExpectedNew { get; init; }

        [JsonPropertyName("expectedInvalidInputs")]
        public string[]? ExpectedInvalidInputs { get; init; }
    }

    private sealed record LabelPairDocument
    {
        [JsonPropertyName("baselineKey")]
        public string? BaselineKey { get; init; }

        [JsonPropertyName("candidateKey")]
        public string? CandidateKey { get; init; }

        [JsonPropertyName("classification")]
        public string? Classification { get; init; }
    }
}
