using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Reads and validates the versioned corpus label contract.
/// </summary>
public static class CorpusLabelReader
{
    private const string SupportedSchemaVersion = "1";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        MaxDepth = ResourceLimits.DefaultMaximumJsonDepth,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

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
        LabelDocument document = JsonSerializer.Deserialize<LabelDocument>(
            stream,
            SerializerOptions)
            ?? throw new InvalidDataException("The corpus label file is empty.");

        if (!string.Equals(
            document.SchemaVersion,
            SupportedSchemaVersion,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Unsupported corpus label schema version '{document.SchemaVersion ?? "<null>"}'.");
        }

        LabelledPair[] pairs = (document.Pairs ?? [])
            .Select(MapPair)
            .OrderBy(item => item.BaselineKey, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey, StringComparer.Ordinal)
            .ToArray();

        EnsureUniquePairs(pairs);

        return new CorpusLabels(
            SupportedSchemaVersion,
            pairs.ToImmutableArray(),
            ToSet(document.ExpectedAmbiguous),
            ToSet(document.ExpectedResolved),
            ToSet(document.ExpectedNew));
    }

    private static LabelledPair MapPair(LabelPairDocument pair)
    {
        ArgumentNullException.ThrowIfNull(pair);
        ArgumentException.ThrowIfNullOrWhiteSpace(pair.BaselineKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(pair.CandidateKey);

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
        return (values ?? [])
            .Select(value =>
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(value);
                return value;
            })
            .ToImmutableHashSet(StringComparer.Ordinal);
    }

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
