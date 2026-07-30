using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Utility;

namespace SarifRegress.Sarif.Fingerprints;

/// <summary>
/// Returns preserved producer fingerprints and deterministic import diagnostics.
/// </summary>
public sealed record FingerprintImportResult(
    ImmutableArray<ProducerFingerprint> Fingerprints,
    ImmutableArray<Diagnostic> Diagnostics);

internal readonly record struct FingerprintIngestionResult(
    ImmutableArray<ProducerFingerprint> Fingerprints,
    ImmutableArray<Diagnostic> Diagnostics);

/// <summary>
/// Imports producer fingerprints, assesses collisions, and derives project-owned identity hashes.
/// </summary>
public static class FingerprintProcessor
{
    /// <summary>
    /// Gets the first derived fingerprint name.
    /// </summary>
    public const string DerivedFingerprintName =
        "sarifregress/rule-path-context/v1";

    /// <summary>
    /// Gets the derived fingerprint algorithm identifier.
    /// </summary>
    public const string DerivedAlgorithmVersion =
        "rule-path-context/v1";

    private const string EmbeddedSnippetAlgorithmVersion =
        "embedded-snippet/v1";

    /// <summary>
    /// Imports full and partial fingerprint maps without coalescing equal names.
    /// </summary>
    /// <param name="fingerprints">The full fingerprint map.</param>
    /// <param name="partialFingerprints">The partial fingerprint map.</param>
    /// <param name="sourceReference">The owning result source pointer.</param>
    /// <returns>Preserved values in stable order.</returns>
    public static FingerprintImportResult Import(
        IReadOnlyDictionary<string, string?>? fingerprints,
        IReadOnlyDictionary<string, string?>? partialFingerprints,
        SourceReference? sourceReference = null)
    {
        var imported = ImportCore(
            fingerprints,
            partialFingerprints,
            sourceReference,
            FingerprintReliability.Unknown);
        return new FingerprintImportResult(
            imported.Fingerprints,
            imported.Diagnostics);
    }

    internal static FingerprintIngestionResult ImportForIngestion(
        IReadOnlyDictionary<string, string?>? fingerprints,
        IReadOnlyDictionary<string, string?>? partialFingerprints,
        SourceReference sourceReference) =>
        ImportCore(
            fingerprints,
            partialFingerprints,
            sourceReference,
            FingerprintReliability.High);

    private static FingerprintIngestionResult ImportCore(
        IReadOnlyDictionary<string, string?>? fingerprints,
        IReadOnlyDictionary<string, string?>? partialFingerprints,
        SourceReference? sourceReference,
        FingerprintReliability initialReliability)
    {
        var fingerprintCount = fingerprints?.Count ?? 0;
        var partialFingerprintCount = partialFingerprints?.Count ?? 0;
        if (fingerprintCount + partialFingerprintCount == 1)
        {
            return fingerprintCount == 1
                ? ImportSingle(
                    fingerprints!,
                    ProducerFingerprintSource.Fingerprint,
                    sourceReference,
                    initialReliability)
                : ImportSingle(
                    partialFingerprints!,
                    ProducerFingerprintSource.PartialFingerprint,
                    sourceReference,
                    initialReliability);
        }

        var imported = new List<ProducerFingerprint>();
        var diagnostics = new List<Diagnostic>();
        ImportMap(
            fingerprints,
            ProducerFingerprintSource.Fingerprint,
            sourceReference,
            initialReliability,
            imported,
            diagnostics);
        ImportMap(
            partialFingerprints,
            ProducerFingerprintSource.PartialFingerprint,
            sourceReference,
            initialReliability,
            imported,
            diagnostics);

        return new FingerprintIngestionResult(
            imported
                .OrderBy(item => item.Family, StringComparer.Ordinal)
                .ThenByDescending(item => item.Version)
                .ThenBy(item => item.Name, StringComparer.Ordinal)
                .ThenBy(item => item.Source)
                .ThenBy(item => item.Value, StringComparer.Ordinal)
                .ToImmutableArray(),
            Diagnostic.Sort(diagnostics));
    }

    /// <summary>
    /// Marks values that collide inside the same run-and-rule bucket as degraded.
    /// </summary>
    /// <param name="findings">Canonical findings from one logical input.</param>
    /// <returns>Findings with immutable assessed producer fingerprints.</returns>
    public static ImmutableArray<Finding> AssessReliability(
        IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var findingArray = findings.ToImmutableArray();
        var occurrencesByFingerprint =
            new Dictionary<FingerprintBucketKey, FingerprintOccurrence>();

        foreach (var finding in findingArray)
        {
            foreach (var fingerprint in finding.ProducerFingerprints)
            {
                var key = new FingerprintBucketKey(
                    finding.Run.StableRunKey,
                    finding.Rule.CanonicalId,
                    fingerprint.Name,
                    fingerprint.Value);
                if (!occurrencesByFingerprint.TryGetValue(
                        key,
                        out var occurrence))
                {
                    occurrencesByFingerprint.Add(
                        key,
                        new FingerprintOccurrence(
                            finding.FindingKey,
                            Collided: false));
                    continue;
                }

                if (!occurrence.Collided &&
                    !string.Equals(
                        occurrence.FirstFindingKey,
                        finding.FindingKey,
                        StringComparison.Ordinal))
                {
                    occurrencesByFingerprint[key] =
                        occurrence with { Collided = true };
                }
            }
        }

        ImmutableArray<Finding>.Builder? assessed = null;
        for (var findingIndex = 0;
             findingIndex < findingArray.Length;
             findingIndex++)
        {
            var finding = findingArray[findingIndex];
            var requiresClone = false;
            foreach (var fingerprint in finding.ProducerFingerprints)
            {
                if (fingerprint.Reliability != GetReliability(
                        finding,
                        fingerprint,
                        occurrencesByFingerprint))
                {
                    requiresClone = true;
                    break;
                }
            }

            if (!requiresClone)
            {
                assessed?.Add(finding);
                continue;
            }

            if (assessed is null)
            {
                assessed = ImmutableArray.CreateBuilder<Finding>(
                    findingArray.Length);
                for (var earlierIndex = 0;
                     earlierIndex < findingIndex;
                     earlierIndex++)
                {
                    assessed.Add(findingArray[earlierIndex]);
                }
            }

            assessed.Add(
                CloneWithFingerprints(
                    finding,
                    finding.ProducerFingerprints.Select(
                        fingerprint => fingerprint with
                        {
                            Reliability = GetReliability(
                                finding,
                                fingerprint,
                                occurrencesByFingerprint),
                        })));
        }

        return assessed is null
            ? findingArray
            : assessed.MoveToImmutable();
    }

    private static FingerprintReliability GetReliability(
        Finding finding,
        ProducerFingerprint fingerprint,
        IReadOnlyDictionary<FingerprintBucketKey, FingerprintOccurrence>
            occurrencesByFingerprint)
    {
        var key = new FingerprintBucketKey(
            finding.Run.StableRunKey,
            finding.Rule.CanonicalId,
            fingerprint.Name,
            fingerprint.Value);
        return occurrencesByFingerprint[key].Collided
            ? FingerprintReliability.Degraded
            : FingerprintReliability.High;
    }

    /// <summary>
    /// Derives a line-number-independent fingerprint from stable rule, path, and source context.
    /// </summary>
    /// <param name="finding">The canonical finding.</param>
    /// <returns>A project-namespaced fingerprint, or null when stable context is unavailable.</returns>
    public static DerivedFingerprint? DeriveRulePathContext(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var repositoryPath =
            finding.PrimaryLocation?.Path.RepositoryRelativePath;
        if (string.IsNullOrEmpty(repositoryPath))
        {
            return null;
        }

        var contextHash = finding.Context?.SnippetHash;
        if (contextHash is null &&
            finding.PrimaryLocation?.EmbeddedSnippet is string embeddedSnippet)
        {
            contextHash = VersionedHash.Compute(
                EmbeddedSnippetAlgorithmVersion,
                NormalizeLineEndings(embeddedSnippet));
        }

        if (contextHash is null)
        {
            return null;
        }

        var value = VersionedHash.Compute(
            DerivedAlgorithmVersion,
            finding.Producer.Family,
            finding.Rule.CanonicalId,
            repositoryPath,
            contextHash);
        return new DerivedFingerprint(
            DerivedFingerprintName,
            value,
            DerivedAlgorithmVersion);
    }

    private static void ImportMap(
        IReadOnlyDictionary<string, string?>? map,
        ProducerFingerprintSource source,
        SourceReference? sourceReference,
        FingerprintReliability initialReliability,
        ICollection<ProducerFingerprint> destination,
        ICollection<Diagnostic> diagnostics)
    {
        if (map is null)
        {
            return;
        }

        foreach (var entry in map.OrderBy(
                     item => item.Key,
                     StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(entry.Key) ||
                string.IsNullOrWhiteSpace(entry.Value))
            {
                diagnostics.Add(
                    new Diagnostic(
                        "CANON0020",
                        DiagnosticSeverity.Warning,
                        DiagnosticStage.Fingerprint,
                        "A producer fingerprint with an empty name or value was ignored.",
                        sourceReference));
                continue;
            }

            ParseHierarchicalName(
                entry.Key,
                out var family,
                out var version);
            destination.Add(
                new ProducerFingerprint(
                    entry.Key,
                    family,
                    version,
                    entry.Value,
                    initialReliability,
                    source));
        }
    }

    private static FingerprintIngestionResult ImportSingle(
        IReadOnlyDictionary<string, string?> map,
        ProducerFingerprintSource source,
        SourceReference? sourceReference,
        FingerprintReliability initialReliability)
    {
        if (!TryGetSingleEntry(map, out var entry))
        {
            return new FingerprintIngestionResult(
                ImmutableArray<ProducerFingerprint>.Empty,
                ImmutableArray<Diagnostic>.Empty);
        }

        if (string.IsNullOrWhiteSpace(entry.Key) ||
            string.IsNullOrWhiteSpace(entry.Value))
        {
            return new FingerprintIngestionResult(
                ImmutableArray<ProducerFingerprint>.Empty,
                [
                    new Diagnostic(
                        "CANON0020",
                        DiagnosticSeverity.Warning,
                        DiagnosticStage.Fingerprint,
                        "A producer fingerprint with an empty name or value was ignored.",
                        sourceReference),
                ]);
        }

        ParseHierarchicalName(
            entry.Key,
            out var family,
            out var version);
        return new FingerprintIngestionResult(
            [
                new ProducerFingerprint(
                    entry.Key,
                    family,
                    version,
                    entry.Value,
                    initialReliability,
                    source),
            ],
            ImmutableArray<Diagnostic>.Empty);
    }

    private static bool TryGetSingleEntry(
        IReadOnlyDictionary<string, string?> map,
        out KeyValuePair<string, string?> entry)
    {
        if (map is Dictionary<string, string?> dictionary)
        {
            var enumerator = dictionary.GetEnumerator();
            if (enumerator.MoveNext())
            {
                entry = enumerator.Current;
                return true;
            }

            entry = default;
            return false;
        }

        using var fallbackEnumerator = map.GetEnumerator();
        if (fallbackEnumerator.MoveNext())
        {
            entry = fallbackEnumerator.Current;
            return true;
        }

        entry = default;
        return false;
    }

    private static void ParseHierarchicalName(
        string name,
        out string family,
        out int? version)
    {
        var versionMarker = name.LastIndexOf("/v", StringComparison.Ordinal);
        if (versionMarker <= 0 ||
            versionMarker + 2 >= name.Length ||
            !int.TryParse(
                name.AsSpan(versionMarker + 2),
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var parsedVersion))
        {
            family = name;
            version = null;
            return;
        }

        family = name[..versionMarker];
        version = parsedVersion;
    }

    private static Finding CloneWithFingerprints(
        Finding finding,
        IEnumerable<ProducerFingerprint> producerFingerprints) =>
        new(
            finding.FindingKey,
            finding.SourceReference,
            finding.Run,
            finding.Producer,
            finding.Rule,
            finding.PrimaryLocation,
            finding.Message,
            producerFingerprints,
            finding.DerivedFingerprints,
            finding.Context,
            finding.RelatedLocations,
            finding.CodeFlow,
            finding.Lossiness,
            finding.Diagnostics,
            finding.Metadata);

    private static string NormalizeLineEndings(string value) =>
        value
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

    private readonly record struct FingerprintBucketKey(
        string Run,
        string Rule,
        string Name,
        string Value);

    private readonly record struct FingerprintOccurrence(
        string FirstFindingKey,
        bool Collided);
}
