using System.Collections.Immutable;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Utility;

namespace SarifRegress.Match;

/// <summary>
/// Counts contextual and derived evidence within each input-side producer/rule bucket.
/// Each evidence value contributes at most one occurrence per finding.
/// </summary>
internal sealed class ContextFingerprintOccurrenceIndex
{
    private const int MaximumInlineEvidenceCharacters = 512;
    private const string ContextEvidenceKind = "context";
    private const string DerivedEvidenceKind = "derived-fingerprint";

    private readonly Dictionary<OccurrenceKey, int> occurrenceCounts;

    private ContextFingerprintOccurrenceIndex(
        Dictionary<OccurrenceKey, int> occurrenceCounts)
    {
        this.occurrenceCounts = occurrenceCounts;
    }

    public static ContextFingerprintOccurrenceIndex Create(
        ImmutableArray<Finding> baseline,
        ImmutableArray<Finding> candidate)
    {
        var occurrenceCounts = new Dictionary<OccurrenceKey, int>();
        AddOccurrences(InputKind.Baseline, baseline, occurrenceCounts);
        AddOccurrences(InputKind.Candidate, candidate, occurrenceCounts);
        return new ContextFingerprintOccurrenceIndex(occurrenceCounts);
    }

    public int GetContextCount(
        InputKind input,
        Finding finding,
        string contextKind,
        string value) =>
        GetCount(CreateContextKey(input, finding, contextKind, value));

    public int GetDerivedFingerprintCount(
        InputKind input,
        Finding finding,
        DerivedFingerprint fingerprint) =>
        GetCount(CreateDerivedKey(input, finding, fingerprint));

    public ImmutableArray<EvidenceRecord> GetDegradationEvidence(
        InputKind input,
        Finding finding)
    {
        var records = ImmutableArray.CreateBuilder<EvidenceRecord>();
        var context = finding.Context;
        if (context is not null)
        {
            AddContextDegradationEvidence(
                records,
                input,
                finding,
                "context-snippet",
                context.SnippetHash);
            AddContextDegradationEvidence(
                records,
                input,
                finding,
                "context-token-window",
                context.TokenWindowHash);
        }

        foreach (var fingerprint in finding.DerivedFingerprints)
        {
            var count = GetDerivedFingerprintCount(input, finding, fingerprint);
            if (count > 1)
            {
                records.Add(CreateEvidenceRecord(
                    input,
                    "derived-fingerprint-collision",
                    FormatDerivedFingerprint(fingerprint, count)));
            }
        }

        return records
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.BaselineValue, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateValue, StringComparer.Ordinal)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    public static string FormatContextOccurrence(
        string contextKind,
        string value,
        int count) =>
        $"{contextKind}:{value}:occurrences={count}";

    public static string FormatDerivedFingerprint(
        DerivedFingerprint fingerprint,
        int count) =>
        $"{fingerprint.Name}/{fingerprint.AlgorithmVersion}:"
        + $"{fingerprint.Value}:occurrences={count}";

    private int GetCount(OccurrenceKey key) =>
        occurrenceCounts.TryGetValue(key, out var count)
            ? count
            : 0;

    private void AddContextDegradationEvidence(
        ICollection<EvidenceRecord> records,
        InputKind input,
        Finding finding,
        string contextKind,
        string? value)
    {
        if (value is null)
        {
            return;
        }

        var count = GetContextCount(input, finding, contextKind, value);
        if (count > 1)
        {
            records.Add(CreateEvidenceRecord(
                input,
                "context-collision",
                FormatContextOccurrence(contextKind, value, count)));
        }
    }

    private static EvidenceRecord CreateEvidenceRecord(
        InputKind input,
        string kind,
        string value)
    {
        var boundedValue = BoundValue(value);
        return new EvidenceRecord(
            kind,
            input == InputKind.Baseline ? boundedValue.Value : null,
            input == InputKind.Candidate ? boundedValue.Value : null,
            EvidenceOrigin.System,
            PrecedenceTier.Refuse,
            boundedValue.Lossy,
            MatchingAlgorithms.EvidenceOccurrenceVersion);
    }

    private static BoundedValue BoundValue(string value) =>
        value.Length <= MaximumInlineEvidenceCharacters
            ? new BoundedValue(value, Lossy: false)
            : new BoundedValue(
                $"sha256:{VersionedHash.Compute(
                    MatchingAlgorithms.EvidenceOccurrenceVersion,
                    value)}",
                Lossy: true);

    private static void AddOccurrences(
        InputKind input,
        ImmutableArray<Finding> findings,
        IDictionary<OccurrenceKey, int> occurrenceCounts)
    {
        foreach (var finding in findings)
        {
            var keysForFinding = new HashSet<OccurrenceKey>();
            var context = finding.Context;
            if (context is not null)
            {
                AddContextKey(
                    keysForFinding,
                    input,
                    finding,
                    "context-snippet",
                    context.SnippetHash);
                AddContextKey(
                    keysForFinding,
                    input,
                    finding,
                    "context-token-window",
                    context.TokenWindowHash);
            }

            foreach (var fingerprint in finding.DerivedFingerprints)
            {
                keysForFinding.Add(CreateDerivedKey(input, finding, fingerprint));
            }

            foreach (var key in keysForFinding)
            {
                occurrenceCounts.TryGetValue(key, out var count);
                occurrenceCounts[key] = count + 1;
            }
        }
    }

    private static void AddContextKey(
        ISet<OccurrenceKey> keys,
        InputKind input,
        Finding finding,
        string contextKind,
        string? value)
    {
        if (value is not null)
        {
            keys.Add(CreateContextKey(input, finding, contextKind, value));
        }
    }

    private static OccurrenceKey CreateContextKey(
        InputKind input,
        Finding finding,
        string contextKind,
        string value) =>
        CreateKey(
            input,
            finding,
            ContextEvidenceKind,
            contextKind,
            MatchingAlgorithms.ContextVersion,
            value);

    private static OccurrenceKey CreateDerivedKey(
        InputKind input,
        Finding finding,
        DerivedFingerprint fingerprint) =>
        CreateKey(
            input,
            finding,
            DerivedEvidenceKind,
            fingerprint.Name,
            fingerprint.AlgorithmVersion,
            fingerprint.Value);

    private static OccurrenceKey CreateKey(
        InputKind input,
        Finding finding,
        string evidenceKind,
        string evidenceName,
        string evidenceAlgorithmVersion,
        string value) =>
        new(
            input,
            finding.Producer.AutomaticIdentity,
            finding.Rule.CanonicalId,
            evidenceKind,
            evidenceName,
            evidenceAlgorithmVersion,
            value);

    private readonly record struct OccurrenceKey(
        InputKind Input,
        string ProducerIdentity,
        string RuleId,
        string EvidenceKind,
        string EvidenceName,
        string EvidenceAlgorithmVersion,
        string Value);

    private readonly record struct BoundedValue(string Value, bool Lossy);
}
