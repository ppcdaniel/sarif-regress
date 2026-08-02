using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Utility;

namespace SarifRegress.Match;

/// <summary>
/// Counts code-flow anchors within each input-side producer/rule bucket.
/// Each anchor contributes at most one occurrence per finding.
/// </summary>
internal sealed class CodeFlowAnchorOccurrenceIndex
{
    private readonly Dictionary<OccurrenceKey, int> occurrenceCounts;
    private readonly PathCaseSensitivity pathCaseSensitivity;

    private CodeFlowAnchorOccurrenceIndex(
        Dictionary<OccurrenceKey, int> occurrenceCounts,
        PathCaseSensitivity pathCaseSensitivity)
    {
        this.occurrenceCounts = occurrenceCounts;
        this.pathCaseSensitivity = pathCaseSensitivity;
    }

    // Time: O(A); Space: O(U), where A is the total anchor count and U is the
    // number of distinct input-side producer/rule/anchor identities.
    public static CodeFlowAnchorOccurrenceIndex Create(
        ImmutableArray<Finding> baseline,
        ImmutableArray<Finding> candidate,
        PathCaseSensitivity pathCaseSensitivity)
    {
        var occurrenceCounts = new Dictionary<OccurrenceKey, int>();
        AddOccurrences(
            InputKind.Baseline,
            baseline,
            pathCaseSensitivity,
            occurrenceCounts);
        AddOccurrences(
            InputKind.Candidate,
            candidate,
            pathCaseSensitivity,
            occurrenceCounts);
        return new CodeFlowAnchorOccurrenceIndex(
            occurrenceCounts,
            pathCaseSensitivity);
    }

    public int GetCount(
        InputKind input,
        Finding finding,
        CodeFlowAnchorIdentity anchor)
    {
        var key = CreateKey(input, finding, anchor);
        return occurrenceCounts.TryGetValue(key, out var count) ? count : 0;
    }

    public static CodeFlowAnchorIdentity CreateIdentity(
        CodeFlowAnchor anchor,
        PathCaseSensitivity pathCaseSensitivity) =>
        new(
            NormalizePath(anchor.CanonicalPath, pathCaseSensitivity),
            anchor.ContextHash);

    public static string GetStableValue(CodeFlowAnchorIdentity anchor) =>
        VersionedHash.Compute(
            MatchingAlgorithms.CodeFlowAnchorVersion,
            anchor.CanonicalPath,
            anchor.ContextHash);

    /// <summary>
    /// Emits one bounded finding-local summary when repeated anchors degraded identity.
    /// Pair-local evidence is intentionally not retained for refused candidate edges.
    /// </summary>
    public ImmutableArray<EvidenceRecord> GetDegradationEvidence(
        InputKind input,
        Finding finding)
    {
        if (finding.CodeFlow is null || finding.CodeFlow.Anchors.IsDefaultOrEmpty)
        {
            return ImmutableArray<EvidenceRecord>.Empty;
        }

        CodeFlowAnchorIdentity[] collidedAnchors = finding.CodeFlow.Anchors
            .Select(anchor => CreateIdentity(anchor, pathCaseSensitivity))
            .Distinct()
            .Where(anchor => GetCount(input, finding, anchor) > 1)
            .OrderBy(GetStableValue, StringComparer.Ordinal)
            .ToArray();
        if (collidedAnchors.Length == 0)
        {
            return ImmutableArray<EvidenceRecord>.Empty;
        }

        string summary = FormatCollisionSummary(input, finding, collidedAnchors);
        return
        [
            new EvidenceRecord(
                "code-flow-anchor-collision",
                input == InputKind.Baseline ? summary : null,
                input == InputKind.Candidate ? summary : null,
                EvidenceOrigin.System,
                PrecedenceTier.Refuse,
                Lossy: true,
                MatchingAlgorithms.CodeFlowOccurrenceVersion),
        ];
    }

    public string FormatCollisionSummary(
        InputKind input,
        Finding finding,
        IReadOnlyList<CodeFlowAnchorIdentity> anchors)
    {
        if (anchors.Count == 0)
        {
            throw new ArgumentException(
                "At least one collided anchor is required.",
                nameof(anchors));
        }

        var firstAnchor = anchors[0];
        return $"shared-collisions={anchors.Count};first="
            + $"{GetStableValue(firstAnchor)}:occurrences="
            + $"{GetCount(input, finding, firstAnchor)}";
    }

    private static void AddOccurrences(
        InputKind input,
        ImmutableArray<Finding> findings,
        PathCaseSensitivity pathCaseSensitivity,
        IDictionary<OccurrenceKey, int> occurrenceCounts)
    {
        foreach (var finding in findings)
        {
            if (finding.CodeFlow is null || finding.CodeFlow.Anchors.IsDefaultOrEmpty)
            {
                continue;
            }

            var anchors = finding.CodeFlow.Anchors
                .Select(anchor => CreateIdentity(anchor, pathCaseSensitivity))
                .ToHashSet();
            foreach (var anchor in anchors)
            {
                var key = CreateKey(input, finding, anchor);
                occurrenceCounts.TryGetValue(key, out var count);
                occurrenceCounts[key] = count + 1;
            }
        }
    }

    private static OccurrenceKey CreateKey(
        InputKind input,
        Finding finding,
        CodeFlowAnchorIdentity anchor) =>
        new(
            input,
            finding.Producer.AutomaticIdentity,
            finding.Rule.CanonicalId,
            anchor);

    private static string NormalizePath(
        string path,
        PathCaseSensitivity pathCaseSensitivity)
    {
        if (pathCaseSensitivity == PathCaseSensitivity.Sensitive)
        {
            return path;
        }

        return string.Create(
            path.Length,
            path,
            static (destination, source) =>
            {
                for (var index = 0; index < source.Length; index++)
                {
                    var value = source[index];
                    destination[index] = value is >= 'A' and <= 'Z'
                        ? (char)(value + ('a' - 'A'))
                        : value;
                }
            });
    }

    private readonly record struct OccurrenceKey(
        InputKind Input,
        string ProducerIdentity,
        string RuleId,
        CodeFlowAnchorIdentity Anchor);
}

internal readonly record struct CodeFlowAnchorIdentity(
    string CanonicalPath,
    string? ContextHash);
