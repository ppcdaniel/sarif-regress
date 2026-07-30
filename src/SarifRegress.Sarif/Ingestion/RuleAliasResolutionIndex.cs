using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Utility;

namespace SarifRegress.Sarif.Ingestion;

/// <summary>
/// Resolves configured rule aliases for one comparison side without scanning
/// the complete alias collection for every result.
/// </summary>
internal sealed class RuleAliasResolutionIndex
{
    private const string RuleAliasAlgorithmVersion = "rule-alias/v2";
    private readonly Dictionary<RuleAliasLookupKey, string> canonicalIds;
    private long lookupProbeCount;

    private RuleAliasResolutionIndex(
        Dictionary<RuleAliasLookupKey, string> canonicalIds,
        int buildAliasVisitCount)
    {
        this.canonicalIds = canonicalIds;
        BuildAliasVisitCount = buildAliasVisitCount;
    }

    /// <summary>
    /// Gets the number of aliases visited while building the index.
    /// </summary>
    internal int BuildAliasVisitCount { get; }

    /// <summary>
    /// Gets the number of dictionary probes performed by result lookups.
    /// </summary>
    internal long LookupProbeCount => lookupProbeCount;

    /// <summary>
    /// Builds the lookup table for one comparison side.
    /// </summary>
    /// <remarks>
    /// When multiple aliases have the same side-specific lookup key, the first
    /// alias in configuration order wins, matching the previous linear scan.
    /// </remarks>
    /// <param name="input">The comparison side being ingested.</param>
    /// <param name="aliases">The aliases in deterministic configuration order.</param>
    /// <returns>The precomputed alias lookup table.</returns>
    // Time: O(a); Space: O(a), where a is the configured alias count.
    internal static RuleAliasResolutionIndex Create(
        InputKind input,
        IEnumerable<RuleAlias> aliases)
    {
        if (input is not InputKind.Baseline and not InputKind.Candidate)
        {
            throw new ArgumentOutOfRangeException(
                nameof(input),
                input,
                "A rule alias index must target the baseline or candidate input.");
        }

        ArgumentNullException.ThrowIfNull(aliases);
        var canonicalIds = new Dictionary<RuleAliasLookupKey, string>();
        var buildAliasVisitCount = 0;
        foreach (var alias in aliases)
        {
            ArgumentNullException.ThrowIfNull(alias);
            buildAliasVisitCount++;
            var baselineProducer = ProducerIdentityResolver.Resolve(
                alias.BaselineProducer);
            var candidateProducer = ProducerIdentityResolver.Resolve(
                alias.CandidateProducer);
            var canonicalId = "alias/" + VersionedHash.Compute(
                RuleAliasAlgorithmVersion,
                baselineProducer.AutomaticIdentity,
                alias.BaselineRule,
                candidateProducer.AutomaticIdentity,
                alias.CandidateRule);
            var key = input switch
            {
                InputKind.Baseline => new RuleAliasLookupKey(
                    baselineProducer.AutomaticIdentity,
                    alias.BaselineRule),
                InputKind.Candidate => new RuleAliasLookupKey(
                    candidateProducer.AutomaticIdentity,
                    alias.CandidateRule),
                _ => throw new InvalidOperationException(
                    "The comparison side was validated before index construction."),
            };

            canonicalIds.TryAdd(key, canonicalId);
        }

        return new RuleAliasResolutionIndex(
            canonicalIds,
            buildAliasVisitCount);
    }

    /// <summary>
    /// Resolves one producer-and-rule pair to its configured canonical alias.
    /// </summary>
    /// <param name="automaticProducerIdentity">
    /// The producer's collision-resistant automatic identity.
    /// </param>
    /// <param name="ruleId">The preserved SARIF rule identifier.</param>
    /// <returns>The canonical alias identifier, or null when no alias applies.</returns>
    // Average time: O(1); Space: O(1).
    internal string? Resolve(
        string automaticProducerIdentity,
        string ruleId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(automaticProducerIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        lookupProbeCount++;
        return canonicalIds.TryGetValue(
            new RuleAliasLookupKey(automaticProducerIdentity, ruleId),
            out var canonicalId)
            ? canonicalId
            : null;
    }

    private readonly record struct RuleAliasLookupKey(
        string AutomaticProducerIdentity,
        string RuleId);
}
