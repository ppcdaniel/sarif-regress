using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Paths;

namespace SarifRegress.Match;

/// <summary>
/// Compiles path aliases into paired compressed complete-prefix indexes.
/// </summary>
internal sealed class PathAliasIndex
{
    private readonly CompletePrefixIndex<PathAlias> baselinePrefixes;
    private readonly CompletePrefixIndex<PathAlias> candidatePrefixes;
    private readonly ImmutableDictionary<TerminalPair, AliasEntry> aliasesByTerminalPair;
    private readonly bool foldAsciiCase;

    private PathAliasIndex(
        CompletePrefixIndex<PathAlias> baselinePrefixes,
        CompletePrefixIndex<PathAlias> candidatePrefixes,
        ImmutableDictionary<TerminalPair, AliasEntry> aliasesByTerminalPair,
        bool foldAsciiCase,
        int configuredEntryCount)
    {
        this.baselinePrefixes = baselinePrefixes;
        this.candidatePrefixes = candidatePrefixes;
        this.aliasesByTerminalPair = aliasesByTerminalPair;
        this.foldAsciiCase = foldAsciiCase;
        ConfiguredEntryCount = configuredEntryCount;
    }

    /// <summary>
    /// Gets the number of aliases with two non-empty prefixes.
    /// </summary>
    internal int ConfiguredEntryCount { get; }

    /// <summary>
    /// Gets the total configured prefix characters visited during construction.
    /// </summary>
    internal int BuildCharacterVisitCount =>
        baselinePrefixes.BuildCharacterVisitCount
        + candidatePrefixes.BuildCharacterVisitCount;

    /// <summary>
    /// Gets the total structural node count across both compressed tries.
    /// </summary>
    internal int NodeCount =>
        baselinePrefixes.NodeCount
        + candidatePrefixes.NodeCount;

    /// <summary>
    /// Gets the total structural edge count across both compressed tries.
    /// </summary>
    internal int EdgeCount =>
        baselinePrefixes.EdgeCount
        + candidatePrefixes.EdgeCount;

    /// <summary>
    /// Builds one immutable alias index in deterministic configuration order.
    /// </summary>
    /// <remarks>
    /// The first alias at an ASCII-case-policy-equivalent terminal pair wins. This
    /// preserves the configuration contract's baseline-length, baseline-ordinal,
    /// and candidate-ordinal precedence for programmatically supplied collisions.
    /// </remarks>
    /// <param name="aliases">The deterministically ordered aliases.</param>
    /// <param name="caseSensitivity">The configured path case policy.</param>
    /// <returns>The compiled paired-prefix index.</returns>
    // Time: O(C); Space: O(C + N), with at most 4N + 2 structural nodes.
    internal static PathAliasIndex Create(
        IEnumerable<PathAlias> aliases,
        PathCaseSensitivity caseSensitivity)
    {
        ArgumentNullException.ThrowIfNull(aliases);

        var orderedAliases = aliases
            .Select(alias =>
            {
                ArgumentNullException.ThrowIfNull(alias);
                return alias;
            })
            .ToImmutableArray();
        var validAliases = orderedAliases
            .Where(alias =>
                alias.Baseline.Length != 0
                && alias.Candidate.Length != 0)
            .ToImmutableArray();
        var baselinePrefixes = CompletePrefixIndex<PathAlias>.Create(
            validAliases.Select(alias =>
                new CompletePrefixEntry<PathAlias>(
                    alias.Baseline,
                    alias)),
            caseSensitivity);
        var candidatePrefixes = CompletePrefixIndex<PathAlias>.Create(
            validAliases.Select(alias =>
                new CompletePrefixEntry<PathAlias>(
                    alias.Candidate,
                    alias)),
            caseSensitivity);
        var entries = new Dictionary<TerminalPair, AliasEntry>();
        for (var configurationOrder = 0;
             configurationOrder < orderedAliases.Length;
             configurationOrder++)
        {
            var alias = orderedAliases[configurationOrder];
            if (alias.Baseline.Length == 0
                || alias.Candidate.Length == 0)
            {
                continue;
            }

            if (!baselinePrefixes.TryGetExactTerminal(
                    alias.Baseline,
                    out var baselineTerminal)
                || !candidatePrefixes.TryGetExactTerminal(
                    alias.Candidate,
                    out var candidateTerminal))
            {
                throw new InvalidOperationException(
                    "A configured path alias must resolve to both compiled prefix terminals.");
            }

            entries.TryAdd(
                new TerminalPair(
                    baselineTerminal,
                    candidateTerminal),
                new AliasEntry(alias, configurationOrder));
        }

        return new PathAliasIndex(
            baselinePrefixes,
            candidatePrefixes,
            entries.ToImmutableDictionary(),
            caseSensitivity == PathCaseSensitivity.AsciiInsensitive,
            validAliases.Length);
    }

    /// <summary>
    /// Finds the highest-precedence alias across repository-relative and canonical
    /// URI representations.
    /// </summary>
    /// <param name="baseline">The baseline canonical path.</param>
    /// <param name="candidate">The candidate canonical path.</param>
    /// <param name="metrics">Deterministic lookup-operation counts.</param>
    /// <returns>The selected configured alias, or null.</returns>
    internal PathAlias? Find(
        CanonicalPath baseline,
        CanonicalPath candidate,
        out PathAliasLookupMetrics metrics)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(candidate);

        var counters = new LookupCounters();
        AliasEntry? match = null;
        if (baseline.RepositoryRelativePath is not null
            && candidate.RepositoryRelativePath is not null)
        {
            match = FindPair(
                baseline.RepositoryRelativePath,
                candidate.RepositoryRelativePath,
                match,
                ref counters);
        }

        match = FindPair(
            baseline.CanonicalUri,
            candidate.CanonicalUri,
            match,
            ref counters);
        metrics = counters.ToMetrics();
        return match?.Alias;
    }

    /// <summary>
    /// Finds the highest-precedence alias for one representation pair.
    /// </summary>
    /// <param name="baselinePath">The baseline path representation.</param>
    /// <param name="candidatePath">The candidate path representation.</param>
    /// <param name="metrics">Deterministic lookup-operation counts.</param>
    /// <returns>The selected configured alias, or null.</returns>
    internal PathAlias? Find(
        string baselinePath,
        string candidatePath,
        out PathAliasLookupMetrics metrics)
    {
        ArgumentNullException.ThrowIfNull(baselinePath);
        ArgumentNullException.ThrowIfNull(candidatePath);

        var counters = new LookupCounters();
        var match = FindPair(
            baselinePath,
            candidatePath,
            currentMatch: null,
            ref counters);
        metrics = counters.ToMetrics();
        return match?.Alias;
    }

    private AliasEntry? FindPair(
        string baselinePath,
        string candidatePath,
        AliasEntry? currentMatch,
        ref LookupCounters counters)
    {
        var commonSuffixLength = CountCommonSuffixCharacters(
            baselinePath,
            candidatePath,
            ref counters);
        var baselineMatches =
            baselinePrefixes.EnumerateMatches(baselinePath);
        var candidateMatches =
            candidatePrefixes.EnumerateMatches(candidatePath);
        var candidateAvailable = candidateMatches.MoveNext();

        while (baselineMatches.MoveNext())
        {
            var baselineMatch = baselineMatches.Current;
            var suffixLength =
                baselinePath.Length - baselineMatch.PrefixLength;
            if (suffixLength > commonSuffixLength)
            {
                continue;
            }

            var requiredCandidatePrefixLength =
                candidatePath.Length - suffixLength;
            while (candidateAvailable
                && candidateMatches.Current.PrefixLength
                    < requiredCandidatePrefixLength)
            {
                candidateAvailable = candidateMatches.MoveNext();
            }

            if (!candidateAvailable
                || candidateMatches.Current.PrefixLength
                    != requiredCandidatePrefixLength)
            {
                continue;
            }

            counters.TerminalPairProbeCount++;
            if (!aliasesByTerminalPair.TryGetValue(
                    new TerminalPair(
                        baselineMatch.TerminalNode,
                        candidateMatches.Current.TerminalNode),
                    out var alias)
                || currentMatch is not null
                    && currentMatch.ConfigurationOrder
                        <= alias.ConfigurationOrder)
            {
                continue;
            }

            currentMatch = alias;
        }

        counters.TrieTransitionCount +=
            baselineMatches.TransitionProbeCount
            + candidateMatches.TransitionProbeCount;
        counters.TrieCharacterComparisonCount +=
            baselineMatches.CharacterComparisonCount
            + candidateMatches.CharacterComparisonCount;
        return currentMatch;
    }

    private int CountCommonSuffixCharacters(
        string baselinePath,
        string candidatePath,
        ref LookupCounters counters)
    {
        var maximumLength = Math.Min(
            baselinePath.Length,
            candidatePath.Length);
        var length = 0;
        while (length < maximumLength)
        {
            counters.SuffixComparisonCount++;
            if (NormalizeCharacter(
                    baselinePath[^(length + 1)])
                != NormalizeCharacter(
                    candidatePath[^(length + 1)]))
            {
                break;
            }

            length++;
        }

        return length;
    }

    private char NormalizeCharacter(char value) =>
        foldAsciiCase && value is >= 'A' and <= 'Z'
            ? (char)(value + ('a' - 'A'))
            : value;

    private sealed record AliasEntry(
        PathAlias Alias,
        int ConfigurationOrder);

    private readonly record struct TerminalPair(
        int BaselineNode,
        int CandidateNode);

    private struct LookupCounters
    {
        public int TrieTransitionCount { get; set; }

        public int TrieCharacterComparisonCount { get; set; }

        public int SuffixComparisonCount { get; set; }

        public int TerminalPairProbeCount { get; set; }

        public readonly PathAliasLookupMetrics ToMetrics() =>
            new(
                TrieTransitionCount,
                TrieCharacterComparisonCount,
                SuffixComparisonCount,
                TerminalPairProbeCount);
    }
}

/// <summary>
/// Captures deterministic path-alias lookup work independently of configuration size.
/// </summary>
/// <param name="TrieTransitionCount">Compressed-edge dictionary probes.</param>
/// <param name="TrieCharacterComparisonCount">Compressed-edge character comparisons.</param>
/// <param name="SuffixComparisonCount">Path-suffix character comparisons.</param>
/// <param name="TerminalPairProbeCount">Terminal-pair dictionary probes.</param>
internal readonly record struct PathAliasLookupMetrics(
    int TrieTransitionCount,
    int TrieCharacterComparisonCount,
    int SuffixComparisonCount,
    int TerminalPairProbeCount);
