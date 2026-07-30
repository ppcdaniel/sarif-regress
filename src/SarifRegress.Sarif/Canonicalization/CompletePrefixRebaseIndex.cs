using SarifRegress.Core.Configuration;
using SarifRegress.Core.Paths;

namespace SarifRegress.Sarif.Canonicalization;

/// <summary>
/// Compiles configured path rebases into a compressed complete-prefix index.
/// </summary>
internal sealed class CompletePrefixRebaseIndex
{
    private readonly CompletePrefixIndex<PathRebase> prefixes;

    private CompletePrefixRebaseIndex(
        CompletePrefixIndex<PathRebase> prefixes)
    {
        this.prefixes = prefixes;
    }

    /// <summary>
    /// Gets the number of configured prefix characters visited during construction.
    /// </summary>
    internal int BuildCharacterVisitCount =>
        prefixes.BuildCharacterVisitCount;

    /// <summary>
    /// Gets the number of non-empty configured rebases.
    /// </summary>
    internal int ConfiguredEntryCount =>
        prefixes.ConfiguredEntryCount;

    /// <summary>
    /// Gets the compressed-trie node count.
    /// </summary>
    internal int NodeCount => prefixes.NodeCount;

    /// <summary>
    /// Gets the compressed-trie edge count.
    /// </summary>
    internal int EdgeCount => prefixes.EdgeCount;

    /// <summary>
    /// Builds one immutable index in deterministic configuration order.
    /// </summary>
    /// <remarks>
    /// The first entry at a case-policy-equivalent terminal wins. The configuration
    /// contract orders rebases by descending source-prefix length and then ordinal
    /// source and target values, preserving the former linear-scan precedence.
    /// </remarks>
    /// <param name="rebases">The deterministically ordered rebases.</param>
    /// <param name="caseSensitivity">The configured path case policy.</param>
    /// <returns>The compiled prefix index.</returns>
    // Time: O(C); Space: O(C + N), with at most 2N + 1 structural nodes.
    internal static CompletePrefixRebaseIndex Create(
        IEnumerable<PathRebase> rebases,
        PathCaseSensitivity caseSensitivity)
    {
        ArgumentNullException.ThrowIfNull(rebases);
        return new CompletePrefixRebaseIndex(
            CompletePrefixIndex<PathRebase>.Create(
                rebases.Select(rebase =>
                {
                    ArgumentNullException.ThrowIfNull(rebase);
                    return new CompletePrefixEntry<PathRebase>(
                        rebase.From,
                        rebase);
                }),
                caseSensitivity));
    }

    /// <summary>
    /// Finds the longest configured prefix that ends on a path-segment boundary.
    /// </summary>
    /// <param name="value">The logical path or URI to inspect.</param>
    /// <param name="metrics">Deterministic compressed-trie lookup counts.</param>
    /// <returns>The selected rebase, or null when none applies.</returns>
    // Time: O(P); Space: O(1), where P is the inspected value-prefix length.
    internal PathRebase? FindLongest(
        string value,
        out CompletePrefixLookupMetrics metrics)
    {
        var enumerator = prefixes.EnumerateMatches(value);
        PathRebase? match = null;
        while (enumerator.MoveNext())
        {
            match = enumerator.Current.Value;
        }

        metrics = new CompletePrefixLookupMetrics(
            enumerator.TransitionProbeCount,
            enumerator.CharacterComparisonCount);
        return match;
    }
}

/// <summary>
/// Captures deterministic compressed-prefix lookup work.
/// </summary>
/// <param name="TransitionProbeCount">Compressed-edge dictionary probes.</param>
/// <param name="CharacterComparisonCount">Compressed-edge character comparisons.</param>
internal readonly record struct CompletePrefixLookupMetrics(
    int TransitionProbeCount,
    int CharacterComparisonCount);
