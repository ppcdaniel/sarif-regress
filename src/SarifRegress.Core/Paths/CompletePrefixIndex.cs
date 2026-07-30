using System.Collections.Immutable;

namespace SarifRegress.Core.Paths;

/// <summary>
/// Represents one value keyed by a complete path prefix.
/// </summary>
/// <typeparam name="T">The immutable configuration value type.</typeparam>
/// <param name="Prefix">The non-empty path prefix.</param>
/// <param name="Value">The value selected when the prefix matches.</param>
internal readonly record struct CompletePrefixEntry<T>(
    string Prefix,
    T Value)
    where T : class;

/// <summary>
/// Represents one complete-prefix match and its compressed-trie terminal.
/// </summary>
/// <typeparam name="T">The immutable configuration value type.</typeparam>
/// <param name="PrefixLength">The matched prefix length.</param>
/// <param name="TerminalNode">The stable compressed-trie terminal identifier.</param>
/// <param name="Value">The first value in deterministic configuration order.</param>
internal readonly record struct CompletePrefixMatch<T>(
    int PrefixLength,
    int TerminalNode,
    T Value)
    where T : class;

/// <summary>
/// Compiles complete path prefixes into an immutable compressed radix trie.
/// </summary>
/// <typeparam name="T">The immutable configuration value type.</typeparam>
internal sealed class CompletePrefixIndex<T>
    where T : class
{
    private readonly ImmutableArray<PrefixNode> nodes;
    private readonly bool foldAsciiCase;

    private CompletePrefixIndex(
        ImmutableArray<PrefixNode> nodes,
        bool foldAsciiCase,
        int configuredEntryCount,
        int buildCharacterVisitCount,
        int uniquePrefixCount)
    {
        this.nodes = nodes;
        this.foldAsciiCase = foldAsciiCase;
        ConfiguredEntryCount = configuredEntryCount;
        BuildCharacterVisitCount = buildCharacterVisitCount;
        UniquePrefixCount = uniquePrefixCount;
    }

    /// <summary>
    /// Gets the number of non-empty entries supplied during construction.
    /// </summary>
    internal int ConfiguredEntryCount { get; }

    /// <summary>
    /// Gets the total configured prefix characters visited during construction.
    /// </summary>
    internal int BuildCharacterVisitCount { get; }

    /// <summary>
    /// Gets the number of distinct prefixes under the configured case policy.
    /// </summary>
    internal int UniquePrefixCount { get; }

    /// <summary>
    /// Gets the compressed-trie node count.
    /// </summary>
    internal int NodeCount => nodes.Length;

    /// <summary>
    /// Gets the compressed-trie edge count.
    /// </summary>
    internal int EdgeCount => nodes.Length - 1;

    /// <summary>
    /// Builds an immutable compressed prefix index.
    /// </summary>
    /// <remarks>
    /// Equivalent prefixes retain the first value in input order. A radix edge stores
    /// a complete shared substring, so structural node count is bounded by twice the
    /// configured entry count rather than by the number of prefix characters.
    /// </remarks>
    /// <param name="entries">Entries in deterministic configuration precedence.</param>
    /// <param name="caseSensitivity">The explicit path case policy.</param>
    /// <returns>The compiled index.</returns>
    // Time: O(C); Space: O(C + N), with at most 2N + 1 nodes, where C is total
    // configured prefix characters and N is the non-empty configured entry count.
    internal static CompletePrefixIndex<T> Create(
        IEnumerable<CompletePrefixEntry<T>> entries,
        PathCaseSensitivity caseSensitivity)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var foldAsciiCase =
            caseSensitivity == PathCaseSensitivity.AsciiInsensitive;
        var nodes = new List<MutablePrefixNode>
        {
            new(),
        };
        var configuredEntryCount = 0;
        var buildCharacterVisitCount = 0;
        var uniquePrefixCount = 0;

        foreach (var entry in entries)
        {
            ArgumentNullException.ThrowIfNull(entry.Prefix);
            ArgumentNullException.ThrowIfNull(entry.Value);
            if (entry.Prefix.Length == 0)
            {
                continue;
            }

            configuredEntryCount++;
            buildCharacterVisitCount += entry.Prefix.Length;
            var normalizedPrefix = Normalize(
                entry.Prefix,
                foldAsciiCase);
            if (Add(
                    nodes,
                    normalizedPrefix,
                    entry.Value))
            {
                uniquePrefixCount++;
            }
        }

        return new CompletePrefixIndex<T>(
            nodes
                .Select(node => new PrefixNode(
                    node.Children.ToImmutableDictionary(),
                    node.IsTerminal,
                    node.Value))
                .ToImmutableArray(),
            foldAsciiCase,
            configuredEntryCount,
            buildCharacterVisitCount,
            uniquePrefixCount);
    }

    /// <summary>
    /// Enumerates complete configured prefixes of one path in ascending length.
    /// </summary>
    /// <param name="value">The path or URI representation.</param>
    /// <returns>A non-allocating compressed-trie enumerator.</returns>
    internal MatchEnumerator EnumerateMatches(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new MatchEnumerator(
            this,
            value);
    }

    /// <summary>
    /// Resolves a complete configured prefix to its terminal identifier.
    /// </summary>
    /// <param name="prefix">The configured prefix spelling.</param>
    /// <param name="terminalNode">The equivalent terminal identifier.</param>
    /// <returns>True when the exact configured prefix exists.</returns>
    // Time: O(P); Space: O(1), where P is the prefix length.
    internal bool TryGetExactTerminal(
        string prefix,
        out int terminalNode)
    {
        ArgumentNullException.ThrowIfNull(prefix);
        terminalNode = 0;
        if (prefix.Length == 0)
        {
            return false;
        }

        var nodeIndex = 0;
        var prefixOffset = 0;
        while (prefixOffset < prefix.Length)
        {
            var key = NormalizeCharacter(
                prefix[prefixOffset],
                foldAsciiCase);
            if (!nodes[nodeIndex].Children.TryGetValue(
                    key,
                    out var edge))
            {
                return false;
            }

            if (!MatchesAt(
                    prefix,
                    prefixOffset,
                    edge.Label,
                    foldAsciiCase))
            {
                return false;
            }

            prefixOffset += edge.Label.Length;
            nodeIndex = edge.ChildNode;
        }

        if (!nodes[nodeIndex].IsTerminal)
        {
            return false;
        }

        terminalNode = nodeIndex;
        return true;
    }

    private static bool Add(
        List<MutablePrefixNode> nodes,
        string prefix,
        T value)
    {
        var nodeIndex = 0;
        var prefixOffset = 0;
        while (prefixOffset < prefix.Length)
        {
            var key = prefix[prefixOffset];
            if (!nodes[nodeIndex].Children.TryGetValue(
                    key,
                    out var edge))
            {
                var childIndex = nodes.Count;
                nodes.Add(new MutablePrefixNode
                {
                    IsTerminal = true,
                    Value = value,
                });
                nodes[nodeIndex].Children.Add(
                    key,
                    new PrefixEdge(
                        prefix[prefixOffset..],
                        childIndex));
                return true;
            }

            var commonLength = CountCommonPrefix(
                prefix.AsSpan(prefixOffset),
                edge.Label);
            if (commonLength == edge.Label.Length)
            {
                prefixOffset += commonLength;
                nodeIndex = edge.ChildNode;
                continue;
            }

            var splitNodeIndex = nodes.Count;
            var splitNode = new MutablePrefixNode();
            nodes.Add(splitNode);
            nodes[nodeIndex].Children[key] = new PrefixEdge(
                edge.Label[..commonLength],
                splitNodeIndex);

            var existingSuffix = edge.Label[commonLength..];
            splitNode.Children.Add(
                existingSuffix[0],
                new PrefixEdge(
                    existingSuffix,
                    edge.ChildNode));
            prefixOffset += commonLength;
            if (prefixOffset == prefix.Length)
            {
                splitNode.IsTerminal = true;
                splitNode.Value = value;
                return true;
            }

            var newChildIndex = nodes.Count;
            nodes.Add(new MutablePrefixNode
            {
                IsTerminal = true,
                Value = value,
            });
            var newSuffix = prefix[prefixOffset..];
            splitNode.Children.Add(
                newSuffix[0],
                new PrefixEdge(
                    newSuffix,
                    newChildIndex));
            return true;
        }

        var terminal = nodes[nodeIndex];
        if (terminal.IsTerminal)
        {
            return false;
        }

        terminal.IsTerminal = true;
        terminal.Value = value;
        return true;
    }

    private static int CountCommonPrefix(
        ReadOnlySpan<char> left,
        ReadOnlySpan<char> right)
    {
        var maximumLength = Math.Min(
            left.Length,
            right.Length);
        var length = 0;
        while (length < maximumLength
            && left[length] == right[length])
        {
            length++;
        }

        return length;
    }

    private static bool MatchesAt(
        string value,
        int offset,
        string edge,
        bool foldAsciiCase)
    {
        if (value.Length - offset < edge.Length)
        {
            return false;
        }

        for (var index = 0; index < edge.Length; index++)
        {
            if (NormalizeCharacter(
                    value[offset + index],
                    foldAsciiCase)
                != edge[index])
            {
                return false;
            }
        }

        return true;
    }

    private static string Normalize(
        string value,
        bool foldAsciiCase)
    {
        if (!foldAsciiCase)
        {
            return value;
        }

        return string.Create(
            value.Length,
            value,
            static (destination, source) =>
            {
                for (var index = 0; index < source.Length; index++)
                {
                    destination[index] = NormalizeCharacter(
                        source[index],
                        foldAsciiCase: true);
                }
            });
    }

    private static char NormalizeCharacter(
        char value,
        bool foldAsciiCase) =>
        foldAsciiCase && value is >= 'A' and <= 'Z'
            ? (char)(value + ('a' - 'A'))
            : value;

    private static bool IsCompletePrefix(
        string value,
        int prefixLength) =>
        value.Length == prefixLength
        || IsPathSeparator(value[prefixLength - 1])
        || IsPathSeparator(value[prefixLength]);

    private static bool IsPathSeparator(char value) =>
        value is '/' or '\\';

    /// <summary>
    /// Enumerates matching terminals without materializing prefix strings.
    /// </summary>
    internal struct MatchEnumerator
    {
        private readonly ImmutableArray<PrefixNode> nodes;
        private readonly string value;
        private readonly bool foldAsciiCase;
        private int nodeIndex;
        private int valueOffset;
        private bool stopped;

        internal MatchEnumerator(
            CompletePrefixIndex<T> owner,
            string value)
        {
            nodes = owner.nodes;
            this.value = value;
            foldAsciiCase = owner.foldAsciiCase;
            nodeIndex = 0;
            valueOffset = 0;
            stopped = false;
            Current = default;
            TransitionProbeCount = 0;
            CharacterComparisonCount = 0;
        }

        /// <summary>
        /// Gets the current complete-prefix match.
        /// </summary>
        internal CompletePrefixMatch<T> Current { get; private set; }

        /// <summary>
        /// Gets the compressed-edge dictionary probe count.
        /// </summary>
        internal int TransitionProbeCount { get; private set; }

        /// <summary>
        /// Gets the compared edge-character count.
        /// </summary>
        internal int CharacterComparisonCount { get; private set; }

        /// <summary>
        /// Advances to the next complete matching terminal.
        /// </summary>
        /// <returns>True when another configured prefix matches.</returns>
        internal bool MoveNext()
        {
            while (!stopped && valueOffset < value.Length)
            {
                TransitionProbeCount++;
                var key = NormalizeCharacter(
                    value[valueOffset],
                    foldAsciiCase);
                if (!nodes[nodeIndex].Children.TryGetValue(
                        key,
                        out var edge))
                {
                    stopped = true;
                    return false;
                }

                for (var edgeOffset = 0;
                     edgeOffset < edge.Label.Length;
                     edgeOffset++)
                {
                    if (valueOffset + edgeOffset >= value.Length)
                    {
                        stopped = true;
                        return false;
                    }

                    CharacterComparisonCount++;
                    if (NormalizeCharacter(
                            value[valueOffset + edgeOffset],
                            foldAsciiCase)
                        != edge.Label[edgeOffset])
                    {
                        stopped = true;
                        return false;
                    }
                }

                valueOffset += edge.Label.Length;
                nodeIndex = edge.ChildNode;
                var node = nodes[nodeIndex];
                if (node.IsTerminal
                    && IsCompletePrefix(value, valueOffset))
                {
                    Current = new CompletePrefixMatch<T>(
                        valueOffset,
                        nodeIndex,
                        node.Value
                            ?? throw new InvalidOperationException(
                                "A prefix terminal must retain its configured value."));
                    return true;
                }
            }

            stopped = true;
            return false;
        }
    }

    private sealed record PrefixNode(
        ImmutableDictionary<char, PrefixEdge> Children,
        bool IsTerminal,
        T? Value);

    private readonly record struct PrefixEdge(
        string Label,
        int ChildNode);

    private sealed class MutablePrefixNode
    {
        public Dictionary<char, PrefixEdge> Children { get; } = [];

        public bool IsTerminal { get; set; }

        public T? Value { get; set; }
    }
}
