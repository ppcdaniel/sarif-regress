using System.Collections.Immutable;
using System.Text;
using SarifRegress.Core.Findings;

namespace SarifRegress.Sarif.Canonicalization;

/// <summary>
/// Produces stable display and comparison forms without stripping semantic message values.
/// </summary>
public static class MessageCanonicalizer
{
    /// <summary>
    /// Gets the message-normalisation algorithm identifier.
    /// </summary>
    public const string AlgorithmVersion = "message-whitespace-case/v1";

    private const string LineEndingsFlag = "normalised-line-endings";
    private const string TrimmedFlag = "trimmed-whitespace";
    private const string CollapsedFlag = "collapsed-whitespace";
    private const string CaseFoldFlag = "invariant-case-fold";

    /// <summary>
    /// Canonicalises a producer message using culture-invariant rules.
    /// </summary>
    /// <param name="originalText">The exact producer text.</param>
    /// <returns>Original, canonical display, and case-folded comparison forms.</returns>
    public static MessageIdentity Canonicalize(string originalText)
    {
        ArgumentNullException.ThrowIfNull(originalText);

        var flags = ImmutableArray.CreateBuilder<string>();
        var normalizedLineEndings = originalText
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');
        if (!string.Equals(
                normalizedLineEndings,
                originalText,
                StringComparison.Ordinal))
        {
            flags.Add(LineEndingsFlag);
        }

        var trimmed = normalizedLineEndings.Trim();
        if (!string.Equals(trimmed, normalizedLineEndings, StringComparison.Ordinal))
        {
            flags.Add(TrimmedFlag);
        }

        var collapsed = CollapseWhitespace(trimmed);
        if (!string.Equals(collapsed, trimmed, StringComparison.Ordinal))
        {
            flags.Add(CollapsedFlag);
        }

        var comparison = collapsed.ToLowerInvariant();
        if (!string.Equals(comparison, collapsed, StringComparison.Ordinal))
        {
            flags.Add(CaseFoldFlag);
        }

        return new MessageIdentity(
            originalText,
            collapsed,
            comparison,
            flags.ToImmutable());
    }

    // Time: O(n), where n is the message length. Space: O(n).
    private static string CollapseWhitespace(string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        var firstChangeIndex = -1;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (!char.IsWhiteSpace(character))
            {
                continue;
            }

            if (character != ' ' ||
                index > 0 && char.IsWhiteSpace(value[index - 1]))
            {
                firstChangeIndex = index;
                break;
            }
        }

        if (firstChangeIndex < 0)
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        builder.Append(value, 0, firstChangeIndex);
        var previousWasWhitespace =
            firstChangeIndex > 0 &&
            char.IsWhiteSpace(value[firstChangeIndex - 1]);
        for (var index = firstChangeIndex; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character))
            {
                if (!previousWasWhitespace)
                {
                    builder.Append(' ');
                    previousWasWhitespace = true;
                }

                continue;
            }

            builder.Append(character);
            previousWasWhitespace = false;
        }

        return builder.ToString();
    }
}
