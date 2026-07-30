using SarifRegress.Sarif.Canonicalization;

namespace SarifRegress.UnitTests;

public sealed class MessageCanonicalizerTests
{
    [Fact]
    public void Canonicalization_normalizes_only_documented_message_features()
    {
        const string original =
            " \tUnsafe FILE42\r\n  at \"quoted-value\".\r ";

        var message = MessageCanonicalizer.Canonicalize(original);

        Assert.Equal(original, message.OriginalText);
        Assert.Equal(
            "Unsafe FILE42 at \"quoted-value\".",
            message.CanonicalText);
        Assert.Equal(
            "unsafe file42 at \"quoted-value\".",
            message.ComparisonText);
        Assert.Equal(
            [
                "normalised-line-endings",
                "trimmed-whitespace",
                "collapsed-whitespace",
                "invariant-case-fold",
            ],
            message.NormalisationFlags);
    }

    [Fact]
    public void Canonicalization_preserves_numbers_identifiers_and_punctuation()
    {
        var first = MessageCanonicalizer.Canonicalize(
            "Issue in user_123 at file-a.cs.");
        var second = MessageCanonicalizer.Canonicalize(
            "Issue in user_124 at file-b.cs.");

        Assert.NotEqual(first.ComparisonText, second.ComparisonText);
        Assert.Contains("user_123", first.ComparisonText, StringComparison.Ordinal);
        Assert.EndsWith("file-a.cs.", first.ComparisonText, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_message_has_stable_empty_forms()
    {
        var message = MessageCanonicalizer.Canonicalize(string.Empty);

        Assert.Equal(string.Empty, message.CanonicalText);
        Assert.Equal(string.Empty, message.ComparisonText);
        Assert.Empty(message.NormalisationFlags);
    }

    [Fact]
    public void Already_canonical_message_reuses_its_original_text()
    {
        var original = new string("already canonical".ToCharArray());

        var message = MessageCanonicalizer.Canonicalize(original);

        Assert.Same(original, message.CanonicalText);
        Assert.Empty(message.NormalisationFlags);
    }
}
