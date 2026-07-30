using System.Text;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;

namespace SarifRegress.Sarif.Repository;

internal enum TokenWindowRefusal
{
    None,
    TooManyRegionTerms,
    TermTooLong,
}

internal readonly record struct TokenWindowResult(
    string? Hash,
    TokenWindowRefusal Refusal);

/// <summary>
/// Creates a bounded, language-agnostic token window without retaining source
/// positions in identity evidence.
/// </summary>
internal static class TokenWindowCanonicalizer
{
    private const int CancellationCheckMask = 1023;

    public static TokenWindowResult Create(
        string sourceText,
        int startLine,
        int endLine,
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourceText);
        ArgumentNullException.ThrowIfNull(limits);
        cancellationToken.ThrowIfCancellationRequested();

        var maximumTerms = limits.MaximumTokenWindowTerms;
        var termsBeforeRegion = new Queue<string>(
            Math.Min(maximumTerms, 16));
        var termsInRegion = new List<string>(
            Math.Min(maximumTerms, 16));
        var termsAfterRegion = new List<string>(
            Math.Min(maximumTerms, 16));
        var line = 1;
        var offset = 0;

        while (offset < sourceText.Length)
        {
            if ((offset & CancellationCheckMask) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            var current = sourceText[offset];
            if (current == '\n')
            {
                line++;
                offset++;
                continue;
            }

            if (char.IsWhiteSpace(current))
            {
                offset++;
                continue;
            }

            var termStart = offset;
            if (IsIdentifierCharacter(current))
            {
                do
                {
                    offset++;
                    if ((offset & CancellationCheckMask) == 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }
                while (offset < sourceText.Length &&
                    sourceText[offset] != '\n' &&
                    IsIdentifierCharacter(sourceText[offset]));
            }
            else
            {
                offset++;
            }

            var termLength = offset - termStart;
            if (termLength > limits.MaximumStringCharacters)
            {
                return new TokenWindowResult(
                    Hash: null,
                    TokenWindowRefusal.TermTooLong);
            }

            var term = sourceText
                .Substring(termStart, termLength)
                .Normalize(NormalizationForm.FormC);
            if (term.Length > limits.MaximumStringCharacters)
            {
                return new TokenWindowResult(
                    Hash: null,
                    TokenWindowRefusal.TermTooLong);
            }

            if (line < startLine)
            {
                termsBeforeRegion.Enqueue(term);
                if (termsBeforeRegion.Count > maximumTerms)
                {
                    termsBeforeRegion.Dequeue();
                }

                continue;
            }

            if (line <= endLine)
            {
                if (termsInRegion.Count == maximumTerms)
                {
                    return new TokenWindowResult(
                        Hash: null,
                        TokenWindowRefusal.TooManyRegionTerms);
                }

                termsInRegion.Add(term);
                continue;
            }

            termsAfterRegion.Add(term);
            if (termsAfterRegion.Count == maximumTerms)
            {
                break;
            }
        }

        var terms = SelectWindow(
            termsBeforeRegion,
            termsInRegion,
            termsAfterRegion,
            maximumTerms);
        if (terms.Count == 0)
        {
            return new TokenWindowResult(
                Hash: null,
                TokenWindowRefusal.None);
        }

        return new TokenWindowResult(
            VersionedHash.Compute(
                FileSystemRepositoryContext.TokenWindowAlgorithmVersion,
                terms.Select(term => (string?)term).ToArray()),
            TokenWindowRefusal.None);
    }

    private static List<string> SelectWindow(
        Queue<string> termsBeforeRegion,
        List<string> termsInRegion,
        List<string> termsAfterRegion,
        int maximumTerms)
    {
        var remaining = maximumTerms - termsInRegion.Count;
        var desiredBefore = remaining / 2;
        var desiredAfter = remaining - desiredBefore;
        if (termsBeforeRegion.Count < desiredBefore)
        {
            desiredAfter += desiredBefore - termsBeforeRegion.Count;
            desiredBefore = termsBeforeRegion.Count;
        }

        if (termsAfterRegion.Count < desiredAfter)
        {
            desiredBefore = Math.Min(
                termsBeforeRegion.Count,
                desiredBefore + desiredAfter - termsAfterRegion.Count);
            desiredAfter = termsAfterRegion.Count;
        }

        var selected = new List<string>(
            desiredBefore + termsInRegion.Count + desiredAfter);
        selected.AddRange(
            termsBeforeRegion.Skip(termsBeforeRegion.Count - desiredBefore));
        selected.AddRange(termsInRegion);
        selected.AddRange(termsAfterRegion.Take(desiredAfter));
        return selected;
    }

    private static bool IsIdentifierCharacter(char value) =>
        value == '_' ||
        char.IsLetterOrDigit(value) ||
        value >= '\u0080';
}
