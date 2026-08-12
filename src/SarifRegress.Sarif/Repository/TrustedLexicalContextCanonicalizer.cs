using System.Text;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;

namespace SarifRegress.Sarif.Repository;

internal enum TrustedLexicalContextRefusal
{
    None,
    NotSingleLine,
    NoStatement,
    NoEnclosingScope,
    TargetLineContainsBrace,
    TooManyTerms,
    TermTooLong,
    ScopeTooDeep,
    UnterminatedLiteralOrComment,
}

internal readonly record struct TrustedLexicalContextResult(
    string? Hash,
    TrustedLexicalContextRefusal Refusal);

internal readonly record struct TrustedLexicalContextIndexResult(
    TrustedLexicalContextResult[]? Results,
    int StoredHashCount)
{
    public static TrustedLexicalContextIndexResult Refused { get; } =
        new(Results: null, StoredHashCount: 0);
}

/// <summary>
/// Creates a producer-neutral source atom from one brace-scope header and one
/// exact single-line statement while excluding line and block comments.
/// </summary>
internal static class TrustedLexicalContextCanonicalizer
{
    private const int CancellationCheckMask = 1023;
    private static readonly HashSet<string> ControlScopeKeywords = new(
        [
            "catch",
            "do",
            "else",
            "for",
            "if",
            "switch",
            "synchronized",
            "try",
            "while",
        ],
        StringComparer.Ordinal);

    // Time: O(file characters). Space: O(line count + bounded scope state).
    public static TrustedLexicalContextIndexResult CreateIndex(
        string normalizedSourceText,
        int lineCount,
        int maximumStoredHashes,
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(normalizedSourceText);
        ArgumentNullException.ThrowIfNull(limits);
        cancellationToken.ThrowIfCancellationRequested();

        if (lineCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(lineCount));
        }

        if (maximumStoredHashes < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumStoredHashes));
        }

        var results = new TrustedLexicalContextResult[lineCount];
        Array.Fill(
            results,
            Refuse(TrustedLexicalContextRefusal.NoStatement));
        var scopeHeaders = new List<string?>(
            Math.Min(limits.MaximumJsonDepth, 16));
        var currentHeaderTerms = new List<string>(
            Math.Min(limits.MaximumTokenWindowTerms, 16));
        var statementTerms = new List<string>(
            Math.Min(limits.MaximumTokenWindowTerms, 16));
        var currentHeaderOverflowed = false;
        var offset = 0;
        var line = 1;
        var currentTokenLine = 0;
        var earlyLineRefusal = TrustedLexicalContextRefusal.None;
        var targetLineContainsBrace = false;
        var storedHashCount = 0;

        while (offset < normalizedSourceText.Length)
        {
            if ((offset & CancellationCheckMask) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            var tokenResult = ReadNextToken(
                normalizedSourceText,
                ref offset,
                ref line,
                limits,
                cancellationToken);
            if (tokenResult.Refusal is not TrustedLexicalContextRefusal.None)
            {
                var refusalLine = tokenResult.RefusalLine;
                if (currentTokenLine > 0 &&
                    currentTokenLine < refusalLine &&
                    !TryFinalizeLine(
                        results,
                        currentTokenLine,
                        statementTerms,
                        scopeHeaders,
                        earlyLineRefusal,
                        targetLineContainsBrace,
                        globalRefusal: TrustedLexicalContextRefusal.None,
                        maximumStoredHashes,
                        ref storedHashCount))
                {
                    return TrustedLexicalContextIndexResult.Refused;
                }

                FillRefusal(
                    results,
                    refusalLine,
                    tokenResult.Refusal);

                return new TrustedLexicalContextIndexResult(
                    results,
                    storedHashCount);
            }

            if (tokenResult.Token is not LexicalToken token)
            {
                continue;
            }

            if (token.Line < 1 || token.Line > lineCount)
            {
                throw new InvalidOperationException(
                    "The lexical token line is outside the source index.");
            }

            if (token.Line != currentTokenLine)
            {
                if (currentTokenLine > 0 &&
                    !TryFinalizeLine(
                        results,
                        currentTokenLine,
                        statementTerms,
                        scopeHeaders,
                        earlyLineRefusal,
                        targetLineContainsBrace,
                        globalRefusal: TrustedLexicalContextRefusal.None,
                        maximumStoredHashes,
                        ref storedHashCount))
                {
                    return TrustedLexicalContextIndexResult.Refused;
                }

                currentTokenLine = token.Line;
                statementTerms.Clear();
                earlyLineRefusal = TrustedLexicalContextRefusal.None;
                targetLineContainsBrace = false;
            }

            if (earlyLineRefusal is TrustedLexicalContextRefusal.None)
            {
                if (token.CrossesLine)
                {
                    earlyLineRefusal =
                        TrustedLexicalContextRefusal.NotSingleLine;
                }
                else if (token.Value is "{" or "}")
                {
                    targetLineContainsBrace = true;
                }
                else
                {
                    if (statementTerms.Count ==
                        limits.MaximumTokenWindowTerms)
                    {
                        earlyLineRefusal =
                            TrustedLexicalContextRefusal.TooManyTerms;
                    }
                    else
                    {
                        statementTerms.Add(token.Value);
                    }
                }
            }

            switch (token.Value)
            {
                case "{":
                    if (scopeHeaders.Count == limits.MaximumJsonDepth)
                    {
                        if (!TryFinalizeLine(
                                results,
                                currentTokenLine,
                                statementTerms,
                                scopeHeaders,
                                earlyLineRefusal,
                                targetLineContainsBrace,
                                TrustedLexicalContextRefusal.ScopeTooDeep,
                                maximumStoredHashes,
                                ref storedHashCount))
                        {
                            return TrustedLexicalContextIndexResult.Refused;
                        }

                        FillRefusal(
                            results,
                            currentTokenLine + 1,
                            TrustedLexicalContextRefusal.ScopeTooDeep);
                        return new TrustedLexicalContextIndexResult(
                            results,
                            storedHashCount);
                    }

                    var inheritedScopeHeader = scopeHeaders.Count == 0
                        ? null
                        : scopeHeaders[^1];
                    scopeHeaders.Add(
                        !currentHeaderOverflowed &&
                        IsMethodLikeScopeHeader(currentHeaderTerms)
                            ? HashTerms(
                                "scope-header",
                                currentHeaderTerms)
                            : inheritedScopeHeader);
                    currentHeaderTerms.Clear();
                    currentHeaderOverflowed = false;
                    break;
                case "}":
                    if (scopeHeaders.Count > 0)
                    {
                        scopeHeaders.RemoveAt(scopeHeaders.Count - 1);
                    }

                    currentHeaderTerms.Clear();
                    currentHeaderOverflowed = false;
                    break;
                case ";":
                    currentHeaderTerms.Clear();
                    currentHeaderOverflowed = false;
                    break;
                default:
                    if (currentHeaderOverflowed)
                    {
                        break;
                    }

                    if (currentHeaderTerms.Count ==
                        limits.MaximumTokenWindowTerms)
                    {
                        currentHeaderTerms.Clear();
                        currentHeaderOverflowed = true;
                        break;
                    }

                    currentHeaderTerms.Add(token.Value);
                    break;
            }
        }

        if (currentTokenLine > 0 &&
            !TryFinalizeLine(
                results,
                currentTokenLine,
                statementTerms,
                scopeHeaders,
                earlyLineRefusal,
                targetLineContainsBrace,
                globalRefusal: TrustedLexicalContextRefusal.None,
                maximumStoredHashes,
                ref storedHashCount))
        {
            return TrustedLexicalContextIndexResult.Refused;
        }

        return new TrustedLexicalContextIndexResult(
            results,
            storedHashCount);
    }

    private static bool TryFinalizeLine(
        TrustedLexicalContextResult[] results,
        int line,
        IReadOnlyList<string> statementTerms,
        IReadOnlyList<string?> scopeHeaders,
        TrustedLexicalContextRefusal earlyLineRefusal,
        bool targetLineContainsBrace,
        TrustedLexicalContextRefusal globalRefusal,
        int maximumStoredHashes,
        ref int storedHashCount)
    {
        if (earlyLineRefusal is not TrustedLexicalContextRefusal.None)
        {
            results[line - 1] = Refuse(earlyLineRefusal);
            return true;
        }

        if (globalRefusal is not TrustedLexicalContextRefusal.None)
        {
            results[line - 1] = Refuse(globalRefusal);
            return true;
        }

        if (targetLineContainsBrace)
        {
            results[line - 1] = Refuse(
                TrustedLexicalContextRefusal.TargetLineContainsBrace);
            return true;
        }

        if (statementTerms.Count == 0)
        {
            return true;
        }

        var scopeHeaderHash = scopeHeaders.Count == 0
            ? null
            : scopeHeaders[^1];
        if (scopeHeaderHash is null)
        {
            results[line - 1] = Refuse(
                TrustedLexicalContextRefusal.NoEnclosingScope);
            return true;
        }

        if (storedHashCount == maximumStoredHashes)
        {
            return false;
        }

        results[line - 1] = new TrustedLexicalContextResult(
            VersionedHash.Compute(
                FileSystemRepositoryContext
                    .TrustedLexicalContextAlgorithmVersion,
                scopeHeaderHash,
                HashTerms("exact-statement", statementTerms)),
            TrustedLexicalContextRefusal.None);
        storedHashCount++;
        return true;
    }

    private static void FillRefusal(
        TrustedLexicalContextResult[] results,
        int firstLine,
        TrustedLexicalContextRefusal refusal)
    {
        for (var line = firstLine; line <= results.Length; line++)
        {
            results[line - 1] = Refuse(refusal);
        }
    }

    private static TokenReadResult ReadNextToken(
        string sourceText,
        ref int offset,
        ref int line,
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
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

            if (current == '/' &&
                offset + 1 < sourceText.Length &&
                sourceText[offset + 1] == '/')
            {
                offset += 2;
                while (offset < sourceText.Length &&
                    sourceText[offset] != '\n')
                {
                    if ((offset & CancellationCheckMask) == 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                    }

                    offset++;
                }

                continue;
            }

            if (current == '/' &&
                offset + 1 < sourceText.Length &&
                sourceText[offset + 1] == '*')
            {
                var commentLine = line;
                offset += 2;
                var terminated = false;
                while (offset < sourceText.Length)
                {
                    if ((offset & CancellationCheckMask) == 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                    }

                    if (sourceText[offset] == '\n')
                    {
                        line++;
                        offset++;
                        continue;
                    }

                    if (sourceText[offset] == '*' &&
                        offset + 1 < sourceText.Length &&
                        sourceText[offset + 1] == '/')
                    {
                        offset += 2;
                        terminated = true;
                        break;
                    }

                    offset++;
                }

                if (!terminated)
                {
                    return TokenReadResult.Refused(
                        TrustedLexicalContextRefusal
                            .UnterminatedLiteralOrComment,
                        commentLine);
                }

                continue;
            }

            break;
        }

        if (offset >= sourceText.Length)
        {
            return TokenReadResult.End;
        }

        var tokenLine = line;
        var tokenStart = offset;
        var quote = sourceText[offset] is '\'' or '"'
            ? sourceText[offset]
            : '\0';
        if (quote != '\0')
        {
            offset++;
            var escaped = false;
            var terminated = false;
            while (offset < sourceText.Length)
            {
                if ((offset & CancellationCheckMask) == 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                var current = sourceText[offset++];
                if (current == '\n')
                {
                    line++;
                }

                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (current == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (current == quote)
                {
                    terminated = true;
                    break;
                }
            }

            if (!terminated)
            {
                return TokenReadResult.Refused(
                    TrustedLexicalContextRefusal
                        .UnterminatedLiteralOrComment,
                    tokenLine);
            }
        }
        else if (IsIdentifierCharacter(sourceText[offset]))
        {
            do
            {
                if ((offset & CancellationCheckMask) == 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                offset++;
            }
            while (offset < sourceText.Length &&
                IsIdentifierCharacter(sourceText[offset]));
        }
        else
        {
            offset++;
        }

        var tokenLength = offset - tokenStart;
        if (tokenLength > limits.MaximumStringCharacters)
        {
            return TokenReadResult.Refused(
                TrustedLexicalContextRefusal.TermTooLong,
                tokenLine);
        }

        var token = sourceText
            .Substring(tokenStart, tokenLength)
            .Normalize(NormalizationForm.FormC);
        if (token.Length > limits.MaximumStringCharacters)
        {
            return TokenReadResult.Refused(
                TrustedLexicalContextRefusal.TermTooLong,
                tokenLine);
        }

        return new TokenReadResult(
            new LexicalToken(
                token,
                tokenLine,
                CrossesLine: line != tokenLine),
            TrustedLexicalContextRefusal.None,
            RefusalLine: 0);
    }

    private static string HashTerms(
        string domain,
        IReadOnlyList<string> terms)
    {
        var fields = new string?[terms.Count + 2];
        fields[0] = domain;
        fields[1] = terms.Count.ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        for (var index = 0; index < terms.Count; index++)
        {
            fields[index + 2] = terms[index];
        }

        return VersionedHash.Compute(
            FileSystemRepositoryContext
                .TrustedLexicalContextAlgorithmVersion,
            fields);
    }

    private static TrustedLexicalContextResult Refuse(
        TrustedLexicalContextRefusal refusal) =>
        new(Hash: null, refusal);

    private static bool IsIdentifierCharacter(char value) =>
        value == '_' ||
        value == '$' ||
        char.IsLetterOrDigit(value) ||
        value >= '\u0080';

    private static bool IsMethodLikeScopeHeader(
        IReadOnlyList<string> headerTerms)
    {
        if (!headerTerms.Contains("(", StringComparer.Ordinal) ||
            !headerTerms.Contains(")", StringComparer.Ordinal))
        {
            return false;
        }

        var firstIdentifier = headerTerms.FirstOrDefault(
            term => term.Length > 0 &&
                (term[0] is '_' or '$' ||
                    char.IsLetter(term[0]) ||
                    term[0] >= '\u0080'));
        return firstIdentifier is not null &&
            !ControlScopeKeywords.Contains(firstIdentifier);
    }

    private readonly record struct LexicalToken(
        string Value,
        int Line,
        bool CrossesLine);

    private readonly record struct TokenReadResult(
        LexicalToken? Token,
        TrustedLexicalContextRefusal Refusal,
        int RefusalLine)
    {
        public static TokenReadResult End { get; } =
            new(
                Token: null,
                TrustedLexicalContextRefusal.None,
                RefusalLine: 0);

        public static TokenReadResult Refused(
            TrustedLexicalContextRefusal refusal,
            int refusalLine) =>
            new(Token: null, refusal, refusalLine);
    }
}
