using System.Text;

namespace SarifRegress.Validation;

/// <summary>
/// Translates the supported ECMA-262 regular-expression subset to equivalent .NET syntax.
/// </summary>
/// <remarks>
/// JSON Schema patterns are not .NET regular expressions. The translator normalizes known
/// dialect differences and rejects constructs whose behavior is not explicitly preserved.
/// </remarks>
internal static class Ecma262RegexTranslator
{
    private const string EcmaWhitespaceClassContent =
        @"\u0009-\u000D\u0020\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF";
    private const string EcmaDigitClassContent = "0-9";
    private const string EcmaWordClassContent = "A-Za-z0-9_";
    private const string EcmaDotEquivalent = @"[^\r\n\u2028\u2029]";

    /// <summary>Translates one bounded JSON Schema pattern without changing its match language.</summary>
    // Time: O(P), Space: O(P), where P is the pattern length.
    public static string Translate(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        var translated = new StringBuilder(pattern.Length);
        var insideCharacterClass = false;
        for (var index = 0; index < pattern.Length; index++)
        {
            char current = pattern[index];
            if (current == '\\')
            {
                TranslateEscape(pattern, ref index, insideCharacterClass, translated);
                continue;
            }

            if (insideCharacterClass)
            {
                if (current == ']')
                {
                    insideCharacterClass = false;
                }
                else if (current == '-'
                    && index + 1 < pattern.Length
                    && pattern[index + 1] == '[')
                {
                    throw Unsupported(".NET character-class subtraction");
                }

                translated.Append(current);
                continue;
            }

            if (current == '[')
            {
                insideCharacterClass = true;
                translated.Append(current);
                continue;
            }

            if (current == '$')
            {
                translated.Append(@"\z");
                continue;
            }

            if (current == '.')
            {
                translated.Append(EcmaDotEquivalent);
                continue;
            }

            if (current == '(' && index + 1 < pattern.Length && pattern[index + 1] == '?')
            {
                RequireSupportedGroupPrefix(pattern, index);
            }

            translated.Append(current);
        }

        if (insideCharacterClass)
        {
            throw new JsonSchemaDefinitionException(
                "A schema regular expression contains an unterminated character class.");
        }

        return translated.ToString();
    }

    private static void TranslateEscape(
        string pattern,
        ref int index,
        bool insideCharacterClass,
        StringBuilder translated)
    {
        if (++index >= pattern.Length)
        {
            throw new JsonSchemaDefinitionException(
                "A schema regular expression ends with an incomplete escape.");
        }

        char escaped = pattern[index];
        switch (escaped)
        {
            case 's':
                AppendPositiveClass(translated, EcmaWhitespaceClassContent, insideCharacterClass);
                return;
            case 'S':
                AppendNegativeClass(
                    translated,
                    EcmaWhitespaceClassContent,
                    insideCharacterClass,
                    "'\\S' inside a character class");
                return;
            case 'd':
                AppendPositiveClass(translated, EcmaDigitClassContent, insideCharacterClass);
                return;
            case 'D':
                AppendNegativeClass(
                    translated,
                    EcmaDigitClassContent,
                    insideCharacterClass,
                    "'\\D' inside a character class");
                return;
            case 'w':
                AppendPositiveClass(translated, EcmaWordClassContent, insideCharacterClass);
                return;
            case 'W':
                AppendNegativeClass(
                    translated,
                    EcmaWordClassContent,
                    insideCharacterClass,
                    "'\\W' inside a character class");
                return;
            case 'b' when insideCharacterClass:
                translated.Append(@"\x08");
                return;
            case 'b':
            case 'B':
                throw Unsupported("ECMA word-boundary escapes");
            case '0':
                if (index + 1 < pattern.Length && char.IsAsciiDigit(pattern[index + 1]))
                {
                    throw Unsupported("legacy octal or numeric escapes");
                }

                translated.Append(@"\u0000");
                return;
            case >= '1' and <= '9':
                throw Unsupported("numeric backreferences");
            case 'A':
            case 'G':
            case 'K':
            case 'R':
            case 'Z':
            case 'z':
            case 'k':
            case 'p':
            case 'P':
                throw Unsupported($"escape '\\{escaped}'");
            case 'c':
                throw Unsupported("control-letter escapes");
            case 'x':
                AppendFixedHexEscape(pattern, ref index, translated, hexadecimalDigits: 2);
                return;
            case 'u':
                AppendFixedHexEscape(pattern, ref index, translated, hexadecimalDigits: 4);
                return;
            case 'f':
            case 'n':
            case 'r':
            case 't':
            case 'v':
                translated.Append('\\').Append(escaped);
                return;
            default:
                if (!IsEscapableSyntaxCharacter(escaped))
                {
                    throw Unsupported($"identity escape '\\{escaped}'");
                }

                translated.Append('\\').Append(escaped);
                return;
        }
    }

    private static void AppendFixedHexEscape(
        string pattern,
        ref int index,
        StringBuilder translated,
        int hexadecimalDigits)
    {
        char prefix = pattern[index];
        if (index + hexadecimalDigits >= pattern.Length)
        {
            throw new JsonSchemaDefinitionException(
                $"A schema regular expression contains an incomplete '\\{prefix}' escape.");
        }

        translated.Append('\\').Append(prefix);
        for (var offset = 1; offset <= hexadecimalDigits; offset++)
        {
            char digit = pattern[index + offset];
            if (!Uri.IsHexDigit(digit))
            {
                throw new JsonSchemaDefinitionException(
                    $"A schema regular expression contains an invalid '\\{prefix}' escape.");
            }

            translated.Append(digit);
        }

        index += hexadecimalDigits;
    }

    private static void AppendPositiveClass(
        StringBuilder translated,
        string classContent,
        bool insideCharacterClass)
    {
        if (insideCharacterClass)
        {
            translated.Append(classContent);
            return;
        }

        translated.Append('[').Append(classContent).Append(']');
    }

    private static void AppendNegativeClass(
        StringBuilder translated,
        string classContent,
        bool insideCharacterClass,
        string constructName)
    {
        if (insideCharacterClass)
        {
            throw Unsupported(constructName);
        }

        translated.Append("[^").Append(classContent).Append(']');
    }

    private static void RequireSupportedGroupPrefix(string pattern, int groupStart)
    {
        if (groupStart + 2 >= pattern.Length)
        {
            throw new JsonSchemaDefinitionException(
                "A schema regular expression contains an incomplete group prefix.");
        }

        char groupKind = pattern[groupStart + 2];
        if (groupKind is ':' or '=' or '!')
        {
            return;
        }

        throw Unsupported("inline options, named groups, lookbehind, or .NET-only groups");
    }

    private static bool IsEscapableSyntaxCharacter(char value) => value is
        '^' or '$' or '\\' or '.' or '*' or '+' or '?' or '(' or ')' or '[' or ']'
        or '{' or '}' or '|' or '/' or '-';

    private static JsonSchemaDefinitionException Unsupported(string construct) => new(
        $"Schema regular-expression construct {construct} is not supported by the bounded "
        + "ECMA-262 translator.");
}
