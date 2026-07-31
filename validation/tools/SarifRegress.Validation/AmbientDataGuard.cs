using System.Text;
using System.Text.RegularExpressions;

namespace SarifRegress.Validation;

/// <summary>
/// Rejects ambient machine data from committed, project-owned normalized reports.
/// </summary>
public static partial class AmbientDataGuard
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>
    /// Ensures output is LF-only UTF-8 and contains no checkout path, host name, or timestamp.
    /// </summary>
    public static void Validate(ReadOnlySpan<byte> bytes, string repositoryRoot)
    {
        if (bytes.IsEmpty || bytes[^1] != (byte)'\n')
        {
            throw new InvalidDataException("A normalized report must end with LF.");
        }

        if (bytes.Contains((byte)'\r'))
        {
            throw new InvalidDataException("A normalized report contains a CR newline.");
        }

        string text = StrictUtf8.GetString(bytes);
        RejectLiteral(text, Path.GetFullPath(repositoryRoot), "checkout path");
        RejectLiteral(text, Environment.CurrentDirectory, "working directory");
        RejectLiteral(text, Path.GetTempPath(), "temporary directory");
        RejectLiteral(text, Environment.MachineName, "host name");
        if (WindowsAbsolutePath().IsMatch(text)
            || PosixAbsoluteJsonValue().IsMatch(text)
            || text.Contains("file:///", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "A normalized report contains an absolute filesystem path.");
        }

        if (IsoTimestamp().IsMatch(text))
        {
            throw new InvalidDataException(
                "A normalized report contains a timestamp derived from its environment.");
        }
    }

    private static void RejectLiteral(string text, string value, string kind)
    {
        string normalized = Path.TrimEndingDirectorySeparator(value);
        if (normalized.Length >= 3
            && text.Contains(normalized, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"A normalized report contains its ambient {kind}.");
        }
    }

    [GeneratedRegex(@"(?<![A-Za-z0-9])[A-Za-z]:[\\/]", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsAbsolutePath();

    [GeneratedRegex("\\\"[^\\\"]+\\\"\\s*:\\s*\\\"/(?!/)", RegexOptions.CultureInvariant)]
    private static partial Regex PosixAbsoluteJsonValue();

    [GeneratedRegex(@"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", RegexOptions.CultureInvariant)]
    private static partial Regex IsoTimestamp();
}
