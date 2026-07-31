using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SarifRegress.Validation;

/// <summary>
/// Creates and verifies an exact lowercase SHA-256 manifest in ordinal filename order.
/// </summary>
public static partial class ChecksumManifest
{
    /// <summary>Computes a deterministic manifest over the supplied in-memory files.</summary>
    public static byte[] Create(IReadOnlyDictionary<string, byte[]> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        var builder = new StringBuilder();
        foreach ((string name, byte[] bytes) in files.OrderBy(
                     item => item.Key,
                     StringComparer.Ordinal))
        {
            ValidateEntryName(name);
            string digest = Convert.ToHexString(SHA256.HashData(bytes))
                .ToLowerInvariant();
            builder.Append(digest).Append("  ").Append(name).Append('\n');
        }

        return new UTF8Encoding(false, true).GetBytes(builder.ToString());
    }

    /// <summary>Parses and validates a checksum manifest without filesystem access.</summary>
    public static ImmutableSortedDictionary<string, string> Parse(
        ReadOnlySpan<byte> bytes)
    {
        string text = new UTF8Encoding(false, true).GetString(bytes);
        if (!text.EndsWith('\n') || text.Contains('\r'))
        {
            throw new InvalidDataException(
                "The checksum manifest must use LF and end with LF.");
        }

        var values = ImmutableSortedDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            System.Text.RegularExpressions.Match match = ChecksumLine().Match(line);
            if (!match.Success)
            {
                throw new InvalidDataException(
                    "The checksum manifest contains an invalid line.");
            }

            string name = match.Groups[2].Value;
            ValidateEntryName(name);
            if (!values.TryAdd(name, match.Groups[1].Value))
            {
                throw new InvalidDataException(
                    $"The checksum manifest repeats '{name}'.");
            }
        }

        if (values.Count == 0)
        {
            throw new InvalidDataException("The checksum manifest is empty.");
        }

        return values.ToImmutable();
    }

    /// <summary>Verifies exact expected names and file bytes beneath one root.</summary>
    public static void VerifyFiles(
        string root,
        ReadOnlySpan<byte> manifestBytes,
        IEnumerable<string> expectedNames)
    {
        ImmutableSortedDictionary<string, string> entries = Parse(manifestBytes);
        string[] names = expectedNames.Order(StringComparer.Ordinal).ToArray();
        if (!entries.Keys.SequenceEqual(names, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The checksum manifest does not contain the exact expected file set.");
        }

        foreach (string name in names)
        {
            string path = Path.Combine(root, name);
            string actual = BoundedJsonFile.ComputeSha256(
                path,
                ValidationLimits.Default.MaximumSarifBytes,
                root);
            if (!string.Equals(actual, entries[name], StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Checksum verification failed for '{name}'.");
            }
        }
    }

    private static void ValidateEntryName(string name)
    {
        StablePath.RequireRepositoryRelative(name, "checksum path");
    }

    [GeneratedRegex("^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ChecksumLine();
}
