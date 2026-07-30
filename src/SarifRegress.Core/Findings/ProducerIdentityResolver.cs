using System.Text;
using SarifRegress.Core.Utility;

namespace SarifRegress.Core.Findings;

/// <summary>
/// Resolves a preserved SARIF tool name into display and automatic identities.
/// </summary>
public static class ProducerIdentityResolver
{
    /// <summary>
    /// Identifies the intentional collapsing of an allowlisted tool name into
    /// a broader semantic producer family.
    /// </summary>
    public const string AllowlistLossinessIdentifier =
        "producer-family-allowlist";

    private const string ToolNameIdentityAlgorithmVersion =
        "producer-tool-name/v1";
    private const string ToolNameIdentityPrefix =
        "producer-tool-name/v1/";
    private const string CodeQlFamily = "codeql";
    private const string CodeQlIdentity = "known-family/codeql";
    private const string SemgrepFamily = "semgrep";
    private const string SemgrepIdentity = "known-family/semgrep";

    private static readonly string[] CodeQlToolNames =
    [
        "CodeQL",
        "CodeQL command-line toolchain",
    ];

    private static readonly string[] SemgrepToolNames =
    [
        "Semgrep",
    ];

    /// <summary>
    /// Resolves a tool name without using the separately reported tool version.
    /// </summary>
    /// <remarks>
    /// Known semantic families use a closed, exact-name allowlist. All other
    /// names use a versioned SHA-256 identity over the complete UTF-8 name, so
    /// display-family normalization cannot merge distinct producers.
    /// </remarks>
    /// <param name="toolName">The validated, non-empty SARIF tool name.</param>
    /// <returns>The display family, automatic identity, and optional lossiness.</returns>
    // Time: O(n); Space: O(n), where n is the tool-name length.
    public static ProducerIdentityResolution Resolve(string toolName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);

        if (IsAllowlistedName(toolName, CodeQlToolNames))
        {
            return new ProducerIdentityResolution(
                CodeQlFamily,
                CodeQlIdentity,
                AllowlistLossinessIdentifier);
        }

        if (IsAllowlistedName(toolName, SemgrepToolNames))
        {
            return new ProducerIdentityResolution(
                SemgrepFamily,
                SemgrepIdentity,
                AllowlistLossinessIdentifier);
        }

        var digest = VersionedHash.Compute(
            ToolNameIdentityAlgorithmVersion,
            toolName);
        return new ProducerIdentityResolution(
            NormalizeDisplayFamily(toolName),
            ToolNameIdentityPrefix + digest,
            LossinessIdentifier: null);
    }

    private static bool IsAllowlistedName(
        string toolName,
        IReadOnlyList<string> allowlistedNames)
    {
        for (var index = 0; index < allowlistedNames.Count; index++)
        {
            if (string.Equals(
                    toolName,
                    allowlistedNames[index],
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string NormalizeDisplayFamily(string toolName)
    {
        var builder = new StringBuilder(toolName.Length);
        var previousWasSeparator = false;
        foreach (var character in toolName)
        {
            var normalized = character switch
            {
                >= 'A' and <= 'Z' => (char)(character + ('a' - 'A')),
                >= 'a' and <= 'z' or >= '0' and <= '9' => character,
                _ => '-',
            };
            if (normalized == '-')
            {
                if (builder.Length > 0 && !previousWasSeparator)
                {
                    builder.Append(normalized);
                }

                previousWasSeparator = true;
                continue;
            }

            builder.Append(normalized);
            previousWasSeparator = false;
        }

        var family = builder.ToString().TrimEnd('-');
        return family.Length == 0 ? "unknown-producer" : family;
    }
}

/// <summary>
/// Carries the display-only family and the separate automatic match identity.
/// </summary>
/// <param name="Family">The human-readable family label.</param>
/// <param name="AutomaticIdentity">
/// The collision-resistant identity used for automatic matching.
/// </param>
/// <param name="LossinessIdentifier">
/// The optional identifier for an intentional allowlist collapse.
/// </param>
public readonly record struct ProducerIdentityResolution(
    string Family,
    string AutomaticIdentity,
    string? LossinessIdentifier);
