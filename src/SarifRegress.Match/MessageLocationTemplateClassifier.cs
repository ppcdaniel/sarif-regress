using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Utility;

namespace SarifRegress.Match;

/// <summary>
/// Recognizes a producer message delta that is fully explained by an accepted finding's move.
/// </summary>
/// <remarks>
/// This classifier runs only after correspondence. It cannot admit a candidate edge or influence
/// assignment. The accepted edge must use an explicit path alias. Both messages must contain
/// exactly one delimited form of their own known repository-relative path, and all text
/// surrounding those tokens must be identical.
/// </remarks>
internal static class MessageLocationTemplateClassifier
{
    private const string TransformationKind =
        "classification-message-location-template";

    /// <summary>
    /// Attempts to explain the entire canonical message delta as a repository-path substitution.
    /// </summary>
    // Time: O(m + p); Space: O(p), where m is the bounded message length and p is the bounded
    // repository-path length. At most two separator forms are examined per side.
    public static bool TryCreateTransformation(
        MatchEdge edge,
        out TransformationRecord? transformation)
    {
        ArgumentNullException.ThrowIfNull(edge);
        transformation = null;

        if (edge.DecisionVector.MessageAgreement != AgreementBand.None
            || edge.DecisionVector.PathMatchKind != PathMatchKind.Aliased
            || edge.Baseline.PrimaryLocation?.Path.RepositoryRelativePath
                is not string baselinePath
            || edge.Candidate.PrimaryLocation?.Path.RepositoryRelativePath
                is not string candidatePath
            || string.Equals(baselinePath, candidatePath, StringComparison.Ordinal))
        {
            return false;
        }

        string baselineMessage = edge.Baseline.Message.CanonicalText;
        string candidateMessage = edge.Candidate.Message.CanonicalText;
        TemplateParts? match = null;
        foreach (string baselineToken in CreatePathTokens(baselinePath))
        {
            if (!TrySplitAtSingleDelimitedToken(
                    baselineMessage,
                    baselineToken,
                    out TemplateParts baselineTemplate))
            {
                continue;
            }

            foreach (string candidateToken in CreatePathTokens(candidatePath))
            {
                if (!TrySplitAtSingleDelimitedToken(
                        candidateMessage,
                        candidateToken,
                        out TemplateParts candidateTemplate)
                    || baselineTemplate != candidateTemplate)
                {
                    continue;
                }

                if (match is not null)
                {
                    // More than one separator-form interpretation is not a unique explanation.
                    return false;
                }

                match = baselineTemplate;
            }
        }

        if (match is null)
        {
            return false;
        }

        string messagePairHash = VersionedHash.Compute(
            MatchingAlgorithms.MessageLocationTemplateVersion,
            "message-pair",
            baselineMessage,
            candidateMessage);
        string templateHash = VersionedHash.Compute(
            MatchingAlgorithms.MessageLocationTemplateVersion,
            "shared-template",
            match.Value.Prefix,
            match.Value.Suffix);
        transformation = new TransformationRecord(
            TransformationKind,
            $"sha256:{messagePairHash}",
            $"sha256:{templateHash}",
            isLossy: true,
            MatchingAlgorithms.MessageLocationTemplateVersion);
        return true;
    }

    private static string[] CreatePathTokens(string repositoryRelativePath)
    {
        string normalized = repositoryRelativePath;
        string alternate = normalized.Contains('/')
            ? normalized.Replace('/', '\\')
            : normalized.Contains('\\')
                ? normalized.Replace('\\', '/')
                : normalized;
        return string.Equals(normalized, alternate, StringComparison.Ordinal)
            ? [normalized]
            : [normalized, alternate];
    }

    private static bool TrySplitAtSingleDelimitedToken(
        string message,
        string token,
        out TemplateParts template)
    {
        template = default;
        if (token.Length == 0)
        {
            return false;
        }

        int index = message.IndexOf(token, StringComparison.Ordinal);
        if (index < 0
            || message.IndexOf(token, index + token.Length, StringComparison.Ordinal) >= 0
            || !HasLeftBoundary(message, index)
            || !HasRightBoundary(message, index + token.Length))
        {
            return false;
        }

        template = new TemplateParts(
            message[..index],
            message[(index + token.Length)..]);
        return true;
    }

    private static bool HasLeftBoundary(string message, int index) =>
        index == 0
        || char.IsWhiteSpace(message[index - 1])
        || message[index - 1] is '"' or '\'' or '`' or '(' or '[' or '{' or '<'
            or '=' or ':';

    private static bool HasRightBoundary(string message, int index)
    {
        if (index == message.Length)
        {
            return true;
        }

        char next = message[index];
        if (char.IsWhiteSpace(next)
            || next is '"' or '\'' or '`' or ')' or ']' or '}' or '>')
        {
            return true;
        }

        return next is '.' or ',' or ';' or ':' or '?' or '!'
            && (index + 1 == message.Length
                || char.IsWhiteSpace(message[index + 1])
                || message[index + 1] is '"' or '\'' or '`' or ')' or ']' or '}' or '>');
    }

    private readonly record struct TemplateParts(string Prefix, string Suffix);
}
