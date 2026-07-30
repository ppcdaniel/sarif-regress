namespace SarifRegress.Core.Security;

/// <summary>
/// Defines hard bounds applied while processing untrusted inputs.
/// </summary>
public sealed record ResourceLimits
{
    /// <summary>
    /// Gets the default maximum size of one SARIF or configuration input.
    /// </summary>
    public const long DefaultMaximumInputBytes = 256L * 1024L * 1024L;

    /// <summary>
    /// Gets the default maximum JSON nesting depth.
    /// </summary>
    public const int DefaultMaximumJsonDepth = 128;

    /// <summary>
    /// Gets the default maximum number of runs in one SARIF log.
    /// </summary>
    public const int DefaultMaximumRuns = 64;

    /// <summary>
    /// Gets the default maximum number of rules, artifacts, or results in one run.
    /// </summary>
    public const int DefaultMaximumRunCollectionItems = 250_000;

    /// <summary>
    /// Gets the default maximum number of locations of one kind on one result.
    /// </summary>
    public const int DefaultMaximumLocationsPerResult = 1_000;

    /// <summary>
    /// Gets the default maximum number of code flows on one result.
    /// </summary>
    public const int DefaultMaximumCodeFlowsPerResult = 100;

    /// <summary>
    /// Gets the default maximum number of thread-flow locations on one result.
    /// </summary>
    public const int DefaultMaximumThreadFlowLocationsPerResult = 10_000;

    /// <summary>
    /// Gets the default maximum number of UTF-16 characters in one input string.
    /// </summary>
    public const int DefaultMaximumStringCharacters = 4 * 1024 * 1024;

    /// <summary>
    /// Gets the default maximum URI-base recursion depth.
    /// </summary>
    public const int DefaultMaximumUriBaseDepth = 32;

    /// <summary>
    /// Gets the default maximum source file size read through repository context.
    /// </summary>
    public const long DefaultMaximumRepositoryFileBytes = 4L * 1024L * 1024L;

    /// <summary>
    /// Gets the default maximum configured source-snippet radius.
    /// </summary>
    public const int DefaultMaximumSnippetRadius = 20;

    /// <summary>
    /// Gets the default maximum number of terms in a token window.
    /// </summary>
    public const int DefaultMaximumTokenWindowTerms = 256;

    /// <summary>
    /// Gets the default maximum number of retained candidate edges per finding.
    /// </summary>
    public const int DefaultMaximumCandidateEdgesPerFinding = 64;

    /// <summary>
    /// Gets the default maximum number of candidate-selection items inspected for either finding.
    /// </summary>
    public const int DefaultMaximumCandidatePairEvaluationsPerFinding = 256;

    /// <summary>
    /// Gets the default maximum number of coarse candidate pairs evaluated by one comparison.
    /// </summary>
    public const long DefaultMaximumCandidatePairEvaluations = 1_000_000;

    /// <summary>
    /// Gets the default maximum number of rejected alternatives emitted per decision.
    /// </summary>
    public const int DefaultMaximumRejectedAlternatives = 100;

    /// <summary>
    /// Gets the matcher-v1 hard maximum number of findings on either side of an exact assignment.
    /// </summary>
    public const int HardMaximumAssignmentSideSize = 12;

    /// <summary>
    /// Gets the default maximum number of findings on either side of an exactly solved component.
    /// </summary>
    public const int DefaultMaximumAssignmentSideSize = HardMaximumAssignmentSideSize;

    /// <summary>
    /// Gets the standard MVP limits.
    /// </summary>
    public static ResourceLimits Default { get; } = new();

    /// <summary>
    /// Gets the maximum input size in bytes.
    /// </summary>
    public long MaximumInputBytes { get; init; } = DefaultMaximumInputBytes;

    /// <summary>
    /// Gets the maximum JSON nesting depth.
    /// </summary>
    public int MaximumJsonDepth { get; init; } = DefaultMaximumJsonDepth;

    /// <summary>
    /// Gets the maximum number of runs.
    /// </summary>
    public int MaximumRuns { get; init; } = DefaultMaximumRuns;

    /// <summary>
    /// Gets the maximum number of rules, artifacts, or results per run.
    /// </summary>
    public int MaximumRunCollectionItems { get; init; } = DefaultMaximumRunCollectionItems;

    /// <summary>
    /// Gets the maximum number of locations of one kind per result.
    /// </summary>
    public int MaximumLocationsPerResult { get; init; } = DefaultMaximumLocationsPerResult;

    /// <summary>
    /// Gets the maximum number of code flows per result.
    /// </summary>
    public int MaximumCodeFlowsPerResult { get; init; } = DefaultMaximumCodeFlowsPerResult;

    /// <summary>
    /// Gets the maximum number of thread-flow locations per result.
    /// </summary>
    public int MaximumThreadFlowLocationsPerResult { get; init; } =
        DefaultMaximumThreadFlowLocationsPerResult;

    /// <summary>
    /// Gets the maximum number of UTF-16 characters in one input string.
    /// </summary>
    public int MaximumStringCharacters { get; init; } = DefaultMaximumStringCharacters;

    /// <summary>
    /// Gets the maximum URI-base recursion depth.
    /// </summary>
    public int MaximumUriBaseDepth { get; init; } = DefaultMaximumUriBaseDepth;

    /// <summary>
    /// Gets the maximum source file size read through repository context.
    /// </summary>
    public long MaximumRepositoryFileBytes { get; init; } = DefaultMaximumRepositoryFileBytes;

    /// <summary>
    /// Gets the maximum configured source-snippet radius.
    /// </summary>
    public int MaximumSnippetRadius { get; init; } = DefaultMaximumSnippetRadius;

    /// <summary>
    /// Gets the maximum token-window size.
    /// </summary>
    public int MaximumTokenWindowTerms { get; init; } = DefaultMaximumTokenWindowTerms;

    /// <summary>
    /// Gets the maximum retained candidate edges per finding.
    /// </summary>
    public int MaximumCandidateEdgesPerFinding { get; init; } =
        DefaultMaximumCandidateEdgesPerFinding;

    /// <summary>
    /// Gets the maximum number of candidate-selection items inspected for either finding.
    /// </summary>
    public int MaximumCandidatePairEvaluationsPerFinding { get; init; } =
        DefaultMaximumCandidatePairEvaluationsPerFinding;

    /// <summary>
    /// Gets the maximum number of coarse candidate pairs evaluated by one comparison.
    /// </summary>
    public long MaximumCandidatePairEvaluations { get; init; } =
        DefaultMaximumCandidatePairEvaluations;

    /// <summary>
    /// Gets the maximum emitted rejected alternatives per decision.
    /// </summary>
    public int MaximumRejectedAlternatives { get; init; } =
        DefaultMaximumRejectedAlternatives;

    /// <summary>
    /// Gets the maximum number of findings on either side of an exactly solved component.
    /// </summary>
    public int MaximumAssignmentSideSize { get; init; } =
        DefaultMaximumAssignmentSideSize;

    /// <summary>
    /// Validates that every configured bound is positive and internally consistent.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when a configured bound is not positive.
    /// </exception>
    public void Validate()
    {
        ValidatePositive(MaximumInputBytes, nameof(MaximumInputBytes));
        ValidatePositive(MaximumJsonDepth, nameof(MaximumJsonDepth));
        ValidatePositive(MaximumRuns, nameof(MaximumRuns));
        ValidatePositive(MaximumRunCollectionItems, nameof(MaximumRunCollectionItems));
        ValidatePositive(MaximumLocationsPerResult, nameof(MaximumLocationsPerResult));
        ValidatePositive(MaximumCodeFlowsPerResult, nameof(MaximumCodeFlowsPerResult));
        ValidatePositive(
            MaximumThreadFlowLocationsPerResult,
            nameof(MaximumThreadFlowLocationsPerResult));
        ValidatePositive(MaximumStringCharacters, nameof(MaximumStringCharacters));
        ValidatePositive(MaximumUriBaseDepth, nameof(MaximumUriBaseDepth));
        ValidatePositive(MaximumRepositoryFileBytes, nameof(MaximumRepositoryFileBytes));
        ValidatePositive(MaximumSnippetRadius, nameof(MaximumSnippetRadius));
        ValidatePositive(MaximumTokenWindowTerms, nameof(MaximumTokenWindowTerms));
        ValidatePositive(
            MaximumCandidateEdgesPerFinding,
            nameof(MaximumCandidateEdgesPerFinding));
        ValidatePositive(
            MaximumCandidatePairEvaluationsPerFinding,
            nameof(MaximumCandidatePairEvaluationsPerFinding));
        ValidatePositive(
            MaximumCandidatePairEvaluations,
            nameof(MaximumCandidatePairEvaluations));
        ValidatePositive(MaximumRejectedAlternatives, nameof(MaximumRejectedAlternatives));
        ValidatePositive(MaximumAssignmentSideSize, nameof(MaximumAssignmentSideSize));

        if (MaximumAssignmentSideSize > HardMaximumAssignmentSideSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumAssignmentSideSize),
                MaximumAssignmentSideSize,
                $"The exact-assignment side limit cannot exceed "
                + $"{HardMaximumAssignmentSideSize} in matcher v1.");
        }

        if (MaximumCandidateEdgesPerFinding > MaximumCandidatePairEvaluationsPerFinding)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumCandidateEdgesPerFinding),
                MaximumCandidateEdgesPerFinding,
                "The retained-edge limit cannot exceed the per-finding "
                + "candidate-selection evaluation limit.");
        }
    }

    private static void ValidatePositive(long value, string parameterName)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                value,
                "Resource limits must be positive.");
        }
    }
}
