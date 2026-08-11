namespace SarifRegress.Validation;

/// <summary>
/// Centralizes validation-only limits applied to untrusted manifests, schemas, and tool output.
/// </summary>
public sealed record ValidationLimits(
    long MaximumManifestBytes,
    long MaximumSchemaBytes,
    long MaximumLabelBytes,
    long MaximumSarifBytes,
    int MaximumJsonDepth,
    int MaximumCases,
    int MaximumResultsPerCase,
    int MaximumStringCharacters,
    int MaximumDecisionTracesPerRelationship,
    int MaximumDecisionTraceItems,
    int MaximumSchemaEvaluationDepth,
    int MaximumSchemaEvaluationSteps,
    int MaximumSchemaNumberCharacters,
    int MaximumProcessOutputCharacters,
    TimeSpan SchemaRegexTimeout,
    TimeSpan ProcessTimeout)
{
    private static readonly TimeSpan DefaultSchemaRegexTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Gets conservative defaults suitable for the small committed holdout.</summary>
    public static ValidationLimits Default { get; } = new(
        MaximumManifestBytes: 2L * 1024 * 1024,
        MaximumSchemaBytes: 2L * 1024 * 1024,
        MaximumLabelBytes: 4L * 1024 * 1024,
        MaximumSarifBytes: 64L * 1024 * 1024,
        MaximumJsonDepth: 128,
        MaximumCases: 64,
        MaximumResultsPerCase: 100_000,
        MaximumStringCharacters: 64 * 1024,
        MaximumDecisionTracesPerRelationship: 2,
        MaximumDecisionTraceItems: 100,
        MaximumSchemaEvaluationDepth: 256,
        MaximumSchemaEvaluationSteps: 10_000_000,
        MaximumSchemaNumberCharacters: 1024,
        MaximumProcessOutputCharacters: 1024 * 1024,
        // Regex timeouts measure wall-clock time, so allow scheduler headroom on loaded CI hosts.
        SchemaRegexTimeout: DefaultSchemaRegexTimeout,
        ProcessTimeout: TimeSpan.FromMinutes(2));

    /// <summary>Fails fast when a caller supplies an internally inconsistent limit set.</summary>
    public void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumManifestBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumSchemaBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumLabelBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumSarifBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumJsonDepth);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumCases);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumResultsPerCase);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumStringCharacters);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            MaximumDecisionTracesPerRelationship);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            MaximumDecisionTraceItems);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            MaximumSchemaEvaluationDepth);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            MaximumSchemaEvaluationSteps);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            MaximumSchemaNumberCharacters);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            MaximumProcessOutputCharacters);
        if (SchemaRegexTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(SchemaRegexTimeout),
                "The schema regular-expression timeout must be positive.");
        }

        if (ProcessTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ProcessTimeout),
                "The external-tool timeout must be positive.");
        }
    }
}
