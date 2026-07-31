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
    int MaximumProcessOutputCharacters,
    TimeSpan ProcessTimeout)
{
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
        MaximumProcessOutputCharacters: 1024 * 1024,
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
            MaximumProcessOutputCharacters);
        if (ProcessTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ProcessTimeout),
                "The external-tool timeout must be positive.");
        }
    }
}
