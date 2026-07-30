namespace SarifRegress.Report;

/// <summary>
/// Records exact deterministic stable-report serialization measurements.
/// </summary>
/// <param name="OutputBytes">Canonical output bytes, including the final LF.</param>
/// <param name="ExplanationBytes">
/// JSON value bytes occupied by per-finding explanations.
/// </param>
/// <param name="OutputSha256">Lowercase SHA-256 over the canonical output bytes.</param>
public sealed record StableJsonSerializationMeasurement(
    int OutputBytes,
    int ExplanationBytes,
    string OutputSha256);
