namespace SarifRegress.Report;

/// <summary>
/// Defines the stable public identifiers emitted by the reporting adapters.
/// </summary>
public static class ReportContractVersions
{
    /// <summary>
    /// The current stable comparison-report schema.
    /// </summary>
    public const string OutputSchema = "1";

    /// <summary>
    /// The explicit JSON property-order and enum-spelling contract.
    /// </summary>
    public const string JsonCanonicalisation = "schema-order-v1";

    /// <summary>
    /// The cross-platform text and path normalisation contract.
    /// </summary>
    public const string CrossPlatformNormalisation = "approved-path-normalisation-v1";

    /// <summary>
    /// The canonical SARIF projection fingerprint algorithm.
    /// </summary>
    public const string SarifFingerprint = "sarifregress/rule-path-context/v1";

    /// <summary>
    /// The algorithm identifier recorded with the canonical SARIF fingerprint.
    /// </summary>
    public const string SarifFingerprintAlgorithm = "rule-path-context/v1";
}
