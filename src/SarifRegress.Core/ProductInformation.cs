namespace SarifRegress.Core;

/// <summary>
/// Defines stable product and public algorithm identities.
/// </summary>
public static class ProductInformation
{
    /// <summary>
    /// Gets the command and report product name.
    /// </summary>
    public const string Name = "sarif-regress";

    /// <summary>
    /// Gets the semantic product version.
    /// </summary>
    public const string Version = "0.1.0";

    /// <summary>
    /// Gets the matching algorithm version recorded in stable reports.
    /// </summary>
    public const string MatcherAlgorithmVersion = "sarifregress/matcher/v3.2";
}
