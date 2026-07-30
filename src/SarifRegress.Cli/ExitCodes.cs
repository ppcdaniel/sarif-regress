namespace SarifRegress.Cli;

/// <summary>
/// Defines the stable process exit-code contract.
/// </summary>
public static class ExitCodes
{
    /// <summary>
    /// Indicates successful execution and a passing configured policy.
    /// </summary>
    public const int Success = 0;

    /// <summary>
    /// Indicates invalid command-line usage, invalid input, or an I/O error.
    /// </summary>
    public const int CommandOrInputError = 1;

    /// <summary>
    /// Indicates a command recognised during bootstrap but not yet implemented.
    /// Reserved for compatibility with the bootstrap history.
    /// </summary>
    public const int NotImplemented = 2;

    /// <summary>
    /// Indicates a completed comparison that failed configured regression policy.
    /// </summary>
    public const int PolicyFailure = 3;

    /// <summary>
    /// Indicates an internal invariant failure.
    /// </summary>
    public const int InternalInvariantFailure = 4;

    /// <summary>
    /// Compatibility alias for parser errors in the bootstrap command tree.
    /// </summary>
    public const int InvalidUsage = CommandOrInputError;
}
