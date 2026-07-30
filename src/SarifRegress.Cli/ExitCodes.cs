namespace SarifRegress.Cli;

/// <summary>
/// Defines the exit codes used by the bootstrap command-line interface.
/// </summary>
public static class ExitCodes
{
    /// <summary>
    /// Indicates invalid command-line usage.
    /// </summary>
    public const int InvalidUsage = 1;

    /// <summary>
    /// Indicates a command recognised during bootstrap but not yet implemented.
    /// </summary>
    public const int NotImplemented = 2;
}
