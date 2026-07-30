namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Captures the already-parsed validate command values.
/// </summary>
internal sealed record ValidateCommandRequest(
    string InputPath,
    string? RepositoryPath,
    string? ConfigurationPath,
    string? JsonOutputPath);
