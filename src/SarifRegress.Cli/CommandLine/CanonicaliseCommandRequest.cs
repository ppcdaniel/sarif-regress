namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Captures the already-parsed canonicalise command values.
/// </summary>
internal sealed record CanonicaliseCommandRequest(
    string InputPath,
    string? RepositoryPath,
    string? ConfigurationPath,
    string? SarifOutputPath);
