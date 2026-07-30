namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Captures the already-parsed compare command values.
/// </summary>
internal sealed record CompareCommandRequest(
    string BaselinePath,
    string CandidatePath,
    string? RepositoryPath,
    string? ConfigurationPath,
    string? JsonOutputPath,
    string? HtmlOutputPath,
    string? SarifOutputPath);
