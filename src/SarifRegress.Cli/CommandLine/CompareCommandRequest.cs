namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Captures the already-parsed compare command values.
/// </summary>
internal sealed record CompareCommandRequest(
    string BaselinePath,
    string CandidatePath,
    string? RepositoryPath,
    string? BaselineRepositoryPath,
    string? BaselineSnapshotManifestPath,
    string? CandidateRepositoryPath,
    string? CandidateSnapshotManifestPath,
    string? ConfigurationPath,
    string? JsonOutputPath,
    string? HtmlOutputPath,
    string? SarifOutputPath);
