namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Captures parsed corpus-run command values.
/// </summary>
internal sealed record CorpusCommandRequest(
    string? CorpusPath,
    string? JsonOutputPath);
