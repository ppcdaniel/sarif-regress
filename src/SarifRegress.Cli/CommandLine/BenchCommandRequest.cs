namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Captures the already-parsed bench command values.
/// </summary>
internal sealed record BenchCommandRequest(
    int? FindingCount,
    string? Dataset,
    string? JsonOutputPath);
