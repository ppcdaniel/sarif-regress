using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the SARIF comparison command.
/// </summary>
public static class CompareCommandFactory
{
    private const string CommandName = "compare";
    private const string CommandDescription =
        "Compare baseline and candidate SARIF files.";

    /// <summary>
    /// Creates the compare command using the process invocation directory.
    /// </summary>
    /// <returns>A configured compare command.</returns>
    public static Command Create()
    {
        return Create(Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Creates the compare command using an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which explicit relative command-line paths are resolved.
    /// </param>
    /// <returns>A configured compare command.</returns>
    public static Command Create(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        Option<string?> baselineOption = CreatePathOption(
            "--baseline",
            "Path to the baseline SARIF file.",
            isRequired: true);
        Option<string?> candidateOption = CreatePathOption(
            "--candidate",
            "Path to the candidate SARIF file.",
            isRequired: true);
        Option<string?> repositoryOption = CreatePathOption(
            "--repo",
            "Optional path to the repository root.",
            isRequired: false);
        Option<string?> configurationOption = CreatePathOption(
            "--config",
            "Optional path to a SarifRegress configuration file.",
            isRequired: false);
        Option<string?> jsonOutputOption = CreatePathOption(
            "--json-out",
            "Optional path for the JSON report.",
            isRequired: false);
        Option<string?> htmlOutputOption = CreatePathOption(
            "--html-out",
            "Optional path for the static HTML report.",
            isRequired: false);
        Option<string?> sarifOutputOption = CreatePathOption(
            "--sarif-out",
            "Optional path for the canonical SARIF report.",
            isRequired: false);

        Command compareCommand = new(CommandName, CommandDescription);
        compareCommand.Options.Add(baselineOption);
        compareCommand.Options.Add(candidateOption);
        compareCommand.Options.Add(repositoryOption);
        compareCommand.Options.Add(configurationOption);
        compareCommand.Options.Add(jsonOutputOption);
        compareCommand.Options.Add(htmlOutputOption);
        compareCommand.Options.Add(sarifOutputOption);
        var handler = new CompareCommandHandler(currentDirectory);
        compareCommand.SetAction(
            async (parseResult, cancellationToken) =>
            {
                var request = new CompareCommandRequest(
                    parseResult.GetValue(baselineOption)!,
                    parseResult.GetValue(candidateOption)!,
                    parseResult.GetValue(repositoryOption),
                    parseResult.GetValue(configurationOption),
                    parseResult.GetValue(jsonOutputOption),
                    parseResult.GetValue(htmlOutputOption),
                    parseResult.GetValue(sarifOutputOption));
                return await handler.ExecuteAsync(
                        request,
                        parseResult.InvocationConfiguration.Output,
                        parseResult.InvocationConfiguration.Error,
                        cancellationToken)
                    .ConfigureAwait(false);
            });

        return compareCommand;
    }

    private static Option<string?> CreatePathOption(
        string name,
        string description,
        bool isRequired)
    {
        return new Option<string?>(name)
        {
            Description = description,
            Required = isRequired,
        };
    }
}
