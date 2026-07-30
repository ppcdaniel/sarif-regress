using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the bootstrap implementation of the compare command.
/// </summary>
public static class CompareCommandFactory
{
    /// <summary>
    /// The deterministic output emitted by a valid placeholder invocation.
    /// </summary>
    public const string PlaceholderOutput =
        "SarifRegress comparison is not implemented yet.\n";

    private const string CommandName = "compare";
    private const string CommandDescription =
        "Compare baseline and candidate SARIF files.";

    /// <summary>
    /// Creates the compare command and its bootstrap options.
    /// </summary>
    /// <returns>A configured compare command.</returns>
    public static Command Create()
    {
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

        Command compareCommand = new(CommandName, CommandDescription);
        compareCommand.Options.Add(baselineOption);
        compareCommand.Options.Add(candidateOption);
        compareCommand.Options.Add(repositoryOption);
        compareCommand.Options.Add(configurationOption);
        compareCommand.Options.Add(jsonOutputOption);
        compareCommand.SetAction(parseResult =>
        {
            parseResult.InvocationConfiguration.Output.Write(PlaceholderOutput);
            return ExitCodes.NotImplemented;
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
