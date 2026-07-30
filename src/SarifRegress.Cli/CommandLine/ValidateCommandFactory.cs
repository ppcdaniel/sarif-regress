using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the bounded SARIF validation command.
/// </summary>
public static class ValidateCommandFactory
{
    /// <summary>
    /// Creates the validate command using the process invocation directory.
    /// </summary>
    /// <returns>A configured validate command.</returns>
    public static Command Create()
    {
        return Create(Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Creates the validate command using an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which explicit relative command-line paths are resolved.
    /// </param>
    /// <returns>A configured validate command.</returns>
    public static Command Create(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        Option<string?> inputOption = CreatePathOption(
            "--input",
            "Path to the SARIF file to validate.",
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
            "Optional path for the validation summary.",
            isRequired: false);

        Command command = new(
            "validate",
            "Validate and canonicalise the supported SARIF subset.");
        command.Options.Add(inputOption);
        command.Options.Add(repositoryOption);
        command.Options.Add(configurationOption);
        command.Options.Add(jsonOutputOption);
        var handler = new ValidateCommandHandler(currentDirectory);
        command.SetAction(
            async (parseResult, cancellationToken) =>
            {
                var request = new ValidateCommandRequest(
                    parseResult.GetValue(inputOption)!,
                    parseResult.GetValue(repositoryOption),
                    parseResult.GetValue(configurationOption),
                    parseResult.GetValue(jsonOutputOption));
                return await handler.ExecuteAsync(
                        request,
                        parseResult.InvocationConfiguration.Output,
                        parseResult.InvocationConfiguration.Error,
                        cancellationToken)
                    .ConfigureAwait(false);
            });

        return command;
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
