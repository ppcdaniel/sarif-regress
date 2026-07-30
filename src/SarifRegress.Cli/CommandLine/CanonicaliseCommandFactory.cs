using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the deterministic SARIF canonicalisation command.
/// </summary>
public static class CanonicaliseCommandFactory
{
    /// <summary>
    /// Creates the canonicalise command using the process invocation directory.
    /// </summary>
    /// <returns>A configured canonicalise command.</returns>
    public static Command Create()
    {
        return Create(Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Creates the canonicalise command using an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which explicit relative command-line paths are resolved.
    /// </param>
    /// <returns>A configured canonicalise command.</returns>
    public static Command Create(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        Option<string?> inputOption = CreatePathOption(
            "--input",
            "Path to the SARIF file to canonicalise.",
            isRequired: true);
        Option<string?> repositoryOption = CreatePathOption(
            "--repo",
            "Optional path to the repository root.",
            isRequired: false);
        Option<string?> configurationOption = CreatePathOption(
            "--config",
            "Optional path to a SarifRegress configuration file.",
            isRequired: false);
        Option<string?> sarifOutputOption = CreatePathOption(
            "--sarif-out",
            "Optional path for canonical SARIF output.",
            isRequired: false);

        Command command = new(
            "canonicalise",
            "Emit deterministic project-owned canonical SARIF.");
        command.Options.Add(inputOption);
        command.Options.Add(repositoryOption);
        command.Options.Add(configurationOption);
        command.Options.Add(sarifOutputOption);
        var handler = new CanonicaliseCommandHandler(currentDirectory);
        command.SetAction(
            async (parseResult, cancellationToken) =>
            {
                var request = new CanonicaliseCommandRequest(
                    parseResult.GetValue(inputOption)!,
                    parseResult.GetValue(repositoryOption),
                    parseResult.GetValue(configurationOption),
                    parseResult.GetValue(sarifOutputOption));
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
