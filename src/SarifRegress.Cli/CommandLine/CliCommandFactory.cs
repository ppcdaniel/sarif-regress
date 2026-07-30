using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the complete SarifRegress command tree.
/// </summary>
public static class CliCommandFactory
{
    private const string Description =
        "Explainable, deterministic SARIF canonicalisation and regression matching.";

    private const string MissingCommandError =
        "A command is required. Use '--help' for usage.\n";

    /// <summary>
    /// Creates a new command tree for one independent invocation.
    /// </summary>
    /// <returns>A configured SarifRegress root command.</returns>
    public static RootCommand Create()
    {
        RootCommand rootCommand = new(Description);
        rootCommand.Subcommands.Add(CompareCommandFactory.Create());
        rootCommand.SetAction(parseResult =>
        {
            parseResult.InvocationConfiguration.Error.Write(MissingCommandError);
            return ExitCodes.InvalidUsage;
        });

        return rootCommand;
    }
}
