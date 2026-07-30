using System.CommandLine;
using SarifRegress.Cli.CommandLine;

namespace SarifRegress.Cli;

/// <summary>
/// Composes and invokes the SarifRegress command-line interface.
/// </summary>
public static class CliApplication
{
    /// <summary>
    /// Runs the command-line interface with injectable output streams.
    /// </summary>
    /// <param name="args">The command-line arguments to parse.</param>
    /// <param name="output">The destination for standard output.</param>
    /// <param name="error">The destination for standard error.</param>
    /// <returns>The exit code produced by parsing or invoking the selected command.</returns>
    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        RootCommand rootCommand = CliCommandFactory.Create();
        InvocationConfiguration invocationConfiguration = new()
        {
            Output = output,
            Error = error,
        };

        return rootCommand.Parse(args).Invoke(invocationConfiguration);
    }
}
