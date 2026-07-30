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
        return Run(args, output, error, Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Runs the command-line interface with an explicit invocation directory.
    /// </summary>
    /// <param name="args">The command-line arguments to parse.</param>
    /// <param name="output">The destination for standard output.</param>
    /// <param name="error">The destination for standard error.</param>
    /// <param name="currentDirectory">
    /// The directory against which explicit relative command-line paths are resolved.
    /// </param>
    /// <returns>The exit code produced by parsing or invoking the selected command.</returns>
    public static int Run(
        string[] args,
        TextWriter output,
        TextWriter error,
        string currentDirectory)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);

        RootCommand rootCommand = CliCommandFactory.Create(currentDirectory);
        InvocationConfiguration invocationConfiguration = new()
        {
            Output = output,
            Error = error,
        };

        var parseResult = rootCommand.Parse(args);
        if (parseResult.Errors.Count > 0)
        {
            foreach (var parseError in parseResult.Errors)
            {
                error.Write(parseError.Message);
                error.Write('\n');
            }

            return ExitCodes.InvalidUsage;
        }

        return parseResult
            .InvokeAsync(invocationConfiguration)
            .GetAwaiter()
            .GetResult();
    }
}
