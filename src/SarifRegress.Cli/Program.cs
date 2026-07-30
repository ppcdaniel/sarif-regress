namespace SarifRegress.Cli;

/// <summary>
/// Provides the executable entry point for SarifRegress.
/// </summary>
public static class Program
{
    /// <summary>
    /// Parses and invokes the requested command.
    /// </summary>
    /// <param name="args">The command-line arguments supplied by the operating system.</param>
    /// <returns>The process exit code produced by the command-line application.</returns>
    public static int Main(string[] args)
    {
        return CliApplication.Run(args, Console.Out, Console.Error);
    }
}
