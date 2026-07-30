using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the dependency-free functional benchmark command.
/// </summary>
public static class BenchCommandFactory
{
    /// <summary>
    /// Creates the bench command using the process invocation directory.
    /// </summary>
    /// <returns>A configured bench command.</returns>
    public static Command Create()
    {
        return Create(Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Creates the bench command using an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which the optional output path is resolved.
    /// </param>
    /// <returns>A configured bench command.</returns>
    public static Command Create(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        Option<int?> sizeOption = new("--size")
        {
            Description =
                "Findings per side: 1000 (default), 10000, or 100000.",
        };
        Option<string?> datasetOption = new("--dataset")
        {
            Description =
                "Dataset shape: unique (default) or pathological.",
        };
        Option<string?> jsonOutputOption = new("--json-out")
        {
            Description = "Optional path for the benchmark JSON report.",
        };
        Option<string?> deterministicOutputOption = new("--deterministic-out")
        {
            Description =
                "Optional path for the byte-stable benchmark projection.",
        };
        Option<bool> enforceBudgetsOption = new("--enforce-budgets")
        {
            Description =
                "Return exit code 3 when the published dataset budget is exceeded.",
        };

        Command command = new(
            "bench",
            "Run bounded parse, canonicalise, compare, and report benchmarks.");
        command.Options.Add(sizeOption);
        command.Options.Add(datasetOption);
        command.Options.Add(jsonOutputOption);
        command.Options.Add(deterministicOutputOption);
        command.Options.Add(enforceBudgetsOption);
        var handler = new BenchCommandHandler(currentDirectory);
        command.SetAction(
            async (parseResult, cancellationToken) =>
            {
                var request = new BenchCommandRequest(
                    parseResult.GetValue(sizeOption),
                    parseResult.GetValue(datasetOption),
                    parseResult.GetValue(jsonOutputOption),
                    parseResult.GetValue(deterministicOutputOption),
                    parseResult.GetValue(enforceBudgetsOption));
                return await handler.ExecuteAsync(
                        request,
                        parseResult.InvocationConfiguration.Output,
                        parseResult.InvocationConfiguration.Error,
                        cancellationToken)
                    .ConfigureAwait(false);
            });

        return command;
    }
}
