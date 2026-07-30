using System.CommandLine;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Creates the labelled-corpus command group.
/// </summary>
public static class CorpusCommandFactory
{
    /// <summary>
    /// Creates <c>corpus run</c> using the process invocation directory.
    /// </summary>
    /// <returns>The configured command group.</returns>
    public static Command Create()
    {
        return Create(Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Creates <c>corpus run</c> using an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which explicit relative paths are resolved.
    /// </param>
    /// <returns>The configured command group.</returns>
    public static Command Create(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        Option<string?> corpusOption = new("--corpus")
        {
            Description =
                "Corpus root containing cases (default: ./corpus).",
        };
        Option<string?> jsonOutputOption = new("--json-out")
        {
            Description =
                "Optional path for deterministic corpus metrics JSON.",
        };
        Command run = new(
            "run",
            "Evaluate the tracked labelled corpus and enforce MVP quality gates.");
        run.Options.Add(corpusOption);
        run.Options.Add(jsonOutputOption);
        var handler = new CorpusCommandHandler(currentDirectory);
        run.SetAction(
            async (parseResult, cancellationToken) =>
            {
                var request = new CorpusCommandRequest(
                    parseResult.GetValue(corpusOption),
                    parseResult.GetValue(jsonOutputOption));
                return await handler.ExecuteAsync(
                        request,
                        parseResult.InvocationConfiguration.Output,
                        parseResult.InvocationConfiguration.Error,
                        cancellationToken)
                    .ConfigureAwait(false);
            });

        Command corpus = new(
            "corpus",
            "Evaluate deterministic labelled SARIF comparison fixtures.");
        corpus.Subcommands.Add(run);
        corpus.SetAction(parseResult =>
        {
            parseResult.InvocationConfiguration.Error.Write(
                "The 'corpus run' command is required. Use '--help' for usage.\n");
            return ExitCodes.InvalidUsage;
        });
        return corpus;
    }
}
