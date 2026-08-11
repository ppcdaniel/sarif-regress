using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using SarifRegress.Cli.Corpus;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Executes the bounded labelled-corpus workflow.
/// </summary>
internal sealed class CorpusCommandHandler
{
    private readonly string currentDirectory;

    /// <summary>
    /// Initializes a handler with an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which relative command paths are resolved.
    /// </param>
    public CorpusCommandHandler(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        this.currentDirectory = Path.GetFullPath(currentDirectory);
    }

    /// <summary>
    /// Executes one corpus run.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification =
            "The CLI boundary converts invariant failures to stable exit code 4 without exposing exception details.")]
    public async Task<int> ExecuteAsync(
        CorpusCommandRequest request,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            string corpusRoot = ResolvePath(request.CorpusPath ?? "corpus");
            string? jsonOutput = request.JsonOutputPath is null
                ? null
                : ResolvePath(request.JsonOutputPath);
            if (jsonOutput is not null
                && PathIdentityResolver.IsOutputWithinInputDirectory(
                    jsonOutput,
                    corpusRoot))
            {
                error.Write(
                    "CORPUS0006 error: Corpus output must be outside the corpus input tree.\n");
                return ExitCodes.CommandOrInputError;
            }

            var result = await new CorpusRunner()
                .RunAsync(
                    new CorpusRunRequest(corpusRoot),
                    cancellationToken)
                .ConfigureAwait(false);
            byte[] bytes = CorpusRunReportSerializer.Serialize(result);
            if (jsonOutput is null)
            {
                output.Write(CorpusRunReportSerializer.Decode(bytes));
            }
            else
            {
                await AtomicOutputWriter.WriteAsync(
                        ImmutableArray.Create(
                            new OutputArtifact(jsonOutput, bytes)),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return result.Passed
                ? ExitCodes.Success
                : ExitCodes.PolicyFailure;
        }
        catch (OperationCanceledException)
        {
            error.Write("CORPUS0003 error: The corpus run was cancelled.\n");
            return ExitCodes.CommandOrInputError;
        }
        catch (ArgumentException)
        {
            error.Write("CORPUS0001 error: A corpus command path is invalid.\n");
            return ExitCodes.CommandOrInputError;
        }
        catch (InvalidDataException)
        {
            error.Write("CORPUS0002 error: A corpus label, configuration, or fixture is invalid.\n");
            return ExitCodes.CommandOrInputError;
        }
        catch (IOException)
        {
            error.Write("CORPUS0004 error: A corpus input or output could not be accessed.\n");
            return ExitCodes.CommandOrInputError;
        }
        catch (UnauthorizedAccessException)
        {
            error.Write("CORPUS0005 error: Access to a corpus input or output was denied.\n");
            return ExitCodes.CommandOrInputError;
        }
        catch (Exception)
        {
            error.Write(
                "INTERNAL0001 error: SarifRegress encountered an internal invariant failure.\n");
            return ExitCodes.InternalInvariantFailure;
        }
    }

    private string ResolvePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Path.GetFullPath(path, currentDirectory);
    }
}
