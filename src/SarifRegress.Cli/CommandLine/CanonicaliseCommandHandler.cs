using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using SarifRegress.Core.Diagnostics;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Canonicalises one bounded SARIF input without making matching decisions.
/// </summary>
internal sealed class CanonicaliseCommandHandler
{
    private static readonly Encoding StableUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly string currentDirectory;

    public CanonicaliseCommandHandler(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        this.currentDirectory = Path.GetFullPath(currentDirectory);
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification =
            "The CLI boundary maps unexpected failures to stable exit code 4 without exposing exception details.")]
    public async Task<int> ExecuteAsync(
        CanonicaliseCommandRequest request,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            var resolved = ValidateCommandSupport.ResolveRequest(
                currentDirectory,
                request.InputPath,
                request.RepositoryPath,
                request.ConfigurationPath,
                request.SarifOutputPath);
            var configurationResult =
                await ValidateCommandSupport.ReadConfigurationAsync(
                        resolved.ConfigurationPath,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (!configurationResult.IsValid)
            {
                ValidateCommandSupport.WriteDiagnostics(
                    error,
                    configurationResult.Diagnostics);
                return ExitCodes.CommandOrInputError;
            }

            var configuration =
                ValidateCommandSupport.ResolveRepositoryConfiguration(
                    configurationResult.Configuration!,
                    resolved.RepositoryPath,
                    resolved.ConfigurationPath);
            var repositoryContext =
                ValidateCommandSupport.CreateRepositoryContext(
                    configuration,
                    request.RepositoryPath is not null);
            if (repositoryContext.Diagnostic is not null)
            {
                ValidateCommandSupport.WriteDiagnostics(
                    error,
                    [repositoryContext.Diagnostic]);
                return ExitCodes.CommandOrInputError;
            }

            using var repositoryContextLifetime = repositoryContext.Context;
            var ingestion = await ValidateCommandSupport.IngestAsync(
                    resolved.InputPath,
                    configuration,
                    repositoryContextLifetime,
                    cancellationToken)
                .ConfigureAwait(false);
            var diagnostics = Diagnostic.Sort(
                configurationResult.Diagnostics
                    .Concat(ingestion.ComparisonInput.Diagnostics));
            if (!ingestion.IsValid)
            {
                ValidateCommandSupport.WriteDiagnostics(error, diagnostics);
                return ExitCodes.CommandOrInputError;
            }

            var canonicalSarif = CanonicaliseSarifSerializer.Serialize(ingestion);
            if (resolved.OutputPath is null)
            {
                output.Write(StableUtf8.GetString(canonicalSarif));
            }
            else
            {
                await AtomicOutputWriter.WriteAsync(
                        ImmutableArray.Create(
                            new OutputArtifact(
                                resolved.OutputPath,
                                canonicalSarif)),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            ValidateCommandSupport.WriteDiagnostics(error, diagnostics);
            return ExitCodes.Success;
        }
        catch (ValidateCommandInputException exception)
        {
            ValidateCommandSupport.WriteDiagnostics(
                error,
                [exception.Diagnostic]);
            return ExitCodes.CommandOrInputError;
        }
        catch (OperationCanceledException)
        {
            return WriteFailure(
                error,
                "CLI0026",
                DiagnosticStage.Io,
                "Canonicalisation was cancelled.");
        }
        catch (IOException)
        {
            return WriteFailure(
                error,
                "CLI0023",
                DiagnosticStage.Io,
                "A canonicalisation input or output could not be accessed.");
        }
        catch (UnauthorizedAccessException)
        {
            return WriteFailure(
                error,
                "CLI0024",
                DiagnosticStage.Io,
                "Access to a canonicalisation input or output was denied.");
        }
        catch (Exception)
        {
            ValidateCommandSupport.WriteDiagnostics(
                error,
                [
                    new Diagnostic(
                        "INTERNAL0020",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Internal,
                        "SarifRegress encountered an internal invariant failure."),
                ]);
            return ExitCodes.InternalInvariantFailure;
        }
    }

    private static int WriteFailure(
        TextWriter error,
        string code,
        DiagnosticStage stage,
        string message)
    {
        ValidateCommandSupport.WriteDiagnostics(
            error,
            [ValidateCommandSupport.CreateDiagnostic(code, stage, message)]);
        return ExitCodes.CommandOrInputError;
    }
}
