using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Compatibility;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Executes bounded supported-subset validation for one SARIF input.
/// </summary>
internal sealed class ValidateCommandHandler
{
    private static readonly Encoding StableUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly string currentDirectory;

    public ValidateCommandHandler(string currentDirectory)
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
        ValidateCommandRequest request,
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
                request.JsonOutputPath);
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

            var ingestion = await ValidateCommandSupport.IngestAsync(
                    resolved.InputPath,
                    configuration,
                    repositoryContext.Context,
                    cancellationToken)
                .ConfigureAwait(false);
            var compatibilityDiagnostics = new GithubCompatibilityChecker()
                .Check(ingestion.Summary);
            var diagnostics = Diagnostic.Sort(
                configurationResult.Diagnostics
                    .Concat(ingestion.ComparisonInput.Diagnostics)
                    .Concat(compatibilityDiagnostics));
            var policyPassed = ingestion.IsValid &&
                (!configuration.Policy.TreatGithubIncompatibilityAsError ||
                 !compatibilityDiagnostics.Any(
                     item => item.Severity is
                         DiagnosticSeverity.Warning or DiagnosticSeverity.Error));
            var summary = ValidateSummarySerializer.Serialize(
                ValidateCommandSupport.LogicalInputName(resolved.InputPath),
                ingestion,
                diagnostics,
                policyPassed);

            if (resolved.OutputPath is null)
            {
                output.Write(StableUtf8.GetString(summary));
            }
            else
            {
                await AtomicOutputWriter.WriteAsync(
                        ImmutableArray.Create(
                            new OutputArtifact(resolved.OutputPath, summary)),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            ValidateCommandSupport.WriteDiagnostics(error, diagnostics);
            return policyPassed
                ? ExitCodes.Success
                : ExitCodes.CommandOrInputError;
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
                "CLI0016",
                DiagnosticStage.Io,
                "Validation was cancelled.");
        }
        catch (IOException)
        {
            return WriteFailure(
                error,
                "CLI0013",
                DiagnosticStage.Io,
                "A validation input or output could not be accessed.");
        }
        catch (UnauthorizedAccessException)
        {
            return WriteFailure(
                error,
                "CLI0014",
                DiagnosticStage.Io,
                "Access to a validation input or output was denied.");
        }
        catch (Exception)
        {
            ValidateCommandSupport.WriteDiagnostics(
                error,
                [
                    new Diagnostic(
                        "INTERNAL0010",
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
