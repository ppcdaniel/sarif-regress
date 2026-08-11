using SarifRegress.Cli.Diagnostics;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Configuration;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Shares path-safe, bounded SARIF setup between single-input commands.
/// </summary>
internal static class ValidateCommandSupport
{
    private const int StreamBufferBytes = 64 * 1024;

    public static ResolvedSingleInputRequest ResolveRequest(
        string currentDirectory,
        string inputPath,
        string? repositoryPath,
        string? configurationPath,
        string? outputPath)
    {
        var input = ResolvePath(
            inputPath,
            currentDirectory,
            "The SARIF input path is invalid.");
        var repository = ResolveOptionalPath(
            repositoryPath,
            currentDirectory,
            "The repository path is invalid.");
        var configuration = ResolveOptionalPath(
            configurationPath,
            currentDirectory,
            "The configuration path is invalid.");
        var output = ResolveOptionalPath(
            outputPath,
            currentDirectory,
            "The output path is invalid.");

        if (output is not null)
        {
            var outputIdentity =
                PathIdentityResolver.ResolveOutputIdentity(output);
            var inputIdentity =
                PathIdentityResolver.ResolveInputIdentity(input);
            var configurationIdentity = configuration is null
                ? null
                : PathIdentityResolver.ResolveInputIdentity(configuration);
            if (PathIdentityResolver.Comparer.Equals(output, input) ||
                configuration is not null &&
                PathIdentityResolver.Comparer.Equals(output, configuration) ||
                PathIdentityResolver.Comparer.Equals(
                    outputIdentity,
                    inputIdentity) ||
                configurationIdentity is not null &&
                PathIdentityResolver.Comparer.Equals(
                    outputIdentity,
                    configurationIdentity))
            {
                throw new ValidateCommandInputException(
                    CreateDiagnostic(
                        "CLI0011",
                        DiagnosticStage.Io,
                        "An output path cannot overwrite an input."));
            }
        }

        return new ResolvedSingleInputRequest(
            input,
            repository,
            configuration,
            output);
    }

    public static async Task<ConfigurationReadResult> ReadConfigurationAsync(
        string? path,
        CancellationToken cancellationToken)
    {
        if (path is null)
        {
            return new ConfigurationReadResult(
                SarifRegressConfiguration.Default,
                [],
                InputBytes: 0);
        }

        await using var stream = OpenInput(path);
        return await new SarifConfigurationReader()
            .ReadAsync(stream, cancellationToken)
            .ConfigureAwait(false);
    }

    public static SarifRegressConfiguration ResolveRepositoryConfiguration(
        SarifRegressConfiguration configuration,
        string? explicitRepositoryPath,
        string? configurationPath)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var repositoryPath = explicitRepositoryPath;
        if (repositoryPath is null && configuration.RepositoryRoot is not null)
        {
            var configurationDirectory = configurationPath is null
                ? throw new InvalidOperationException(
                    "A configured repository root requires a configuration path.")
                : Path.GetDirectoryName(configurationPath)
                    ?? throw new InvalidOperationException(
                        "The configuration path has no containing directory.");
            repositoryPath = ResolvePath(
                configuration.RepositoryRoot,
                configurationDirectory,
                "The configured repository root is invalid.");
        }

        if (string.Equals(
                repositoryPath,
                configuration.RepositoryRoot,
                PathComparison()))
        {
            return configuration;
        }

        return configuration.WithRepositoryRoot(repositoryPath);
    }

    public static RepositoryContextCreationResult CreateRepositoryContext(
        SarifRegressConfiguration configuration,
        bool explicitlySelected)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (!configuration.Matching.EnableRepositoryContext ||
            configuration.RepositoryRoot is null)
        {
            return new RepositoryContextCreationResult(null, null);
        }

        if (!Directory.Exists(configuration.RepositoryRoot))
        {
            var message = explicitlySelected
                ? "The explicitly selected repository root does not exist."
                : "The configured repository root does not exist.";
            return new RepositoryContextCreationResult(
                null,
                CreateDiagnostic("CLI0012", DiagnosticStage.Io, message));
        }

        return new RepositoryContextCreationResult(
            new FileSystemRepositoryContext(
                configuration.RepositoryRoot,
                configuration.Limits),
            null);
    }

    public static async Task<SarifIngestionResult> IngestAsync(
        string path,
        SarifRegressConfiguration configuration,
        IRepositoryContext? repositoryContext,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenInput(path);
        return await new SarifIngestor(repositoryContext)
            .IngestAsync(
                stream,
                new SarifIngestionRequest(
                    InputKind.Candidate,
                    LogicalInputName(path),
                    configuration),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public static string LogicalInputName(string path)
    {
        var name = Path.GetFileName(path);
        return string.IsNullOrWhiteSpace(name) ? "input.sarif" : name;
    }

    public static void WriteDiagnostics(
        TextWriter error,
        IEnumerable<Diagnostic> diagnostics)
    {
        var formatted = StableDiagnosticFormatter.Format(diagnostics);
        if (formatted.Length > 0)
        {
            error.Write(formatted);
        }
    }

    public static Diagnostic CreateDiagnostic(
        string code,
        DiagnosticStage stage,
        string message) =>
        new(code, DiagnosticSeverity.Error, stage, message);

    private static FileStream OpenInput(string path) =>
        new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            StreamBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static string? ResolveOptionalPath(
        string? path,
        string baseDirectory,
        string errorMessage) =>
        path is null ? null : ResolvePath(path, baseDirectory, errorMessage);

    private static string ResolvePath(
        string path,
        string baseDirectory,
        string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ValidateCommandInputException(
                CreateDiagnostic("CLI0010", DiagnosticStage.Io, errorMessage));
        }

        try
        {
            return Path.GetFullPath(path, baseDirectory);
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            NotSupportedException or
            PathTooLongException)
        {
            throw new ValidateCommandInputException(
                CreateDiagnostic("CLI0010", DiagnosticStage.Io, errorMessage));
        }
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
}

internal sealed record ResolvedSingleInputRequest(
    string InputPath,
    string? RepositoryPath,
    string? ConfigurationPath,
    string? OutputPath);

internal sealed record RepositoryContextCreationResult(
    IRepositoryContext? Context,
    Diagnostic? Diagnostic);

internal sealed class ValidateCommandInputException : Exception
{
    public ValidateCommandInputException(Diagnostic diagnostic)
        : base(diagnostic.Message)
    {
        Diagnostic = diagnostic;
    }

    public Diagnostic Diagnostic { get; }
}
