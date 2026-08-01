using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using SarifRegress.Cli.Diagnostics;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Reporting;
using SarifRegress.Match;
using SarifRegress.Report;
using SarifRegress.Sarif.Compatibility;
using SarifRegress.Sarif.Configuration;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Composes bounded adapters around the pure matcher for one compare invocation.
/// </summary>
internal sealed class CompareCommandHandler
{
    private const int StreamBufferBytes = 64 * 1024;
    private static readonly Encoding StableUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly string currentDirectory;

    /// <summary>
    /// Initializes a comparison handler with an explicit invocation directory.
    /// </summary>
    /// <param name="currentDirectory">
    /// The directory against which explicit relative command-line paths are resolved.
    /// </param>
    public CompareCommandHandler(string currentDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        this.currentDirectory = Path.GetFullPath(currentDirectory);
    }

    /// <summary>
    /// Executes one complete comparison without network or code execution.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification =
            "The CLI boundary must convert unexpected invariant failures into stable exit code 4 without exposing exception details.")]
    public async Task<int> ExecuteAsync(
        CompareCommandRequest request,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            var resolved = ResolveRequest(request);
            var configurationResult = await ReadConfigurationAsync(
                    resolved.ConfigurationPath,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!configurationResult.IsValid)
            {
                WriteDiagnostics(error, configurationResult.Diagnostics);
                return ExitCodes.CommandOrInputError;
            }

            var configuration = ResolveRepositoryConfiguration(
                configurationResult.Configuration!,
                resolved.RepositoryPath,
                resolved.ConfigurationPath);
            var repositoryContextResult = CreateRepositoryContext(
                configuration,
                request.RepositoryPath is not null);
            if (repositoryContextResult.Diagnostic is not null)
            {
                WriteDiagnostics(error, [repositoryContextResult.Diagnostic]);
                return ExitCodes.CommandOrInputError;
            }

            var ingestor = new SarifIngestor(repositoryContextResult.Context);
            var baseline = await IngestAsync(
                    ingestor,
                    resolved.BaselinePath,
                    InputKind.Baseline,
                    LogicalInputName(resolved.BaselinePath, "baseline.sarif"),
                    configuration,
                    cancellationToken)
                .ConfigureAwait(false);
            var candidate = await IngestAsync(
                    ingestor,
                    resolved.CandidatePath,
                    InputKind.Candidate,
                    LogicalInputName(resolved.CandidatePath, "candidate.sarif"),
                    configuration,
                    cancellationToken)
                .ConfigureAwait(false);

            var inputDiagnostics = configurationResult.Diagnostics
                .Concat(baseline.ComparisonInput.Diagnostics)
                .Concat(candidate.ComparisonInput.Diagnostics)
                .ToImmutableArray();
            if (!baseline.IsValid || !candidate.IsValid)
            {
                WriteDiagnostics(error, inputDiagnostics);
                return ExitCodes.CommandOrInputError;
            }

            var compatibilityChecker = new GithubCompatibilityChecker();
            var compatibilityDiagnostics = compatibilityChecker
                .Check(baseline.Summary)
                .Concat(compatibilityChecker.Check(candidate.Summary))
                .ToImmutableArray();
            var matchResult = new FindingMatcher().Match(
                baseline.ComparisonInput,
                candidate.ComparisonInput,
                configuration);
            matchResult = matchResult with
            {
                Diagnostics = Diagnostic.Sort(
                    inputDiagnostics
                        .Concat(compatibilityDiagnostics)
                        .Concat(matchResult.Diagnostics)),
            };

            var metadata = new ComparisonReportMetadata(
                ProductInformation.Version,
                baseline.ComparisonInput.LogicalName,
                candidate.ComparisonInput.LogicalName,
                ProductInformation.MatcherAlgorithmVersion);
            ComparisonReport report = ComparisonReportFactory.Create(
                matchResult,
                metadata);
            byte[] stableJson = StableJsonReportSerializer.Serialize(report);
            var artifacts = CreateOutputArtifacts(resolved, stableJson);
            await AtomicOutputWriter.WriteAsync(artifacts, cancellationToken)
                .ConfigureAwait(false);

            if (resolved.JsonOutputPath is null)
            {
                output.Write(StableUtf8.GetString(stableJson));
            }

            WriteDiagnostics(error, matchResult.Diagnostics);
            return PolicyFailed(
                matchResult,
                compatibilityDiagnostics,
                configuration.Policy)
                    ? ExitCodes.PolicyFailure
                    : ExitCodes.Success;
        }
        catch (CommandInputException exception)
        {
            WriteDiagnostics(error, [exception.Diagnostic]);
            return ExitCodes.CommandOrInputError;
        }
        catch (OperationCanceledException)
        {
            WriteDiagnostics(
                error,
                [
                    CreateCliDiagnostic(
                        "CLI0007",
                        DiagnosticStage.Io,
                        "The comparison was cancelled."),
                ]);
            return ExitCodes.CommandOrInputError;
        }
        catch (IOException)
        {
            WriteDiagnostics(
                error,
                [
                    CreateCliDiagnostic(
                        "CLI0002",
                        DiagnosticStage.Io,
                        "A comparison input or output could not be accessed."),
                ]);
            return ExitCodes.CommandOrInputError;
        }
        catch (UnauthorizedAccessException)
        {
            WriteDiagnostics(
                error,
                [
                    CreateCliDiagnostic(
                        "CLI0003",
                        DiagnosticStage.Io,
                        "Access to a comparison input or output was denied."),
                ]);
            return ExitCodes.CommandOrInputError;
        }
        catch (Exception)
        {
            WriteDiagnostics(
                error,
                [
                    new Diagnostic(
                        "INTERNAL0001",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Internal,
                        "SarifRegress encountered an internal invariant failure."),
                ]);
            return ExitCodes.InternalInvariantFailure;
        }
    }

    private ResolvedCompareRequest ResolveRequest(CompareCommandRequest request)
    {
        var baselinePath = ResolvePath(
            request.BaselinePath,
            currentDirectory,
            "CLI0001",
            "The baseline path is invalid.");
        var candidatePath = ResolvePath(
            request.CandidatePath,
            currentDirectory,
            "CLI0001",
            "The candidate path is invalid.");
        var configurationPath = ResolveOptionalPath(
            request.ConfigurationPath,
            currentDirectory,
            "The configuration path is invalid.");
        var repositoryPath = ResolveOptionalPath(
            request.RepositoryPath,
            currentDirectory,
            "The repository path is invalid.");
        var jsonOutputPath = ResolveOptionalPath(
            request.JsonOutputPath,
            currentDirectory,
            "The JSON output path is invalid.");
        var htmlOutputPath = ResolveOptionalPath(
            request.HtmlOutputPath,
            currentDirectory,
            "The HTML output path is invalid.");
        var sarifOutputPath = ResolveOptionalPath(
            request.SarifOutputPath,
            currentDirectory,
            "The SARIF output path is invalid.");

        ValidateOutputPaths(
            baselinePath,
            candidatePath,
            configurationPath,
            jsonOutputPath,
            htmlOutputPath,
            sarifOutputPath);
        return new ResolvedCompareRequest(
            baselinePath,
            candidatePath,
            repositoryPath,
            configurationPath,
            jsonOutputPath,
            htmlOutputPath,
            sarifOutputPath);
    }

    private static async Task<ConfigurationReadResult> ReadConfigurationAsync(
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

    private static SarifRegressConfiguration ResolveRepositoryConfiguration(
        SarifRegressConfiguration configuration,
        string? explicitRepositoryPath,
        string? configurationPath)
    {
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
                "CLI0004",
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

    private static RepositoryContextCreationResult CreateRepositoryContext(
        SarifRegressConfiguration configuration,
        bool explicitlySelected)
    {
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
                CreateCliDiagnostic(
                    "CLI0005",
                    DiagnosticStage.Io,
                    message));
        }

        return new RepositoryContextCreationResult(
            new FileSystemRepositoryContext(
                configuration.RepositoryRoot,
                configuration.Limits),
            null);
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        SarifIngestor ingestor,
        string path,
        InputKind input,
        string logicalName,
        SarifRegressConfiguration configuration,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenInput(path);
        return await ingestor.IngestAsync(
                stream,
                new SarifIngestionRequest(input, logicalName, configuration),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static FileStream OpenInput(string path) =>
        new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            StreamBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static ImmutableArray<OutputArtifact> CreateOutputArtifacts(
        ResolvedCompareRequest request,
        byte[] stableJson)
    {
        var artifacts = ImmutableArray.CreateBuilder<OutputArtifact>();
        if (request.JsonOutputPath is not null)
        {
            artifacts.Add(new OutputArtifact(request.JsonOutputPath, stableJson));
        }

        if (request.HtmlOutputPath is not null)
        {
            artifacts.Add(
                new OutputArtifact(
                    request.HtmlOutputPath,
                    StaticHtmlReportRenderer.Render(stableJson)));
        }

        if (request.SarifOutputPath is not null)
        {
            artifacts.Add(
                new OutputArtifact(
                    request.SarifOutputPath,
                    CanonicalSarifExporter.Project(stableJson)));
        }

        return artifacts.ToImmutable();
    }

    private static bool PolicyFailed(
        MatchResult matchResult,
        ImmutableArray<Diagnostic> compatibilityDiagnostics,
        PolicyConfiguration policy)
    {
        var classificationFailure = matchResult.Decisions.Any(
            decision => policy.FailOn.Contains(decision.Classification));
        var githubFailure =
            policy.TreatGithubIncompatibilityAsError &&
            compatibilityDiagnostics.Any(
                diagnostic =>
                    diagnostic.Severity is
                        DiagnosticSeverity.Warning or DiagnosticSeverity.Error);
        return classificationFailure || githubFailure;
    }

    private static void ValidateOutputPaths(
        string baselinePath,
        string candidatePath,
        string? configurationPath,
        params string?[] outputPaths)
    {
        var outputs = outputPaths
            .Where(path => path is not null)
            .Cast<string>()
            .ToArray();
        var outputIdentities = outputs
            .Select(PathIdentityResolver.ResolveOutputIdentity)
            .ToArray();
        if (outputs.Distinct(PathIdentityResolver.Comparer).Count() !=
                outputs.Length ||
            outputIdentities.Distinct(PathIdentityResolver.Comparer).Count() !=
                outputIdentities.Length)
        {
            throw new CommandInputException(
                CreateCliDiagnostic(
                    "CLI0006",
                    DiagnosticStage.Io,
                    "Output paths must be distinct."));
        }

        var protectedInputs = new[]
        {
            baselinePath,
            candidatePath,
            configurationPath,
        }.Where(path => path is not null).Cast<string>();
        var protectedInputPaths = protectedInputs.ToArray();
        var protectedInputIdentities = protectedInputPaths
            .Select(PathIdentityResolver.ResolveInputIdentity)
            .ToArray();
        if (outputs.Any(
                outputPath => protectedInputPaths.Contains(
                    outputPath,
                    PathIdentityResolver.Comparer)) ||
            outputIdentities.Any(
                outputIdentity => protectedInputIdentities.Contains(
                    outputIdentity,
                    PathIdentityResolver.Comparer)))
        {
            throw new CommandInputException(
                CreateCliDiagnostic(
                    "CLI0006",
                    DiagnosticStage.Io,
                    "An output path cannot overwrite an input."));
        }
    }

    private static string? ResolveOptionalPath(
        string? path,
        string baseDirectory,
        string errorMessage)
    {
        return path is null
            ? null
            : ResolvePath(path, baseDirectory, "CLI0001", errorMessage);
    }

    private static string ResolvePath(
        string path,
        string baseDirectory,
        string diagnosticCode,
        string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new CommandInputException(
                CreateCliDiagnostic(
                    diagnosticCode,
                    DiagnosticStage.Io,
                    errorMessage));
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
            throw new CommandInputException(
                CreateCliDiagnostic(
                    diagnosticCode,
                    DiagnosticStage.Io,
                    errorMessage));
        }
    }

    private static string LogicalInputName(string path, string fallback)
    {
        var name = Path.GetFileName(path);
        return string.IsNullOrWhiteSpace(name) ? fallback : name;
    }

    private static Diagnostic CreateCliDiagnostic(
        string code,
        DiagnosticStage stage,
        string message) =>
        new(
            code,
            DiagnosticSeverity.Error,
            stage,
            message);

    private static void WriteDiagnostics(
        TextWriter error,
        IEnumerable<Diagnostic> diagnostics)
    {
        var formatted = StableDiagnosticFormatter.Format(diagnostics);
        if (formatted.Length > 0)
        {
            error.Write(formatted);
        }
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

    private sealed record ResolvedCompareRequest(
        string BaselinePath,
        string CandidatePath,
        string? RepositoryPath,
        string? ConfigurationPath,
        string? JsonOutputPath,
        string? HtmlOutputPath,
        string? SarifOutputPath);

    private sealed record RepositoryContextCreationResult(
        IRepositoryContext? Context,
        Diagnostic? Diagnostic);

    private sealed class CommandInputException : Exception
    {
        public CommandInputException(Diagnostic diagnostic)
            : base(diagnostic.Message)
        {
            Diagnostic = diagnostic;
        }

        public Diagnostic Diagnostic { get; }
    }
}
