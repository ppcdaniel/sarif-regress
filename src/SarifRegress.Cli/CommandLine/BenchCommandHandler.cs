using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using SarifRegress.Cli.Benchmarking;
using SarifRegress.Core.Diagnostics;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Executes one bounded functional benchmark selection.
/// </summary>
internal sealed class BenchCommandHandler
{
    private static readonly Encoding StableUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly string currentDirectory;

    public BenchCommandHandler(string currentDirectory)
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
        BenchCommandRequest request,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            var findingCount = request.FindingCount ?? 1_000;
            if (!BenchmarkDatasetGenerator.SupportedSizes.Contains(findingCount))
            {
                return WriteInputFailure(
                    error,
                    "Benchmark size must be 1000, 10000, or 100000.");
            }

            if (!TryParseDataset(request.Dataset, out var datasetKind))
            {
                return WriteInputFailure(
                    error,
                    "Benchmark dataset must be 'unique' or 'pathological'.");
            }

            var outputPath = ResolveOutputPath(request.JsonOutputPath);
            var deterministicOutputPath = ResolveOutputPath(
                request.DeterministicOutputPath);
            if (outputPath is not null &&
                deterministicOutputPath is not null &&
                (PathIdentityResolver.Comparer.Equals(
                     outputPath,
                     deterministicOutputPath) ||
                 PathIdentityResolver.Comparer.Equals(
                     PathIdentityResolver.ResolveOutputIdentity(outputPath),
                     PathIdentityResolver.ResolveOutputIdentity(
                         deterministicOutputPath))))
            {
                return WriteInputFailure(
                    error,
                    "Benchmark output paths must be distinct.");
            }

            var report = await new BenchmarkRunner()
                .RunAsync(
                    findingCount,
                    datasetKind,
                    cancellationToken)
                .ConfigureAwait(false);
            var json = BenchmarkReportSerializer.Serialize(report);
            var deterministicJson =
                BenchmarkReportSerializer.SerializeDeterministicProjection(
                    report);
            var artifacts = ImmutableArray.CreateBuilder<OutputArtifact>(2);
            if (outputPath is not null)
            {
                artifacts.Add(new OutputArtifact(outputPath, json));
            }

            if (deterministicOutputPath is not null)
            {
                artifacts.Add(
                    new OutputArtifact(
                        deterministicOutputPath,
                        deterministicJson));
            }

            await AtomicOutputWriter.WriteAsync(
                    artifacts.ToImmutable(),
                    cancellationToken)
                .ConfigureAwait(false);
            if (outputPath is null)
            {
                output.Write(StableUtf8.GetString(json));
            }

            return request.EnforceBudgets && !report.Budget.Passed
                ? ExitCodes.PolicyFailure
                : ExitCodes.Success;
        }
        catch (OperationCanceledException)
        {
            return WriteFailure(
                error,
                "CLI0036",
                DiagnosticStage.Io,
                "The benchmark was cancelled.");
        }
        catch (IOException)
        {
            return WriteFailure(
                error,
                "CLI0033",
                DiagnosticStage.Io,
                "The benchmark output could not be accessed.");
        }
        catch (UnauthorizedAccessException)
        {
            return WriteFailure(
                error,
                "CLI0034",
                DiagnosticStage.Io,
                "Access to the benchmark output was denied.");
        }
        catch (Exception)
        {
            ValidateCommandSupport.WriteDiagnostics(
                error,
                [
                    new Diagnostic(
                        "INTERNAL0030",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Internal,
                        "SarifRegress encountered an internal invariant failure."),
                ]);
            return ExitCodes.InternalInvariantFailure;
        }
    }

    private string? ResolveOutputPath(string? outputPath)
    {
        if (outputPath is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            throw new IOException("The benchmark output path is invalid.");
        }

        try
        {
            return Path.GetFullPath(outputPath, currentDirectory);
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            NotSupportedException or
            PathTooLongException)
        {
            throw new IOException(
                "The benchmark output path is invalid.",
                exception);
        }
    }

    private static bool TryParseDataset(
        string? value,
        out BenchmarkDatasetKind kind)
    {
        if (value is null ||
            string.Equals(value, "unique", StringComparison.Ordinal))
        {
            kind = BenchmarkDatasetKind.UniqueFingerprints;
            return true;
        }

        if (string.Equals(value, "pathological", StringComparison.Ordinal))
        {
            kind = BenchmarkDatasetKind.PathologicalBucket;
            return true;
        }

        kind = default;
        return false;
    }

    private static int WriteInputFailure(
        TextWriter error,
        string message) =>
        WriteFailure(
            error,
            "CLI0030",
            DiagnosticStage.Schema,
            message);

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
