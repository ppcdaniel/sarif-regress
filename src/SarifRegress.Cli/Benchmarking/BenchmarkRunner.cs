using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Reporting;
using SarifRegress.Core.Security;
using SarifRegress.Match;
using SarifRegress.Report;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.Cli.Benchmarking;

/// <summary>
/// Runs the dependency-free functional benchmark pipeline.
/// </summary>
public sealed class BenchmarkRunner
{
    /// <summary>
    /// Generates, parses, canonicalises, compares, and serializes one dataset.
    /// </summary>
    /// <param name="findingCount">One supported dataset size.</param>
    /// <param name="kind">The deterministic dataset shape.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The stable operation counts and explicit runtime observations.</returns>
    public async Task<BenchmarkReport> RunAsync(
        int findingCount,
        BenchmarkDatasetKind kind,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var dataset = BenchmarkDatasetGenerator.Generate(findingCount, kind);
        var allocatedBefore = GC.GetTotalAllocatedBytes(precise: false);

        var stopwatch = Stopwatch.StartNew();
        cancellationToken.ThrowIfCancellationRequested();
        Parse(dataset.BaselineSarif);
        cancellationToken.ThrowIfCancellationRequested();
        Parse(dataset.CandidateSarif);
        cancellationToken.ThrowIfCancellationRequested();
        stopwatch.Stop();
        var parseElapsed = stopwatch.Elapsed;

        stopwatch.Restart();
        var baseline = await IngestAsync(
                dataset.BaselineSarif,
                InputKind.Baseline,
                "benchmark-baseline.sarif",
                cancellationToken)
            .ConfigureAwait(false);
        var candidate = await IngestAsync(
                dataset.CandidateSarif,
                InputKind.Candidate,
                "benchmark-candidate.sarif",
                cancellationToken)
            .ConfigureAwait(false);
        stopwatch.Stop();
        var canonicaliseElapsed = stopwatch.Elapsed;
        EnsureValid(baseline, candidate, findingCount);

        stopwatch.Restart();
        var matchResult = new FindingMatcher().Match(
            baseline.ComparisonInput,
            candidate.ComparisonInput);
        stopwatch.Stop();
        var compareElapsed = stopwatch.Elapsed;

        stopwatch.Restart();
        var comparisonReport = ComparisonReportFactory.Create(
            matchResult,
            new ComparisonReportMetadata(
                ProductInformation.Version,
                baseline.ComparisonInput.LogicalName,
                candidate.ComparisonInput.LogicalName,
                ProductInformation.MatcherAlgorithmVersion));
        var comparisonOutput =
            StableJsonReportSerializer.Serialize(comparisonReport);
        stopwatch.Stop();
        var serializeElapsed = stopwatch.Elapsed;

        using var process = Process.GetCurrentProcess();
        process.Refresh();
        var allocatedAfter = GC.GetTotalAllocatedBytes(precise: false);
        var operations = new BenchmarkOperations(
            ParsedDocumentCount: 2,
            CanonicalFindingCount:
                baseline.ComparisonInput.Findings.Length +
                candidate.ComparisonInput.Findings.Length,
            MaximumCandidateBucketSize:
                kind == BenchmarkDatasetKind.UniqueFingerprints
                    ? 1
                    : findingCount,
            CandidateEdgeCount: matchResult.CandidateEdgeCount,
            ComponentCount: matchResult.ComponentCount,
            MaximumComponentFindingCount:
                kind == BenchmarkDatasetKind.UniqueFingerprints
                    ? 2
                    : checked(2 * findingCount),
            AmbiguousComponentCount: matchResult.AmbiguousComponentCount,
            DiagnosticCount: matchResult.Diagnostics.Length,
            ComparisonOutputBytes: comparisonOutput.Length,
            ComparisonOutputSha256:
                Convert.ToHexString(SHA256.HashData(comparisonOutput))
                .ToLowerInvariant(),
            DiagnosticCodes: matchResult.Diagnostics
                .Select(item => item.Code)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToImmutableArray());
        var limits = baseline.ComparisonInput.Findings.Length == findingCount
            ? SarifRegressConfiguration.Default.Limits
            : throw new InvalidOperationException(
                "The benchmark canonical finding count is inconsistent.");
        var observations = new BenchmarkObservations(
            parseElapsed.TotalMilliseconds,
            Rate(
                (long)dataset.BaselineSarif.Length +
                dataset.CandidateSarif.Length,
                parseElapsed),
            canonicaliseElapsed.TotalMilliseconds,
            Rate(checked(2L * findingCount), canonicaliseElapsed),
            compareElapsed.TotalMilliseconds,
            serializeElapsed.TotalMilliseconds,
            Math.Max(0, allocatedAfter - allocatedBefore),
            process.WorkingSet64,
            process.PeakWorkingSet64);
        return new BenchmarkReport(
            kind,
            findingCount,
            dataset.BaselineSarif.Length,
            dataset.CandidateSarif.Length,
            limits.MaximumCandidatePairEvaluationsPerFinding,
            limits.MaximumCandidatePairEvaluations,
            operations,
            observations);
    }

    private static void Parse(byte[] bytes)
    {
        using var document = JsonDocument.Parse(
            bytes.AsMemory(),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = ResourceLimits.DefaultMaximumJsonDepth,
            });
        _ = document.RootElement.ValueKind;
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        byte[] bytes,
        InputKind input,
        string logicalName,
        CancellationToken cancellationToken)
    {
        await using var stream = new MemoryStream(
            bytes,
            writable: false);
        return await new SarifIngestor()
            .IngestAsync(
                stream,
                new SarifIngestionRequest(input, logicalName),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static void EnsureValid(
        SarifIngestionResult baseline,
        SarifIngestionResult candidate,
        int findingCount)
    {
        if (!baseline.IsValid ||
            !candidate.IsValid ||
            baseline.ComparisonInput.Findings.Length != findingCount ||
            candidate.ComparisonInput.Findings.Length != findingCount)
        {
            throw new InvalidOperationException(
                "The generated benchmark dataset did not canonicalise successfully.");
        }
    }

    private static long Rate(long units, TimeSpan elapsed)
    {
        if (elapsed.Ticks <= 0)
        {
            return 0;
        }

        var rate = units / elapsed.TotalSeconds;
        return rate >= long.MaxValue
            ? long.MaxValue
            : (long)Math.Round(
                rate,
                MidpointRounding.AwayFromZero);
    }
}
