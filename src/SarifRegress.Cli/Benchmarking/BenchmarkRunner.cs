using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
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
        var serialization =
            StableJsonReportSerializer.MeasureCanonical(comparisonReport);
        stopwatch.Stop();
        var serializeElapsed = stopwatch.Elapsed;

        using var process = Process.GetCurrentProcess();
        process.Refresh();
        var allocatedAfter = GC.GetTotalAllocatedBytes(precise: false);
        var candidateBucketSizes = MeasureCandidateBucketSizes(
            candidate.ComparisonInput.Findings);
        var componentSizes = MeasureComponentSizes(
            matchResult,
            baseline.ComparisonInput.Findings.Length,
            candidate.ComparisonInput.Findings.Length);
        var operations = new BenchmarkOperations(
            ParsedDocumentCount: 2,
            CanonicalFindingCount:
                baseline.ComparisonInput.Findings.Length +
                candidate.ComparisonInput.Findings.Length,
            MaximumCandidateBucketSize: MaximumOrZero(candidateBucketSizes),
            CandidateBucketSizeDistribution: Distribution(candidateBucketSizes),
            CandidateEdgeCount: matchResult.CandidateEdgeCount,
            ComponentCount: matchResult.ComponentCount,
            MaximumComponentFindingCount: MaximumOrZero(componentSizes),
            ComponentSizeDistribution: Distribution(componentSizes),
            AmbiguousComponentCount: matchResult.AmbiguousComponentCount,
            Classifications: CountClassifications(matchResult),
            DiagnosticCount: matchResult.Diagnostics.Length,
            ExplanationOutputBytes: serialization.ExplanationBytes,
            ComparisonOutputBytes: serialization.OutputBytes,
            ComparisonOutputSha256: serialization.OutputSha256,
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
        var budget = EvaluateBudget(
            kind,
            findingCount,
            operations,
            observations);
        return new BenchmarkReport(
            kind,
            findingCount,
            dataset.BaselineSarif.Length,
            dataset.CandidateSarif.Length,
            limits.MaximumCandidatePairEvaluationsPerFinding,
            limits.MaximumCandidatePairEvaluations,
            operations,
            observations,
            budget);
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

    private static ImmutableArray<int> MeasureCandidateBucketSizes(
        ImmutableArray<Finding> findings) =>
        findings
            .GroupBy(
                finding => (
                    finding.Producer.Family,
                    finding.Rule.CanonicalId))
            .Select(group => group.Count())
            .Order()
            .ToImmutableArray();

    private static ImmutableArray<int> MeasureComponentSizes(
        MatchResult result,
        int baselineFindingCount,
        int candidateFindingCount)
    {
        if (result.ComponentCount == 0)
        {
            return ImmutableArray<int>.Empty;
        }

        if (HasCandidatePairRefusal(result))
        {
            return [checked(baselineFindingCount + candidateFindingCount)];
        }

        var sizes = result.Decisions
            .Where(decision =>
                decision.Baseline is not null &&
                decision.Candidate is not null)
            .Select(_ => 2)
            .ToList();
        var ambiguousFindingCount = result.Decisions.Count(
            decision => decision.Classification == FindingClassification.Ambiguous);
        if (ambiguousFindingCount > 0)
        {
            if (result.AmbiguousComponentCount != 1)
            {
                throw new InvalidOperationException(
                    "The benchmark cannot derive multiple ambiguous component sizes.");
            }

            sizes.Add(ambiguousFindingCount);
        }

        if (sizes.Count != result.ComponentCount)
        {
            throw new InvalidOperationException(
                "The benchmark component measurements are inconsistent.");
        }

        return sizes.Order().ToImmutableArray();
    }

    private static bool HasCandidatePairRefusal(MatchResult result) =>
        result.Diagnostics.Any(
            diagnostic => diagnostic.Code is "MATCH0007" or "MATCH0008" or "MATCH0009");

    private static ImmutableArray<BenchmarkSizeDistributionEntry> Distribution(
        ImmutableArray<int> sizes) =>
        sizes
            .GroupBy(size => size)
            .OrderBy(group => group.Key)
            .Select(group => new BenchmarkSizeDistributionEntry(
                group.Key,
                group.Count()))
            .ToImmutableArray();

    private static int MaximumOrZero(ImmutableArray<int> values) =>
        values.IsEmpty ? 0 : values.Max();

    private static BenchmarkClassificationCounts CountClassifications(
        MatchResult result)
    {
        return new BenchmarkClassificationCounts(
            New: Count(FindingClassification.New),
            Unchanged: Count(FindingClassification.Unchanged),
            Moved: Count(FindingClassification.Moved),
            Modified: Count(FindingClassification.Modified),
            Resolved: Count(FindingClassification.Resolved),
            Ambiguous: Count(FindingClassification.Ambiguous));

        int Count(FindingClassification classification) =>
            result.Decisions.Count(
                decision => decision.Classification == classification);
    }

    private static BenchmarkBudgetEvaluation EvaluateBudget(
        BenchmarkDatasetKind kind,
        int findingCount,
        BenchmarkOperations operations,
        BenchmarkObservations observations)
    {
        var (maximumLatencyMilliseconds, maximumPeakWorkingSetBytes) =
            findingCount switch
            {
                1_000 => (10_000d, 512L * 1024 * 1024),
                10_000 => (20_000d, 768L * 1024 * 1024),
                100_000 => (60_000d, 1024L * 1024 * 1024),
                _ => throw new ArgumentOutOfRangeException(
                    nameof(findingCount),
                    findingCount,
                    "Unknown benchmark size."),
            };
        var failures = ImmutableArray.CreateBuilder<string>();
        var pipelineLatency =
            observations.ParseLatencyMilliseconds +
            observations.CanonicaliseLatencyMilliseconds +
            observations.CompareLatencyMilliseconds +
            observations.SerializeLatencyMilliseconds;
        if (pipelineLatency > maximumLatencyMilliseconds)
        {
            failures.Add("latency-budget-exceeded");
        }

        if (observations.PeakWorkingSetBytes > maximumPeakWorkingSetBytes)
        {
            failures.Add("working-set-budget-exceeded");
        }

        if (kind == BenchmarkDatasetKind.PathologicalBucket &&
            (operations.CandidateEdgeCount != 0 ||
             operations.AmbiguousComponentCount == 0 ||
             !operations.DiagnosticCodes.Any(
                 code => code is "MATCH0007" or "MATCH0008" or "MATCH0009")))
        {
            failures.Add("pathological-bucket-not-bounded");
        }

        var orderedFailures = failures
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToImmutableArray();
        return new BenchmarkBudgetEvaluation(
            maximumLatencyMilliseconds,
            maximumPeakWorkingSetBytes,
            orderedFailures.IsEmpty,
            orderedFailures);
    }
}
