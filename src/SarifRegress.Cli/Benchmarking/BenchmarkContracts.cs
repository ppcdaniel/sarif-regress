using System.Collections.Immutable;

namespace SarifRegress.Cli.Benchmarking;

/// <summary>
/// Identifies a deterministic benchmark dataset shape.
/// </summary>
public enum BenchmarkDatasetKind
{
    /// <summary>
    /// Every finding has a unique producer/rule bucket and fingerprint.
    /// </summary>
    UniqueFingerprints,

    /// <summary>
    /// Findings share one producer, rule, and file to exercise pair-budget refusal.
    /// </summary>
    PathologicalBucket,
}

/// <summary>
/// Holds one generated baseline/candidate benchmark pair.
/// </summary>
public sealed record BenchmarkDataset(
    BenchmarkDatasetKind Kind,
    int FindingCount,
    byte[] BaselineSarif,
    byte[] CandidateSarif);

/// <summary>
/// Counts benchmark structures of one measured size.
/// </summary>
public sealed record BenchmarkSizeDistributionEntry(
    int Size,
    int Count);

/// <summary>
/// Counts each project-level classification in one benchmark result.
/// </summary>
public sealed record BenchmarkClassificationCounts(
    int New,
    int Unchanged,
    int Moved,
    int Modified,
    int Resolved,
    int Ambiguous);

/// <summary>
/// Captures deterministic operation counts and comparison-output identity.
/// </summary>
public sealed record BenchmarkOperations(
    int ParsedDocumentCount,
    int CanonicalFindingCount,
    int MaximumCandidateBucketSize,
    ImmutableArray<BenchmarkSizeDistributionEntry> CandidateBucketSizeDistribution,
    int CandidateEdgeCount,
    int ComponentCount,
    int MaximumComponentFindingCount,
    ImmutableArray<BenchmarkSizeDistributionEntry> ComponentSizeDistribution,
    int AmbiguousComponentCount,
    BenchmarkClassificationCounts Classifications,
    int DiagnosticCount,
    int ExplanationOutputBytes,
    int ComparisonOutputBytes,
    string ComparisonOutputSha256,
    ImmutableArray<string> DiagnosticCodes);

/// <summary>
/// Captures non-deterministic benchmark observations.
/// </summary>
public sealed record BenchmarkObservations(
    double ParseLatencyMilliseconds,
    long ParseThroughputBytesPerSecond,
    double CanonicaliseLatencyMilliseconds,
    long CanonicaliseThroughputFindingsPerSecond,
    double CompareLatencyMilliseconds,
    double SerializeLatencyMilliseconds,
    long ParseAllocatedBytesProxy,
    long CanonicaliseAllocatedBytesProxy,
    long CompareAllocatedBytesProxy,
    long SerializeAllocatedBytesProxy,
    long AllocatedBytesProxy,
    long WorkingSetBytes,
    long PeakWorkingSetBytes);

/// <summary>
/// Publishes the selected dataset resource ceiling and a stable pass/fail result.
/// </summary>
public sealed record BenchmarkBudgetEvaluation(
    double MaximumPipelineLatencyMilliseconds,
    long MaximumPeakWorkingSetBytes,
    bool Passed,
    ImmutableArray<string> FailureCodes);

/// <summary>
/// Represents one versioned benchmark result.
/// </summary>
public sealed record BenchmarkReport(
    BenchmarkDatasetKind DatasetKind,
    int FindingCount,
    int BaselineBytes,
    int CandidateBytes,
    int MaximumCandidatePairsPerFinding,
    long MaximumCandidatePairs,
    BenchmarkOperations Operations,
    BenchmarkObservations Observations,
    BenchmarkBudgetEvaluation Budget);
