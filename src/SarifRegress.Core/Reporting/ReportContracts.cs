using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;

namespace SarifRegress.Core.Reporting;

/// <summary>
/// Summarises deterministic classification counts.
/// </summary>
public sealed record ComparisonSummary(
    int BaselineCount,
    int CandidateCount,
    int New,
    int Unchanged,
    int Moved,
    int Modified,
    int Resolved,
    int Ambiguous);

/// <summary>
/// Captures deterministic algorithm-operation metrics.
/// </summary>
public sealed record ComparisonMetrics(
    int CandidateEdges,
    int AssignmentComponents,
    int AmbiguousComponents,
    int Diagnostics);

/// <summary>
/// Identifies stable report and cross-platform normalization algorithms.
/// </summary>
public sealed record DeterminismDescriptor(
    string JsonCanonicalisation,
    string CrossPlatformNormalisation,
    string MatcherAlgorithm);

/// <summary>
/// Provides comparison-relevant finding values without exposing adapter internals.
/// </summary>
public sealed record FindingSnapshot(
    string FindingKey,
    string ProducerFamily,
    string CanonicalRule,
    string? CanonicalUri,
    Region? Region,
    string CanonicalMessage,
    FindingMetadata SourceMetadata,
    ImmutableArray<string> MessageNormalisationFlags,
    ImmutableArray<string> Lossiness,
    ImmutableArray<DerivedFingerprint> DerivedFingerprints);

/// <summary>
/// Represents one stable output decision.
/// </summary>
public sealed record FindingReport(
    FindingClassification Classification,
    SourceReference? BaselineReference,
    SourceReference? CandidateReference,
    FindingSnapshot? Baseline,
    FindingSnapshot? Candidate,
    DecisionTrace Decision);

/// <summary>
/// Represents the versioned, stable JSON source-of-truth contract.
/// </summary>
public sealed record ComparisonReport(
    string OutputSchemaVersion,
    string ToolName,
    string ToolVersion,
    string BaselineInputName,
    string CandidateInputName,
    ComparisonSummary Summary,
    ImmutableArray<FindingReport> Findings,
    ImmutableArray<Diagnostic> Diagnostics,
    ComparisonMetrics Metrics,
    DeterminismDescriptor Determinism);

/// <summary>
/// Creates stable report snapshots from canonical findings.
/// </summary>
public static class FindingSnapshotFactory
{
    /// <summary>
    /// Creates a comparison-relevant snapshot.
    /// </summary>
    /// <param name="finding">The canonical finding.</param>
    /// <returns>The immutable snapshot.</returns>
    public static FindingSnapshot Create(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return new FindingSnapshot(
            finding.FindingKey,
            finding.Producer.Family,
            finding.Rule.CanonicalId,
            finding.PrimaryLocation?.Path.CanonicalUri,
            finding.PrimaryLocation?.Region,
            finding.Message.CanonicalText,
            finding.Metadata,
            finding.Message.NormalisationFlags,
            finding.Lossiness,
            finding.DerivedFingerprints);
    }
}
