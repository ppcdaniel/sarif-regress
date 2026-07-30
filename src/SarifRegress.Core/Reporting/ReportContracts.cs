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
/// <param name="FindingKey">The stable input-side finding key.</param>
/// <param name="ProducerFamily">The human-readable producer-family label.</param>
/// <param name="ProducerToolName">The exact source producer tool name.</param>
/// <param name="ProducerToolVersion">The optional source producer tool version.</param>
/// <param name="AutomaticProducerIdentity">
/// The collision-resistant identity used for automatic same-producer decisions.
/// </param>
/// <param name="CanonicalRule">The canonical rule identity.</param>
/// <param name="CanonicalUri">The optional canonical primary-location URI.</param>
/// <param name="Region">The optional primary-location region.</param>
/// <param name="CanonicalMessage">The canonical message text.</param>
/// <param name="SourceMetadata">Audit-only metadata preserved from SARIF.</param>
/// <param name="MessageNormalisationFlags">Applied message-normalisation identifiers.</param>
/// <param name="Lossiness">Accumulated lossiness identifiers.</param>
/// <param name="DerivedFingerprints">Project-owned derived fingerprints.</param>
public sealed record FindingSnapshot(
    string FindingKey,
    string ProducerFamily,
    string ProducerToolName,
    string? ProducerToolVersion,
    string AutomaticProducerIdentity,
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
            finding.Producer.ToolName,
            finding.Producer.ToolVersion,
            finding.Producer.AutomaticIdentity,
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
