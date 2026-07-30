using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Paths;

namespace SarifRegress.Core.Matching;

/// <summary>
/// Identifies a project-level finding classification.
/// </summary>
public enum FindingClassification
{
    /// <summary>
    /// A candidate finding without an accepted baseline match.
    /// </summary>
    New,

    /// <summary>
    /// A high-tier match with stable logical location and context.
    /// </summary>
    Unchanged,

    /// <summary>
    /// A continuity match whose path or region moved.
    /// </summary>
    Moved,

    /// <summary>
    /// A continuity match whose message or source context changed materially.
    /// </summary>
    Modified,

    /// <summary>
    /// A baseline finding without an accepted candidate match.
    /// </summary>
    Resolved,

    /// <summary>
    /// A finding in a component that cannot be resolved without an arbitrary choice.
    /// </summary>
    Ambiguous,
}

/// <summary>
/// Identifies deterministic evidence precedence.
/// </summary>
public enum PrecedenceTier
{
    /// <summary>
    /// No admissible match evidence.
    /// </summary>
    Refuse = 0,

    /// <summary>
    /// Weak contextual evidence.
    /// </summary>
    WeakContextual = 1,

    /// <summary>
    /// Supporting path or code-flow evidence.
    /// </summary>
    PathProblem = 2,

    /// <summary>
    /// Stable context across a moved logical location.
    /// </summary>
    StrongMoved = 3,

    /// <summary>
    /// Exact canonical rule, path, and derived context.
    /// </summary>
    ExactCanonical = 4,

    /// <summary>
    /// Exact reliable producer fingerprint evidence.
    /// </summary>
    ExactProducer = 5,

    /// <summary>
    /// An explicit user mapping.
    /// </summary>
    Override = 6,
}

/// <summary>
/// Identifies a coarse path relationship for an evidence vector.
/// </summary>
public enum PathMatchKind
{
    /// <summary>
    /// Paths conflict or are unavailable.
    /// </summary>
    None = 0,

    /// <summary>
    /// Paths are connected by an explicit alias or rebase.
    /// </summary>
    Aliased = 1,

    /// <summary>
    /// Canonical paths are identical.
    /// </summary>
    Exact = 2,
}

/// <summary>
/// Identifies an ordinal evidence-agreement band.
/// </summary>
public enum AgreementBand
{
    /// <summary>
    /// Evidence is unavailable or contradictory.
    /// </summary>
    None = 0,

    /// <summary>
    /// Evidence is compatible but not exact.
    /// </summary>
    Compatible = 1,

    /// <summary>
    /// Evidence agrees exactly.
    /// </summary>
    Exact = 2,
}

/// <summary>
/// Identifies a deterministic display confidence.
/// </summary>
public enum DisplayConfidence
{
    /// <summary>
    /// Low confidence.
    /// </summary>
    Low,

    /// <summary>
    /// Medium confidence.
    /// </summary>
    Medium,

    /// <summary>
    /// High confidence.
    /// </summary>
    High,
}

/// <summary>
/// Identifies the origin of evidence.
/// </summary>
public enum EvidenceOrigin
{
    /// <summary>
    /// Producer-supplied evidence.
    /// </summary>
    Producer,

    /// <summary>
    /// Explicit configuration.
    /// </summary>
    Configuration,

    /// <summary>
    /// Bounded repository context.
    /// </summary>
    Repository,

    /// <summary>
    /// SarifRegress-derived evidence.
    /// </summary>
    System,
}

/// <summary>
/// Represents the semantic portion of one lexicographic match decision.
/// </summary>
public readonly record struct DecisionVector(
    PrecedenceTier PrecedenceTier,
    int ProducerFingerprintStrength,
    PathMatchKind PathMatchKind,
    AgreementBand ContextAgreement,
    AgreementBand CodeFlowAgreement,
    AgreementBand MessageAgreement,
    int RegionDriftBand);

/// <summary>
/// Records one exact item of evidence behind a decision.
/// </summary>
public sealed record EvidenceRecord(
    string Kind,
    string? BaselineValue,
    string? CandidateValue,
    EvidenceOrigin Origin,
    PrecedenceTier PrecedenceTier,
    bool Lossy,
    string AlgorithmVersion);

/// <summary>
/// Records a candidate that was considered but not selected.
/// </summary>
public sealed record RejectedAlternative(
    string FindingKey,
    string Reason,
    PrecedenceTier PrecedenceTier,
    DecisionVector DecisionVector);

/// <summary>
/// Represents one admissible baseline/candidate edge.
/// </summary>
public sealed record MatchEdge(
    Finding Baseline,
    Finding Candidate,
    DecisionVector DecisionVector,
    string StableIdentityKey,
    ImmutableArray<EvidenceRecord> Evidence,
    ImmutableArray<TransformationRecord> Transformations);

/// <summary>
/// Represents an accepted one-to-one assignment.
/// </summary>
public sealed record MatchAssignment(
    Finding Baseline,
    Finding Candidate,
    FindingClassification Classification,
    DecisionTrace Decision);

/// <summary>
/// Represents the complete structured explanation for one result decision.
/// </summary>
public sealed record DecisionTrace(
    PrecedenceTier PrecedenceTier,
    DisplayConfidence DisplayConfidence,
    bool Ambiguous,
    string MatcherAlgorithmVersion,
    ImmutableArray<EvidenceRecord> Evidence,
    ImmutableArray<RejectedAlternative> RejectedAlternatives,
    ImmutableArray<TransformationRecord> Transformations,
    ImmutableArray<Diagnostic> Diagnostics);

/// <summary>
/// Represents an output decision for a matched, unmatched, or refused finding.
/// </summary>
public sealed record FindingDecision(
    FindingClassification Classification,
    Finding? Baseline,
    Finding? Candidate,
    DecisionTrace Decision);

/// <summary>
/// Represents deterministic matching output and operation counts.
/// </summary>
public sealed record MatchResult(
    ImmutableArray<FindingDecision> Decisions,
    int CandidateEdgeCount,
    int ComponentCount,
    int AmbiguousComponentCount,
    ImmutableArray<Diagnostic> Diagnostics);
