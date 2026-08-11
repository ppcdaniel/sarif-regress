using System.Collections.Immutable;
using SarifRegress.Core.Matching;

namespace SarifRegress.Validation;

/// <summary>Defines the frozen source-context variants in report order.</summary>
public static class SparseExperimentVariants
{
    public const string SarifOnlyControl = "sarif-only-control";
    public const string ExactRegionSnippet = "exact-region-snippet";
    public const string TokenWindow = "token-window";
    public const string RelativeContext = "relative-context";
    public const string AgreementOnlyCombination = "agreement-only-combination";

    public static ImmutableArray<string> Ordered { get; } =
    [
        SarifOnlyControl,
        ExactRegionSnippet,
        TokenWindow,
        RelativeContext,
        AgreementOnlyCombination,
    ];
}

/// <summary>Defines the frozen sparse-research scenarios in report order.</summary>
public static class SparseExperimentScenarios
{
    public static ImmutableArray<string> Ordered { get; } =
    [
        "exact-unchanged-source-location",
        "region-drift-equivalent-token-context",
        "file-method-movement-equivalent-token-context",
        "repeated-context-ambiguity",
        "missing-source-file",
        "mismatched-source-snapshot",
        "baseline-root-bound-to-candidate",
        "candidate-root-bound-to-baseline",
        "both-roots-swapped",
        "same-observation-different-method-file",
    ];
}

/// <summary>Represents a complete natural finding selector without a result index.</summary>
public sealed record SparseNaturalSelector(
    string RuleId,
    string ArtifactUri,
    SparseRegionSelector Region,
    string Message);

/// <summary>Represents a complete one-based SARIF region.</summary>
public sealed record SparseRegionSelector(
    int StartLine,
    int StartColumn,
    int EndLine,
    int EndColumn);

/// <summary>Represents one label-neutral accepted correspondence.</summary>
public sealed record SparseAcceptedPair(
    SparseNaturalSelector Baseline,
    SparseNaturalSelector Candidate,
    FindingClassification Classification,
    PrecedenceTier PrecedenceTier);

/// <summary>Reports source-index and matcher work without exposing identity keys.</summary>
public sealed record SparseOperationCounts(
    int SourceFindingsIndexed,
    int SourceAtomsIndexed,
    int SourceIndexLookups,
    int CandidateEdges,
    int Components,
    int AmbiguousComponents);

/// <summary>Reports one side-pair run for a clean fixture family.</summary>
public sealed record SparseFamilyObservation(
    string FamilyId,
    string BaselineSarifSha256,
    string CandidateSarifSha256,
    string BaselineSourceTreeSha256,
    string CandidateSourceTreeSha256,
    ImmutableArray<SparseAcceptedPair> AcceptedPairs,
    ImmutableArray<SparseNaturalSelector> NewFindings,
    ImmutableArray<SparseNaturalSelector> ResolvedFindings,
    ImmutableArray<SparseNaturalSelector> AmbiguousBaselineFindings,
    ImmutableArray<SparseNaturalSelector> AmbiguousCandidateFindings,
    ImmutableArray<string> DiagnosticCodes,
    SparseOperationCounts OperationCounts,
    int IngestionFailures,
    int StructuralFailures);

/// <summary>Reports one family's scenario outcome without consulting ground truth.</summary>
public sealed record SparseFamilyScenarioObservation(
    string FamilyId,
    bool PreflightAccepted,
    ImmutableArray<SparseAcceptedPair> AcceptedPairs,
    ImmutableArray<SparseNaturalSelector> AffectedBaselineFindings,
    ImmutableArray<SparseNaturalSelector> AffectedCandidateFindings,
    int BaselineReadsFromCandidateRoot,
    int CandidateReadsFromBaselineRoot,
    int ContainmentViolations,
    int IngestionFailures,
    int StructuralFailures);

/// <summary>Reports one fixed scenario with independently scoped family outcomes.</summary>
public sealed record SparseScenarioObservation(
    string ScenarioId,
    ImmutableArray<SparseFamilyScenarioObservation> Families);

/// <summary>Reports the exact fixed parameters used by one source variant.</summary>
public sealed record SparseVariantParameters(
    int SnippetLineRadius,
    int MaximumTokenWindowTerms,
    int MaximumRelativeSurroundingTerms,
    int MaximumRelativeRegionTerms,
    bool EndColumnIsExclusive,
    string RelativeContextParts,
    string SourceTextNormalization,
    bool RequireUniqueOnBothSides,
    bool AgreementOnly);

/// <summary>Reports aggregate label-neutral ingestion facts.</summary>
public sealed record SparseIngestionObservation(
    int CasesEvaluated,
    int Failures,
    int StructuralFailures);

/// <summary>Reports aggregate label-neutral security facts.</summary>
public sealed record SparseSecurityObservation(
    int BaselineReadsFromCandidateRoot,
    int CandidateReadsFromBaselineRoot,
    int ContainmentViolations,
    int RootConfusions);

/// <summary>Reports the same experiment without corpus-specific tree hashes.</summary>
public sealed record SparseProductionApplicabilityObservation(
    bool TrustedTreeHashPreflightEnabled,
    ImmutableArray<SparseFamilyObservation> Families,
    ImmutableArray<SparseScenarioObservation> ScenariosWithoutTrustedTreeHashes,
    SparseIngestionObservation Ingestion,
    SparseSecurityObservation Security);

/// <summary>Reports one complete label-neutral variant observation.</summary>
public sealed record SparseVariantObservation(
    string Id,
    string AlgorithmVersion,
    SparseVariantParameters Parameters,
    ImmutableArray<SparseFamilyObservation> Families,
    ImmutableArray<SparseScenarioObservation> Scenarios,
    SparseIngestionObservation Ingestion,
    SparseSecurityObservation Security,
    SparseProductionApplicabilityObservation ProductionApplicability);

/// <summary>Root label-neutral experiment artifact.</summary>
public sealed record SparseExperimentObservations(
    string SchemaVersion,
    string Kind,
    string CorpusManifestSha256,
    string ImplementationManifestSha256,
    ImmutableArray<SparseVariantObservation> Variants);

/// <summary>Reports exact correspondence metrics.</summary>
public sealed record SparseMetrics(
    int AcceptedPairs,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    decimal Precision,
    decimal Recall,
    decimal F1);

/// <summary>Reports one family's post-label metrics.</summary>
public sealed record SparseFamilyMetrics(string FamilyId, SparseMetrics Metrics);

/// <summary>Reports classification correctness for accepted labelled relationships.</summary>
public sealed record SparseClassificationMetrics(
    int MatchedRelationships,
    int ClassificationMismatches);

/// <summary>Reports independently expected and observed lifecycle accuracy.</summary>
public sealed record SparseLifecycleMetrics(
    int ExpectedNew,
    int CorrectNew,
    int IncorrectNew,
    int ExpectedResolved,
    int CorrectResolved,
    int IncorrectResolved);

/// <summary>Reports post-label ambiguity refusal.</summary>
public sealed record SparseAmbiguityMetrics(
    int LabelledUnits,
    int CorrectRefusals,
    int IncorrectAutoMatches);

/// <summary>Reports one family's post-label scenario projection.</summary>
public sealed record SparseFamilyScenarioGateEvidence(
    string FamilyId,
    bool AssertionsPassed,
    bool PreflightAccepted,
    int AcceptedRelationships,
    int AffectedEndpointMatches,
    int BaselineReadsFromCandidateRoot,
    int CandidateReadsFromBaselineRoot,
    int ContainmentViolations,
    int UnexplainedIngestionFailures,
    int StructuralFailures);

/// <summary>Reports one post-label scenario with independently scored families.</summary>
public sealed record SparseScenarioGateEvidence(
    string ScenarioId,
    ImmutableArray<SparseFamilyScenarioGateEvidence> Families);

/// <summary>Reports the production-applicability result without trusted tree hashes.</summary>
public sealed record SparseProductionApplicabilityGateEvidence(
    bool TrustedTreeHashPreflightEnabled,
    SparseMetrics MetricsWithoutTrustedTreeHashes,
    ImmutableArray<SparseScenarioGateEvidence> ScenariosWithoutTrustedTreeHashes,
    bool CorpusSpecificPreflightRequired);

/// <summary>Reports one scored source-context variant.</summary>
public sealed record SparseVariantGateEvidence(
    string Id,
    SparseMetrics Metrics,
    ImmutableArray<SparseFamilyMetrics> ByFamily,
    SparseClassificationMetrics Classification,
    SparseLifecycleMetrics Lifecycle,
    SparseAmbiguityMetrics Ambiguity,
    SparseIngestionObservation Ingestion,
    SparseSecurityObservation Security,
    SparseProductionApplicabilityGateEvidence ProductionApplicability,
    ImmutableArray<SparseScenarioGateEvidence> Scenarios);

/// <summary>Root post-label gate-evidence artifact.</summary>
public sealed record SparseExperimentGateEvidence(
    string SchemaVersion,
    string Kind,
    string CorpusManifestSha256,
    string ObservationsSha256,
    ImmutableArray<SparseVariantGateEvidence> Variants);
