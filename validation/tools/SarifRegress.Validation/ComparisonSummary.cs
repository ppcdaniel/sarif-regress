using System.Collections.Immutable;

namespace SarifRegress.Validation;

/// <summary>Hashes every deterministic input and normalized component report.</summary>
public sealed record ComparisonReportHashes(
    string HoldoutManifestSha256,
    string EvaluationMetadataSha256,
    string SarifRegressReportSha256,
    string SarifMultitoolBaselineReportSha256,
    string MatcherV31ReportSha256,
    string V31ToV32DeltaReportSha256);

/// <summary>Freezes release gates before evaluating the holdout.</summary>
public sealed record ReleaseThresholds(
    decimal MinimumPrecision,
    decimal MinimumRecall,
    int MaximumIncorrectlyAutoMatchedAmbiguousCases,
    int MaximumUnexplainedIngestionFailures,
    int MaximumStructuralFailures,
    bool RequireCompleteLabelGraph,
    bool RequireCrossPlatformByteIdentity,
    bool RequireCompletedEvaluation)
{
    /// <summary>Gets the minimum precision required from every producer.</summary>
    public decimal MinimumPerProducerPrecision { get; init; } = 0.95m;

    /// <summary>Gets the minimum recall required from every producer.</summary>
    public decimal MinimumPerProducerRecall { get; init; } = 0.80m;

    /// <summary>Gets whether every changed v3 decision requires an explanation trace.</summary>
    public bool RequireChangedDecisionExplanations { get; init; } = true;

    /// <summary>Gets the architecture-aligned, predeclared milestone thresholds.</summary>
    public static ReleaseThresholds Frozen { get; } = new(
        MinimumPrecision: 0.95m,
        MinimumRecall: 0.90m,
        MaximumIncorrectlyAutoMatchedAmbiguousCases: 0,
        MaximumUnexplainedIngestionFailures: 0,
        MaximumStructuralFailures: 0,
        RequireCompleteLabelGraph: true,
        RequireCrossPlatformByteIdentity: true,
        RequireCompletedEvaluation: true)
    {
        MinimumPerProducerPrecision = 0.95m,
        MinimumPerProducerRecall = 0.80m,
        RequireChangedDecisionExplanations = true,
    };
}

/// <summary>Records each independently evaluated release gate.</summary>
public sealed record ReleaseConditions(
    bool PrecisionMet,
    bool RecallMet,
    bool ZeroIncorrectAmbiguityMatches,
    bool NoUnexplainedIngestionFailures,
    bool NoStructuralFailures,
    bool CompleteLabelGraphSatisfied,
    bool CrossPlatformByteIdentity,
    bool EvaluationCompleted)
{
    /// <summary>Gets whether every producer met its precision threshold.</summary>
    public bool AllProducerPrecisionMet { get; init; } = true;

    /// <summary>Gets whether every producer met its recall threshold.</summary>
    public bool AllProducerRecallMet { get; init; } = true;

    /// <summary>Gets whether every changed matcher decision has an explanation trace.</summary>
    public bool EveryChangedDecisionExplained { get; init; } = true;
}

/// <summary>Projects the SarifRegress metrics used by release comparison.</summary>
public sealed record SarifRegressComparisonMetrics(
    int GroundTruthUnits,
    int LabelledRelationships,
    int LabelledMatches,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    int ClassificationMismatches,
    int CorrectAmbiguityRefusals,
    int IncorrectlyAutoMatchedAmbiguousCases,
    int IngestionFailures,
    int UnexplainedIngestionFailures,
    int StructuralFailures,
    decimal Precision,
    decimal Recall,
    decimal F1)
{
    /// <summary>Gets the number of labelled candidate-only lifecycle units.</summary>
    public int ExpectedNewClassifications { get; init; }

    /// <summary>Gets the number of correctly classified candidate-only units.</summary>
    public int CorrectNewClassifications { get; init; }

    /// <summary>Gets the number of incorrectly classified candidate-only units.</summary>
    public int IncorrectNewClassifications { get; init; }

    /// <summary>Gets exact new-classification accuracy, or one for no labelled units.</summary>
    public decimal NewClassificationAccuracy { get; init; } = 1m;

    /// <summary>Gets the number of labelled baseline-only lifecycle units.</summary>
    public int ExpectedResolvedClassifications { get; init; }

    /// <summary>Gets the number of correctly classified baseline-only units.</summary>
    public int CorrectResolvedClassifications { get; init; }

    /// <summary>Gets the number of incorrectly classified baseline-only units.</summary>
    public int IncorrectResolvedClassifications { get; init; }

    /// <summary>Gets exact resolved-classification accuracy, or one for no labelled units.</summary>
    public decimal ResolvedClassificationAccuracy { get; init; } = 1m;
}

/// <summary>Wraps SarifRegress comparison metrics.</summary>
public sealed record SarifRegressComparisonSummary(
    SarifRegressComparisonMetrics Metrics);

/// <summary>Projects comparable Multitool identity metrics.</summary>
public sealed record MultitoolComparisonMetrics(
    int GroundTruthUnits,
    int LabelledRelationships,
    int ComparableRelationships,
    int NonComparableRelationships,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    decimal Precision,
    decimal Recall,
    decimal F1);

/// <summary>Names the external baseline and its exact comparison metrics.</summary>
public sealed record MultitoolComparisonSummary(
    string ToolName,
    string ExactVersion,
    MultitoolComparisonMetrics Metrics);

/// <summary>Counts all ground-truth units by shared correctness.</summary>
public sealed record ToolComparisonMetrics(
    int GroundTruthUnits,
    int PositiveMatchRelationships,
    int ComparableUnits,
    int BothToolsAgree,
    int BothToolsCorrect,
    int SarifRegressOnlyCorrect,
    int MultitoolOnlyCorrect,
    int BothIncorrect,
    int NonComparable);

/// <summary>Records fixed precision and recall gates for one producer.</summary>
public sealed record ProducerQualityGates(
    decimal MinimumPrecision,
    decimal MinimumRecall,
    bool PrecisionMet,
    bool RecallMet);

/// <summary>Compares both tools for one producer family.</summary>
public sealed record ProducerComparison(
    string ProducerId,
    SarifRegressComparisonMetrics SarifRegress,
    MultitoolComparisonMetrics SarifMultitool,
    ToolComparisonMetrics Comparison)
{
    /// <summary>Gets the producer's independently evaluated quality gates.</summary>
    public ProducerQualityGates QualityGates { get; init; } = new(
        MinimumPrecision: 0m,
        MinimumRecall: 0m,
        PrecisionMet: true,
        RecallMet: true);
}

/// <summary>Summarizes whether matcher-v3 decision changes retain explanation traces.</summary>
public sealed record ChangedDecisionExplanationCoverage(
    int ChangedDecisionCount,
    int ChangedDecisionTraceCount)
{
    /// <summary>Gets whether every changed decision has a retained explanation trace.</summary>
    public bool EveryChangedDecisionExplained =>
        ChangedDecisionCount >= 0
        && ChangedDecisionTraceCount == ChangedDecisionCount;

    /// <summary>Validates the bounded relationship between changed and traced decisions.</summary>
    public void Validate()
    {
        if (ChangedDecisionCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ChangedDecisionCount),
                ChangedDecisionCount,
                "The changed-decision count cannot be negative.");
        }

        if (ChangedDecisionTraceCount < 0
            || ChangedDecisionTraceCount > ChangedDecisionCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ChangedDecisionTraceCount),
                ChangedDecisionTraceCount,
                "The trace count must be between zero and the changed-decision count.");
        }
    }
}

/// <summary>Compares correctness for one ground-truth unit.</summary>
public sealed record RelationshipComparison(
    string RelationshipId,
    string CaseId,
    string ProducerId,
    bool SarifRegressCorrect,
    bool? MultitoolCorrect,
    bool? ToolsAgree,
    string CorrectnessCategory,
    string? NonComparableReason);

/// <summary>Lists one explicitly non-comparable external-baseline unit.</summary>
public sealed record NonComparableRelationship(
    string RelationshipId,
    string CaseId,
    string ProducerId,
    string Reason);

/// <summary>Explains one semantic difference without producer-controlled text.</summary>
public sealed record SemanticDifference(
    string Code,
    ImmutableArray<string> AffectedRelationshipIds,
    string Explanation);

/// <summary>Defines the complete deterministic external comparison report.</summary>
public sealed record ComparisonSummaryReport(
    EvaluationIdentity Evaluation,
    ComparisonReportHashes ReportHashes,
    ReleaseThresholds Thresholds,
    ReleaseConditions ReleaseConditions,
    SarifRegressComparisonSummary SarifRegress,
    MultitoolComparisonSummary SarifMultitool,
    ToolComparisonMetrics Aggregate,
    ImmutableArray<ProducerComparison> Producers,
    ImmutableArray<RelationshipComparison> Relationships,
    ImmutableArray<NonComparableRelationship> NonComparableRelationships,
    ImmutableArray<SemanticDifference> SemanticDifferences,
    string ReleaseRecommendation,
    ImmutableArray<string> RecommendationReasons);

/// <summary>Builds an identity/lifecycle comparison without treating Multitool as an oracle.</summary>
public static class ComparisonSummaryBuilder
{
    /// <summary>Creates one complete comparison and derives the release recommendation.</summary>
    public static ComparisonSummaryReport Create(
        SarifRegressHoldoutReport sarifRegress,
        SarifMultitoolBaselineReport sarifMultitool,
        ComparisonReportHashes reportHashes,
        bool crossPlatformByteIdentity,
        bool evaluationCompleted = true,
        ChangedDecisionExplanationCoverage? changedDecisionExplanations = null)
    {
        ArgumentNullException.ThrowIfNull(sarifRegress);
        ArgumentNullException.ThrowIfNull(sarifMultitool);
        ArgumentNullException.ThrowIfNull(reportHashes);
        ValidateReportHashes(reportHashes, sarifRegress.Evaluation);
        changedDecisionExplanations?.Validate();
        if (sarifRegress.Evaluation != sarifMultitool.Evaluation)
        {
            throw new InvalidDataException(
                "The two normalized reports do not identify the same frozen evaluation.");
        }

        ImmutableArray<RelationshipComparison> relationships = CompareRelationships(
            sarifRegress.Cases,
            sarifMultitool.Cases);
        ImmutableArray<NonComparableRelationship> nonComparable = relationships
            .Where(item => item.CorrectnessCategory == "non-comparable")
            .Select(item => new NonComparableRelationship(
                item.RelationshipId,
                item.CaseId,
                item.ProducerId,
                item.NonComparableReason!))
            .ToImmutableArray();
        ToolComparisonMetrics aggregate = CreateComparisonMetrics(
            relationships,
            sarifRegress.Aggregate.LabelledRelationships);
        ReleaseThresholds thresholds = ReleaseThresholds.Frozen;
        ImmutableArray<ProducerComparison> producers = CreateProducerComparisons(
            sarifRegress,
            sarifMultitool,
            relationships,
            thresholds);
        SarifRegressComparisonMetrics sarifMetrics = Project(sarifRegress.Aggregate);
        MultitoolComparisonMetrics multitoolMetrics = Project(
            sarifMultitool.Aggregate);
        bool completeLabelGraph = CompleteLabelGraphSatisfied(
            sarifRegress,
            sarifMetrics);
        bool allProducerPrecisionsMet = producers.All(item =>
            item.QualityGates.PrecisionMet);
        bool allProducerRecallsMet = producers.All(item =>
            item.QualityGates.RecallMet);
        bool everyChangedDecisionExplained =
            !thresholds.RequireChangedDecisionExplanations
            || changedDecisionExplanations?.EveryChangedDecisionExplained == true;
        var conditions = new ReleaseConditions(
            sarifMetrics.Precision >= thresholds.MinimumPrecision,
            sarifMetrics.Recall >= thresholds.MinimumRecall,
            sarifMetrics.IncorrectlyAutoMatchedAmbiguousCases
                <= thresholds.MaximumIncorrectlyAutoMatchedAmbiguousCases,
            sarifMetrics.UnexplainedIngestionFailures
                <= thresholds.MaximumUnexplainedIngestionFailures,
            sarifMetrics.StructuralFailures <= thresholds.MaximumStructuralFailures,
            completeLabelGraph,
            crossPlatformByteIdentity,
            evaluationCompleted)
        {
            AllProducerPrecisionMet = allProducerPrecisionsMet,
            AllProducerRecallMet = allProducerRecallsMet,
            EveryChangedDecisionExplained = everyChangedDecisionExplained,
        };
        ImmutableArray<string> reasons = RecommendationReasons(conditions);
        string recommendation = !conditions.EvaluationCompleted
            ? "inconclusive"
            : reasons.IsEmpty
                ? "ready"
                : "blocked";
        return new ComparisonSummaryReport(
            sarifRegress.Evaluation,
            reportHashes,
            thresholds,
            conditions,
            new SarifRegressComparisonSummary(sarifMetrics),
            new MultitoolComparisonSummary(
                sarifMultitool.Tool.Name,
                sarifMultitool.Tool.ExactVersion,
                multitoolMetrics),
            aggregate,
            producers,
            relationships,
            nonComparable,
            CreateSemanticDifferences(
                nonComparable,
                sarifMultitool.Cases.SelectMany(item => item.RelationshipResults)),
            recommendation,
            reasons);
    }

    private static void ValidateReportHashes(
        ComparisonReportHashes hashes,
        EvaluationIdentity evaluation)
    {
        foreach ((string name, string value) in new[]
                 {
                     ("holdout manifest", hashes.HoldoutManifestSha256),
                     ("evaluation metadata", hashes.EvaluationMetadataSha256),
                     ("SarifRegress report", hashes.SarifRegressReportSha256),
                     ("Multitool report", hashes.SarifMultitoolBaselineReportSha256),
                     ("matcher-v3.1 report", hashes.MatcherV31ReportSha256),
                     ("v3.1-to-v3.2 delta report", hashes.V31ToV32DeltaReportSha256),
                 })
        {
            if (value is null
                || value.Length != 64
                || value.Any(character =>
                    (character < '0' || character > '9')
                    && (character < 'a' || character > 'f')))
            {
                throw new InvalidDataException(
                    $"The comparison {name} SHA-256 is not lowercase hexadecimal.");
            }
        }

        if (!string.Equals(
                hashes.HoldoutManifestSha256,
                evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The comparison hashes identify a different holdout manifest.");
        }
    }

    private static ImmutableArray<RelationshipComparison> CompareRelationships(
        ImmutableArray<SarifRegressCaseResult> sarifCases,
        ImmutableArray<MultitoolCaseResult> multitoolCases)
    {
        Dictionary<string, MultitoolCaseResult> multitoolByCase = multitoolCases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        if (!sarifCases.Select(item => item.CaseId).Order(StringComparer.Ordinal)
            .SequenceEqual(
                multitoolByCase.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The two normalized reports do not contain the same case set.");
        }

        var output = ImmutableArray.CreateBuilder<RelationshipComparison>();
        foreach (SarifRegressCaseResult sarifCase in sarifCases.OrderBy(
                     item => item.CaseId,
                     StringComparer.Ordinal))
        {
            MultitoolCaseResult multitoolCase = multitoolByCase[sarifCase.CaseId];
            if (!string.Equals(
                sarifCase.ProducerId,
                multitoolCase.ProducerId,
                StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Case '{sarifCase.CaseId}' has inconsistent producer identities.");
            }

            Dictionary<string, MultitoolRelationshipResult> multitoolRelationships =
                multitoolCase.RelationshipResults.ToDictionary(
                    item => item.RelationshipId,
                    StringComparer.Ordinal);
            if (!sarifCase.RelationshipResults
                .Select(item => item.RelationshipId)
                .Order(StringComparer.Ordinal)
                .SequenceEqual(
                    multitoolRelationships.Keys.Order(StringComparer.Ordinal),
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    $"Case '{sarifCase.CaseId}' does not contain the same relationship set in both reports.");
            }

            foreach (RelationshipResult sarifRelationship in sarifCase.RelationshipResults
                         .OrderBy(item => item.RelationshipId, StringComparer.Ordinal))
            {
                MultitoolRelationshipResult multitoolRelationship =
                    multitoolRelationships[sarifRelationship.RelationshipId];
                if (sarifRelationship.GroundTruth != multitoolRelationship.GroundTruth)
                {
                    throw new InvalidDataException(
                        $"Relationship '{sarifRelationship.RelationshipId}' has inconsistent ground truth.");
                }

                bool sarifCorrect = IsSarifRegressCorrect(
                    sarifRelationship.Outcome,
                    requireClassification: false);
                bool? multitoolCorrect = multitoolRelationship.Comparable
                    ? multitoolRelationship.Correct
                    : null;
                bool? agree = multitoolCorrect.HasValue
                    ? sarifCorrect == multitoolCorrect.Value
                    : null;
                string category = multitoolCorrect switch
                {
                    null => "non-comparable",
                    true when sarifCorrect => "both-correct",
                    false when sarifCorrect => "sarif-regress-only-correct",
                    true => "multitool-only-correct",
                    false => "both-incorrect",
                };
                output.Add(new RelationshipComparison(
                    sarifRelationship.RelationshipId,
                    sarifCase.CaseId,
                    sarifCase.ProducerId,
                    sarifCorrect,
                    multitoolCorrect,
                    agree,
                    category,
                    multitoolRelationship.Comparable
                        ? null
                        : multitoolRelationship.ComparabilityReason));
            }
        }

        return output.ToImmutable();
    }

    private static ImmutableArray<ProducerComparison> CreateProducerComparisons(
        SarifRegressHoldoutReport sarifRegress,
        SarifMultitoolBaselineReport sarifMultitool,
        ImmutableArray<RelationshipComparison> relationships,
        ReleaseThresholds thresholds)
    {
        Dictionary<string, HoldoutMetrics> sarifMetrics = sarifRegress.Producers
            .ToDictionary(item => item.ProducerId, item => item.Metrics, StringComparer.Ordinal);
        Dictionary<string, MultitoolMetrics> multitoolMetrics = sarifMultitool.Producers
            .ToDictionary(item => item.ProducerId, item => item.Metrics, StringComparer.Ordinal);
        if (!sarifMetrics.Keys.Order(StringComparer.Ordinal).SequenceEqual(
            multitoolMetrics.Keys.Order(StringComparer.Ordinal),
            StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The two normalized reports do not contain the same producer set.");
        }

        return sarifMetrics.Keys.Order(StringComparer.Ordinal)
            .Select(producerId => CreateProducerComparison(producerId))
            .ToImmutableArray();

        ProducerComparison CreateProducerComparison(string producerId)
        {
            SarifRegressComparisonMetrics projected = Project(sarifMetrics[producerId]);
            return new ProducerComparison(
                producerId,
                projected,
                Project(multitoolMetrics[producerId]),
                CreateComparisonMetrics(
                    relationships.Where(item => item.ProducerId == producerId),
                    sarifMetrics[producerId].LabelledRelationships))
            {
                QualityGates = new ProducerQualityGates(
                    thresholds.MinimumPerProducerPrecision,
                    thresholds.MinimumPerProducerRecall,
                    projected.Precision >= thresholds.MinimumPerProducerPrecision,
                    projected.Recall >= thresholds.MinimumPerProducerRecall),
            };
        }
    }

    private static ToolComparisonMetrics CreateComparisonMetrics(
        IEnumerable<RelationshipComparison> relationships,
        int positiveMatchRelationships)
    {
        RelationshipComparison[] values = relationships.ToArray();
        int nonComparable = values.Count(item =>
            item.CorrectnessCategory == "non-comparable");
        int comparable = values.Length - nonComparable;
        int bothCorrect = Count("both-correct");
        int sarifOnly = Count("sarif-regress-only-correct");
        int multitoolOnly = Count("multitool-only-correct");
        int bothIncorrect = Count("both-incorrect");
        int agree = values.Count(item => item.ToolsAgree == true);
        if (bothCorrect + sarifOnly + multitoolOnly + bothIncorrect != comparable)
        {
            throw new InvalidDataException(
                "Comparison correctness categories do not cover every comparable ground-truth unit.");
        }

        return new ToolComparisonMetrics(
            values.Length,
            positiveMatchRelationships,
            comparable,
            agree,
            bothCorrect,
            sarifOnly,
            multitoolOnly,
            bothIncorrect,
            nonComparable);

        int Count(string category) => values.Count(item =>
            item.CorrectnessCategory == category);
    }

    private static SarifRegressComparisonMetrics Project(HoldoutMetrics value) => new(
        value.GroundTruthUnits,
        value.LabelledRelationships,
        value.LabelledMatches,
        value.TruePositives,
        value.FalsePositives,
        value.FalseNegatives,
        value.ClassificationMismatches,
        value.CorrectAmbiguityRefusals,
        value.IncorrectlyAutoMatchedAmbiguousCases,
        value.IngestionFailures,
        value.IngestionFailures,
        value.StructuralFailures,
        value.Precision,
        value.Recall,
        value.F1)
    {
        ExpectedNewClassifications = value.ExpectedNewClassifications,
        CorrectNewClassifications = value.CorrectNewClassifications,
        IncorrectNewClassifications = value.IncorrectNewClassifications,
        NewClassificationAccuracy = value.NewClassificationAccuracy,
        ExpectedResolvedClassifications = value.ExpectedResolvedClassifications,
        CorrectResolvedClassifications = value.CorrectResolvedClassifications,
        IncorrectResolvedClassifications = value.IncorrectResolvedClassifications,
        ResolvedClassificationAccuracy = value.ResolvedClassificationAccuracy,
    };

    private static MultitoolComparisonMetrics Project(MultitoolMetrics value) => new(
        value.GroundTruthUnits,
        value.LabelledRelationships,
        value.ComparableRelationships,
        value.NonComparableRelationships,
        value.TruePositives,
        value.FalsePositives,
        value.FalseNegatives,
        value.Precision,
        value.Recall,
        value.F1);

    private static bool IsSarifRegressCorrect(
        string outcome,
        bool requireClassification) => outcome switch
        {
            "true-positive" or "correct-new" or "correct-resolved"
                or "correct-ambiguity-refusal" => true,
            "classification-mismatch" => !requireClassification,
            _ => false,
        };

    private static bool CompleteLabelGraphSatisfied(
        SarifRegressHoldoutReport report,
        SarifRegressComparisonMetrics metrics) =>
        report.Aggregate.ClassificationMismatches == 0
        && metrics.IncorrectNewClassifications == 0
        && metrics.IncorrectResolvedClassifications == 0
        && report.Aggregate.UnexpectedAmbiguityRefusals == 0
        && report.Aggregate.IncorrectlyAutoMatchedAmbiguousCases == 0
        && report.Aggregate.IngestionFailures == 0
        && report.Aggregate.StructuralFailures == 0
        && report.Cases.SelectMany(item => item.RelationshipResults)
            .All(item => IsSarifRegressCorrect(
                item.Outcome,
                requireClassification: true));

    private static ImmutableArray<string> RecommendationReasons(
        ReleaseConditions conditions)
    {
        var reasons = ImmutableArray.CreateBuilder<string>();
        Add(!conditions.PrecisionMet, "precision-below-threshold");
        Add(!conditions.RecallMet, "recall-below-threshold");
        Add(!conditions.AllProducerPrecisionMet,
            "per-producer-precision-below-threshold");
        Add(!conditions.AllProducerRecallMet,
            "per-producer-recall-below-threshold");
        Add(!conditions.ZeroIncorrectAmbiguityMatches,
            "incorrectly-auto-matched-ambiguity");
        Add(!conditions.NoUnexplainedIngestionFailures,
            "unexplained-ingestion-failure");
        Add(!conditions.NoStructuralFailures, "structural-failure");
        Add(!conditions.CompleteLabelGraphSatisfied,
            "complete-label-graph-failed");
        Add(!conditions.CrossPlatformByteIdentity,
            "cross-platform-determinism-failed");
        Add(!conditions.EveryChangedDecisionExplained,
            "changed-decision-explanation-missing");
        Add(!conditions.EvaluationCompleted, "evaluation-incomplete");
        return reasons.ToImmutable();

        void Add(bool condition, string value)
        {
            if (condition)
            {
                reasons.Add(value);
            }
        }
    }

    private static ImmutableArray<SemanticDifference> CreateSemanticDifferences(
        ImmutableArray<NonComparableRelationship> relationships,
        IEnumerable<MultitoolRelationshipResult> multitoolRelationships)
    {
        MultitoolRelationshipResult[] multitoolValues = multitoolRelationships
            .ToArray();
        var differences = ImmutableArray.CreateBuilder<SemanticDifference>();
        Add(
            "taxonomy-granularity",
            relationships.Where(item => item.Reason is
                    "multitool-taxonomy-not-equivalent"
                    or "path-rebase-configuration-not-supported")
                .Select(item => item.RelationshipId)
                .Concat(multitoolValues
                    .Where(item => item.GroundTruth.Kind == "match"
                        && (item.MultitoolState == "updated"
                            || item.GroundTruth.ExpectedClassification
                                is "moved" or "modified"))
                    .Select(item => item.RelationshipId)),
            "The comparison uses common identity and lifecycle semantics; Multitool updated does not distinguish moved from modified, and project path-rebase configuration has no equivalent external state.");
        Add(
            "ambiguity-semantics",
            relationships.Where(item =>
                    item.Reason == "multitool-does-not-express-ambiguity")
                .Select(item => item.RelationshipId),
            "Multitool run-to-run states do not express SarifRegress ambiguity refusal semantics.");
        Add(
            "identity-semantics",
            relationships.Where(item =>
                    item.Reason == "missing-correspondence-data")
                .Select(item => item.RelationshipId),
            "The external output did not expose enough correspondence data to establish exact labelled identity.");
        Add(
            "run-to-run-scope",
            relationships.Where(item =>
                    item.Reason == "run-to-run-not-applicable")
                .Select(item => item.RelationshipId),
            "The labelled relationship is outside Multitool run-to-run matching scope.");
        Add(
            "unsupported-input",
            relationships.Where(item =>
                    item.Reason == "unsupported-sarif-shape")
                .Select(item => item.RelationshipId),
            "The external baseline could not classify the committed SARIF shape.");
        Add(
            "tool-error",
            relationships.Where(item => item.Reason == "tool-error")
                .Select(item => item.RelationshipId),
            "The external baseline did not complete a trustworthy classification for this unit.");
        return differences.ToImmutable();

        void Add(
            string code,
            IEnumerable<string> affected,
            string explanation)
        {
            ImmutableArray<string> identifiers = affected
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToImmutableArray();
            if (!identifiers.IsEmpty)
            {
                differences.Add(new SemanticDifference(
                    code,
                    identifiers,
                    explanation));
            }
        }
    }
}
