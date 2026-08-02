using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SarifRegress.Validation;

/// <summary>Captures the checksum-anchored matcher-v3 history used by the v3.1 delta.</summary>
public sealed record MatcherV3HistorySnapshot(
    SarifRegressHoldoutReport Report,
    string HistoryChecksumManifestSha256,
    string ReportSha256);

/// <summary>Binds the matcher-v3 to matcher-v3.1 delta to its exact input bytes.</summary>
public sealed record MatcherV3ToV31InputHashes(
    string MatcherV3HistoryChecksumManifestSha256,
    string MatcherV3ReportSha256,
    string MatcherV31ReportSha256,
    string HoldoutManifestSha256);

/// <summary>Reports one algorithm version before and after the v3.1 revision.</summary>
public sealed record MatcherV3ToV31AlgorithmVersionChange(
    string Name,
    string? MatcherV3Version,
    string? MatcherV31Version,
    bool Changed);

/// <summary>Projects the correspondence identity counts independently of classification.</summary>
public sealed record MatcherCorrespondenceIdentity(
    int TruePositives,
    int FalsePositives,
    int FalseNegatives);

/// <summary>Reports whether correspondence identity changed across the revision.</summary>
public sealed record MatcherCorrespondenceIdentityDelta(
    MatcherCorrespondenceIdentity MatcherV3,
    MatcherCorrespondenceIdentity MatcherV31,
    bool Unchanged);

/// <summary>References one relationship transition without producer-controlled payload.</summary>
public sealed record MatcherV3ToV31RelationshipReference(
    string CaseId,
    string ProducerId,
    string RelationshipId,
    string MatcherV3Outcome,
    string MatcherV31Outcome,
    string MatcherV3State,
    string MatcherV31State);

/// <summary>Separates fixed, regressed, and persistently failing cases.</summary>
public sealed record MatcherV3ToV31CaseDelta(
    ImmutableArray<MatcherDeltaCaseReference> Fixed,
    ImmutableArray<MatcherDeltaCaseReference> Regressed,
    ImmutableArray<MatcherDeltaCaseReference> StillFailing);

/// <summary>Separates fixed, regressed, and persistently failing relationships.</summary>
public sealed record MatcherV3ToV31RelationshipDelta(
    ImmutableArray<MatcherV3ToV31RelationshipReference> Fixed,
    ImmutableArray<MatcherV3ToV31RelationshipReference> Regressed,
    ImmutableArray<MatcherV3ToV31RelationshipReference> StillFailing);

/// <summary>Reports classification mismatch repairs and introductions explicitly.</summary>
public sealed record MatcherV3ToV31ClassificationMismatchDelta(
    int MatcherV3Count,
    int MatcherV31Count,
    ImmutableArray<MatcherV3ToV31RelationshipReference> Fixed,
    ImmutableArray<MatcherV3ToV31RelationshipReference> Introduced);

/// <summary>Reports ambiguity behavior across the v3.1 revision.</summary>
public sealed record MatcherV3ToV31AmbiguityDelta(
    int MatcherV3CorrectRefusals,
    int MatcherV31CorrectRefusals,
    int MatcherV3UnexpectedRefusals,
    int MatcherV31UnexpectedRefusals,
    int MatcherV3IncorrectAutoMatches,
    int MatcherV31IncorrectAutoMatches,
    ImmutableArray<MatcherV3ToV31RelationshipReference> Fixed,
    ImmutableArray<MatcherV3ToV31RelationshipReference> Regressed,
    ImmutableArray<MatcherV3ToV31RelationshipReference> StillFailing,
    ImmutableArray<MatcherV3ToV31RelationshipReference> UnexpectedRefusalsResolved,
    ImmutableArray<MatcherV3ToV31RelationshipReference> UnexpectedRefusalsIntroduced);

/// <summary>Reports case-level ingestion transitions across the v3.1 revision.</summary>
public sealed record MatcherV3ToV31IngestionDelta(
    int MatcherV3Failures,
    int MatcherV31Failures,
    ImmutableArray<MatcherDeltaCaseReference> NewlySuccessful,
    ImmutableArray<MatcherDeltaCaseReference> NewlyFailed,
    ImmutableArray<MatcherDeltaCaseReference> StillFailing);

/// <summary>Defines the deterministic matcher-v3 to matcher-v3.1 holdout delta.</summary>
public sealed record MatcherV3ToV31DeltaReport(
    MatcherV3ToV31InputHashes InputHashes,
    MatcherMetricsSnapshot MatcherV3,
    MatcherMetricsSnapshot MatcherV31,
    ImmutableArray<MatcherV3ToV31AlgorithmVersionChange> AlgorithmVersionChanges,
    MatcherCorrespondenceIdentityDelta CorrespondenceIdentity,
    MatcherV3ToV31ClassificationMismatchDelta ClassificationMismatchChanges,
    MatcherV3ToV31CaseDelta Cases,
    MatcherV3ToV31RelationshipDelta Relationships,
    ImmutableArray<MatcherV3ToV31RelationshipReference> NewlyIntroducedFalseMatches,
    MatcherV3ToV31AmbiguityDelta AmbiguityChanges,
    MatcherV3ToV31IngestionDelta IngestionSuccessChanges,
    ImmutableArray<MatcherV3ToV31RelationshipReference> RemainingFailures,
    int ChangedDecisionCount,
    int ChangedDecisionTraceCount,
    int ChangedDecisionWithoutTraceCount,
    ImmutableArray<MatcherV3ToV31RelationshipReference> ChangedDecisionsWithoutTrace,
    bool EveryChangedDecisionHasTrace);

/// <summary>
/// Reads matcher-v3 history only after verifying its immutable checksum anchor and graph.
/// </summary>
public sealed class MatcherV3HistoryReader
{
    public const string MatcherV3AlgorithmVersion = "sarifregress/matcher/v3";
    public const string MatcherV31AlgorithmVersion = "sarifregress/matcher/v3.1";
    public const string MatcherV3HistoryChecksumManifestSha256 =
        "39f880e379dc08dc94945bf31eda2c72b13a0f281f54e3e0528b7d04ba677a0c";
    public const string MatcherV3ReportSha256 =
        "c9411e318678412ae757739749a58a999aa0fc6640b6a76460b4b59ad083dd99";

    private const string HistoryRoot = "validation/history/matcher-v3";
    private const string HistoryManifest = HistoryRoot + "/checksums.sha256";
    private const string HistoryReport = HistoryRoot + "/sarif-regress-holdout.json";
    private const string CurrentManifest = "validation/holdout/manifest.json";
    private const string ExpectedHoldoutManifestSha256 =
        "b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379";

    private static readonly ImmutableArray<string> HistoryFiles =
    [
        HistoryRoot + "/comparison-summary.json",
        HistoryRoot + "/cross-platform-attestation.json",
        HistoryRoot + "/evaluation-metadata.json",
        HistoryRoot + "/metadata.json",
        HistoryRoot + "/original-checksums.sha256",
        HistoryRoot + "/sarif-multitool-baseline.json",
        HistoryReport,
        HistoryRoot + "/schemas/comparison-summary.schema.json",
        HistoryRoot + "/schemas/cross-platform-attestation.schema.json",
        HistoryRoot + "/schemas/evaluation-metadata.schema.json",
        HistoryRoot + "/schemas/history-metadata.schema.json",
        HistoryRoot + "/schemas/sarif-multitool-baseline-report.schema.json",
        HistoryRoot + "/schemas/sarif-regress-holdout-report.schema.json",
        HistoryRoot + "/schemas/v2-to-v3-delta.schema.json",
        "validation/history/v2-to-v3-delta.json",
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly ValidationLimits limits;

    /// <summary>Creates a reader with bounded, repository-contained inputs.</summary>
    public MatcherV3HistoryReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>Reads and verifies the frozen matcher-v3 report and current label manifest.</summary>
    public MatcherV3HistorySnapshot Read(string repositoryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        string root = Path.GetFullPath(repositoryRoot);
        byte[] checksumBytes = Read(HistoryManifest, limits.MaximumManifestBytes);
        string checksumHash = Hash(checksumBytes);
        if (!string.Equals(
                checksumHash,
                MatcherV3HistoryChecksumManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3 checksum manifest differs from its immutable anchor.");
        }

        ChecksumManifest.VerifyFiles(root, checksumBytes, HistoryFiles);
        ImmutableSortedDictionary<string, string> checksums =
            ChecksumManifest.Parse(checksumBytes);
        if (!string.Equals(
                checksums[HistoryReport],
                MatcherV3ReportSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3 history manifest identifies an unexpected report.");
        }

        byte[] reportBytes = Read(HistoryReport, limits.MaximumSarifBytes);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            reportBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        HistoricalReportDocument document = Deserialize<HistoricalReportDocument>(
            reportBytes,
            "matcher-v3 report");
        RequireEqual("report schema version", "2", document.SchemaVersion);
        RequireEqual(
            "report kind",
            "sarif-regress-independent-holdout",
            document.ReportKind);
        var report = new SarifRegressHoldoutReport(
            document.Evaluation,
            document.Aggregate,
            document.Producers.ToImmutableArray(),
            document.Cases.ToImmutableArray(),
            document.DiagnosticCounts.ToImmutableArray());
        MatcherV2ToV3DeltaBuilder.ValidateReport(
            report,
            limits,
            requireTraceFree: false);
        RequireEqual(
            "matcher algorithm version",
            MatcherV3AlgorithmVersion,
            report.Evaluation.MatcherAlgorithmVersion);
        RequireEqual(
            "report holdout manifest hash",
            ExpectedHoldoutManifestSha256,
            report.Evaluation.HoldoutManifestSha256);
        if (!reportBytes.AsSpan().SequenceEqual(StableReportSerializer.Serialize(report)))
        {
            throw new InvalidDataException(
                "The matcher-v3 report is not the canonical stable projection.");
        }

        byte[] currentManifestBytes = Read(
            CurrentManifest,
            limits.MaximumManifestBytes);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            currentManifestBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        RequireEqual(
            "current holdout manifest hash",
            ExpectedHoldoutManifestSha256,
            Hash(currentManifestBytes));

        return new MatcherV3HistorySnapshot(
            report,
            checksumHash,
            Hash(reportBytes));

        byte[] Read(string relativePath, long maximumBytes) =>
            BoundedJsonFile.ReadBytes(
                StablePath.Resolve(root, relativePath),
                maximumBytes,
                root);
    }

    private static T Deserialize<T>(byte[] bytes, string logicalName)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, SerializerOptions)
                ?? throw new InvalidDataException($"The {logicalName} is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"The {logicalName} does not match its closed contract.",
                exception);
        }
    }

    private static void RequireEqual(string name, string expected, string observed)
    {
        if (!string.Equals(expected, observed, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The matcher-v3 {name} '{observed}' does not equal '{expected}'.");
        }
    }

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class HistoricalReportDocument
    {
        public required string SchemaVersion { get; init; }
        public required string ReportKind { get; init; }
        public required EvaluationIdentity Evaluation { get; init; }
        public required HoldoutMetrics Aggregate { get; init; }
        public required ProducerHoldoutMetrics[] Producers { get; init; }
        public required SarifRegressCaseResult[] Cases { get; init; }
        public required DiagnosticCount[] DiagnosticCounts { get; init; }
    }
}

/// <summary>Builds an ordinal, payload-free delta over one unchanged holdout graph.</summary>
public static class MatcherV3ToV31DeltaBuilder
{
    private const int MaximumAlgorithmVersions = 32;
    private const string ClassificationMessageLocationTemplateKind =
        "classification-message-location-template";
    private const string ClassificationMessageLocationTemplateVersion =
        "sarifregress/message-location-template/v1";

    /// <summary>Compares checksum-anchored matcher-v3 history with matcher-v3.1.</summary>
    public static MatcherV3ToV31DeltaReport Create(
        MatcherV3HistorySnapshot matcherV3,
        SarifRegressHoldoutReport matcherV31,
        MatcherV3ToV31InputHashes inputHashes,
        ValidationLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(matcherV3);
        ArgumentNullException.ThrowIfNull(matcherV31);
        ArgumentNullException.ThrowIfNull(inputHashes);
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        effectiveLimits.Validate();
        if (!string.Equals(
                matcherV3.HistoryChecksumManifestSha256,
                MatcherV3HistoryReader.MatcherV3HistoryChecksumManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                matcherV3.ReportSha256,
                MatcherV3HistoryReader.MatcherV3ReportSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3 snapshot does not identify the immutable history anchor.");
        }

        MatcherV2ToV3DeltaBuilder.ValidateReport(
            matcherV3.Report,
            effectiveLimits,
            requireTraceFree: false);
        MatcherV2ToV3DeltaBuilder.ValidateReport(
            matcherV31,
            effectiveLimits,
            requireTraceFree: false);
        if (!string.Equals(
                Hash(StableReportSerializer.Serialize(matcherV3.Report)),
                matcherV3.ReportSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3 report payload differs from its immutable anchor.");
        }

        ValidateOutcomeConsistency(matcherV3.Report, "matcher-v3");
        ValidateOutcomeConsistency(matcherV31, "matcher-v3.1");
        ValidateInputHashes(matcherV3, matcherV31, inputHashes);
        RequireVersion(
            matcherV3.Report.Evaluation.MatcherAlgorithmVersion,
            MatcherV3HistoryReader.MatcherV3AlgorithmVersion,
            "matcher-v3");
        RequireVersion(
            matcherV31.Evaluation.MatcherAlgorithmVersion,
            MatcherV3HistoryReader.MatcherV31AlgorithmVersion,
            "matcher-v3.1");
        if (!string.Equals(
                matcherV3.Report.Evaluation.HoldoutManifestSha256,
                matcherV31.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Matcher-v3 and matcher-v3.1 do not identify the same holdout manifest.");
        }

        ImmutableArray<CasePair> cases = PairExactGraph(matcherV3.Report, matcherV31);
        ImmutableArray<RelationshipPair> relationships = cases
            .SelectMany(item => item.Relationships)
            .OrderBy(item => item.CaseId, StringComparer.Ordinal)
            .ThenBy(item => item.MatcherV3.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
        RequireClassificationMismatchCount(
            "matcher-v3",
            matcherV3.Report.Aggregate.ClassificationMismatches,
            relationships.Count(item =>
                item.MatcherV3.Outcome == "classification-mismatch"));
        RequireClassificationMismatchCount(
            "matcher-v3.1",
            matcherV31.Aggregate.ClassificationMismatches,
            relationships.Count(item =>
                item.MatcherV31.Outcome == "classification-mismatch"));
        ImmutableArray<RelationshipPair> changed = relationships
            .Where(DecisionChanged)
            .ToImmutableArray();
        ImmutableArray<RelationshipPair> withoutTrace = changed
            .Where(item => !HasRequiredDecisionExplanation(item))
            .ToImmutableArray();
        int traceCount = checked(changed.Length - withoutTrace.Length);

        MatcherCorrespondenceIdentity oldIdentity = Identity(matcherV3.Report);
        MatcherCorrespondenceIdentity newIdentity = Identity(matcherV31);
        return new MatcherV3ToV31DeltaReport(
            inputHashes,
            Snapshot(matcherV3.Report),
            Snapshot(matcherV31),
            AlgorithmChanges(matcherV3.Report, matcherV31),
            new MatcherCorrespondenceIdentityDelta(
                oldIdentity,
                newIdentity,
                oldIdentity == newIdentity),
            new MatcherV3ToV31ClassificationMismatchDelta(
                matcherV3.Report.Aggregate.ClassificationMismatches,
                matcherV31.Aggregate.ClassificationMismatches,
                SelectRelationships(relationships, item =>
                    item.MatcherV3.Outcome == "classification-mismatch"
                    && IsCorrect(item.MatcherV31.Outcome)),
                SelectRelationships(relationships, item =>
                    item.MatcherV3.Outcome != "classification-mismatch"
                    && item.MatcherV31.Outcome == "classification-mismatch")),
            new MatcherV3ToV31CaseDelta(
                SelectCases(cases, item => !CaseCorrect(item.MatcherV3)
                    && CaseCorrect(item.MatcherV31)),
                SelectCases(cases, item => CaseCorrect(item.MatcherV3)
                    && !CaseCorrect(item.MatcherV31)),
                SelectCases(cases, item => !CaseCorrect(item.MatcherV3)
                    && !CaseCorrect(item.MatcherV31))),
            new MatcherV3ToV31RelationshipDelta(
                SelectRelationships(relationships, item =>
                    !IsCorrect(item.MatcherV3.Outcome)
                    && IsCorrect(item.MatcherV31.Outcome)),
                SelectRelationships(relationships, item =>
                    IsCorrect(item.MatcherV3.Outcome)
                    && !IsCorrect(item.MatcherV31.Outcome)),
                SelectRelationships(relationships, item =>
                    !IsCorrect(item.MatcherV3.Outcome)
                    && !IsCorrect(item.MatcherV31.Outcome))),
            SelectRelationships(relationships, item =>
                IsFalseMatch(item.MatcherV31.Outcome)
                && !IsFalseMatch(item.MatcherV3.Outcome)),
            AmbiguityChanges(relationships, matcherV3.Report, matcherV31),
            IngestionChanges(cases, matcherV3.Report, matcherV31),
            SelectRelationships(relationships, item =>
                !IsCorrect(item.MatcherV31.Outcome)),
            changed.Length,
            traceCount,
            withoutTrace.Length,
            SelectRelationships(withoutTrace, _ => true),
            withoutTrace.IsEmpty);
    }

    internal static void ValidateOutcomeConsistency(
        SarifRegressHoldoutReport report,
        string logicalName)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalName);
        foreach (SarifRegressCaseResult caseResult in report.Cases)
        {
            ValidateCaseOutcomeConsistency(caseResult, logicalName);
        }
    }

    private static void ValidateCaseOutcomeConsistency(
        SarifRegressCaseResult caseResult,
        string logicalName)
    {
        foreach (RelationshipResult relationship in caseResult.RelationshipResults)
        {
            ValidateGroundTruthShape(relationship);
        }

        AcceptedPair[] expectedPairs = caseResult.RelationshipResults
            .Where(item => item.GroundTruth.Kind == "match")
            .Select(item => new AcceptedPair(
                item.GroundTruth.BaselineKey!,
                item.GroundTruth.CandidateKey!))
            .ToArray();
        HashSet<AcceptedPair> expectedPairSet = expectedPairs.ToHashSet();
        if (expectedPairSet.Count != expectedPairs.Length)
        {
            throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                "contains duplicate labelled match pairs");
        }

        foreach (RelationshipResult relationship in caseResult.RelationshipResults)
        {
            ValidateRelationshipOutcome(
                caseResult,
                relationship,
                expectedPairSet,
                logicalName);
        }

        ValidateOutcomeDetails(caseResult, logicalName);

        HashSet<AcceptedPair> acceptedPairs = caseResult.RelationshipResults
            .Where(item => item.Outcome is
                "true-positive" or "classification-mismatch" or "false-match"
                    or "incorrect-ambiguity-match")
            .Select(item => new AcceptedPair(
                item.Actual.BaselineKey!,
                item.Actual.CandidateKey!))
            .ToHashSet();
        int truePositives = acceptedPairs.Count(expectedPairSet.Contains);
        int falsePositives = checked(acceptedPairs.Count - truePositives);
        int falseNegatives = checked(expectedPairSet.Count - truePositives);
        int expectedNew = CountGroundTruth(caseResult, "new");
        int correctNew = CountOutcome(caseResult, "correct-new");
        int expectedResolved = CountGroundTruth(caseResult, "resolved");
        int correctResolved = CountOutcome(caseResult, "correct-resolved");
        HoldoutMetrics metrics = caseResult.Metrics;
        RequireCount(
            metrics.GroundTruthUnits,
            caseResult.RelationshipResults.Length,
            "ground-truth units");
        RequireCount(
            metrics.LabelledRelationships,
            expectedPairSet.Count,
            "labelled relationships");
        RequireCount(metrics.LabelledMatches, acceptedPairs.Count, "labelled matches");
        RequireCount(metrics.TruePositives, truePositives, "true positives");
        RequireCount(metrics.FalsePositives, falsePositives, "false positives");
        RequireCount(metrics.FalseNegatives, falseNegatives, "false negatives");
        RequireCount(
            metrics.ClassificationMismatches,
            CountOutcome(caseResult, "classification-mismatch"),
            "classification mismatches");
        RequireCount(
            metrics.ExpectedNewClassifications,
            expectedNew,
            "expected new classifications");
        RequireCount(
            metrics.CorrectNewClassifications,
            correctNew,
            "correct new classifications");
        RequireCount(
            metrics.IncorrectNewClassifications,
            checked(expectedNew - correctNew),
            "incorrect new classifications");
        RequireCount(
            metrics.ExpectedResolvedClassifications,
            expectedResolved,
            "expected resolved classifications");
        RequireCount(
            metrics.CorrectResolvedClassifications,
            correctResolved,
            "correct resolved classifications");
        RequireCount(
            metrics.IncorrectResolvedClassifications,
            checked(expectedResolved - correctResolved),
            "incorrect resolved classifications");
        RequireCount(
            metrics.CorrectAmbiguityRefusals,
            CountOutcome(caseResult, "correct-ambiguity-refusal"),
            "correct ambiguity refusals");
        RequireCount(
            metrics.UnexpectedAmbiguityRefusals,
            CountOutcome(caseResult, "unexpected-ambiguity-refusal"),
            "unexpected ambiguity refusals");
        RequireCount(
            metrics.IncorrectlyAutoMatchedAmbiguousCases,
            CountOutcome(caseResult, "incorrect-ambiguity-match"),
            "incorrect ambiguity matches");
        RequireCount(
            metrics.IngestionFailures,
            caseResult.Outcomes.IngestionFailures.Length,
            "ingestion failures");
        RequireCount(
            metrics.StructuralFailures,
            caseResult.Outcomes.StructuralFailures.Length,
            "structural failures");
        RequireRatio(metrics.Precision, Divide(truePositives, acceptedPairs.Count),
            "precision");
        RequireRatio(
            metrics.Recall,
            Divide(truePositives, checked(truePositives + falseNegatives)),
            "recall");
        decimal precision = Divide(truePositives, acceptedPairs.Count);
        decimal recall = Divide(
            truePositives,
            checked(truePositives + falseNegatives));
        RequireRatio(
            metrics.F1,
            precision + recall == 0
                ? 0
                : decimal.Round(
                    2 * precision * recall / (precision + recall),
                    6,
                    MidpointRounding.ToEven),
            "F1");
        RequireRatio(
            metrics.NewClassificationAccuracy,
            Divide(correctNew, expectedNew),
            "new classification accuracy");
        RequireRatio(
            metrics.ResolvedClassificationAccuracy,
            Divide(correctResolved, expectedResolved),
            "resolved classification accuracy");
        if (metrics.NewClassifications < 0
            || metrics.ResolvedClassifications < 0
            || metrics.AmbiguousClassifications < 0)
        {
            throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                "contains a negative producer-observation count");
        }

        void RequireCount(int observed, int expected, string metric)
        {
            if (observed != expected)
            {
                throw Inconsistent(
                    logicalName,
                    caseResult.CaseId,
                    $"reports {metric}={observed}, expected {expected}");
            }
        }

        void RequireRatio(decimal observed, decimal expected, string metric)
        {
            if (observed != expected)
            {
                throw Inconsistent(
                    logicalName,
                    caseResult.CaseId,
                    $"reports {metric}={observed}, expected {expected}");
            }
        }
    }

    private static void ValidateGroundTruthShape(RelationshipResult relationship)
    {
        GroundTruthRelationship groundTruth = relationship.GroundTruth;
        bool valid = groundTruth.Kind switch
        {
            "match" => groundTruth.BaselineKey is not null
                && groundTruth.CandidateKey is not null
                && IsAcceptedState(groundTruth.ExpectedClassification),
            "new" => groundTruth.BaselineKey is null
                && groundTruth.CandidateKey is not null
                && groundTruth.ExpectedClassification == "new",
            "resolved" => groundTruth.BaselineKey is not null
                && groundTruth.CandidateKey is null
                && groundTruth.ExpectedClassification == "resolved",
            "ambiguous" => groundTruth.BaselineKey is not null
                && groundTruth.CandidateKey is not null
                && groundTruth.ExpectedClassification == "ambiguous",
            _ => false,
        };
        if (!valid)
        {
            throw new InvalidDataException(
                $"Relationship '{relationship.RelationshipId}' has invalid ground truth.");
        }
    }

    private static void ValidateRelationshipOutcome(
        SarifRegressCaseResult caseResult,
        RelationshipResult relationship,
        IReadOnlySet<AcceptedPair> expectedPairs,
        string logicalName)
    {
        GroundTruthRelationship groundTruth = relationship.GroundTruth;
        ActualRelationship actual = relationship.Actual;
        bool exactPair = IsExactPair(groundTruth, actual);
        bool acceptedPair = IsAcceptedState(actual.State)
            && actual.BaselineKey is not null
            && actual.CandidateKey is not null;
        bool touchesGroundTruth = TouchesGroundTruth(groundTruth, actual);
        bool valid = relationship.Outcome switch
        {
            "true-positive" => groundTruth.Kind == "match"
                && exactPair
                && actual.State == groundTruth.ExpectedClassification,
            "classification-mismatch" => groundTruth.Kind == "match"
                && exactPair
                && IsAcceptedState(actual.State)
                && actual.State != groundTruth.ExpectedClassification,
            "false-match" => groundTruth.Kind is "match" or "new" or "resolved"
                && acceptedPair
                && touchesGroundTruth
                && !expectedPairs.Contains(new AcceptedPair(
                    actual.BaselineKey!,
                    actual.CandidateKey!)),
            "missed-match" => groundTruth.Kind is "match" or "ambiguous"
                && IsNotReported(actual),
            "unexpected-ambiguity-refusal" => groundTruth.Kind == "match"
                && actual.State == "ambiguous"
                && touchesGroundTruth,
            "correct-new" => groundTruth.Kind == "new"
                && actual.State == "new"
                && actual.BaselineKey is null
                && actual.CandidateKey == groundTruth.CandidateKey,
            "incorrect-new" => groundTruth.Kind == "new"
                && !acceptedPair
                && !IsCorrectLifecycle(actual, groundTruth, candidateSide: true)
                && (IsNotReported(actual)
                    || actual.CandidateKey == groundTruth.CandidateKey),
            "correct-resolved" => groundTruth.Kind == "resolved"
                && actual.State == "resolved"
                && actual.BaselineKey == groundTruth.BaselineKey
                && actual.CandidateKey is null,
            "incorrect-resolved" => groundTruth.Kind == "resolved"
                && !acceptedPair
                && !IsCorrectLifecycle(actual, groundTruth, candidateSide: false)
                && (IsNotReported(actual)
                    || actual.BaselineKey == groundTruth.BaselineKey),
            "correct-ambiguity-refusal" => groundTruth.Kind == "ambiguous"
                && exactPair
                && actual.State == "ambiguous",
            "incorrect-ambiguity-match" => groundTruth.Kind == "ambiguous"
                && acceptedPair
                && touchesGroundTruth,
            "ingestion-failure" => caseResult.Status == "ingestion-failure"
                && actual.State == "ingestion-failure"
                && actual.BaselineKey is null
                && actual.CandidateKey is null,
            "structural-failure" => caseResult.Status == "structural-failure"
                && actual.State == "structural-failure"
                && actual.BaselineKey is null
                && actual.CandidateKey is null,
            _ => false,
        };
        if (!valid)
        {
            throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                $"relationship '{relationship.RelationshipId}' has contradictory "
                    + "ground truth, outcome, state, or keys");
        }
    }

    private static void ValidateOutcomeDetails(
        SarifRegressCaseResult caseResult,
        string logicalName)
    {
        OutcomeDetails outcomes = caseResult.Outcomes
            ?? throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                "has no outcome details");
        if (outcomes.FalseMatches.IsDefault
            || outcomes.MissedMatches.IsDefault
            || outcomes.ClassificationMismatches.IsDefault
            || outcomes.AmbiguityRefusals.IsDefault
            || outcomes.IncorrectAmbiguityMatches.IsDefault
            || outcomes.IngestionFailures.IsDefault
            || outcomes.StructuralFailures.IsDefault)
        {
            throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                "contains a default outcome-detail array");
        }

        RequireReferences(outcomes.FalseMatches, "false-match", "false matches");
        RequireReferences(outcomes.MissedMatches, "missed-match", "missed matches");
        RequireReferences(
            outcomes.ClassificationMismatches,
            "classification-mismatch",
            "classification mismatches");
        RequireReferences(
            outcomes.IncorrectAmbiguityMatches,
            "incorrect-ambiguity-match",
            "incorrect ambiguity matches");
        ImmutableArray<AmbiguityRefusal> expectedRefusals = caseResult
            .RelationshipResults
            .Where(item => item.Outcome is
                "correct-ambiguity-refusal" or "unexpected-ambiguity-refusal")
            .Select(item => new AmbiguityRefusal(
                item.RelationshipId,
                item.Outcome == "correct-ambiguity-refusal"))
            .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
        if (!outcomes.AmbiguityRefusals.SequenceEqual(expectedRefusals))
        {
            throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                "ambiguity-refusal details differ from relationship outcomes");
        }

        bool allIngestion = caseResult.RelationshipResults.All(item =>
            item.Outcome == "ingestion-failure");
        bool allStructural = caseResult.RelationshipResults.All(item =>
            item.Outcome == "structural-failure");
        bool validStatus = caseResult.Status switch
        {
            "evaluated" => outcomes.IngestionFailures.IsEmpty
                && outcomes.StructuralFailures.IsEmpty
                && !caseResult.RelationshipResults.Any(item => item.Outcome is
                    "ingestion-failure" or "structural-failure"),
            "ingestion-failure" => !outcomes.IngestionFailures.IsEmpty
                && outcomes.StructuralFailures.IsEmpty
                && allIngestion,
            "structural-failure" => outcomes.IngestionFailures.IsEmpty
                && !outcomes.StructuralFailures.IsEmpty
                && allStructural,
            _ => false,
        };
        if (!validStatus)
        {
            throw Inconsistent(
                logicalName,
                caseResult.CaseId,
                "status differs from failure details and relationship outcomes");
        }

        void RequireReferences(
            ImmutableArray<RelationshipReference> observed,
            string outcome,
            string name)
        {
            ImmutableArray<RelationshipReference> expected = caseResult
                .RelationshipResults
                .Where(item => item.Outcome == outcome)
                .Select(item => new RelationshipReference(item.RelationshipId))
                .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
                .ToImmutableArray();
            if (!observed.SequenceEqual(expected))
            {
                throw Inconsistent(
                    logicalName,
                    caseResult.CaseId,
                    $"{name} details differ from relationship outcomes");
            }
        }
    }

    private static int CountGroundTruth(
        SarifRegressCaseResult caseResult,
        string kind) => caseResult.RelationshipResults.Count(item =>
        item.GroundTruth.Kind == kind);

    private static int CountOutcome(
        SarifRegressCaseResult caseResult,
        string outcome) => caseResult.RelationshipResults.Count(item =>
        item.Outcome == outcome);

    private static bool IsExactPair(
        GroundTruthRelationship groundTruth,
        ActualRelationship actual) =>
        actual.BaselineKey == groundTruth.BaselineKey
        && actual.CandidateKey == groundTruth.CandidateKey;

    private static bool TouchesGroundTruth(
        GroundTruthRelationship groundTruth,
        ActualRelationship actual) =>
        (groundTruth.BaselineKey is not null
            && actual.BaselineKey == groundTruth.BaselineKey)
        || (groundTruth.CandidateKey is not null
            && actual.CandidateKey == groundTruth.CandidateKey);

    private static bool IsCorrectLifecycle(
        ActualRelationship actual,
        GroundTruthRelationship groundTruth,
        bool candidateSide) => candidateSide
        ? actual.State == "new"
            && actual.BaselineKey is null
            && actual.CandidateKey == groundTruth.CandidateKey
        : actual.State == "resolved"
            && actual.BaselineKey == groundTruth.BaselineKey
            && actual.CandidateKey is null;

    private static bool IsNotReported(ActualRelationship actual) =>
        actual.State == "not-reported"
        && actual.BaselineKey is null
        && actual.CandidateKey is null;

    private static bool IsAcceptedState(string state) => state is
        "unchanged" or "moved" or "modified";

    private static decimal Divide(int numerator, int denominator) => denominator == 0
        ? 1
        : decimal.Round(
            (decimal)numerator / denominator,
            6,
            MidpointRounding.ToEven);

    private static InvalidDataException Inconsistent(
        string logicalName,
        string caseId,
        string detail) => new(
        $"The {logicalName} case '{caseId}' {detail}.");

    private static void ValidateInputHashes(
        MatcherV3HistorySnapshot matcherV3,
        SarifRegressHoldoutReport matcherV31,
        MatcherV3ToV31InputHashes inputHashes)
    {
        RequireHash(
            inputHashes.MatcherV3HistoryChecksumManifestSha256,
            "matcher-v3 history checksum manifest");
        RequireHash(inputHashes.MatcherV3ReportSha256, "matcher-v3 report");
        RequireHash(inputHashes.MatcherV31ReportSha256, "matcher-v3.1 report");
        RequireHash(inputHashes.HoldoutManifestSha256, "holdout manifest");
        if (!string.Equals(
                inputHashes.MatcherV3HistoryChecksumManifestSha256,
                matcherV3.HistoryChecksumManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.MatcherV3ReportSha256,
                matcherV3.ReportSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.MatcherV31ReportSha256,
                Hash(StableReportSerializer.Serialize(matcherV31)),
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.HoldoutManifestSha256,
                matcherV3.Report.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.HoldoutManifestSha256,
                matcherV31.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The delta input hashes do not identify its exact reports and holdout.");
        }
    }

    private static void RequireHash(string value, string name)
    {
        if (value.Length != 64
            || value.Any(character =>
                (character < '0' || character > '9')
                && (character < 'a' || character > 'f')))
        {
            throw new InvalidDataException(
                $"The {name} SHA-256 is not lowercase hexadecimal.");
        }
    }

    private static ImmutableArray<CasePair> PairExactGraph(
        SarifRegressHoldoutReport matcherV3,
        SarifRegressHoldoutReport matcherV31)
    {
        Dictionary<string, SarifRegressCaseResult> oldCases = matcherV3.Cases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        Dictionary<string, SarifRegressCaseResult> newCases = matcherV31.Cases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        if (!oldCases.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                newCases.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Matcher-v3 and matcher-v3.1 do not contain the same case graph.");
        }

        var result = ImmutableArray.CreateBuilder<CasePair>(oldCases.Count);
        foreach (string caseId in oldCases.Keys.Order(StringComparer.Ordinal))
        {
            SarifRegressCaseResult oldCase = oldCases[caseId];
            SarifRegressCaseResult newCase = newCases[caseId];
            if (!string.Equals(
                    oldCase.ProducerId,
                    newCase.ProducerId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Case '{caseId}' changed producer identity.");
            }

            Dictionary<string, RelationshipResult> oldRelationships = oldCase
                .RelationshipResults.ToDictionary(
                    item => item.RelationshipId,
                    StringComparer.Ordinal);
            Dictionary<string, RelationshipResult> newRelationships = newCase
                .RelationshipResults.ToDictionary(
                    item => item.RelationshipId,
                    StringComparer.Ordinal);
            if (!oldRelationships.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                    newRelationships.Keys.Order(StringComparer.Ordinal),
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    $"Case '{caseId}' changed its relationship graph.");
            }

            ImmutableArray<RelationshipPair> relationships = oldRelationships.Keys
                .Order(StringComparer.Ordinal)
                .Select(relationshipId =>
                {
                    RelationshipResult oldValue = oldRelationships[relationshipId];
                    RelationshipResult newValue = newRelationships[relationshipId];
                    if (oldValue.GroundTruth != newValue.GroundTruth)
                    {
                        throw new InvalidDataException(
                            $"Relationship '{relationshipId}' changed ground truth.");
                    }

                    return new RelationshipPair(
                        caseId,
                        oldCase.ProducerId,
                        oldValue,
                        newValue);
                })
                .ToImmutableArray();
            result.Add(new CasePair(oldCase, newCase, relationships));
        }

        return result.ToImmutable();
    }

    private static MatcherMetricsSnapshot Snapshot(SarifRegressHoldoutReport report) =>
        new(
            report.Evaluation with
            {
                FingerprintAlgorithmVersions = report.Evaluation
                    .FingerprintAlgorithmVersions
                    .OrderBy(item => item.Name, StringComparer.Ordinal)
                    .ThenBy(item => item.Version, StringComparer.Ordinal)
                    .ToImmutableArray(),
            },
            report.Aggregate,
            report.Producers.OrderBy(item => item.ProducerId, StringComparer.Ordinal)
                .ToImmutableArray());

    private static ImmutableArray<MatcherV3ToV31AlgorithmVersionChange>
        AlgorithmChanges(
            SarifRegressHoldoutReport matcherV3,
            SarifRegressHoldoutReport matcherV31)
    {
        Dictionary<string, string> oldValues = AlgorithmMap(matcherV3);
        Dictionary<string, string> newValues = AlgorithmMap(matcherV31);
        string[] names = oldValues.Keys.Concat(newValues.Keys)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (names.Length > MaximumAlgorithmVersions)
        {
            throw new InvalidDataException(
                "The matcher revision exposes too many algorithm versions.");
        }

        return names
            .Select(name =>
            {
                oldValues.TryGetValue(name, out string? oldVersion);
                newValues.TryGetValue(name, out string? newVersion);
                return new MatcherV3ToV31AlgorithmVersionChange(
                    name,
                    oldVersion,
                    newVersion,
                    !string.Equals(oldVersion, newVersion, StringComparison.Ordinal));
            })
            .ToImmutableArray();

        static Dictionary<string, string> AlgorithmMap(
            SarifRegressHoldoutReport report)
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (NamedAlgorithmVersion item in report.Evaluation
                         .FingerprintAlgorithmVersions)
            {
                AddOrRequireEqual(values, item.Name, item.Version);
            }

            AddOrRequireEqual(
                values,
                "matcher",
                report.Evaluation.MatcherAlgorithmVersion);
            foreach (DecisionTraceProjection trace in report.Cases
                         .SelectMany(item => item.RelationshipResults)
                         .SelectMany(item => item.Actual.DecisionTraces))
            {
                foreach (DecisionEvidenceProjection item in trace.Evidence)
                {
                    AddOrRequireEqual(
                        values,
                        TraceAlgorithmName("decision-evidence", item.Kind),
                        item.AlgorithmVersion);
                }

                foreach (DecisionTransformationProjection item in
                         trace.Transformations)
                {
                    AddOrRequireEqual(
                        values,
                        TraceAlgorithmName("decision-transformation", item.Kind),
                        item.AlgorithmVersion);
                }
            }

            return values;
        }

        static void AddOrRequireEqual(
            IDictionary<string, string> values,
            string name,
            string version)
        {
            RequireAlgorithmName(name);
            RequireAlgorithmVersion(version);
            if (values.TryGetValue(name, out string? existing)
                && !string.Equals(existing, version, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Algorithm '{name}' has conflicting versions in one report.");
            }

            values[name] = version;
            if (values.Count > MaximumAlgorithmVersions)
            {
                throw new InvalidDataException(
                    "A matcher report exposes too many algorithm versions.");
            }
        }

        static string TraceAlgorithmName(string category, string kind)
        {
            RequireAlgorithmName(kind);
            string name = category + "." + kind;
            RequireAlgorithmName(name);
            return name;
        }

        static void RequireAlgorithmName(string value)
        {
            if (value.Length is < 1 or > 128
                || !IsLowerAlphaNumeric(value[0])
                || value.Any(character =>
                    !IsLowerAlphaNumeric(character)
                    && character is not '.' and not '_' and not '-'))
            {
                throw new InvalidDataException(
                    "An algorithm name is not a bounded stable identifier.");
            }
        }

        static void RequireAlgorithmVersion(string value)
        {
            if (value.Length is < 1 or > 256
                || !char.IsAsciiLetterOrDigit(value[0])
                || value.Any(character =>
                    !char.IsAsciiLetterOrDigit(character)
                    && character is not '.' and not '_' and not '+' and not '/'
                        and not '-'))
            {
                throw new InvalidDataException(
                    "An algorithm version is not a bounded stable identifier.");
            }
        }

        static bool IsLowerAlphaNumeric(char value) =>
            value is >= 'a' and <= 'z' or >= '0' and <= '9';
    }

    private static MatcherCorrespondenceIdentity Identity(
        SarifRegressHoldoutReport report) => new(
        report.Aggregate.TruePositives,
        report.Aggregate.FalsePositives,
        report.Aggregate.FalseNegatives);

    private static MatcherV3ToV31AmbiguityDelta AmbiguityChanges(
        ImmutableArray<RelationshipPair> relationships,
        SarifRegressHoldoutReport matcherV3,
        SarifRegressHoldoutReport matcherV31)
    {
        ImmutableArray<RelationshipPair> ambiguity = relationships
            .Where(item => item.MatcherV3.GroundTruth.Kind == "ambiguous")
            .ToImmutableArray();
        return new MatcherV3ToV31AmbiguityDelta(
            matcherV3.Aggregate.CorrectAmbiguityRefusals,
            matcherV31.Aggregate.CorrectAmbiguityRefusals,
            matcherV3.Aggregate.UnexpectedAmbiguityRefusals,
            matcherV31.Aggregate.UnexpectedAmbiguityRefusals,
            matcherV3.Aggregate.IncorrectlyAutoMatchedAmbiguousCases,
            matcherV31.Aggregate.IncorrectlyAutoMatchedAmbiguousCases,
            SelectRelationships(ambiguity, item =>
                !IsCorrect(item.MatcherV3.Outcome)
                && IsCorrect(item.MatcherV31.Outcome)),
            SelectRelationships(ambiguity, item =>
                IsCorrect(item.MatcherV3.Outcome)
                && !IsCorrect(item.MatcherV31.Outcome)),
            SelectRelationships(ambiguity, item =>
                !IsCorrect(item.MatcherV3.Outcome)
                && !IsCorrect(item.MatcherV31.Outcome)),
            SelectRelationships(relationships, item =>
                item.MatcherV3.Outcome == "unexpected-ambiguity-refusal"
                && item.MatcherV31.Outcome != "unexpected-ambiguity-refusal"),
            SelectRelationships(relationships, item =>
                item.MatcherV3.Outcome != "unexpected-ambiguity-refusal"
                && item.MatcherV31.Outcome == "unexpected-ambiguity-refusal"));
    }

    private static MatcherV3ToV31IngestionDelta IngestionChanges(
        ImmutableArray<CasePair> cases,
        SarifRegressHoldoutReport matcherV3,
        SarifRegressHoldoutReport matcherV31) => new(
        matcherV3.Aggregate.IngestionFailures,
        matcherV31.Aggregate.IngestionFailures,
        SelectCases(cases, item => !IngestionSucceeded(item.MatcherV3)
            && IngestionSucceeded(item.MatcherV31)),
        SelectCases(cases, item => IngestionSucceeded(item.MatcherV3)
            && !IngestionSucceeded(item.MatcherV31)),
        SelectCases(cases, item => !IngestionSucceeded(item.MatcherV3)
            && !IngestionSucceeded(item.MatcherV31)));

    private static bool IngestionSucceeded(SarifRegressCaseResult value) =>
        value.Metrics.IngestionFailures == 0
        && value.Status != "ingestion-failure";

    private static bool CaseCorrect(SarifRegressCaseResult value) =>
        value.Metrics.IngestionFailures == 0
        && value.Metrics.StructuralFailures == 0
        && value.RelationshipResults.All(item => IsCorrect(item.Outcome));

    private static bool IsCorrect(string outcome) => outcome is
        "true-positive" or "correct-new" or "correct-resolved"
            or "correct-ambiguity-refusal";

    private static bool IsFalseMatch(string outcome) => outcome is
        "false-match" or "incorrect-ambiguity-match";

    private static bool DecisionChanged(RelationshipPair item) =>
        item.MatcherV3.Outcome != item.MatcherV31.Outcome
        || item.MatcherV3.Actual.State != item.MatcherV31.Actual.State
        || item.MatcherV3.Actual.BaselineKey != item.MatcherV31.Actual.BaselineKey
        || item.MatcherV3.Actual.CandidateKey != item.MatcherV31.Actual.CandidateKey;

    private static bool HasRequiredDecisionExplanation(RelationshipPair item)
    {
        DecisionTraceProjection[] aligned = item.MatcherV31.Actual.DecisionTraces
            .Where(trace => string.Equals(
                    trace.MatcherAlgorithmVersion,
                    MatcherV3HistoryReader.MatcherV31AlgorithmVersion,
                    StringComparison.Ordinal)
                && string.Equals(
                    trace.Classification,
                    item.MatcherV31.Actual.State,
                    StringComparison.Ordinal))
            .ToArray();
        if (aligned.Length == 0)
        {
            return false;
        }

        bool classificationRepair =
            item.MatcherV3.Outcome == "classification-mismatch"
            && IsCorrect(item.MatcherV31.Outcome);
        if (classificationRepair)
        {
            return aligned.Any(trace => trace.Transformations.Any(
                transformation => transformation.Lossy
                    && string.Equals(
                        transformation.Kind,
                        ClassificationMessageLocationTemplateKind,
                        StringComparison.Ordinal)
                    && string.Equals(
                        transformation.AlgorithmVersion,
                        ClassificationMessageLocationTemplateVersion,
                        StringComparison.Ordinal)));
        }

        return true;
    }

    private static ImmutableArray<MatcherDeltaCaseReference> SelectCases(
        IEnumerable<CasePair> values,
        Func<CasePair, bool> predicate) => values
        .Where(predicate)
        .Select(item => new MatcherDeltaCaseReference(
            item.MatcherV3.CaseId,
            item.MatcherV3.ProducerId))
        .OrderBy(item => item.CaseId, StringComparer.Ordinal)
        .ThenBy(item => item.ProducerId, StringComparer.Ordinal)
        .ToImmutableArray();

    private static ImmutableArray<MatcherV3ToV31RelationshipReference>
        SelectRelationships(
            IEnumerable<RelationshipPair> values,
            Func<RelationshipPair, bool> predicate) => values
        .Where(predicate)
        .Select(item => new MatcherV3ToV31RelationshipReference(
            item.CaseId,
            item.ProducerId,
            item.MatcherV3.RelationshipId,
            item.MatcherV3.Outcome,
            item.MatcherV31.Outcome,
            item.MatcherV3.Actual.State,
            item.MatcherV31.Actual.State))
        .OrderBy(item => item.CaseId, StringComparer.Ordinal)
        .ThenBy(item => item.RelationshipId, StringComparer.Ordinal)
        .ToImmutableArray();

    private static void RequireVersion(string observed, string expected, string name)
    {
        if (!string.Equals(observed, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The {name} report identifies '{observed}', not '{expected}'.");
        }
    }

    private static void RequireClassificationMismatchCount(
        string name,
        int metricCount,
        int outcomeCount)
    {
        if (metricCount != outcomeCount)
        {
            throw new InvalidDataException(
                $"The {name} classification mismatch metric differs from its outcomes.");
        }
    }

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record CasePair(
        SarifRegressCaseResult MatcherV3,
        SarifRegressCaseResult MatcherV31,
        ImmutableArray<RelationshipPair> Relationships);

    private sealed record RelationshipPair(
        string CaseId,
        string ProducerId,
        RelationshipResult MatcherV3,
        RelationshipResult MatcherV31);

    private readonly record struct AcceptedPair(
        string BaselineKey,
        string CandidateKey);
}
