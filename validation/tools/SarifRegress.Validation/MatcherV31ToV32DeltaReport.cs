using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SarifRegress.Validation;

/// <summary>Captures the checksum-anchored matcher-v3.1 history used by the v3.2 delta.</summary>
public sealed record MatcherV31HistorySnapshot(
    SarifRegressHoldoutReport Report,
    string HistoryChecksumManifestSha256,
    string ReportSha256);

/// <summary>Binds the matcher-v3.1 to matcher-v3.2 delta to its exact input bytes.</summary>
public sealed record MatcherV31ToV32InputHashes(
    string MatcherV31HistoryChecksumManifestSha256,
    string MatcherV31ReportSha256,
    string MatcherV32ReportSha256,
    string HoldoutManifestSha256);

/// <summary>Reports one algorithm version before and after the v3.2 revision.</summary>
public sealed record MatcherV31ToV32AlgorithmVersionChange(
    string Name,
    string? MatcherV31Version,
    string? MatcherV32Version,
    bool Changed);

/// <summary>Projects the correspondence identity counts independently of classification.</summary>
public sealed record MatcherV31ToV32CorrespondenceIdentity(
    int TruePositives,
    int FalsePositives,
    int FalseNegatives);

/// <summary>Reports whether correspondence identity changed across the revision.</summary>
public sealed record MatcherV31ToV32CorrespondenceIdentityDelta(
    MatcherV31ToV32CorrespondenceIdentity MatcherV31,
    MatcherV31ToV32CorrespondenceIdentity MatcherV32,
    bool Unchanged);

/// <summary>References one relationship transition without producer-controlled payload.</summary>
public sealed record MatcherV31ToV32RelationshipReference(
    string CaseId,
    string ProducerId,
    string RelationshipId,
    string MatcherV31Outcome,
    string MatcherV32Outcome,
    string MatcherV31State,
    string MatcherV32State);

/// <summary>Separates fixed, regressed, and persistently failing cases.</summary>
public sealed record MatcherV31ToV32CaseDelta(
    ImmutableArray<MatcherDeltaCaseReference> Fixed,
    ImmutableArray<MatcherDeltaCaseReference> Regressed,
    ImmutableArray<MatcherDeltaCaseReference> StillFailing);

/// <summary>Separates fixed, regressed, and persistently failing relationships.</summary>
public sealed record MatcherV31ToV32RelationshipDelta(
    ImmutableArray<MatcherV31ToV32RelationshipReference> Fixed,
    ImmutableArray<MatcherV31ToV32RelationshipReference> Regressed,
    ImmutableArray<MatcherV31ToV32RelationshipReference> StillFailing);

/// <summary>Reports classification mismatch repairs and introductions explicitly.</summary>
public sealed record MatcherV31ToV32ClassificationMismatchDelta(
    int MatcherV31Count,
    int MatcherV32Count,
    ImmutableArray<MatcherV31ToV32RelationshipReference> Fixed,
    ImmutableArray<MatcherV31ToV32RelationshipReference> Introduced);

/// <summary>Reports ambiguity behavior across the v3.2 revision.</summary>
public sealed record MatcherV31ToV32AmbiguityDelta(
    int MatcherV31CorrectRefusals,
    int MatcherV32CorrectRefusals,
    int MatcherV31UnexpectedRefusals,
    int MatcherV32UnexpectedRefusals,
    int MatcherV31IncorrectAutoMatches,
    int MatcherV32IncorrectAutoMatches,
    ImmutableArray<MatcherV31ToV32RelationshipReference> Fixed,
    ImmutableArray<MatcherV31ToV32RelationshipReference> Regressed,
    ImmutableArray<MatcherV31ToV32RelationshipReference> StillFailing,
    ImmutableArray<MatcherV31ToV32RelationshipReference> UnexpectedRefusalsResolved,
    ImmutableArray<MatcherV31ToV32RelationshipReference> UnexpectedRefusalsIntroduced);

/// <summary>Reports case-level ingestion transitions across the v3.2 revision.</summary>
public sealed record MatcherV31ToV32IngestionDelta(
    int MatcherV31Failures,
    int MatcherV32Failures,
    ImmutableArray<MatcherDeltaCaseReference> NewlySuccessful,
    ImmutableArray<MatcherDeltaCaseReference> NewlyFailed,
    ImmutableArray<MatcherDeltaCaseReference> StillFailing);

/// <summary>Defines the deterministic matcher-v3.1 to matcher-v3.2 holdout delta.</summary>
public sealed record MatcherV31ToV32DeltaReport(
    MatcherV31ToV32InputHashes InputHashes,
    MatcherMetricsSnapshot MatcherV31,
    MatcherMetricsSnapshot MatcherV32,
    ImmutableArray<MatcherV31ToV32AlgorithmVersionChange> AlgorithmVersionChanges,
    MatcherV31ToV32CorrespondenceIdentityDelta CorrespondenceIdentity,
    MatcherV31ToV32ClassificationMismatchDelta ClassificationMismatchChanges,
    MatcherV31ToV32CaseDelta Cases,
    MatcherV31ToV32RelationshipDelta Relationships,
    ImmutableArray<MatcherV31ToV32RelationshipReference> NewlyIntroducedFalseMatches,
    MatcherV31ToV32AmbiguityDelta AmbiguityChanges,
    MatcherV31ToV32IngestionDelta IngestionSuccessChanges,
    ImmutableArray<MatcherV31ToV32RelationshipReference> RemainingFailures,
    int ChangedDecisionCount,
    int ChangedDecisionTraceCount,
    int ChangedDecisionWithoutTraceCount,
    ImmutableArray<MatcherV31ToV32RelationshipReference> ChangedDecisionsWithoutTrace,
    bool EveryChangedDecisionHasTrace);

/// <summary>
/// Reads matcher-v3.1 history only after verifying its immutable checksum anchor and graph.
/// </summary>
public sealed class MatcherV31HistoryReader
{
    public const string MatcherV31AlgorithmVersion = "sarifregress/matcher/v3.1";
    public const string MatcherV32AlgorithmVersion = "sarifregress/matcher/v3.2";
    public const string MatcherV31HistoryChecksumManifestSha256 =
        "d6b154b440541fa429b1ad1c7b4c6005e0b9e382cb8bcd5544e235617506b22b";
    public const string MatcherV31ReportSha256 =
        "c1237ba0af8684eafbed5fc295606c09a0cce012c6e7a9febfed2f6a5a080f8e";

    private const string HistoryRoot = "validation/history/matcher-v3.1";
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
        HistoryRoot + "/original-checksums.sha256",
        HistoryRoot + "/sarif-multitool-baseline.json",
        HistoryReport,
        HistoryRoot + "/schemas/comparison-summary.schema.json",
        HistoryRoot + "/schemas/cross-platform-attestation.schema.json",
        HistoryRoot + "/schemas/evaluation-metadata.schema.json",
        HistoryRoot + "/schemas/sarif-multitool-baseline-report.schema.json",
        HistoryRoot + "/schemas/sarif-regress-holdout-report.schema.json",
        HistoryRoot + "/schemas/v3-to-v3.1-delta.schema.json",
        HistoryRoot + "/v3-to-v3.1-delta.json",
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly ValidationLimits limits;

    /// <summary>Creates a reader with bounded, repository-contained inputs.</summary>
    public MatcherV31HistoryReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>Reads and verifies the frozen matcher-v3.1 report and current label manifest.</summary>
    public MatcherV31HistorySnapshot Read(string repositoryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        string root = Path.GetFullPath(repositoryRoot);
        byte[] checksumBytes = Read(HistoryManifest, limits.MaximumManifestBytes);
        string checksumHash = Hash(checksumBytes);
        if (!string.Equals(
                checksumHash,
                MatcherV31HistoryChecksumManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3.1 checksum manifest differs from its immutable anchor.");
        }

        ChecksumManifest.VerifyFiles(root, checksumBytes, HistoryFiles);
        ImmutableSortedDictionary<string, string> checksums =
            ChecksumManifest.Parse(checksumBytes);
        if (!string.Equals(
                checksums[HistoryReport],
                MatcherV31ReportSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3.1 history manifest identifies an unexpected report.");
        }

        byte[] reportBytes = Read(HistoryReport, limits.MaximumSarifBytes);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            reportBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        HistoricalReportDocument document = Deserialize<HistoricalReportDocument>(
            reportBytes,
            "matcher-v3.1 report");
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
            MatcherV31AlgorithmVersion,
            report.Evaluation.MatcherAlgorithmVersion);
        RequireEqual(
            "report holdout manifest hash",
            ExpectedHoldoutManifestSha256,
            report.Evaluation.HoldoutManifestSha256);
        if (!reportBytes.AsSpan().SequenceEqual(StableReportSerializer.Serialize(report)))
        {
            throw new InvalidDataException(
                "The matcher-v3.1 report is not the canonical stable projection.");
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

        return new MatcherV31HistorySnapshot(
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
                $"The matcher-v3.1 {name} '{observed}' does not equal '{expected}'.");
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
public static class MatcherV31ToV32DeltaBuilder
{
    private const int MaximumAlgorithmVersions = 32;
    private const string ClassificationMessageLocationTemplateKind =
        "classification-message-location-template";
    private const string ClassificationMessageLocationTemplateVersion =
        "sarifregress/message-location-template/v1";

    /// <summary>Compares checksum-anchored matcher-v3.1 history with matcher-v3.2.</summary>
    public static MatcherV31ToV32DeltaReport Create(
        MatcherV31HistorySnapshot matcherV31,
        SarifRegressHoldoutReport matcherV32,
        MatcherV31ToV32InputHashes inputHashes,
        ValidationLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(matcherV31);
        ArgumentNullException.ThrowIfNull(matcherV32);
        ArgumentNullException.ThrowIfNull(inputHashes);
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        effectiveLimits.Validate();
        if (!string.Equals(
                matcherV31.HistoryChecksumManifestSha256,
                MatcherV31HistoryReader.MatcherV31HistoryChecksumManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                matcherV31.ReportSha256,
                MatcherV31HistoryReader.MatcherV31ReportSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3.1 snapshot does not identify the immutable history anchor.");
        }

        MatcherV2ToV3DeltaBuilder.ValidateReport(
            matcherV31.Report,
            effectiveLimits,
            requireTraceFree: false);
        MatcherV2ToV3DeltaBuilder.ValidateReport(
            matcherV32,
            effectiveLimits,
            requireTraceFree: false);
        if (!string.Equals(
                Hash(StableReportSerializer.Serialize(matcherV31.Report)),
                matcherV31.ReportSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v3.1 report payload differs from its immutable anchor.");
        }

        ValidateOutcomeConsistency(matcherV31.Report, "matcher-v3.1");
        ValidateOutcomeConsistency(matcherV32, "matcher-v3.2");
        ValidateInputHashes(matcherV31, matcherV32, inputHashes);
        RequireVersion(
            matcherV31.Report.Evaluation.MatcherAlgorithmVersion,
            MatcherV31HistoryReader.MatcherV31AlgorithmVersion,
            "matcher-v3.1");
        RequireVersion(
            matcherV32.Evaluation.MatcherAlgorithmVersion,
            MatcherV31HistoryReader.MatcherV32AlgorithmVersion,
            "matcher-v3.2");
        if (!string.Equals(
                matcherV31.Report.Evaluation.HoldoutManifestSha256,
                matcherV32.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Matcher-v3.1 and matcher-v3.2 do not identify the same holdout manifest.");
        }

        ImmutableArray<CasePair> cases = PairExactGraph(matcherV31.Report, matcherV32);
        ImmutableArray<RelationshipPair> relationships = cases
            .SelectMany(item => item.Relationships)
            .OrderBy(item => item.CaseId, StringComparer.Ordinal)
            .ThenBy(item => item.MatcherV31.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
        RequireClassificationMismatchCount(
            "matcher-v3.1",
            matcherV31.Report.Aggregate.ClassificationMismatches,
            relationships.Count(item =>
                item.MatcherV31.Outcome == "classification-mismatch"));
        RequireClassificationMismatchCount(
            "matcher-v3.2",
            matcherV32.Aggregate.ClassificationMismatches,
            relationships.Count(item =>
                item.MatcherV32.Outcome == "classification-mismatch"));
        ImmutableArray<RelationshipPair> changed = relationships
            .Where(DecisionChanged)
            .ToImmutableArray();
        ImmutableArray<RelationshipPair> withoutTrace = changed
            .Where(item => !HasRequiredDecisionExplanation(item))
            .ToImmutableArray();
        int traceCount = checked(changed.Length - withoutTrace.Length);

        MatcherV31ToV32CorrespondenceIdentity oldIdentity = Identity(matcherV31.Report);
        MatcherV31ToV32CorrespondenceIdentity newIdentity = Identity(matcherV32);
        return new MatcherV31ToV32DeltaReport(
            inputHashes,
            Snapshot(matcherV31.Report),
            Snapshot(matcherV32),
            AlgorithmChanges(matcherV31.Report, matcherV32),
            new MatcherV31ToV32CorrespondenceIdentityDelta(
                oldIdentity,
                newIdentity,
                oldIdentity == newIdentity),
            new MatcherV31ToV32ClassificationMismatchDelta(
                matcherV31.Report.Aggregate.ClassificationMismatches,
                matcherV32.Aggregate.ClassificationMismatches,
                SelectRelationships(relationships, item =>
                    item.MatcherV31.Outcome == "classification-mismatch"
                    && IsCorrect(item.MatcherV32.Outcome)),
                SelectRelationships(relationships, item =>
                    item.MatcherV31.Outcome != "classification-mismatch"
                    && item.MatcherV32.Outcome == "classification-mismatch")),
            new MatcherV31ToV32CaseDelta(
                SelectCases(cases, item => !CaseCorrect(item.MatcherV31)
                    && CaseCorrect(item.MatcherV32)),
                SelectCases(cases, item => CaseCorrect(item.MatcherV31)
                    && !CaseCorrect(item.MatcherV32)),
                SelectCases(cases, item => !CaseCorrect(item.MatcherV31)
                    && !CaseCorrect(item.MatcherV32))),
            new MatcherV31ToV32RelationshipDelta(
                SelectRelationships(relationships, item =>
                    !IsCorrect(item.MatcherV31.Outcome)
                    && IsCorrect(item.MatcherV32.Outcome)),
                SelectRelationships(relationships, item =>
                    IsCorrect(item.MatcherV31.Outcome)
                    && !IsCorrect(item.MatcherV32.Outcome)),
                SelectRelationships(relationships, item =>
                    !IsCorrect(item.MatcherV31.Outcome)
                    && !IsCorrect(item.MatcherV32.Outcome))),
            SelectRelationships(relationships, item =>
                IsFalseMatch(item.MatcherV32.Outcome)
                && !IsFalseMatch(item.MatcherV31.Outcome)),
            AmbiguityChanges(relationships, matcherV31.Report, matcherV32),
            IngestionChanges(cases, matcherV31.Report, matcherV32),
            SelectRelationships(relationships, item =>
                !IsCorrect(item.MatcherV32.Outcome)),
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
        MatcherV31HistorySnapshot matcherV31,
        SarifRegressHoldoutReport matcherV32,
        MatcherV31ToV32InputHashes inputHashes)
    {
        RequireHash(
            inputHashes.MatcherV31HistoryChecksumManifestSha256,
            "matcher-v3.1 history checksum manifest");
        RequireHash(inputHashes.MatcherV31ReportSha256, "matcher-v3.1 report");
        RequireHash(inputHashes.MatcherV32ReportSha256, "matcher-v3.2 report");
        RequireHash(inputHashes.HoldoutManifestSha256, "holdout manifest");
        if (!string.Equals(
                inputHashes.MatcherV31HistoryChecksumManifestSha256,
                matcherV31.HistoryChecksumManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.MatcherV31ReportSha256,
                matcherV31.ReportSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.MatcherV32ReportSha256,
                Hash(StableReportSerializer.Serialize(matcherV32)),
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.HoldoutManifestSha256,
                matcherV31.Report.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.HoldoutManifestSha256,
                matcherV32.Evaluation.HoldoutManifestSha256,
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
        SarifRegressHoldoutReport matcherV31,
        SarifRegressHoldoutReport matcherV32)
    {
        Dictionary<string, SarifRegressCaseResult> oldCases = matcherV31.Cases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        Dictionary<string, SarifRegressCaseResult> newCases = matcherV32.Cases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        if (!oldCases.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                newCases.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Matcher-v3.1 and matcher-v3.2 do not contain the same case graph.");
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

    private static ImmutableArray<MatcherV31ToV32AlgorithmVersionChange>
        AlgorithmChanges(
            SarifRegressHoldoutReport matcherV31,
            SarifRegressHoldoutReport matcherV32)
    {
        Dictionary<string, string> oldValues = AlgorithmMap(matcherV31);
        Dictionary<string, string> newValues = AlgorithmMap(matcherV32);
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
                return new MatcherV31ToV32AlgorithmVersionChange(
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

    private static MatcherV31ToV32CorrespondenceIdentity Identity(
        SarifRegressHoldoutReport report) => new(
        report.Aggregate.TruePositives,
        report.Aggregate.FalsePositives,
        report.Aggregate.FalseNegatives);

    private static MatcherV31ToV32AmbiguityDelta AmbiguityChanges(
        ImmutableArray<RelationshipPair> relationships,
        SarifRegressHoldoutReport matcherV31,
        SarifRegressHoldoutReport matcherV32)
    {
        ImmutableArray<RelationshipPair> ambiguity = relationships
            .Where(item => item.MatcherV31.GroundTruth.Kind == "ambiguous")
            .ToImmutableArray();
        return new MatcherV31ToV32AmbiguityDelta(
            matcherV31.Aggregate.CorrectAmbiguityRefusals,
            matcherV32.Aggregate.CorrectAmbiguityRefusals,
            matcherV31.Aggregate.UnexpectedAmbiguityRefusals,
            matcherV32.Aggregate.UnexpectedAmbiguityRefusals,
            matcherV31.Aggregate.IncorrectlyAutoMatchedAmbiguousCases,
            matcherV32.Aggregate.IncorrectlyAutoMatchedAmbiguousCases,
            SelectRelationships(ambiguity, item =>
                !IsCorrect(item.MatcherV31.Outcome)
                && IsCorrect(item.MatcherV32.Outcome)),
            SelectRelationships(ambiguity, item =>
                IsCorrect(item.MatcherV31.Outcome)
                && !IsCorrect(item.MatcherV32.Outcome)),
            SelectRelationships(ambiguity, item =>
                !IsCorrect(item.MatcherV31.Outcome)
                && !IsCorrect(item.MatcherV32.Outcome)),
            SelectRelationships(relationships, item =>
                item.MatcherV31.Outcome == "unexpected-ambiguity-refusal"
                && item.MatcherV32.Outcome != "unexpected-ambiguity-refusal"),
            SelectRelationships(relationships, item =>
                item.MatcherV31.Outcome != "unexpected-ambiguity-refusal"
                && item.MatcherV32.Outcome == "unexpected-ambiguity-refusal"));
    }

    private static MatcherV31ToV32IngestionDelta IngestionChanges(
        ImmutableArray<CasePair> cases,
        SarifRegressHoldoutReport matcherV31,
        SarifRegressHoldoutReport matcherV32) => new(
        matcherV31.Aggregate.IngestionFailures,
        matcherV32.Aggregate.IngestionFailures,
        SelectCases(cases, item => !IngestionSucceeded(item.MatcherV31)
            && IngestionSucceeded(item.MatcherV32)),
        SelectCases(cases, item => IngestionSucceeded(item.MatcherV31)
            && !IngestionSucceeded(item.MatcherV32)),
        SelectCases(cases, item => !IngestionSucceeded(item.MatcherV31)
            && !IngestionSucceeded(item.MatcherV32)));

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
        item.MatcherV31.Outcome != item.MatcherV32.Outcome
        || item.MatcherV31.Actual.State != item.MatcherV32.Actual.State
        || item.MatcherV31.Actual.BaselineKey != item.MatcherV32.Actual.BaselineKey
        || item.MatcherV31.Actual.CandidateKey != item.MatcherV32.Actual.CandidateKey;

    private static bool HasRequiredDecisionExplanation(RelationshipPair item)
    {
        DecisionTraceProjection[] aligned = item.MatcherV32.Actual.DecisionTraces
            .Where(trace => string.Equals(
                    trace.MatcherAlgorithmVersion,
                    MatcherV31HistoryReader.MatcherV32AlgorithmVersion,
                    StringComparison.Ordinal)
                && string.Equals(
                    trace.Classification,
                    item.MatcherV32.Actual.State,
                    StringComparison.Ordinal))
            .ToArray();
        if (aligned.Length == 0)
        {
            return false;
        }

        bool classificationRepair =
            item.MatcherV31.Outcome == "classification-mismatch"
            && IsCorrect(item.MatcherV32.Outcome);
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
            item.MatcherV31.CaseId,
            item.MatcherV31.ProducerId))
        .OrderBy(item => item.CaseId, StringComparer.Ordinal)
        .ThenBy(item => item.ProducerId, StringComparer.Ordinal)
        .ToImmutableArray();

    private static ImmutableArray<MatcherV31ToV32RelationshipReference>
        SelectRelationships(
            IEnumerable<RelationshipPair> values,
            Func<RelationshipPair, bool> predicate) => values
        .Where(predicate)
        .Select(item => new MatcherV31ToV32RelationshipReference(
            item.CaseId,
            item.ProducerId,
            item.MatcherV31.RelationshipId,
            item.MatcherV31.Outcome,
            item.MatcherV32.Outcome,
            item.MatcherV31.Actual.State,
            item.MatcherV32.Actual.State))
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
        SarifRegressCaseResult MatcherV31,
        SarifRegressCaseResult MatcherV32,
        ImmutableArray<RelationshipPair> Relationships);

    private sealed record RelationshipPair(
        string CaseId,
        string ProducerId,
        RelationshipResult MatcherV31,
        RelationshipResult MatcherV32);

    private readonly record struct AcceptedPair(
        string BaselineKey,
        string CandidateKey);
}
