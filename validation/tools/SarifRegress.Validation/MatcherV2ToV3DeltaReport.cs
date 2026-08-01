using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SarifRegress.Validation;

/// <summary>Captures the immutable matcher-v2 evidence used by the delta builder.</summary>
public sealed record MatcherV2HistorySnapshot(
    SarifRegressHoldoutReport Report,
    string HistoryChecksumManifestSha256,
    string ReportSha256);

/// <summary>Binds the delta to the exact reports and frozen holdout inputs.</summary>
public sealed record MatcherDeltaInputHashes(
    string MatcherV2HistoryChecksumManifestSha256,
    string MatcherV2ReportSha256,
    string MatcherV3ReportSha256,
    string HoldoutManifestSha256);

/// <summary>Projects one matcher version without producer-controlled payload text.</summary>
public sealed record MatcherMetricsSnapshot(
    EvaluationIdentity Evaluation,
    HoldoutMetrics Aggregate,
    ImmutableArray<ProducerHoldoutMetrics> Producers);

/// <summary>Reports one named algorithm version before and after the matcher change.</summary>
public sealed record AlgorithmVersionChange(
    string Name,
    string? MatcherV2Version,
    string? MatcherV3Version,
    bool Changed);

/// <summary>References one holdout case without including producer payload.</summary>
public sealed record MatcherDeltaCaseReference(string CaseId, string ProducerId);

/// <summary>References one changed relationship and its two exact outcomes.</summary>
public sealed record MatcherDeltaRelationshipReference(
    string CaseId,
    string ProducerId,
    string RelationshipId,
    string MatcherV2Outcome,
    string MatcherV3Outcome);

/// <summary>Separates fixed, regressed, and persistently failing cases.</summary>
public sealed record MatcherCaseDelta(
    ImmutableArray<MatcherDeltaCaseReference> Fixed,
    ImmutableArray<MatcherDeltaCaseReference> Regressed,
    ImmutableArray<MatcherDeltaCaseReference> StillFailing);

/// <summary>Separates fixed, regressed, and persistently failing relationships.</summary>
public sealed record MatcherRelationshipDelta(
    ImmutableArray<MatcherDeltaRelationshipReference> Fixed,
    ImmutableArray<MatcherDeltaRelationshipReference> Regressed,
    ImmutableArray<MatcherDeltaRelationshipReference> StillFailing);

/// <summary>Reports changes to expected and unexpected ambiguity handling.</summary>
public sealed record MatcherAmbiguityDelta(
    int MatcherV2CorrectRefusals,
    int MatcherV3CorrectRefusals,
    int MatcherV2UnexpectedRefusals,
    int MatcherV3UnexpectedRefusals,
    int MatcherV2IncorrectAutoMatches,
    int MatcherV3IncorrectAutoMatches,
    ImmutableArray<MatcherDeltaRelationshipReference> Fixed,
    ImmutableArray<MatcherDeltaRelationshipReference> Regressed,
    ImmutableArray<MatcherDeltaRelationshipReference> StillFailing,
    ImmutableArray<MatcherDeltaRelationshipReference> UnexpectedRefusalsResolved,
    ImmutableArray<MatcherDeltaRelationshipReference> UnexpectedRefusalsIntroduced);

/// <summary>Reports case-level ingestion transitions between matcher evaluations.</summary>
public sealed record MatcherIngestionSuccessDelta(
    int MatcherV2Failures,
    int MatcherV3Failures,
    ImmutableArray<MatcherDeltaCaseReference> NewlySuccessful,
    ImmutableArray<MatcherDeltaCaseReference> NewlyFailed,
    ImmutableArray<MatcherDeltaCaseReference> StillFailing);

/// <summary>Defines the deterministic matcher-v2 to matcher-v3 comparison.</summary>
public sealed record MatcherV2ToV3DeltaReport(
    MatcherDeltaInputHashes InputHashes,
    MatcherMetricsSnapshot MatcherV2,
    MatcherMetricsSnapshot MatcherV3,
    ImmutableArray<AlgorithmVersionChange> AlgorithmVersionChanges,
    MatcherCaseDelta Cases,
    MatcherRelationshipDelta Relationships,
    ImmutableArray<MatcherDeltaRelationshipReference> NewlyIntroducedFalseMatches,
    MatcherAmbiguityDelta AmbiguityChanges,
    MatcherIngestionSuccessDelta IngestionSuccessChanges,
    ImmutableArray<MatcherDeltaRelationshipReference> RemainingFailures,
    int ChangedDecisionCount,
    int ChangedDecisionTraceCount,
    int ChangedDecisionWithoutTraceCount,
    ImmutableArray<MatcherDeltaRelationshipReference> ChangedDecisionsWithoutTrace,
    bool EveryChangedDecisionHasTrace);

/// <summary>
/// Reads the exact matcher-v2 history through bounded handles and verifies its immutable anchor.
/// </summary>
public sealed class MatcherV2HistoryReader
{
    public const string MatcherV2AlgorithmVersion = "sarifregress/matcher/v2";
    public const string MatcherV3AlgorithmVersion = "sarifregress/matcher/v3";

    private const string HistoryRoot = "validation/history/matcher-v2";
    private const string HistoryManifest = HistoryRoot + "/checksums.sha256";
    private const string HistoryMetadata = HistoryRoot + "/metadata.json";
    private const string HistoryEvaluationMetadata =
        HistoryRoot + "/evaluation-metadata.json";
    private const string HistoryReport =
        HistoryRoot + "/sarif-regress-holdout.json";
    private const string OriginalChecksums =
        HistoryRoot + "/original-checksums.sha256";
    private const string CurrentManifest = "validation/holdout/manifest.json";
    public const string MatcherV2HistoryChecksumManifestSha256 =
        "04ed4d840b20a5cd681ee25303d0488e32aeaef46007a765c7ad29fd2c702f1a";
    private const string ExpectedHoldoutManifestSha256 =
        "b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379";
    private const string ExpectedValidationHead =
        "0231d6fe779203a92469099b90d446fafe67b064";

    private static readonly ImmutableArray<string> HistoryFiles =
    [
        HistoryRoot + "/comparison-summary.json",
        HistoryRoot + "/cross-platform-attestation.json",
        HistoryEvaluationMetadata,
        HistoryMetadata,
        OriginalChecksums,
        HistoryRoot + "/sarif-multitool-baseline.json",
        HistoryReport,
        HistoryRoot + "/semgrep-config.json",
    ];

    private static readonly ImmutableArray<string> OriginalFiles =
    [
        "validation/expected/comparison-summary.json",
        "validation/expected/sarif-multitool-baseline.json",
        "validation/expected/sarif-regress-holdout.json",
        "validation/holdout/cross-platform-attestation.json",
        "validation/holdout/evaluation-metadata.json",
        CurrentManifest,
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly ValidationLimits limits;

    /// <summary>Creates a reader with conservative validation limits.</summary>
    public MatcherV2HistoryReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>Reads and cross-checks the frozen history and current holdout manifest.</summary>
    public MatcherV2HistorySnapshot Read(string repositoryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        string root = Path.GetFullPath(repositoryRoot);
        byte[] historyManifestBytes = Read(HistoryManifest, limits.MaximumManifestBytes);
        string historyManifestHash = Hash(historyManifestBytes);
        if (!string.Equals(
                historyManifestHash,
                MatcherV2HistoryChecksumManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v2 checksum manifest differs from its immutable anchor.");
        }

        var historyBytes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (string relativePath in HistoryFiles)
        {
            byte[] bytes = Read(relativePath, limits.MaximumSarifBytes);
            historyBytes.Add(relativePath, bytes);
            if (relativePath.EndsWith(".json", StringComparison.Ordinal))
            {
                BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
                    bytes,
                    limits.MaximumJsonDepth,
                    limits.MaximumStringCharacters);
            }
        }

        ChecksumManifest.VerifyFiles(root, historyManifestBytes, HistoryFiles);
        VerifyOriginalChecksums(historyBytes);

        byte[] currentManifestBytes = Read(CurrentManifest, limits.MaximumManifestBytes);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            currentManifestBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        string currentManifestHash = Hash(currentManifestBytes);
        if (!string.Equals(
                currentManifestHash,
                ExpectedHoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The holdout manifest differs from the manifest frozen for matcher-v2.");
        }

        HistoryMetadataDocument metadata = Deserialize<HistoryMetadataDocument>(
            historyBytes[HistoryMetadata],
            "matcher-v2 metadata");
        EvaluationMetadataDocument evaluationMetadata =
            Deserialize<EvaluationMetadataDocument>(
                historyBytes[HistoryEvaluationMetadata],
                "matcher-v2 evaluation metadata");
        HistoricalReportDocument document = Deserialize<HistoricalReportDocument>(
            historyBytes[HistoryReport],
            "matcher-v2 report");
        RequireEqual("report schema version", "1", document.SchemaVersion);
        RequireEqual(
            "report kind",
            "sarif-regress-independent-holdout",
            document.ReportKind);
        SarifRegressHoldoutReport report = EnrichHistoricalReport(document);

        ValidateHistory(metadata, evaluationMetadata, report, currentManifestHash);
        MatcherV2ToV3DeltaBuilder.ValidateReport(
            report,
            limits,
            requireTraceFree: true);
        return new MatcherV2HistorySnapshot(
            report,
            historyManifestHash,
            Hash(historyBytes[HistoryReport]));

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

    private static SarifRegressHoldoutReport EnrichHistoricalReport(
        HistoricalReportDocument document)
    {
        ImmutableArray<SarifRegressCaseResult> cases = document.Cases
            .Select(item => item with
            {
                Metrics = EnrichLifecycleMetrics(
                    item.Metrics,
                    item.RelationshipResults),
            })
            .OrderBy(item => item.CaseId, StringComparer.Ordinal)
            .ToImmutableArray();
        HoldoutMetrics aggregate = HoldoutMetricsCalculator.Aggregate(
            cases.Select(item => item.Metrics));
        ImmutableArray<ProducerHoldoutMetrics> producers = cases
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerHoldoutMetrics(
                group.Key,
                HoldoutMetricsCalculator.Aggregate(
                    group.Select(item => item.Metrics))))
            .ToImmutableArray();
        if (!LegacyMetricsEqual(document.Aggregate, aggregate))
        {
            throw new InvalidDataException(
                "The matcher-v2 report aggregate differs from its case metrics.");
        }

        ProducerHoldoutMetrics[] historicalProducers = document.Producers
            .OrderBy(item => item.ProducerId, StringComparer.Ordinal)
            .ToArray();
        if (historicalProducers.Length != producers.Length
            || historicalProducers.Where((item, index) =>
                    item.ProducerId != producers[index].ProducerId
                    || !LegacyMetricsEqual(item.Metrics, producers[index].Metrics))
                .Any())
        {
            throw new InvalidDataException(
                "The matcher-v2 report producer metrics differ from its cases.");
        }

        return new SarifRegressHoldoutReport(
            document.Evaluation,
            aggregate,
            producers,
            cases,
            document.DiagnosticCounts.OrderBy(item => item.Code, StringComparer.Ordinal)
                .ToImmutableArray());
    }

    private static HoldoutMetrics EnrichLifecycleMetrics(
        HoldoutMetrics metrics,
        ImmutableArray<RelationshipResult> relationships)
    {
        int expectedNew = relationships.Count(item =>
            item.GroundTruth.Kind == "new");
        int expectedResolved = relationships.Count(item =>
            item.GroundTruth.Kind == "resolved");
        int incorrectNew = checked(
            expectedNew - metrics.CorrectNewClassifications);
        int incorrectResolved = checked(
            expectedResolved - metrics.CorrectResolvedClassifications);
        if (incorrectNew < 0 || incorrectResolved < 0)
        {
            throw new InvalidDataException(
                "The matcher-v2 lifecycle metrics exceed their ground-truth units.");
        }

        return metrics with
        {
            ExpectedNewClassifications = expectedNew,
            IncorrectNewClassifications = incorrectNew,
            NewClassificationAccuracy = Divide(
                metrics.CorrectNewClassifications,
                expectedNew),
            ExpectedResolvedClassifications = expectedResolved,
            IncorrectResolvedClassifications = incorrectResolved,
            ResolvedClassificationAccuracy = Divide(
                metrics.CorrectResolvedClassifications,
                expectedResolved),
        };
    }

    private static bool LegacyMetricsEqual(HoldoutMetrics left, HoldoutMetrics right) =>
        left.GroundTruthUnits == right.GroundTruthUnits
        && left.LabelledRelationships == right.LabelledRelationships
        && left.LabelledMatches == right.LabelledMatches
        && left.TruePositives == right.TruePositives
        && left.FalsePositives == right.FalsePositives
        && left.FalseNegatives == right.FalseNegatives
        && left.ClassificationMismatches == right.ClassificationMismatches
        && left.NewClassifications == right.NewClassifications
        && left.ResolvedClassifications == right.ResolvedClassifications
        && left.AmbiguousClassifications == right.AmbiguousClassifications
        && left.CorrectNewClassifications == right.CorrectNewClassifications
        && left.CorrectResolvedClassifications == right.CorrectResolvedClassifications
        && left.CorrectAmbiguityRefusals == right.CorrectAmbiguityRefusals
        && left.UnexpectedAmbiguityRefusals == right.UnexpectedAmbiguityRefusals
        && left.IncorrectlyAutoMatchedAmbiguousCases
            == right.IncorrectlyAutoMatchedAmbiguousCases
        && left.IngestionFailures == right.IngestionFailures
        && left.StructuralFailures == right.StructuralFailures
        && left.Precision == right.Precision
        && left.Recall == right.Recall
        && left.F1 == right.F1;

    private static decimal Divide(int numerator, int denominator) => denominator == 0
        ? 1m
        : decimal.Round(
            (decimal)numerator / denominator,
            6,
            MidpointRounding.ToEven);

    private static void VerifyOriginalChecksums(
        IReadOnlyDictionary<string, byte[]> historyBytes)
    {
        ImmutableSortedDictionary<string, string> original = ChecksumManifest.Parse(
            historyBytes[OriginalChecksums]);
        if (!original.Keys.SequenceEqual(OriginalFiles, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v2 original checksum manifest has an unexpected file set.");
        }

        RequireOriginalHash(
            "validation/expected/comparison-summary.json",
            HistoryRoot + "/comparison-summary.json");
        RequireOriginalHash(
            "validation/expected/sarif-multitool-baseline.json",
            HistoryRoot + "/sarif-multitool-baseline.json");
        RequireOriginalHash(
            "validation/expected/sarif-regress-holdout.json",
            HistoryReport);
        RequireOriginalHash(
            "validation/holdout/cross-platform-attestation.json",
            HistoryRoot + "/cross-platform-attestation.json");
        RequireOriginalHash(
            "validation/holdout/evaluation-metadata.json",
            HistoryEvaluationMetadata);
        if (!string.Equals(
                original[CurrentManifest],
                ExpectedHoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The original checksum manifest identifies a different holdout manifest.");
        }

        void RequireOriginalHash(string originalPath, string historyPath)
        {
            if (!string.Equals(
                    original[originalPath],
                    Hash(historyBytes[historyPath]),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The matcher-v2 history copy for '{originalPath}' is not exact.");
            }
        }
    }

    private static void ValidateHistory(
        HistoryMetadataDocument metadata,
        EvaluationMetadataDocument evaluationMetadata,
        SarifRegressHoldoutReport report,
        string currentManifestHash)
    {
        RequireEqual("history schema version", "1", metadata.HistorySchemaVersion);
        RequireEqual(
            "history record kind",
            "frozen-independent-holdout-evaluation",
            metadata.Record);
        RequireEqual("validation head", ExpectedValidationHead, metadata.ValidationHeadCommit);
        RequireEqual(
            "matcher version",
            MatcherV2AlgorithmVersion,
            metadata.MatcherAlgorithmVersion);
        RequireEqual(
            "evaluation metadata schema version",
            "1",
            evaluationMetadata.SchemaVersion);
        RequireEqual(
            "holdout manifest hash",
            ExpectedHoldoutManifestSha256,
            currentManifestHash);
        RequireEqual(
            "metadata manifest hash",
            currentManifestHash,
            metadata.HoldoutManifestSha256);
        RequireEqual(
            "evaluation metadata manifest hash",
            currentManifestHash,
            evaluationMetadata.HoldoutManifestSha256);
        RequireEqual(
            "report manifest hash",
            currentManifestHash,
            report.Evaluation.HoldoutManifestSha256);
        RequireEqual(
            "base implementation commit",
            report.Evaluation.RepositoryCommitSha,
            metadata.BaseImplementationCommit);
        RequireEqual(
            "evaluation repository commit",
            report.Evaluation.RepositoryCommitSha,
            evaluationMetadata.RepositoryCommitSha);
        RequireEqual(
            "evaluation source tree hash",
            report.Evaluation.SourceTreeSha256,
            evaluationMetadata.SourceTreeSha256);
        RequireEqual(
            "tool version",
            report.Evaluation.SarifRegressToolVersion,
            evaluationMetadata.SarifRegressToolVersion);
        RequireEqual(
            "report matcher version",
            MatcherV2AlgorithmVersion,
            report.Evaluation.MatcherAlgorithmVersion);
        RequireEqual(
            "evaluation matcher version",
            MatcherV2AlgorithmVersion,
            evaluationMetadata.MatcherAlgorithmVersion);
        RequireEqual(
            "configuration schema version",
            report.Evaluation.ConfigurationSchemaVersion,
            metadata.ConfigurationSchemaVersion);
        RequireEqual(
            "evaluation configuration schema version",
            report.Evaluation.ConfigurationSchemaVersion,
            evaluationMetadata.ConfigurationSchemaVersion);
        RequireEqual(
            "output schema version",
            report.Evaluation.OutputSchemaVersion,
            metadata.OutputSchemaVersion);
        RequireEqual(
            "evaluation output schema version",
            report.Evaluation.OutputSchemaVersion,
            evaluationMetadata.OutputSchemaVersion);
        RequireEqual(
            "SDK version",
            metadata.DotnetSdkVersion,
            evaluationMetadata.Environment.DotnetSdkVersion);
        RequireAlgorithms(
            metadata.FingerprintAlgorithmVersions,
            report.Evaluation.FingerprintAlgorithmVersions,
            "history metadata");
        RequireAlgorithms(
            evaluationMetadata.FingerprintAlgorithmVersions,
            report.Evaluation.FingerprintAlgorithmVersions,
            "evaluation metadata");

        if (metadata.Metrics.TruePositives != report.Aggregate.TruePositives
            || metadata.Metrics.FalsePositives != report.Aggregate.FalsePositives
            || metadata.Metrics.FalseNegatives != report.Aggregate.FalseNegatives
            || metadata.Metrics.IngestionFailures != report.Aggregate.IngestionFailures
            || metadata.Metrics.Precision != report.Aggregate.Precision
            || metadata.Metrics.Recall != report.Aggregate.Recall
            || metadata.Metrics.F1 != report.Aggregate.F1)
        {
            throw new InvalidDataException(
                "The matcher-v2 history summary metrics differ from the report.");
        }

        if (metadata.ReleaseRecommendation != "blocked"
            || metadata.OriginalCaseConfiguration != "semgrep-config.json"
            || metadata.Immutability.HoldoutLabelsChanged
            || metadata.Immutability.QualityThresholdsChanged
            || metadata.Immutability.DifficultCasesRemoved)
        {
            throw new InvalidDataException(
                "The matcher-v2 history no longer records the frozen blocked evaluation.");
        }

        RequireEqual(
            "validation pull request",
            "https://github.com/ppcdaniel/sarif-regress/pull/8",
            metadata.Links.ValidationPullRequest);
        RequireEqual(
            "external URI-base issue",
            "https://github.com/ppcdaniel/sarif-regress/issues/9",
            metadata.Links.ExternalUriBaseIssue);
        RequireEqual(
            "context collision issue",
            "https://github.com/ppcdaniel/sarif-regress/issues/10",
            metadata.Links.ContextCollisionIssue);
        RequireEqual(
            "sparse SARIF issue",
            "https://github.com/ppcdaniel/sarif-regress/issues/11",
            metadata.Links.SparseSarifIssue);
    }

    private static void RequireAlgorithms(
        IEnumerable<NamedAlgorithmVersion> observed,
        IEnumerable<NamedAlgorithmVersion> expected,
        string source)
    {
        NamedAlgorithmVersion[] observedValues = observed
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Version, StringComparer.Ordinal)
            .ToArray();
        NamedAlgorithmVersion[] expectedValues = expected
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Version, StringComparer.Ordinal)
            .ToArray();
        if (!observedValues.SequenceEqual(expectedValues))
        {
            throw new InvalidDataException(
                $"The {source} fingerprint algorithm versions differ from the report.");
        }
    }

    private static void RequireEqual(string name, string expected, string observed)
    {
        if (!string.Equals(expected, observed, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The matcher-v2 {name} '{observed}' does not equal '{expected}'.");
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

    private sealed class HistoryMetadataDocument
    {
        public required string HistorySchemaVersion { get; init; }
        public required string Record { get; init; }
        public required string BaseImplementationCommit { get; init; }
        public required string ValidationHeadCommit { get; init; }
        public required string MatcherAlgorithmVersion { get; init; }
        public required NamedAlgorithmVersion[] FingerprintAlgorithmVersions { get; init; }
        public required string ConfigurationSchemaVersion { get; init; }
        public required string OutputSchemaVersion { get; init; }
        public required string DotnetSdkVersion { get; init; }
        public required string HoldoutManifestSha256 { get; init; }
        public required HistoryMetricsDocument Metrics { get; init; }
        public required string ReleaseRecommendation { get; init; }
        public required string OriginalCaseConfiguration { get; init; }
        public required HistoryLinksDocument Links { get; init; }
        public required HistoryImmutabilityDocument Immutability { get; init; }
    }

    private sealed class HistoryMetricsDocument
    {
        public required int TruePositives { get; init; }
        public required int FalsePositives { get; init; }
        public required int FalseNegatives { get; init; }
        public required decimal Precision { get; init; }
        public required decimal Recall { get; init; }
        public required decimal F1 { get; init; }
        public required int IngestionFailures { get; init; }
    }

    private sealed class HistoryLinksDocument
    {
        public required string ValidationPullRequest { get; init; }
        public required string ExternalUriBaseIssue { get; init; }
        public required string ContextCollisionIssue { get; init; }
        public required string SparseSarifIssue { get; init; }
    }

    private sealed class HistoryImmutabilityDocument
    {
        public required bool HoldoutLabelsChanged { get; init; }
        public required bool QualityThresholdsChanged { get; init; }
        public required bool DifficultCasesRemoved { get; init; }
    }

    private sealed class EvaluationMetadataDocument
    {
        public required string SchemaVersion { get; init; }
        public required string RepositoryCommitSha { get; init; }
        public required string SourceTreeSha256 { get; init; }
        public required string SarifRegressToolVersion { get; init; }
        public required string MatcherAlgorithmVersion { get; init; }
        public required NamedAlgorithmVersion[] FingerprintAlgorithmVersions { get; init; }
        public required string OutputSchemaVersion { get; init; }
        public required string ConfigurationSchemaVersion { get; init; }
        public required string HoldoutManifestSha256 { get; init; }
        public required HistoryEnvironmentDocument Environment { get; init; }
    }

    private sealed class HistoryEnvironmentDocument
    {
        public required string OperatingSystem { get; init; }
        public required string Architecture { get; init; }
        public required string DotnetSdkVersion { get; init; }
    }
}

/// <summary>Builds an ordinal, payload-free delta over one unchanged label graph.</summary>
public static class MatcherV2ToV3DeltaBuilder
{
    /// <summary>Compares matcher-v2 history with one matcher-v3 holdout report.</summary>
    public static MatcherV2ToV3DeltaReport Create(
        MatcherV2HistorySnapshot matcherV2,
        SarifRegressHoldoutReport matcherV3,
        MatcherDeltaInputHashes inputHashes,
        ValidationLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(matcherV2);
        ArgumentNullException.ThrowIfNull(matcherV3);
        ArgumentNullException.ThrowIfNull(inputHashes);
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        effectiveLimits.Validate();
        if (!string.Equals(
                matcherV2.HistoryChecksumManifestSha256,
                MatcherV2HistoryReader.MatcherV2HistoryChecksumManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The matcher-v2 snapshot does not identify the immutable history anchor.");
        }

        ValidateReport(matcherV2.Report, effectiveLimits, requireTraceFree: true);
        ValidateReport(matcherV3, effectiveLimits, requireTraceFree: false);
        ValidateInputHashes(matcherV2, matcherV3, inputHashes);
        RequireVersion(
            matcherV2.Report.Evaluation.MatcherAlgorithmVersion,
            MatcherV2HistoryReader.MatcherV2AlgorithmVersion,
            "matcher-v2");
        RequireVersion(
            matcherV3.Evaluation.MatcherAlgorithmVersion,
            MatcherV2HistoryReader.MatcherV3AlgorithmVersion,
            "matcher-v3");
        if (!string.Equals(
                matcherV2.Report.Evaluation.HoldoutManifestSha256,
                matcherV3.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Matcher-v2 and matcher-v3 do not identify the same holdout manifest.");
        }

        ImmutableArray<CasePair> pairs = PairExactGraph(matcherV2.Report, matcherV3);
        ImmutableArray<RelationshipPair> relationships = pairs
            .SelectMany(item => item.Relationships)
            .OrderBy(item => item.CaseId, StringComparer.Ordinal)
            .ThenBy(item => item.MatcherV2.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
        ImmutableArray<MatcherDeltaRelationshipReference> fixedRelationships =
            SelectRelationships(relationships, item =>
                !IsCorrect(item.MatcherV2.Outcome)
                && IsCorrect(item.MatcherV3.Outcome));
        ImmutableArray<MatcherDeltaRelationshipReference> regressedRelationships =
            SelectRelationships(relationships, item =>
                IsCorrect(item.MatcherV2.Outcome)
                && !IsCorrect(item.MatcherV3.Outcome));
        ImmutableArray<MatcherDeltaRelationshipReference> stillFailingRelationships =
            SelectRelationships(relationships, item =>
                !IsCorrect(item.MatcherV2.Outcome)
                && !IsCorrect(item.MatcherV3.Outcome));
        ImmutableArray<RelationshipPair> changedDecisions = relationships
            .Where(DecisionChanged)
            .ToImmutableArray();
        ImmutableArray<MatcherDeltaRelationshipReference> withoutTrace =
            SelectRelationships(
                changedDecisions,
                item => item.MatcherV3.Actual.DecisionTraces.IsDefaultOrEmpty);
        int traceCount = changedDecisions.Length - withoutTrace.Length;

        return new MatcherV2ToV3DeltaReport(
            inputHashes,
            Snapshot(matcherV2.Report),
            Snapshot(matcherV3),
            AlgorithmChanges(matcherV2.Report.Evaluation, matcherV3.Evaluation),
            new MatcherCaseDelta(
                SelectCases(pairs, item => !CaseCorrect(item.MatcherV2)
                    && CaseCorrect(item.MatcherV3)),
                SelectCases(pairs, item => CaseCorrect(item.MatcherV2)
                    && !CaseCorrect(item.MatcherV3)),
                SelectCases(pairs, item => !CaseCorrect(item.MatcherV2)
                    && !CaseCorrect(item.MatcherV3))),
            new MatcherRelationshipDelta(
                fixedRelationships,
                regressedRelationships,
                stillFailingRelationships),
            SelectRelationships(relationships, item =>
                IsFalseMatch(item.MatcherV3.Outcome)
                && !IsFalseMatch(item.MatcherV2.Outcome)),
            AmbiguityChanges(relationships, matcherV2.Report, matcherV3),
            IngestionChanges(pairs, matcherV2.Report, matcherV3),
            SelectRelationships(relationships, item =>
                !IsCorrect(item.MatcherV3.Outcome)),
            changedDecisions.Length,
            traceCount,
            withoutTrace.Length,
            withoutTrace,
            withoutTrace.IsEmpty);
    }

    private static void ValidateInputHashes(
        MatcherV2HistorySnapshot matcherV2,
        SarifRegressHoldoutReport matcherV3,
        MatcherDeltaInputHashes inputHashes)
    {
        RequireHash(
            inputHashes.MatcherV2HistoryChecksumManifestSha256,
            "matcher-v2 history checksum manifest");
        RequireHash(inputHashes.MatcherV2ReportSha256, "matcher-v2 report");
        RequireHash(inputHashes.MatcherV3ReportSha256, "matcher-v3 report");
        RequireHash(inputHashes.HoldoutManifestSha256, "holdout manifest");
        if (!string.Equals(
                inputHashes.MatcherV2HistoryChecksumManifestSha256,
                matcherV2.HistoryChecksumManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.MatcherV2ReportSha256,
                matcherV2.ReportSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.MatcherV3ReportSha256,
                Hash(StableReportSerializer.Serialize(matcherV3)),
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.HoldoutManifestSha256,
                matcherV2.Report.Evaluation.HoldoutManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                inputHashes.HoldoutManifestSha256,
                matcherV3.Evaluation.HoldoutManifestSha256,
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

    internal static void ValidateReport(
        SarifRegressHoldoutReport report,
        ValidationLimits limits,
        bool requireTraceFree)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Cases.IsDefault || report.Producers.IsDefault
            || report.DiagnosticCounts.IsDefault
            || report.Evaluation.FingerprintAlgorithmVersions.IsDefault)
        {
            throw new InvalidDataException("A holdout report contains a default array.");
        }

        if (report.Cases.Length == 0 || report.Cases.Length > limits.MaximumCases)
        {
            throw new InvalidDataException("A holdout report has an invalid case count.");
        }

        RequireUnique(report.Cases.Select(item => item.CaseId), "case id");
        RequireUnique(report.Producers.Select(item => item.ProducerId), "producer id");
        RequireUnique(
            report.Evaluation.FingerprintAlgorithmVersions.Select(item => item.Name),
            "fingerprint algorithm name");
        foreach (SarifRegressCaseResult item in report.Cases)
        {
            if (item.RelationshipResults.IsDefault
                || item.RelationshipResults.Length > limits.MaximumResultsPerCase)
            {
                throw new InvalidDataException(
                    $"Case '{item.CaseId}' has an invalid relationship count.");
            }

            RequireUnique(
                item.RelationshipResults.Select(value => value.RelationshipId),
                $"relationship id in case '{item.CaseId}'");
            if (item.RelationshipResults.Length != item.Metrics.GroundTruthUnits)
            {
                throw new InvalidDataException(
                    $"Case '{item.CaseId}' metrics do not cover its exact label graph.");
            }

            foreach (RelationshipResult relationship in item.RelationshipResults)
            {
                if (relationship.Actual.DecisionTraces.IsDefault)
                {
                    throw new InvalidDataException(
                        $"Relationship '{relationship.RelationshipId}' has a default trace array.");
                }

                if (requireTraceFree && !relationship.Actual.DecisionTraces.IsEmpty)
                {
                    throw new InvalidDataException(
                        "The immutable matcher-v2 history unexpectedly contains matcher-v3 traces.");
                }

                ImmutableArray<DecisionTraceProjection> ordered =
                    DecisionTraceProjectionFactory.OrderAndValidate(
                        relationship.Actual.DecisionTraces,
                        limits);
                if (!relationship.Actual.DecisionTraces.SequenceEqual(ordered))
                {
                    throw new InvalidDataException(
                        $"Relationship '{relationship.RelationshipId}' traces are not ordinal.");
                }

                foreach (DecisionTraceProjection trace in ordered)
                {
                    ValidateTraceItems(trace, limits, relationship.RelationshipId);
                }
            }
        }

        RequireUnique(
            report.Cases.SelectMany(item => item.RelationshipResults)
                .Select(item => item.RelationshipId),
            "global relationship id");
        HoldoutMetrics aggregate = HoldoutMetricsCalculator.Aggregate(
            report.Cases.Select(item => item.Metrics));
        if (aggregate != report.Aggregate)
        {
            throw new InvalidDataException(
                "Holdout aggregate metrics do not equal the case aggregates.");
        }

        ProducerHoldoutMetrics[] expectedProducers = report.Cases
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerHoldoutMetrics(
                group.Key,
                HoldoutMetricsCalculator.Aggregate(group.Select(item => item.Metrics))))
            .ToArray();
        ProducerHoldoutMetrics[] observedProducers = report.Producers
            .OrderBy(item => item.ProducerId, StringComparer.Ordinal)
            .ToArray();
        if (!observedProducers.SequenceEqual(expectedProducers))
        {
            throw new InvalidDataException(
                "Holdout producer metrics do not equal the case aggregates.");
        }
    }

    private static void ValidateTraceItems(
        DecisionTraceProjection trace,
        ValidationLimits limits,
        string relationshipId)
    {
        if (trace.Evidence.IsDefault
            || trace.RejectedAlternatives.IsDefault
            || trace.Transformations.IsDefault
            || trace.Diagnostics.IsDefault
            || trace.Evidence.Any(item => item.Count <= 0)
            || trace.RejectedAlternatives.Any(item => item.Count <= 0)
            || trace.Transformations.Any(item => item.Count <= 0)
            || trace.Diagnostics.Any(item => item.Count <= 0))
        {
            throw new InvalidDataException(
                $"Relationship '{relationshipId}' contains a default trace array.");
        }

        RequireBounded(trace.Evidence.Select(item => item.Count), "evidence");
        RequireBounded(
            trace.RejectedAlternatives.Select(item => item.Count),
            "rejected alternatives");
        RequireBounded(
            trace.Transformations.Select(item => item.Count),
            "transformations");
        RequireBounded(trace.Diagnostics.Select(item => item.Count), "diagnostics");

        void RequireBounded(IEnumerable<int> counts, string kind)
        {
            int itemCount;
            try
            {
                itemCount = counts.Sum(item => checked(item));
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException(
                    $"Relationship '{relationshipId}' {kind} counts overflow.",
                    exception);
            }

            if (itemCount > limits.MaximumDecisionTraceItems)
            {
                throw new InvalidDataException(
                    $"Relationship '{relationshipId}' exceeds the {kind} item limit.");
            }
        }
    }

    private static ImmutableArray<CasePair> PairExactGraph(
        SarifRegressHoldoutReport matcherV2,
        SarifRegressHoldoutReport matcherV3)
    {
        Dictionary<string, SarifRegressCaseResult> v2Cases = matcherV2.Cases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        Dictionary<string, SarifRegressCaseResult> v3Cases = matcherV3.Cases
            .ToDictionary(item => item.CaseId, StringComparer.Ordinal);
        if (!v2Cases.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                v3Cases.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Matcher-v2 and matcher-v3 do not contain the same case graph.");
        }

        var result = ImmutableArray.CreateBuilder<CasePair>(v2Cases.Count);
        foreach (string caseId in v2Cases.Keys.Order(StringComparer.Ordinal))
        {
            SarifRegressCaseResult v2 = v2Cases[caseId];
            SarifRegressCaseResult v3 = v3Cases[caseId];
            if (!string.Equals(v2.ProducerId, v3.ProducerId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Case '{caseId}' changed producer identity.");
            }

            Dictionary<string, RelationshipResult> v2Relationships =
                v2.RelationshipResults.ToDictionary(
                    item => item.RelationshipId,
                    StringComparer.Ordinal);
            Dictionary<string, RelationshipResult> v3Relationships =
                v3.RelationshipResults.ToDictionary(
                    item => item.RelationshipId,
                    StringComparer.Ordinal);
            if (!v2Relationships.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                    v3Relationships.Keys.Order(StringComparer.Ordinal),
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    $"Case '{caseId}' changed its relationship graph.");
            }

            ImmutableArray<RelationshipPair> relationships = v2Relationships.Keys
                .Order(StringComparer.Ordinal)
                .Select(relationshipId =>
                {
                    RelationshipResult oldValue = v2Relationships[relationshipId];
                    RelationshipResult newValue = v3Relationships[relationshipId];
                    if (oldValue.GroundTruth != newValue.GroundTruth)
                    {
                        throw new InvalidDataException(
                            $"Relationship '{relationshipId}' changed ground truth.");
                    }

                    return new RelationshipPair(
                        caseId,
                        v2.ProducerId,
                        oldValue,
                        newValue);
                })
                .ToImmutableArray();
            result.Add(new CasePair(v2, v3, relationships));
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

    private static ImmutableArray<AlgorithmVersionChange> AlgorithmChanges(
        EvaluationIdentity matcherV2,
        EvaluationIdentity matcherV3)
    {
        Dictionary<string, string> oldValues = AlgorithmMap(matcherV2);
        Dictionary<string, string> newValues = AlgorithmMap(matcherV3);
        return oldValues.Keys.Concat(newValues.Keys)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .Select(name =>
            {
                oldValues.TryGetValue(name, out string? oldVersion);
                newValues.TryGetValue(name, out string? newVersion);
                return new AlgorithmVersionChange(
                    name,
                    oldVersion,
                    newVersion,
                    !string.Equals(oldVersion, newVersion, StringComparison.Ordinal));
            })
            .ToImmutableArray();

        static Dictionary<string, string> AlgorithmMap(EvaluationIdentity identity)
        {
            Dictionary<string, string> values = identity.FingerprintAlgorithmVersions
                .ToDictionary(item => item.Name, item => item.Version, StringComparer.Ordinal);
            values.Add("matcher", identity.MatcherAlgorithmVersion);
            return values;
        }
    }

    private static MatcherAmbiguityDelta AmbiguityChanges(
        ImmutableArray<RelationshipPair> relationships,
        SarifRegressHoldoutReport matcherV2,
        SarifRegressHoldoutReport matcherV3)
    {
        ImmutableArray<RelationshipPair> ambiguity = relationships
            .Where(item => item.MatcherV2.GroundTruth.Kind == "ambiguous")
            .ToImmutableArray();
        return new MatcherAmbiguityDelta(
            matcherV2.Aggregate.CorrectAmbiguityRefusals,
            matcherV3.Aggregate.CorrectAmbiguityRefusals,
            matcherV2.Aggregate.UnexpectedAmbiguityRefusals,
            matcherV3.Aggregate.UnexpectedAmbiguityRefusals,
            matcherV2.Aggregate.IncorrectlyAutoMatchedAmbiguousCases,
            matcherV3.Aggregate.IncorrectlyAutoMatchedAmbiguousCases,
            SelectRelationships(ambiguity, item =>
                !IsCorrect(item.MatcherV2.Outcome)
                && IsCorrect(item.MatcherV3.Outcome)),
            SelectRelationships(ambiguity, item =>
                IsCorrect(item.MatcherV2.Outcome)
                && !IsCorrect(item.MatcherV3.Outcome)),
            SelectRelationships(ambiguity, item =>
                !IsCorrect(item.MatcherV2.Outcome)
                && !IsCorrect(item.MatcherV3.Outcome)),
            SelectRelationships(relationships, item =>
                item.MatcherV2.Outcome == "unexpected-ambiguity-refusal"
                && item.MatcherV3.Outcome != "unexpected-ambiguity-refusal"),
            SelectRelationships(relationships, item =>
                item.MatcherV2.Outcome != "unexpected-ambiguity-refusal"
                && item.MatcherV3.Outcome == "unexpected-ambiguity-refusal"));
    }

    private static MatcherIngestionSuccessDelta IngestionChanges(
        ImmutableArray<CasePair> pairs,
        SarifRegressHoldoutReport matcherV2,
        SarifRegressHoldoutReport matcherV3) => new(
        matcherV2.Aggregate.IngestionFailures,
        matcherV3.Aggregate.IngestionFailures,
        SelectCases(pairs, item => !IngestionSucceeded(item.MatcherV2)
            && IngestionSucceeded(item.MatcherV3)),
        SelectCases(pairs, item => IngestionSucceeded(item.MatcherV2)
            && !IngestionSucceeded(item.MatcherV3)),
        SelectCases(pairs, item => !IngestionSucceeded(item.MatcherV2)
            && !IngestionSucceeded(item.MatcherV3)));

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
        item.MatcherV2.Outcome != item.MatcherV3.Outcome
        || item.MatcherV2.Actual.State != item.MatcherV3.Actual.State
        || item.MatcherV2.Actual.BaselineKey != item.MatcherV3.Actual.BaselineKey
        || item.MatcherV2.Actual.CandidateKey != item.MatcherV3.Actual.CandidateKey;

    private static ImmutableArray<MatcherDeltaCaseReference> SelectCases(
        IEnumerable<CasePair> values,
        Func<CasePair, bool> predicate) => values
        .Where(predicate)
        .Select(item => new MatcherDeltaCaseReference(
            item.MatcherV2.CaseId,
            item.MatcherV2.ProducerId))
        .OrderBy(item => item.CaseId, StringComparer.Ordinal)
        .ThenBy(item => item.ProducerId, StringComparer.Ordinal)
        .ToImmutableArray();

    private static ImmutableArray<MatcherDeltaRelationshipReference>
        SelectRelationships(
            IEnumerable<RelationshipPair> values,
            Func<RelationshipPair, bool> predicate) => values
        .Where(predicate)
        .Select(item => new MatcherDeltaRelationshipReference(
            item.CaseId,
            item.ProducerId,
            item.MatcherV2.RelationshipId,
            item.MatcherV2.Outcome,
            item.MatcherV3.Outcome))
        .OrderBy(item => item.CaseId, StringComparer.Ordinal)
        .ThenBy(item => item.RelationshipId, StringComparer.Ordinal)
        .ToImmutableArray();

    private static void RequireUnique(IEnumerable<string> values, string kind)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string value in values)
        {
            if (string.IsNullOrWhiteSpace(value) || !seen.Add(value))
            {
                throw new InvalidDataException(
                    $"A holdout report repeats or omits a {kind}.");
            }
        }
    }

    private static void RequireVersion(string observed, string expected, string name)
    {
        if (!string.Equals(observed, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The {name} report identifies '{observed}', not '{expected}'.");
        }
    }

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record CasePair(
        SarifRegressCaseResult MatcherV2,
        SarifRegressCaseResult MatcherV3,
        ImmutableArray<RelationshipPair> Relationships);

    private sealed record RelationshipPair(
        string CaseId,
        string ProducerId,
        RelationshipResult MatcherV2,
        RelationshipResult MatcherV3);
}
