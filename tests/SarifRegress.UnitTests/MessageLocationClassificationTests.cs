using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Match;

namespace SarifRegress.UnitTests;

public sealed class MessageLocationClassificationTests
{
    private const string ClassificationTransformationKind =
        "classification-message-location-template";
    private const string ClassificationAlgorithm =
        "sarifregress/message-location-template/v1";

    private readonly FindingMatcher matcher = new();

    [Theory]
    [InlineData("01")]
    [InlineData("02")]
    [InlineData("03")]
    [InlineData("04")]
    [InlineData("05")]
    public void Unique_location_token_substitution_is_a_moved_finding(
        string ordinal)
    {
        string baselinePath = $"src/renamed-old/item-{ordinal}.env";
        string candidatePath = $"src/renamed-new/item-{ordinal}.env";
        var fingerprint = MatchingTestData.ProducerFingerprint($"stable-{ordinal}");

        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                baselinePath,
                Message(baselinePath),
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                candidatePath,
                Message(candidatePath),
                producerFingerprints: [fingerprint]),
            RenamedConfiguration());

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.Equal(PrecedenceTier.ExactProducer, decision.Decision.PrecedenceTier);
        Assert.Contains(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "message"
                && evidence.BaselineValue != evidence.CandidateValue);
        AssertClassificationTransformation(decision);
    }

    [Theory]
    [InlineData(
        "Secret in src/renamed-old/item.env.",
        "Secret in src/renamed-new/item.env. Candidate text.")]
    [InlineData(
        "Secret in src/renamed-old/item.env and src/renamed-old/item.env.",
        "Secret in src/renamed-new/item.env and src/renamed-new/item.env.")]
    [InlineData(
        "Secret in prefixsrc/renamed-old/item.env.",
        "Secret in prefixsrc/renamed-new/item.env.")]
    [InlineData(
        "Secret in src/renamed-old/item.env.backup.",
        "Secret in src/renamed-new/item.env.backup.")]
    [InlineData(
        "Secret in src/renamed-old/item.env/child.",
        "Secret in src/renamed-new/item.env/child.")]
    [InlineData(
        "Secret in src/renamed-old/item.env?view=raw.",
        "Secret in src/renamed-new/item.env?view=raw.")]
    [InlineData(
        "Secret in src/renamed-old/item.env:stream.",
        "Secret in src/renamed-new/item.env:stream.")]
    [InlineData(
        "Secret in src/renamed-old/item.env;param=x.",
        "Secret in src/renamed-new/item.env;param=x.")]
    [InlineData(
        "Secret in src/renamed-old/item.env!suffix.",
        "Secret in src/renamed-new/item.env!suffix.")]
    public void Non_exact_location_token_substitution_remains_modified(
        string baselineMessage,
        string candidateMessage)
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                "src/renamed-old/item.env",
                baselineMessage,
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                "src/renamed-new/item.env",
                candidateMessage,
                producerFingerprints: [fingerprint]),
            RenamedConfiguration());

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Modified, decision.Classification);
        Assert.DoesNotContain(
            decision.Decision.Transformations,
            transformation => transformation.Kind ==
                ClassificationTransformationKind);
    }

    [Fact]
    public void Windows_separator_forms_are_recognized_without_changing_path_identity()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                "src/old/item.env",
                @"Secret in src\old\item.env.",
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                "src/new/item.env",
                @"Secret in src\new\item.env.",
                producerFingerprints: [fingerprint]),
            SimpleMoveConfiguration());

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        AssertClassificationTransformation(decision);
    }

    [Fact]
    public void Region_only_movement_is_moved_without_template_evidence()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                "src/item.env",
                "Stable message.",
                startLine: 10,
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                "src/item.env",
                "Stable message.",
                startLine: 40,
                producerFingerprints: [fingerprint]));

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.DoesNotContain(
            decision.Decision.Transformations,
            transformation => transformation.Kind ==
                ClassificationTransformationKind);
    }

    [Fact]
    public void Message_only_change_is_modified()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                "src/item.env",
                "Baseline message.",
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                "src/item.env",
                "Candidate message.",
                producerFingerprints: [fingerprint]));

        Assert.Equal(
            FindingClassification.Modified,
            Assert.Single(result.Decisions).Classification);
    }

    [Fact]
    public void Incidental_whole_word_path_values_without_alias_remain_modified()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                "alpha",
                "Risk level alpha.",
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                "beta",
                "Risk level beta.",
                producerFingerprints: [fingerprint]));

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Modified, decision.Classification);
        Assert.Empty(decision.Decision.Transformations);
    }

    [Fact]
    public void Context_only_change_is_modified()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                "src/item.env",
                "Stable message.",
                contextHash: "baseline-context",
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                "src/item.env",
                "Stable message.",
                contextHash: "candidate-context",
                producerFingerprints: [fingerprint]));

        Assert.Equal(
            FindingClassification.Modified,
            Assert.Single(result.Decisions).Classification);
    }

    [Fact]
    public void Context_change_wins_even_when_path_message_delta_is_explained()
    {
        string baselinePath = "src/old/item.env";
        string candidatePath = "src/new/item.env";
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                baselinePath,
                Message(baselinePath),
                contextHash: "baseline-context",
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                candidatePath,
                Message(candidatePath),
                contextHash: "candidate-context",
                producerFingerprints: [fingerprint]),
            SimpleMoveConfiguration());

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Modified, decision.Classification);
        AssertClassificationTransformation(decision);
    }

    [Fact]
    public void Path_and_region_movement_with_only_location_message_delta_is_moved()
    {
        string baselinePath = "src/old/item.env";
        string candidatePath = "src/new/item.env";
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                baselinePath,
                Message(baselinePath),
                startLine: 10,
                producerFingerprints: [fingerprint]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                candidatePath,
                Message(candidatePath),
                startLine: 40,
                producerFingerprints: [fingerprint]),
            SimpleMoveConfiguration());

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        AssertClassificationTransformation(decision);
    }

    [Fact]
    public void Location_template_recognition_cannot_admit_a_candidate_edge()
    {
        Finding[] baseline =
        [
            ContextFinding(
                InputKind.Baseline,
                "baseline:a",
                "src/baseline/a.env"),
            ContextFinding(
                InputKind.Baseline,
                "baseline:b",
                "src/baseline/b.env"),
        ];
        Finding[] candidate =
        [
            ContextFinding(
                InputKind.Candidate,
                "candidate:a",
                "src/candidate/a.env"),
            ContextFinding(
                InputKind.Candidate,
                "candidate:b",
                "src/candidate/b.env"),
        ];

        MatchResult result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(allowWeakMessageSimilarity: true));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(
            2,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.Equal(
            2,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Baseline is not null && decision.Candidate is not null);
    }

    [Fact]
    public void Repeated_redacted_context_is_order_invariant_and_keeps_bounded_explanations()
    {
        Finding[] baseline =
        [
            ContextFinding(
                InputKind.Baseline,
                "baseline:a",
                "src/old/a.env",
                startLine: 10),
            ContextFinding(
                InputKind.Baseline,
                "baseline:b",
                "src/old/b.env",
                startLine: 20),
        ];
        Finding[] candidate =
        [
            ContextFinding(
                InputKind.Candidate,
                "candidate:a",
                "src/new/a.env",
                startLine: 40),
            ContextFinding(
                InputKind.Candidate,
                "candidate:b",
                "src/new/b.env",
                startLine: 50),
        ];
        ResourceLimits limits = ResourceLimits.Default with
        {
            MaximumRejectedAlternatives = 1,
        };
        SarifRegressConfiguration configuration = MatchingTestData.Configuration(
            pathAliases: [new PathAlias("src/old/", "src/new/")],
            limits: limits);

        MatchResult forward = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration);
        MatchResult reversed = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline.Reverse().ToArray()),
            MatchingTestData.Input(InputKind.Candidate, candidate.Reverse().ToArray()),
            configuration);

        Assert.Equal(Project(forward), Project(reversed));
        Assert.Equal(2, forward.CandidateEdgeCount);
        Assert.All(
            forward.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Moved, decision.Classification);
                Assert.Equal(
                    PrecedenceTier.WeakContextual,
                    decision.Decision.PrecedenceTier);
                EvidenceRecord evidence = Assert.Single(
                    decision.Decision.Evidence);
                Assert.Equal(
                    "sarifregress/evidence-occurrence/v1",
                    evidence.AlgorithmVersion);
                Assert.Contains(
                    "collision",
                    evidence.Kind,
                    StringComparison.Ordinal);
                AssertClassificationTransformation(decision);
                Assert.Contains(
                    decision.Decision.Diagnostics,
                    diagnostic => diagnostic.Code == "MATCH0004");
            });
    }

    [Fact]
    public void Classification_transform_cap_retains_one_other_transform_without_duplication()
    {
        string baselinePath = "src/old/item.env";
        string candidatePath = "src/new/item.env";
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        ResourceLimits limits = ResourceLimits.Default with
        {
            MaximumRejectedAlternatives = 2,
        };
        MatchResult result = MatchOne(
            Finding(
                InputKind.Baseline,
                "baseline:one",
                baselinePath,
                Message(baselinePath),
                producerFingerprints: [fingerprint],
                pathTransformations:
                [
                    new TransformationRecord(
                        "zz-baseline-transform",
                        "before-baseline",
                        "after-baseline",
                        isLossy: false,
                        "test-transform/v1"),
                ]),
            Finding(
                InputKind.Candidate,
                "candidate:one",
                candidatePath,
                Message(candidatePath),
                producerFingerprints: [fingerprint],
                pathTransformations:
                [
                    new TransformationRecord(
                        "zz-candidate-transform",
                        "before-candidate",
                        "after-candidate",
                        isLossy: false,
                        "test-transform/v1"),
                ]),
            SimpleMoveConfiguration(limits));

        FindingDecision decision = Assert.Single(result.Decisions);
        Assert.Equal(2, decision.Decision.Transformations.Length);
        AssertClassificationTransformation(decision);
        Assert.Contains(
            decision.Decision.Transformations,
            transformation => transformation.Kind == "zz-baseline-transform");
        Assert.DoesNotContain(
            decision.Decision.Transformations,
            transformation => transformation.Kind == "zz-candidate-transform");
        Assert.Contains(
            decision.Decision.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0004");
    }

    private MatchResult MatchOne(
        Finding baseline,
        Finding candidate,
        SarifRegressConfiguration? configuration = null) =>
        matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration ?? SarifRegressConfiguration.Default);

    private static Finding Finding(
        InputKind input,
        string key,
        string path,
        string message,
        int startLine = 10,
        IEnumerable<ProducerFingerprint>? producerFingerprints = null,
        string? contextHash = null,
        IEnumerable<TransformationRecord>? pathTransformations = null) =>
        MatchingTestData.Finding(
            input,
            key,
            path: path,
            message: message,
            startLine: startLine,
            producerFingerprints: producerFingerprints,
            contextHash: contextHash,
            pathTransformations: pathTransformations);

    private static Finding ContextFinding(
        InputKind input,
        string key,
        string path,
        int startLine = 10) =>
        Finding(
            input,
            key,
            path,
            Message(path),
            startLine,
            contextHash: "REDACTED");

    private static string Message(string path) =>
        $"Synthetic check found a secret in file {path}.";

    private static SarifRegressConfiguration RenamedConfiguration() =>
        MatchingTestData.Configuration(
            pathAliases:
            [
                new PathAlias("src/renamed-old/", "src/renamed-new/"),
            ]);

    private static SarifRegressConfiguration SimpleMoveConfiguration(
        ResourceLimits? limits = null) =>
        MatchingTestData.Configuration(
            pathAliases:
            [
                new PathAlias("src/old/", "src/new/"),
            ],
            limits: limits);

    private static string[] Project(MatchResult result) =>
        result.Decisions
            .Select(decision =>
                $"{decision.Classification}|{decision.Baseline?.FindingKey}|"
                + $"{decision.Candidate?.FindingKey}|"
                + $"{decision.Decision.PrecedenceTier}|"
                + string.Join(
                    ";",
                    decision.Decision.Evidence.Select(evidence =>
                        $"{evidence.Kind}:{evidence.BaselineValue}:"
                        + $"{evidence.CandidateValue}:"
                        + $"{evidence.AlgorithmVersion}"))
                + "|"
                + string.Join(
                    ";",
                    decision.Decision.Transformations.Select(transformation =>
                        $"{transformation.Kind}:{transformation.OriginalValue}:"
                        + $"{transformation.TransformedValue}:"
                        + $"{transformation.AlgorithmVersion}")))
            .ToArray();

    private static void AssertClassificationTransformation(FindingDecision decision)
    {
        var transformation = Assert.Single(
            decision.Decision.Transformations,
            item => item.Kind == ClassificationTransformationKind);
        Assert.Equal(ClassificationAlgorithm, transformation.AlgorithmVersion);
        Assert.True(transformation.IsLossy);
        string originalValue = Assert.IsType<string>(transformation.OriginalValue);
        string transformedValue = Assert.IsType<string>(
            transformation.TransformedValue);
        Assert.StartsWith("sha256:", originalValue, StringComparison.Ordinal);
        Assert.StartsWith("sha256:", transformedValue, StringComparison.Ordinal);
        Assert.Equal(71, originalValue.Length);
        Assert.Equal(71, transformedValue.Length);
        Assert.NotEqual(originalValue, transformedValue);
    }
}
