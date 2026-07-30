using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Match;

namespace SarifRegress.UnitTests;

public sealed class AssignmentSolverTests
{
    private readonly FindingMatcher matcher = new();

    [Fact]
    public void Maximum_cardinality_solver_avoids_the_greedy_high_edge_trap()
    {
        var baselineOne = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src/shared.cs",
            message: "Weak pair.",
            derivedFingerprints:
            [
                MatchingTestData.DerivedFingerprint("exact-derived"),
            ]);
        var baselineTwo = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:two",
            path: "src/other.cs",
            message: "Flow pair.",
            codeFlowPaths: ["src/flow-anchor.cs"]);
        var candidateOne = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/shared.cs",
            message: "Different message.",
            derivedFingerprints:
            [
                MatchingTestData.DerivedFingerprint("exact-derived"),
            ],
            codeFlowPaths: ["src/flow-anchor.cs"]);
        var candidateTwo = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:two",
            path: "src/shared.cs",
            message: "Weak pair.");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baselineOne, baselineTwo),
            MatchingTestData.Input(InputKind.Candidate, candidateOne, candidateTwo),
            MatchingTestData.Configuration(allowWeakMessageSimilarity: true));

        Assert.Equal(2, result.Decisions.Length);
        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Baseline?.FindingKey == "baseline:one"
                && decision.Candidate?.FindingKey == "candidate:two");
        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Baseline?.FindingKey == "baseline:two"
                && decision.Candidate?.FindingKey == "candidate:one");
    }

    [Fact]
    public void Shuffling_canonical_input_arrays_does_not_change_decisions()
    {
        var baselineOne = ExactCanonical(
            InputKind.Baseline,
            "baseline:one",
            "src/one.cs",
            "derived-one");
        var baselineTwo = ExactCanonical(
            InputKind.Baseline,
            "baseline:two",
            "src/two.cs",
            "derived-two");
        var candidateOne = ExactCanonical(
            InputKind.Candidate,
            "candidate:one",
            "src/one.cs",
            "derived-one");
        var candidateTwo = ExactCanonical(
            InputKind.Candidate,
            "candidate:two",
            "src/two.cs",
            "derived-two");

        var ordered = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baselineOne, baselineTwo),
            MatchingTestData.Input(InputKind.Candidate, candidateOne, candidateTwo));
        var shuffled = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baselineTwo, baselineOne),
            MatchingTestData.Input(InputKind.Candidate, candidateTwo, candidateOne));

        Assert.Equal(ProjectDecisions(ordered), ProjectDecisions(shuffled));
        Assert.Equal(ordered.CandidateEdgeCount, shuffled.CandidateEdgeCount);
        Assert.Equal(ordered.ComponentCount, shuffled.ComponentCount);
    }

    [Fact]
    public void Independent_exact_pairs_preserve_component_and_explanation_contracts()
    {
        var firstFingerprint = MatchingTestData.ProducerFingerprint("first");
        var secondFingerprint = MatchingTestData.ProducerFingerprint("second");
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:first",
                    ruleId: "scanner/first",
                    producerFingerprints: [firstFingerprint]),
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:second",
                    ruleId: "scanner/second",
                    producerFingerprints: [secondFingerprint]),
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:resolved",
                    ruleId: "scanner/resolved")),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:second",
                    ruleId: "scanner/second",
                    producerFingerprints: [secondFingerprint]),
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:first",
                    ruleId: "scanner/first",
                    producerFingerprints: [firstFingerprint]),
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:new",
                    ruleId: "scanner/new")));

        Assert.Equal(2, result.CandidateEdgeCount);
        Assert.Equal(2, result.ComponentCount);
        Assert.Equal(0, result.AmbiguousComponentCount);
        var matches = result.Decisions
            .Where(decision =>
                decision.Baseline is not null
                && decision.Candidate is not null)
            .ToArray();
        Assert.Equal(2, matches.Length);
        Assert.All(
            matches,
            decision =>
            {
                Assert.Equal(
                    PrecedenceTier.ExactProducer,
                    decision.Decision.PrecedenceTier);
                Assert.Empty(decision.Decision.RejectedAlternatives);
            });
        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Baseline?.FindingKey == "baseline:resolved"
                && decision.Classification == FindingClassification.Resolved);
        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Candidate?.FindingKey == "candidate:new"
                && decision.Classification == FindingClassification.New);
    }

    [Fact]
    public void Single_residual_edge_preserves_exact_canonical_assignment()
    {
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                ExactCanonical(
                    InputKind.Baseline,
                    "baseline:one",
                    "src/one.cs",
                    "derived")),
            MatchingTestData.Input(
                InputKind.Candidate,
                ExactCanonical(
                    InputKind.Candidate,
                    "candidate:one",
                    "src/one.cs",
                    "derived")));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(1, result.CandidateEdgeCount);
        Assert.Equal(1, result.ComponentCount);
        Assert.Equal(FindingClassification.Unchanged, decision.Classification);
        Assert.Equal(
            PrecedenceTier.ExactCanonical,
            decision.Decision.PrecedenceTier);
        Assert.Empty(decision.Decision.RejectedAlternatives);
    }

    [Fact]
    public void One_to_two_equal_optimum_is_refused_without_using_stable_keys()
    {
        var baseline = TiedFinding(InputKind.Baseline, "baseline:one");
        var candidateOne = TiedFinding(InputKind.Candidate, "candidate:a");
        var candidateTwo = TiedFinding(InputKind.Candidate, "candidate:z");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidateTwo, candidateOne));

        AssertAmbiguous(result, expectedDecisionCount: 3);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0001");
    }

    [Fact]
    public void Two_to_two_equal_optimum_is_refused()
    {
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one"),
                TiedFinding(InputKind.Baseline, "baseline:two")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one"),
                TiedFinding(InputKind.Candidate, "candidate:two")));

        AssertAmbiguous(result, expectedDecisionCount: 4);
    }

    [Fact]
    public void Many_to_one_equal_optimum_is_refused()
    {
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one"),
                TiedFinding(InputKind.Baseline, "baseline:two")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one")));

        AssertAmbiguous(result, expectedDecisionCount: 3);
    }

    [Fact]
    public void Oversized_component_is_refused_before_exact_solving()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumAssignmentSideSize = 1,
        };
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one"),
                TiedFinding(InputKind.Baseline, "baseline:two")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one"),
                TiedFinding(InputKind.Candidate, "candidate:two")),
            MatchingTestData.Configuration(limits: limits));

        AssertAmbiguous(result, expectedDecisionCount: 4);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0002");
    }

    [Fact]
    public void Matcher_v1_rejects_an_assignment_side_limit_above_twelve()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumAssignmentSideSize =
                ResourceLimits.HardMaximumAssignmentSideSize + 1,
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            matcher.Match(
                MatchingTestData.Input(InputKind.Baseline),
                MatchingTestData.Input(InputKind.Candidate),
                MatchingTestData.Configuration(limits: limits)));

        Assert.Equal("MaximumAssignmentSideSize", exception.ParamName);
    }

    [Fact]
    public void Oversized_coarse_bucket_is_refused_before_any_edge_is_scored()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 4,
            MaximumCandidatePairEvaluationsPerFinding = 4,
            MaximumCandidatePairEvaluations = 10_000,
        };
        var candidates = Enumerable.Range(0, 1_000)
            .Select(index => TiedFinding(
                InputKind.Candidate,
                $"candidate:{index:D4}"))
            .ToArray();

        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one")),
            MatchingTestData.Input(InputKind.Candidate, candidates),
            MatchingTestData.Configuration(limits: limits));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(1_001, result.Decisions.Length);
        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.Equal(
                    FindingClassification.Ambiguous,
                    decision.Classification);
                Assert.True(decision.Decision.Ambiguous);
                Assert.Equal(PrecedenceTier.Refuse, decision.Decision.PrecedenceTier);
                Assert.Empty(decision.Decision.Diagnostics);
            });
        AssertGlobalPreflightRefusal(result, "MATCH0007");
    }

    [Fact]
    public void Comparison_wide_pair_budget_refuses_before_edge_scoring()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 3,
            MaximumCandidatePairEvaluationsPerFinding = 3,
            MaximumCandidatePairEvaluations = 5,
        };
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one"),
                TiedFinding(InputKind.Baseline, "baseline:two")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one"),
                TiedFinding(InputKind.Candidate, "candidate:two"),
                TiedFinding(InputKind.Candidate, "candidate:three")),
            MatchingTestData.Configuration(limits: limits));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.All(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Ambiguous,
                decision.Classification));
        AssertGlobalPreflightRefusal(result, "MATCH0008");
    }

    [Fact]
    public void Incoming_pair_pressure_is_bounded_before_edge_scoring()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 2,
            MaximumCandidatePairEvaluationsPerFinding = 2,
            MaximumCandidatePairEvaluations = 10,
        };
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one"),
                TiedFinding(InputKind.Baseline, "baseline:two"),
                TiedFinding(InputKind.Baseline, "baseline:three")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one")),
            MatchingTestData.Configuration(limits: limits));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.All(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Ambiguous,
                decision.Classification));
        AssertGlobalPreflightRefusal(result, "MATCH0009");
    }

    [Fact]
    public void Incoming_retained_edge_cap_refuses_the_complete_component()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 1,
            MaximumCandidatePairEvaluationsPerFinding = 10,
            MaximumCandidatePairEvaluations = 10,
        };
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one"),
                TiedFinding(InputKind.Baseline, "baseline:two")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one")),
            MatchingTestData.Configuration(limits: limits));

        Assert.Equal(2, result.CandidateEdgeCount);
        AssertAmbiguous(result, expectedDecisionCount: 3);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0010");
    }

    [Fact]
    public void Candidate_edge_overflow_refuses_the_complete_component()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 1,
        };
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one"),
                TiedFinding(InputKind.Candidate, "candidate:two")),
            MatchingTestData.Configuration(limits: limits));

        AssertAmbiguous(result, expectedDecisionCount: 3);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0003");
    }

    [Fact]
    public void Indisputable_unique_producer_match_is_committed_before_edge_cap_refusal()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 1,
        };
        var fingerprint = MatchingTestData.ProducerFingerprint("indisputable");
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFingerprints: [fingerprint],
            contextHash: "shared-context");
        var exactCandidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:exact",
            producerFingerprints: [fingerprint],
            contextHash: "shared-context");
        var contextualCandidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:contextual",
            contextHash: "shared-context");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(
                InputKind.Candidate,
                contextualCandidate,
                exactCandidate),
            MatchingTestData.Configuration(limits: limits));

        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Baseline?.FindingKey == "baseline:one"
                && decision.Candidate?.FindingKey == "candidate:exact"
                && decision.Decision.PrecedenceTier == PrecedenceTier.ExactProducer);
        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Candidate?.FindingKey == "candidate:contextual"
                && decision.Classification == FindingClassification.New);
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Classification == FindingClassification.Ambiguous);
    }

    [Fact]
    public void Indisputable_unique_producer_match_is_committed_before_incoming_cap_refusal()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = 1,
        };
        var fingerprint = MatchingTestData.ProducerFingerprint("indisputable");
        var exactBaseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:exact",
            producerFingerprints: [fingerprint],
            contextHash: "shared-context");
        var contextualBaseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:contextual",
            contextHash: "shared-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFingerprints: [fingerprint],
            contextHash: "shared-context");

        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                contextualBaseline,
                exactBaseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(limits: limits));

        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Baseline?.FindingKey == "baseline:exact"
                && decision.Candidate?.FindingKey == "candidate:one"
                && decision.Decision.PrecedenceTier == PrecedenceTier.ExactProducer);
        Assert.Contains(
            result.Decisions,
            decision =>
                decision.Baseline?.FindingKey == "baseline:contextual"
                && decision.Classification == FindingClassification.Resolved);
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Classification == FindingClassification.Ambiguous);
    }

    [Fact]
    public void Decision_explanations_and_rejections_are_capped()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRejectedAlternatives = 1,
        };
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                TiedFinding(InputKind.Baseline, "baseline:one")),
            MatchingTestData.Input(
                InputKind.Candidate,
                TiedFinding(InputKind.Candidate, "candidate:one"),
                TiedFinding(InputKind.Candidate, "candidate:two"),
                TiedFinding(InputKind.Candidate, "candidate:three")),
            MatchingTestData.Configuration(limits: limits));

        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.True(decision.Decision.Evidence.Length <= 1);
                Assert.True(decision.Decision.RejectedAlternatives.Length <= 1);
            });
        Assert.Contains(
            result.Decisions.SelectMany(decision => decision.Decision.Diagnostics),
            diagnostic => diagnostic.Code == "MATCH0004");
    }

    private static Finding ExactCanonical(
        InputKind input,
        string key,
        string path,
        string derivedValue) =>
        MatchingTestData.Finding(
            input,
            key,
            path: path,
            derivedFingerprints:
            [
                MatchingTestData.DerivedFingerprint(derivedValue),
            ]);

    private static Finding TiedFinding(InputKind input, string key) =>
        MatchingTestData.Finding(
            input,
            key,
            contextHash: "shared-context");

    private static string[] ProjectDecisions(MatchResult result) =>
        result.Decisions
            .Select(decision =>
                $"{decision.Classification}|"
                + $"{decision.Baseline?.FindingKey}|"
                + $"{decision.Candidate?.FindingKey}|"
                + $"{decision.Decision.PrecedenceTier}|"
                + $"{decision.Decision.Ambiguous}")
            .ToArray();

    private static void AssertAmbiguous(MatchResult result, int expectedDecisionCount)
    {
        Assert.Equal(expectedDecisionCount, result.Decisions.Length);
        Assert.All(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Ambiguous,
                decision.Classification));
    }

    private static void AssertGlobalPreflightRefusal(
        MatchResult result,
        string diagnosticCode)
    {
        Assert.All(
            result.Decisions,
            decision => Assert.Empty(decision.Decision.Diagnostics));
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == diagnosticCode);
        Assert.Null(diagnostic.SourceReference);
    }
}
