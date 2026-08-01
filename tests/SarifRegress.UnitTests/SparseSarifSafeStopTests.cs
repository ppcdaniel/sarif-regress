using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Match;

namespace SarifRegress.UnitTests;

public sealed class SparseSarifSafeStopTests
{
    private readonly FindingMatcher matcher = new();

    [Fact]
    public void Default_policy_does_not_match_one_exact_sparse_signature()
    {
        MatchResult result = Match(
            [SparseFinding(InputKind.Baseline, "baseline:one")],
            [SparseFinding(InputKind.Candidate, "candidate:one")]);

        AssertNoMatch(result);
    }

    [Fact]
    public void Default_policy_does_not_match_same_message_in_different_files()
    {
        MatchResult result = Match(
            [SparseFinding(
                InputKind.Baseline,
                "baseline:one",
                path: "src/first.java")],
            [SparseFinding(
                InputKind.Candidate,
                "candidate:one",
                path: "src/second.java")]);

        AssertNoMatch(result);
    }

    [Fact]
    public void Default_policy_does_not_match_same_message_in_different_regions()
    {
        MatchResult result = Match(
            [SparseFinding(InputKind.Baseline, "baseline:one", startLine: 34)],
            [SparseFinding(InputKind.Candidate, "candidate:one", startLine: 35)]);

        AssertNoMatch(result);
    }

    [Fact]
    public void Default_policy_does_not_match_different_exact_messages_on_the_same_path()
    {
        MatchResult result = Match(
            [SparseFinding(
                InputKind.Baseline,
                "baseline:one",
                message: "First exact message.")],
            [SparseFinding(
                InputKind.Candidate,
                "candidate:one",
                message: "Second exact message.")]);

        AssertNoMatch(result);
    }

    [Fact]
    public void Default_policy_does_not_infer_pairs_across_duplicate_sparse_signatures()
    {
        Finding[] baseline =
        [
            SparseFinding(InputKind.Baseline, "baseline:one"),
            SparseFinding(InputKind.Baseline, "baseline:two"),
        ];
        Finding[] candidate =
        [
            SparseFinding(InputKind.Candidate, "candidate:one"),
            SparseFinding(InputKind.Candidate, "candidate:two"),
        ];

        MatchResult result = Match(baseline, candidate);
        MatchResult reversed = Match(
            baseline.Reverse().ToArray(),
            candidate.Reverse().ToArray());

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(4, result.Decisions.Length);
        Assert.Equal(
            2,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.Equal(
            2,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.All(result.Decisions, AssertOneSidedAndNoSparseTier);
        Assert.Equal(Project(result), Project(reversed));
    }

    [Fact]
    public void Duplicate_sparse_ambiguity_is_input_order_invariant_under_explicit_weak_mode()
    {
        Finding[] baseline =
        [
            SparseFinding(InputKind.Baseline, "baseline:one"),
            SparseFinding(InputKind.Baseline, "baseline:two"),
        ];
        Finding[] candidate =
        [
            SparseFinding(InputKind.Candidate, "candidate:one"),
            SparseFinding(InputKind.Candidate, "candidate:two"),
        ];
        SarifRegressConfiguration configuration = MatchingTestData.Configuration(
            allowWeakMessageSimilarity: true);

        MatchResult ordered = Match(baseline, candidate, configuration);
        MatchResult reversed = Match(
            baseline.Reverse().ToArray(),
            candidate.Reverse().ToArray(),
            configuration);

        Assert.Equal(4, ordered.CandidateEdgeCount);
        Assert.Equal(1, ordered.AmbiguousComponentCount);
        Assert.All(
            ordered.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Ambiguous, decision.Classification);
                Assert.True(decision.Decision.Ambiguous);
                AssertOneSidedAndNoSparseTier(decision);
            });
        Assert.Contains(
            ordered.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0001");
        Assert.Equal(Project(ordered), Project(reversed));
    }

    private MatchResult Match(
        Finding[] baseline,
        Finding[] candidate,
        SarifRegressConfiguration? configuration = null) =>
        matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration);

    private static Finding SparseFinding(
        InputKind input,
        string key,
        string path = "src/repeated.java",
        string message = "Avoid the controlled call.",
        int startLine = 34) =>
        MatchingTestData.Finding(
            input,
            key,
            path: path,
            message: message,
            producerFamily: "general-static-analyser",
            toolName: "General Static Analyser",
            ruleId: "general/exact-location",
            startLine: startLine,
            producerFingerprints: null,
            derivedFingerprints: null,
            contextHash: null,
            tokenWindowHash: null,
            enclosingSymbol: null);

    private static void AssertNoMatch(MatchResult result)
    {
        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(2, result.Decisions.Length);
        Assert.Single(
            result.Decisions,
            decision => decision.Classification == FindingClassification.Resolved);
        Assert.Single(
            result.Decisions,
            decision => decision.Classification == FindingClassification.New);
        Assert.All(result.Decisions, AssertOneSidedAndNoSparseTier);
    }

    private static void AssertOneSidedAndNoSparseTier(FindingDecision decision)
    {
        Assert.True((decision.Baseline is null) != (decision.Candidate is null));
        Assert.False(ContainsSparseContinuity(
            decision.Decision.PrecedenceTier.ToString()));
        Assert.DoesNotContain(
            decision.Decision.Evidence,
            evidence => ContainsSparseContinuity(evidence.Kind)
                || ContainsSparseContinuity(evidence.AlgorithmVersion));
    }

    private static bool ContainsSparseContinuity(string value) =>
        value.Contains("sparse", StringComparison.OrdinalIgnoreCase);

    private static string[] Project(MatchResult result) =>
        result.Decisions
            .Select(decision =>
                $"{decision.Classification}|{decision.Baseline?.FindingKey}|"
                + $"{decision.Candidate?.FindingKey}|{decision.Decision.PrecedenceTier}|"
                + $"{decision.Decision.Ambiguous}")
            .Concat(result.Diagnostics.Select(diagnostic =>
                $"{diagnostic.Code}|{diagnostic.Message}"))
            .ToArray();
}
