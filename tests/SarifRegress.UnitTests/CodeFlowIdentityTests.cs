using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Match;

namespace SarifRegress.UnitTests;

public sealed class CodeFlowIdentityTests
{
    private const string SharedContext = "shared-independent-context";

    private readonly FindingMatcher matcher = new();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unique_code_flow_does_not_override_primary_path_or_message_conflict(
        bool keepPrimaryPath)
    {
        var baseline = CodeFlowFinding(
            InputKind.Baseline,
            "baseline:one",
            "src/baseline.cs",
            "Baseline message.",
            ["src/shared-sink.cs"]);
        var candidate = CodeFlowFinding(
            InputKind.Candidate,
            "candidate:one",
            keepPrimaryPath ? "src/baseline.cs" : "src/candidate.cs",
            "Candidate message.",
            ["src/shared-sink.cs"]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        AssertNoCorrespondence(result, baselineCount: 1, candidateCount: 1);
    }

    [Fact]
    public void Collided_helpers_and_sinks_cannot_rank_an_otherwise_ambiguous_component()
    {
        var baseline = CollisionPattern(InputKind.Baseline);
        var candidate = CollisionPattern(InputKind.Candidate);

        var ordered = Match(baseline, candidate);
        var reversed = Match(
            baseline.Reverse().ToArray(),
            candidate.Reverse().ToArray());

        Assert.Equal(Project(ordered), Project(reversed));
        Assert.Equal(9, ordered.CandidateEdgeCount);
        Assert.All(
            ordered.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Ambiguous, decision.Classification);
                Assert.True(decision.Decision.Ambiguous);
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "code-flow-anchor-collision"
                        && evidence.AlgorithmVersion
                            == "sarifregress/code-flow-occurrence/v1"
                        && evidence.Lossy);
            });
    }

    [Fact]
    public void Unique_code_flow_can_rank_edges_admitted_by_independent_context()
    {
        var baseline = new[]
        {
            CollisionFinding(InputKind.Baseline, "baseline:a", ["src/helper-a.cs"]),
            CollisionFinding(InputKind.Baseline, "baseline:b", ["src/helper-b.cs"]),
        };
        var candidate = new[]
        {
            CollisionFinding(InputKind.Candidate, "candidate:a", ["src/helper-a.cs"]),
            CollisionFinding(InputKind.Candidate, "candidate:b", ["src/helper-b.cs"]),
        };

        var result = Match(baseline, candidate);

        Assert.Equal(4, result.CandidateEdgeCount);
        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Unchanged, decision.Classification);
                Assert.Equal(
                    decision.Baseline!.FindingKey["baseline:".Length..],
                    decision.Candidate!.FindingKey["candidate:".Length..]);
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "code-flow");
            });
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 1)]
    public void Repeated_helper_one_to_many_and_many_to_one_create_no_edges(
        int baselineCount,
        int candidateCount)
    {
        var baseline = Enumerable.Range(0, baselineCount)
            .Select(index => CodeFlowFinding(
                InputKind.Baseline,
                $"baseline:{index}",
                $"src/baseline-{index}.cs",
                $"Baseline {index}.",
                ["src/common-helper.cs"]))
            .ToArray();
        var candidate = Enumerable.Range(0, candidateCount)
            .Select(index => CodeFlowFinding(
                InputKind.Candidate,
                $"candidate:{index}",
                $"src/candidate-{index}.cs",
                $"Candidate {index}.",
                ["src/common-helper.cs"]))
            .ToArray();

        var ordered = Match(baseline, candidate);
        var reversed = Match(
            baseline.Reverse().ToArray(),
            candidate.Reverse().ToArray());

        Assert.Equal(Project(ordered), Project(reversed));
        AssertNoCorrespondence(ordered, baselineCount, candidateCount);
        FindingDecision[] repeatedSide = baselineCount > 1
            ? ordered.Decisions.Where(decision => decision.Baseline is not null).ToArray()
            : ordered.Decisions.Where(decision => decision.Candidate is not null).ToArray();
        Assert.All(
            repeatedSide,
            decision => Assert.Contains(
                decision.Decision.Evidence,
                evidence => evidence.Kind == "code-flow-anchor-collision"
                    && evidence.AlgorithmVersion
                        == "sarifregress/code-flow-occurrence/v1"
                    && evidence.Lossy));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 1)]
    public void Collided_anchor_cannot_rank_independently_admitted_asymmetric_edges(
        int baselineCount,
        int candidateCount)
    {
        Finding[] baseline = AmbiguousCollisionSide(InputKind.Baseline, baselineCount);
        Finding[] candidate = AmbiguousCollisionSide(InputKind.Candidate, candidateCount);

        MatchResult ordered = Match(baseline, candidate);
        MatchResult reversed = Match(
            baseline.Reverse().ToArray(),
            candidate.Reverse().ToArray());

        Assert.Equal(Project(ordered), Project(reversed));
        Assert.Equal(2, ordered.CandidateEdgeCount);
        Assert.All(
            ordered.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Ambiguous, decision.Classification);
                Assert.True(decision.Decision.Ambiguous);
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "code-flow-anchor-collision"
                        && evidence.AlgorithmVersion
                            == "sarifregress/code-flow-occurrence/v1");
            });
    }

    [Fact]
    public void Explanation_cap_retains_code_flow_occurrence_evidence()
    {
        Finding[] baseline =
        [
            CollisionFinding(
                InputKind.Baseline,
                "baseline:a",
                ["src/common-helper.cs"],
                contextHash: "context-a"),
            CollisionFinding(
                InputKind.Baseline,
                "baseline:b",
                ["src/common-helper.cs"],
                contextHash: "context-b"),
        ];
        Finding[] candidate =
        [
            CollisionFinding(
                InputKind.Candidate,
                "candidate:a",
                ["src/common-helper.cs"],
                contextHash: "context-a"),
            CollisionFinding(
                InputKind.Candidate,
                "candidate:b",
                ["src/common-helper.cs"],
                contextHash: "context-b"),
        ];
        ResourceLimits limits = ResourceLimits.Default with
        {
            MaximumRejectedAlternatives = 1,
        };

        MatchResult result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(limits: limits));

        Assert.Equal(2, result.CandidateEdgeCount);
        Assert.All(
            result.Decisions,
            decision =>
            {
                EvidenceRecord evidence = Assert.Single(decision.Decision.Evidence);
                Assert.Equal(
                    "sarifregress/code-flow-occurrence/v1",
                    evidence.AlgorithmVersion);
                Assert.Equal("code-flow-anchor-collision", evidence.Kind);
                Assert.Contains(
                    decision.Decision.Diagnostics,
                    diagnostic => diagnostic.Code == "MATCH0004");
            });
    }

    private MatchResult Match(Finding[] baseline, Finding[] candidate) =>
        matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

    private static Finding[] CollisionPattern(InputKind input) =>
    [
        CollisionFinding(input, $"{Prefix(input)}:a", ["src/helper-a.cs"]),
        CollisionFinding(
            input,
            $"{Prefix(input)}:ab",
            ["src/helper-a.cs", "src/helper-b.cs"]),
        CollisionFinding(input, $"{Prefix(input)}:b", ["src/helper-b.cs"]),
    ];

    private static Finding[] AmbiguousCollisionSide(InputKind input, int count) =>
        Enumerable.Range(0, count)
            .Select(index => CollisionFinding(
                input,
                $"{Prefix(input)}:{index}",
                index == 0
                    ? ["src/common-helper.cs"]
                    : ["src/common-helper.cs", "src/side-only-helper.cs"]))
            .ToArray();

    private static Finding CollisionFinding(
        InputKind input,
        string key,
        string[] codeFlowPaths,
        string contextHash = SharedContext) =>
        CodeFlowFinding(
            input,
            key,
            "src/shared.cs",
            "Shared message.",
            codeFlowPaths,
            contextHash);

    private static Finding CodeFlowFinding(
        InputKind input,
        string key,
        string path,
        string message,
        string[] codeFlowPaths,
        string? contextHash = null) =>
        MatchingTestData.Finding(
            input,
            key,
            path: path,
            message: message,
            ruleId: "scanner/shared-flow",
            contextHash: contextHash,
            codeFlowPaths: codeFlowPaths);

    private static void AssertNoCorrespondence(
        MatchResult result,
        int baselineCount,
        int candidateCount)
    {
        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(
            baselineCount,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.Equal(
            candidateCount,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Baseline is not null && decision.Candidate is not null);
    }

    private static string[] Project(MatchResult result) =>
        result.Decisions
            .Select(decision =>
                $"{decision.Classification}|{decision.Baseline?.FindingKey}|"
                + $"{decision.Candidate?.FindingKey}|{decision.Decision.Ambiguous}|"
                + string.Join(
                    ";",
                    decision.Decision.Evidence.Select(evidence =>
                        $"{evidence.Kind}:{evidence.BaselineValue}:"
                        + $"{evidence.CandidateValue}:{evidence.AlgorithmVersion}")))
            .Concat(result.Diagnostics.Select(diagnostic =>
                $"{diagnostic.Code}|{diagnostic.Message}"))
            .ToArray();

    private static string Prefix(InputKind input) =>
        input == InputKind.Baseline ? "baseline" : "candidate";
}
