using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Match;
using SarifRegress.Report;

namespace SarifRegress.PropertyTests;

public sealed class MatcherAndReportingPropertyTests
{
    private readonly FindingMatcher matcher = new();

    [Fact]
    public void Matcher_and_stable_json_are_invariant_under_all_input_permutations()
    {
        var baseline = Enumerable.Range(0, 3)
            .Select(index => PropertyTestData.Finding(
                InputKind.Baseline,
                $"baseline:{index:D2}",
                index,
                identityToken: $"identity-{index:D2}"))
            .ToArray();
        var candidate = Enumerable.Range(0, 3)
            .Select(index => PropertyTestData.Finding(
                InputKind.Candidate,
                $"candidate:{index:D2}",
                index,
                identityToken: $"identity-{index:D2}"))
            .ToArray();
        var baselinePermutations = PropertyTestData.Permutations(baseline);
        var candidatePermutations = PropertyTestData.Permutations(candidate);
        string? expectedMatchSignature = null;
        byte[]? expectedJson = null;
        string[] cultures = ["en-US", "tr-TR", "ar-SA"];

        for (var baselineIndex = 0;
             baselineIndex < baselinePermutations.Count;
             baselineIndex++)
        {
            for (var candidateIndex = 0;
                 candidateIndex < candidatePermutations.Count;
                 candidateIndex++)
            {
                var caseId = $"perm-{baselineIndex:D2}-{candidateIndex:D2}";
                var result = matcher.Match(
                    PropertyTestData.Input(
                        InputKind.Baseline,
                        baselinePermutations[baselineIndex]),
                    PropertyTestData.Input(
                        InputKind.Candidate,
                        candidatePermutations[candidateIndex]));

                PropertyTestData.AssertOneToOne(result, caseId);
                Assert.True(
                    result.Decisions.Length == 3,
                    $"case={caseId}; field=decision-count");
                Assert.True(
                    result.Decisions.All(
                        decision =>
                            decision.Classification ==
                            FindingClassification.Unchanged),
                    $"case={caseId}; field=classification");

                var signature = PropertyTestData.MatchSignature(result);
                expectedMatchSignature ??= signature;
                Assert.True(
                    string.Equals(
                        expectedMatchSignature,
                        signature,
                        StringComparison.Ordinal),
                    $"case={caseId}; field=matcher-output");

                var report = PropertyTestData.Report(result);
                var culture =
                    cultures[(baselineIndex + candidateIndex) % cultures.Length];
                byte[] json;
                byte[] repeated;
                using (new CultureScope(culture))
                {
                    json = StableJsonReportSerializer.Serialize(report);
                    repeated = StableJsonReportSerializer.Serialize(report);
                }

                expectedJson ??= json;
                Assert.True(
                    json.SequenceEqual(repeated),
                    $"case={caseId}; culture={culture}; field=repeated-json");
                Assert.True(
                    expectedJson.SequenceEqual(json),
                    $"case={caseId}; culture={culture}; field=permuted-json");
            }
        }

        var stableJson = expectedJson
            ?? throw new InvalidOperationException(
                "The exhaustive permutation set was unexpectedly empty.");
        Assert.True(
            stableJson[^1] == (byte)'\n',
            "case=stable-json; field=final-newline");
        Assert.True(
            !stableJson.Contains((byte)'\r'),
            "case=stable-json; field=line-endings");
        Assert.True(
            stableJson.Length < 3
            || stableJson[0] != 0xEF
            || stableJson[1] != 0xBB
            || stableJson[2] != 0xBF,
            "case=stable-json; field=bom");
    }

    [Fact]
    public void Equal_semantic_optima_remain_ambiguous_under_reversal()
    {
        (int BaselineCount, int CandidateCount)[] dimensions =
        [
            (1, 2),
            (2, 1),
            (2, 2),
            (2, 3),
            (3, 2),
            (3, 3),
        ];

        foreach (var dimension in dimensions)
        {
            var caseId =
                $"tie-{dimension.BaselineCount}x{dimension.CandidateCount}";
            var baseline = CreateTiedFindings(
                InputKind.Baseline,
                dimension.BaselineCount);
            var candidate = CreateTiedFindings(
                InputKind.Candidate,
                dimension.CandidateCount);
            var forward = matcher.Match(
                PropertyTestData.Input(InputKind.Baseline, baseline),
                PropertyTestData.Input(InputKind.Candidate, candidate));
            var reversed = matcher.Match(
                PropertyTestData.Input(InputKind.Baseline, baseline.Reverse()),
                PropertyTestData.Input(InputKind.Candidate, candidate.Reverse()));

            AssertAmbiguous(
                forward,
                dimension.BaselineCount + dimension.CandidateCount,
                $"{caseId}-forward");
            AssertAmbiguous(
                reversed,
                dimension.BaselineCount + dimension.CandidateCount,
                $"{caseId}-reverse");
            Assert.True(
                string.Equals(
                    PropertyTestData.MatchSignature(forward),
                    PropertyTestData.MatchSignature(reversed),
                    StringComparison.Ordinal),
                $"case={caseId}; field=permutation");
        }
    }

    private static Finding[] CreateTiedFindings(
        InputKind input,
        int count) =>
        Enumerable.Range(0, count)
            .Select(index => PropertyTestData.Finding(
                input,
                input == InputKind.Baseline
                    ? $"baseline:tie-{index:D2}"
                    : $"candidate:tie-{index:D2}",
                index,
                identityToken: null,
                contextHash: "shared-tie-context"))
            .ToArray();

    private static void AssertAmbiguous(
        MatchResult result,
        int expectedDecisionCount,
        string caseId)
    {
        PropertyTestData.AssertOneToOne(result, caseId);
        Assert.True(
            result.Decisions.Length == expectedDecisionCount,
            $"case={caseId}; field=decision-count");
        Assert.True(
            result.Decisions.All(
                decision =>
                    decision.Classification ==
                    FindingClassification.Ambiguous
                    && decision.Decision.Ambiguous),
            $"case={caseId}; field=classification");
        Assert.True(
            result.AmbiguousComponentCount == 1,
            $"case={caseId}; field=ambiguous-components");
    }
}
