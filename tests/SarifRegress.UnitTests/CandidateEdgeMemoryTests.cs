using System.Collections.Immutable;
using System.Diagnostics;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Match;

namespace SarifRegress.UnitTests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CandidateEdgeMemoryTestCollection
{
    public const string Name = "Candidate-edge memory stress";
}

[Collection(CandidateEdgeMemoryTestCollection.Name)]
public sealed class CandidateEdgeMemoryTests
{
    private const int FindingsPerBucketPerSide = 64;
    private const int CandidatePairsPerBucket =
        FindingsPerBucketPerSide * FindingsPerBucketPerSide;
    private const int ResidualFindingsPerBucketPerSide = 24;
    private const int ResidualCandidatePairs =
        ResidualFindingsPerBucketPerSide * ResidualFindingsPerBucketPerSide;
    private const int RetainedEdgesPerFinding = 1;

    [Fact]
    public void Many_small_buckets_at_the_global_cap_remain_bounded_and_complete()
    {
        var fullBucketCount = checked((int)(
            ResourceLimits.DefaultMaximumCandidatePairEvaluations
            / CandidatePairsPerBucket));
        var bucketCount = fullBucketCount + 1;
        var findingsPerSide = fullBucketCount * FindingsPerBucketPerSide
            + ResidualFindingsPerBucketPerSide;
        var baselineFindings = new List<Finding>(findingsPerSide);
        var candidateFindings = new List<Finding>(findingsPerSide);
        for (var bucketIndex = 0; bucketIndex < fullBucketCount; bucketIndex++)
        {
            AddBucketFindings(
                baselineFindings,
                InputKind.Baseline,
                "baseline",
                bucketIndex,
                FindingsPerBucketPerSide);
            AddBucketFindings(
                candidateFindings,
                InputKind.Candidate,
                "candidate",
                bucketIndex,
                FindingsPerBucketPerSide);
        }

        AddBucketFindings(
            baselineFindings,
            InputKind.Baseline,
            "baseline",
            fullBucketCount,
            ResidualFindingsPerBucketPerSide);
        AddBucketFindings(
            candidateFindings,
            InputKind.Candidate,
            "candidate",
            fullBucketCount,
            ResidualFindingsPerBucketPerSide);

        var limits = ResourceLimits.Default with
        {
            MaximumCandidateEdgesPerFinding = RetainedEdgesPerFinding,
            MaximumCandidatePairEvaluationsPerFinding = FindingsPerBucketPerSide,
        };
        var allocatedBytesBefore = GC.GetTotalAllocatedBytes(precise: true);
        var stopwatch = Stopwatch.StartNew();
        var materializedEdgeCount = 0;

        var result = new FindingMatcher(() => materializedEdgeCount++).Match(
            MatchingTestData.Input(InputKind.Baseline, baselineFindings.ToArray()),
            MatchingTestData.Input(InputKind.Candidate, candidateFindings.ToArray()),
            MatchingTestData.Configuration(
                allowWeakMessageSimilarity: true,
                limits: limits));

        stopwatch.Stop();
        var allocatedBytes = GC.GetTotalAllocatedBytes(precise: true)
            - allocatedBytesBefore;
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        TestContext.Current.TestOutputHelper?.WriteLine(
            "candidatePairs={0}; buckets={1}; elapsedMilliseconds={2:F3}; "
            + "allocatedBytesProxy={3}; peakWorkingSetBytes={4}",
            result.CandidateEdgeCount,
            bucketCount,
            stopwatch.Elapsed.TotalMilliseconds,
            allocatedBytes,
            process.PeakWorkingSet64);

        var expectedCandidatePairCount = fullBucketCount * CandidatePairsPerBucket
            + ResidualCandidatePairs;
        Assert.Equal(
            ResourceLimits.DefaultMaximumCandidatePairEvaluations,
            expectedCandidatePairCount);
        Assert.Equal(expectedCandidatePairCount, result.CandidateEdgeCount);
        Assert.Equal(findingsPerSide, materializedEdgeCount);
        Assert.True(materializedEdgeCount < result.CandidateEdgeCount / 10);
        Assert.Equal(bucketCount, result.ComponentCount);
        Assert.Equal(bucketCount, result.AmbiguousComponentCount);
        Assert.Equal(findingsPerSide * 2, result.Decisions.Length);
        Assert.All(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Ambiguous,
                decision.Classification));
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0003");
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0010");
    }

    [Fact]
    public void Compact_descriptor_order_matches_full_edge_retention_order()
    {
        ImmutableArray<Finding> baselines =
        [
            MatchingTestData.Finding(InputKind.Baseline, "baseline:z", ruleId: "rule"),
            MatchingTestData.Finding(InputKind.Baseline, "baseline:a", ruleId: "rule"),
        ];
        ImmutableArray<Finding> candidates =
        [
            MatchingTestData.Finding(InputKind.Candidate, "candidate:y", ruleId: "rule"),
            MatchingTestData.Finding(InputKind.Candidate, "candidate:b", ruleId: "rule"),
            MatchingTestData.Finding(InputKind.Candidate, "candidate:x", ruleId: "rule"),
        ];
        DecisionVector exactProducer = new(
            PrecedenceTier.ExactProducer,
            ProducerFingerprintStrength: 2,
            PathMatchKind.Exact,
            AgreementBand.Exact,
            AgreementBand.Exact,
            AgreementBand.Exact,
            RegionDriftBand: 3);
        DecisionVector strongMoved = new(
            PrecedenceTier.StrongMoved,
            ProducerFingerprintStrength: 0,
            PathMatchKind.Aliased,
            AgreementBand.Exact,
            AgreementBand.Compatible,
            AgreementBand.Exact,
            RegionDriftBand: 2);
        TestEdge[] testEdges =
        [
            CreateTestEdge(0, 0, exactProducer, baselines, candidates),
            CreateTestEdge(0, 1, exactProducer, baselines, candidates),
            CreateTestEdge(1, 2, exactProducer, baselines, candidates),
            CreateTestEdge(1, 0, strongMoved, baselines, candidates),
        ];
        int[] exactCountsByBaseline = [2, 1];
        int[] exactCountsByCandidate = [1, 1, 1];
        var descriptorComparer = new FindingMatcher.CandidateEdgeDescriptorComparer(
            baselines,
            candidates,
            exactCountsByBaseline,
            exactCountsByCandidate);

        (int BaselineIndex, int CandidateIndex)[] expected = testEdges
            .OrderByDescending(edge =>
                edge.Edge.DecisionVector.PrecedenceTier == PrecedenceTier.ExactProducer
                && exactCountsByBaseline[edge.BaselineIndex] == 1
                && exactCountsByCandidate[edge.CandidateIndex] == 1)
            .ThenBy(edge => edge.Edge, MatchEdgePreferenceComparer.Instance)
            .Select(edge => (edge.BaselineIndex, edge.CandidateIndex))
            .ToArray();
        (int BaselineIndex, int CandidateIndex)[] actual = testEdges
            .Select(edge => new FindingMatcher.CandidateEdgeDescriptor(
                edge.BaselineIndex,
                edge.CandidateIndex,
                edge.Edge.DecisionVector))
            .Order(descriptorComparer)
            .Select(edge => (edge.BaselineIndex, edge.CandidateIndex))
            .ToArray();

        Assert.Equal(expected, actual);
    }

    private static TestEdge CreateTestEdge(
        int baselineIndex,
        int candidateIndex,
        DecisionVector decisionVector,
        ImmutableArray<Finding> baselines,
        ImmutableArray<Finding> candidates)
    {
        Finding baseline = baselines[baselineIndex];
        Finding candidate = candidates[candidateIndex];
        string stableIdentity = string.Concat(
            CandidateEdgeFactory.CreateStableFindingKey(baseline.FindingKey),
            CandidateEdgeFactory.CreateStableFindingKey(candidate.FindingKey));
        return new TestEdge(
            baselineIndex,
            candidateIndex,
            new MatchEdge(
                baseline,
                candidate,
                decisionVector,
                stableIdentity,
                ImmutableArray<EvidenceRecord>.Empty,
                ImmutableArray<TransformationRecord>.Empty));
    }

    private static void AddBucketFindings(
        ICollection<Finding> findings,
        InputKind input,
        string side,
        int bucketIndex,
        int findingsPerBucket)
    {
        var bucketIdentity = bucketIndex.ToString("D4", System.Globalization.CultureInfo.InvariantCulture);
        for (var findingIndex = 0;
             findingIndex < findingsPerBucket;
             findingIndex++)
        {
            findings.Add(MatchingTestData.Finding(
                input,
                $"{side}:{bucketIdentity}:{findingIndex:D2}",
                ruleId: $"scanner/rule-{bucketIdentity}"));
        }
    }

    private sealed record TestEdge(
        int BaselineIndex,
        int CandidateIndex,
        MatchEdge Edge);
}
