using System.Collections.Immutable;
using SarifRegress.Core.Matching;

namespace SarifRegress.Match;

internal sealed record AssignmentSolution(
    ImmutableArray<MatchEdge> Edges,
    bool HasEqualOptimum);

internal sealed class BoundedAssignmentSolver
{
    private sealed record SolverState(
        AssignmentObjective Objective,
        ImmutableArray<MatchEdge> Edges,
        int OptimalAssignmentCount);

    private readonly ImmutableArray<int> baselineIndexes;
    private readonly Dictionary<int, int> candidateBitByIndex;
    private readonly Dictionary<int, ImmutableArray<MatchEdge>> edgesByBaseline;
    private readonly Dictionary<(int BaselinePosition, int UsedCandidateMask), SolverState> memo =
        [];

    public BoundedAssignmentSolver(
        ImmutableArray<int> baselineIndexes,
        ImmutableArray<int> candidateIndexes,
        IEnumerable<MatchEdge> componentEdges,
        IReadOnlyDictionary<string, int> baselineIndexByKey,
        IReadOnlyDictionary<string, int> candidateIndexByKey)
    {
        this.baselineIndexes = baselineIndexes;
        candidateBitByIndex = candidateIndexes
            .Select((candidateIndex, bit) => (candidateIndex, bit))
            .ToDictionary(item => item.candidateIndex, item => item.bit);

        edgesByBaseline = componentEdges
            .GroupBy(edge => baselineIndexByKey[edge.Baseline.FindingKey])
            .ToDictionary(
                group => group.Key,
                group => group
                    .Where(edge => candidateBitByIndex.ContainsKey(
                        candidateIndexByKey[edge.Candidate.FindingKey]))
                    .Order(MatchEdgePreferenceComparer.Instance)
                    .ToImmutableArray());

        CandidateIndexByKey = candidateIndexByKey;
    }

    private IReadOnlyDictionary<string, int> CandidateIndexByKey { get; }

    /// <summary>
    /// Finds the maximum-cardinality assignment and then compares the sorted multiset of
    /// semantic decision vectors lexicographically. Stable keys choose only a representative
    /// after semantic equality has already been recorded as ambiguity.
    /// </summary>
    // Time: O(B² × C × 2^C); Space: O(B² × 2^C), with both sides hard-bounded by configuration.
    public AssignmentSolution Solve()
    {
        var state = SolveState(baselinePosition: 0, usedCandidateMask: 0);
        return new AssignmentSolution(
            state.Edges
                .OrderBy(edge => edge.Baseline.FindingKey, StringComparer.Ordinal)
                .ThenBy(edge => edge.Candidate.FindingKey, StringComparer.Ordinal)
                .ToImmutableArray(),
            state.OptimalAssignmentCount > 1);
    }

    private SolverState SolveState(int baselinePosition, int usedCandidateMask)
    {
        if (baselinePosition == baselineIndexes.Length)
        {
            return new SolverState(
                AssignmentObjective.Empty,
                ImmutableArray<MatchEdge>.Empty,
                OptimalAssignmentCount: 1);
        }

        var memoKey = (baselinePosition, usedCandidateMask);
        if (memo.TryGetValue(memoKey, out var cached))
        {
            return cached;
        }

        var best = SolveState(baselinePosition + 1, usedCandidateMask);
        var baselineIndex = baselineIndexes[baselinePosition];

        if (edgesByBaseline.TryGetValue(baselineIndex, out var availableEdges))
        {
            foreach (var edge in availableEdges)
            {
                var candidateIndex = CandidateIndexByKey[edge.Candidate.FindingKey];
                var candidateBit = 1 << candidateBitByIndex[candidateIndex];
                if ((usedCandidateMask & candidateBit) != 0)
                {
                    continue;
                }

                var child = SolveState(
                    baselinePosition + 1,
                    usedCandidateMask | candidateBit);
                var candidateState = new SolverState(
                    child.Objective.Add(edge.DecisionVector),
                    child.Edges.Add(edge),
                    child.OptimalAssignmentCount);
                best = SelectBetter(best, candidateState);
            }
        }

        memo[memoKey] = best;
        return best;
    }

    private static SolverState SelectBetter(SolverState current, SolverState candidate)
    {
        var comparison = AssignmentObjectiveComparer.Instance.Compare(
            candidate.Objective,
            current.Objective);
        if (comparison > 0)
        {
            return candidate;
        }

        if (comparison < 0)
        {
            return current;
        }

        var optimalAssignmentCount = Math.Min(
            2,
            current.OptimalAssignmentCount + candidate.OptimalAssignmentCount);
        return CompareRepresentativeAssignments(candidate.Edges, current.Edges) < 0
            ? candidate with { OptimalAssignmentCount = optimalAssignmentCount }
            : current with { OptimalAssignmentCount = optimalAssignmentCount };
    }

    private static int CompareRepresentativeAssignments(
        ImmutableArray<MatchEdge> left,
        ImmutableArray<MatchEdge> right)
    {
        var leftKeys = left
            .Select(edge => edge.StableIdentityKey)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var rightKeys = right
            .Select(edge => edge.StableIdentityKey)
            .Order(StringComparer.Ordinal)
            .ToArray();

        for (var index = 0; index < leftKeys.Length; index++)
        {
            var comparison = StringComparer.Ordinal.Compare(leftKeys[index], rightKeys[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        return 0;
    }
}
