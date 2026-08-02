using System.Collections.Immutable;
using SarifRegress.Core;
using SarifRegress.Core.Matching;

namespace SarifRegress.Match;

internal static class MatchingAlgorithms
{
    public const string MatcherVersion = ProductInformation.MatcherAlgorithmVersion;
    public const string RuleIdentityVersion = "sarifregress/rule-identity/v2";
    public const string RuleAliasVersion = "sarifregress/rule-alias/v2";
    public const string ProducerFingerprintVersion =
        "sarifregress/producer-fingerprint-common-version/v1";
    public const string DerivedFingerprintVersion =
        "sarifregress/derived-fingerprint-compare/v2";
    public const string PathVersion = "sarifregress/path-evidence/v1";
    public const string PathAliasVersion = "sarifregress/path-alias/v1";
    public const string ContextVersion = "sarifregress/context-evidence/v2";
    public const string EvidenceOccurrenceVersion =
        "sarifregress/evidence-occurrence/v1";
    public const string MessageVersion = "sarifregress/message-evidence/v1";
    public const string MessageLocationTemplateVersion =
        "sarifregress/message-location-template/v1";
    public const string RegionVersion = "sarifregress/region-evidence/v1";
    public const string CodeFlowAnchorVersion = "sarifregress/code-flow-anchor/v1";
    public const string CodeFlowSetVersion = "sarifregress/code-flow-set/v1";
    public const string CodeFlowOccurrenceVersion =
        "sarifregress/code-flow-occurrence/v1";
    public const string RelatedLocationSetVersion =
        "sarifregress/related-location-set/v1";
    public const string AssignmentOutcomeVersion =
        "sarifregress/assignment-outcome/v1";
}

internal sealed class DecisionVectorComparer : IComparer<DecisionVector>
{
    public static DecisionVectorComparer Instance { get; } = new();

    public int Compare(DecisionVector left, DecisionVector right)
    {
        var comparison = left.PrecedenceTier.CompareTo(right.PrecedenceTier);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = left.ProducerFingerprintStrength.CompareTo(
            right.ProducerFingerprintStrength);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = left.PathMatchKind.CompareTo(right.PathMatchKind);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = left.ContextAgreement.CompareTo(right.ContextAgreement);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = left.CodeFlowAgreement.CompareTo(right.CodeFlowAgreement);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = left.MessageAgreement.CompareTo(right.MessageAgreement);
        return comparison != 0
            ? comparison
            : left.RegionDriftBand.CompareTo(right.RegionDriftBand);
    }
}

internal sealed class MatchEdgePreferenceComparer : IComparer<MatchEdge>
{
    public static MatchEdgePreferenceComparer Instance { get; } = new();

    public int Compare(MatchEdge? left, MatchEdge? right)
    {
        if (ReferenceEquals(left, right))
        {
            return 0;
        }

        if (left is null)
        {
            return 1;
        }

        if (right is null)
        {
            return -1;
        }

        var semanticComparison = DecisionVectorComparer.Instance.Compare(
            right.DecisionVector,
            left.DecisionVector);
        return semanticComparison != 0
            ? semanticComparison
            : StringComparer.Ordinal.Compare(left.StableIdentityKey, right.StableIdentityKey);
    }
}

internal sealed class AssignmentObjective
{
    public static AssignmentObjective Empty { get; } = new(
        0,
        ImmutableArray<DecisionVector>.Empty);

    public AssignmentObjective(
        int cardinality,
        ImmutableArray<DecisionVector> orderedDecisionVectors)
    {
        Cardinality = cardinality;
        OrderedDecisionVectors = orderedDecisionVectors;
    }

    public int Cardinality { get; }

    public ImmutableArray<DecisionVector> OrderedDecisionVectors { get; }

    public AssignmentObjective Add(DecisionVector decisionVector)
    {
        var builder = OrderedDecisionVectors.ToBuilder();
        var insertionIndex = 0;
        while (insertionIndex < builder.Count
            && DecisionVectorComparer.Instance.Compare(
                builder[insertionIndex],
                decisionVector) >= 0)
        {
            insertionIndex++;
        }

        builder.Insert(insertionIndex, decisionVector);
        return new AssignmentObjective(Cardinality + 1, builder.ToImmutable());
    }
}

internal sealed class AssignmentObjectiveComparer : IComparer<AssignmentObjective>
{
    public static AssignmentObjectiveComparer Instance { get; } = new();

    public int Compare(AssignmentObjective? left, AssignmentObjective? right)
    {
        if (ReferenceEquals(left, right))
        {
            return 0;
        }

        if (left is null)
        {
            return -1;
        }

        if (right is null)
        {
            return 1;
        }

        var comparison = left.Cardinality.CompareTo(right.Cardinality);
        if (comparison != 0)
        {
            return comparison;
        }

        for (var index = 0; index < left.OrderedDecisionVectors.Length; index++)
        {
            comparison = DecisionVectorComparer.Instance.Compare(
                left.OrderedDecisionVectors[index],
                right.OrderedDecisionVectors[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        return 0;
    }
}

internal sealed class DisjointSet
{
    private readonly int[] parent;
    private readonly byte[] rank;

    public DisjointSet(int size)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(size);
        parent = new int[size];
        rank = new byte[size];

        for (var index = 0; index < size; index++)
        {
            parent[index] = index;
        }
    }

    public int Find(int item)
    {
        var root = item;
        while (parent[root] != root)
        {
            root = parent[root];
        }

        while (parent[item] != item)
        {
            var next = parent[item];
            parent[item] = root;
            item = next;
        }

        return root;
    }

    public void Union(int left, int right)
    {
        var leftRoot = Find(left);
        var rightRoot = Find(right);
        if (leftRoot == rightRoot)
        {
            return;
        }

        if (rank[leftRoot] < rank[rightRoot])
        {
            parent[leftRoot] = rightRoot;
            return;
        }

        parent[rightRoot] = leftRoot;
        if (rank[leftRoot] == rank[rightRoot])
        {
            rank[leftRoot]++;
        }
    }
}
