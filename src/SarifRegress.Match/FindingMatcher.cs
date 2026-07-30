using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;

namespace SarifRegress.Match;

/// <summary>
/// Compares immutable canonical findings using deterministic, explainable one-to-one matching.
/// </summary>
public sealed class FindingMatcher
{
    /// <summary>
    /// Matches a baseline input to a candidate input.
    /// </summary>
    /// <param name="baseline">The canonical baseline findings.</param>
    /// <param name="candidate">The canonical candidate findings.</param>
    /// <param name="configuration">
    /// The immutable matching configuration, or <see langword="null"/> for deterministic defaults.
    /// </param>
    /// <returns>The stable decisions, explanations, diagnostics, and operation counts.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when input kinds, finding arrays, or finding keys violate the canonical contract.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when a configured resource limit is invalid.
    /// </exception>
    public MatchResult Match(
        ComparisonInput baseline,
        ComparisonInput candidate,
        SarifRegressConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(candidate);

        configuration ??= SarifRegressConfiguration.Default;
        configuration.Limits.Validate();
        ValidateInput(baseline, InputKind.Baseline, nameof(baseline));
        ValidateInput(candidate, InputKind.Candidate, nameof(candidate));

        var baselineFindings = OrderFindings(baseline.Findings);
        var candidateFindings = OrderFindings(candidate.Findings);
        ValidateUniqueFindingKeys(baselineFindings, nameof(baseline));
        ValidateUniqueFindingKeys(candidateFindings, nameof(candidate));

        var fingerprintOccurrences = ProducerFingerprintOccurrenceIndex.Create(
            baselineFindings,
            candidateFindings);
        var edgeFactory = new CandidateEdgeFactory(configuration, fingerprintOccurrences);
        var candidateBuckets = CandidateBucketIndex.Create(
            candidateFindings,
            configuration.RuleAliases);
        var graph = BuildCandidateGraph(
            baselineFindings,
            candidateFindings,
            configuration,
            candidateBuckets,
            edgeFactory);
        return ResolveGraph(
            baselineFindings,
            candidateFindings,
            configuration,
            graph,
            fingerprintOccurrences.Diagnostics);
    }

    private static void ValidateInput(
        ComparisonInput input,
        InputKind expectedKind,
        string parameterName)
    {
        if (input.Input != expectedKind)
        {
            throw new ArgumentException(
                $"Expected a {expectedKind.ToString().ToLowerInvariant()} comparison input.",
                parameterName);
        }

        if (input.Findings.IsDefault)
        {
            throw new ArgumentException(
                "The comparison input must contain an initialized finding array.",
                parameterName);
        }
    }

    private static ImmutableArray<Finding> OrderFindings(ImmutableArray<Finding> findings) =>
        findings
            .OrderBy(item => item.FindingKey, StringComparer.Ordinal)
            .ThenBy(item => item.SourceReference.RunIndex)
            .ThenBy(item => item.SourceReference.ResultIndex)
            .ThenBy(item => item.SourceReference.JsonPointer, StringComparer.Ordinal)
            .ToImmutableArray();

    private static void ValidateUniqueFindingKeys(
        ImmutableArray<Finding> findings,
        string parameterName)
    {
        for (var index = 1; index < findings.Length; index++)
        {
            if (string.Equals(
                    findings[index - 1].FindingKey,
                    findings[index].FindingKey,
                    StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"Finding key '{findings[index].FindingKey}' occurs more than once.",
                    parameterName);
            }
        }
    }

    /// <summary>
    /// Generates admissible edges through producer/rule buckets and unions the complete graph.
    /// Edges retained for solving are independently bounded per baseline finding.
    /// </summary>
    // Time: O(P × (E + log S) + (B + C) α(B + C)); Space: O(P + B + C), where
    // P is preflight-bounded candidate pairs, E is bounded evidence work, and S is the
    // per-finding selection bound.
    private static CandidateGraph BuildCandidateGraph(
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        SarifRegressConfiguration configuration,
        CandidateBucketIndex candidateBuckets,
        CandidateEdgeFactory edgeFactory)
    {
        var preflight = PreflightCandidatePairs(
            baselineFindings,
            candidateFindings,
            configuration,
            candidateBuckets);
        if (preflight.Refusal is not null)
        {
            return new CandidateGraph(
                ImmutableArray<MatchEdge>.Empty,
                ImmutableArray<GraphComponent>.Empty,
                ImmutableArray<int>.Empty,
                ImmutableArray<int>.Empty,
                new int[baselineFindings.Length].ToImmutableArray(),
                new int[candidateFindings.Length].ToImmutableArray(),
                baselineFindings.IsEmpty && candidateFindings.IsEmpty ? 0 : 1,
                CandidateEdgeCount: 0,
                ImmutableArray<Diagnostic>.Empty,
                preflight.Refusal);
        }

        var nodeCount = baselineFindings.Length + candidateFindings.Length;
        var completeGraphSets = new DisjointSet(nodeCount);
        var activeNodes = new bool[nodeCount];
        var allAdmissibleEdges = new List<MatchEdge>();
        var admissibleEdgeCountsByBaseline = new int[baselineFindings.Length];
        var admissibleEdgeCountsByCandidate = new int[candidateFindings.Length];
        var exactProducerCountsByBaseline = new int[baselineFindings.Length];
        var exactProducerCountsByCandidate = new int[candidateFindings.Length];
        long candidateEdgeCount = 0;

        for (var baselineIndex = 0; baselineIndex < baselineFindings.Length; baselineIndex++)
        {
            var baseline = baselineFindings[baselineIndex];
            foreach (var candidateIndex in preflight.CandidateIndexesByBaseline[baselineIndex])
            {
                var edge = edgeFactory.Create(baseline, candidateFindings[candidateIndex]);
                if (edge is null)
                {
                    continue;
                }

                candidateEdgeCount++;
                allAdmissibleEdges.Add(edge);
                admissibleEdgeCountsByBaseline[baselineIndex]++;
                admissibleEdgeCountsByCandidate[candidateIndex]++;
                if (edge.DecisionVector.PrecedenceTier == PrecedenceTier.ExactProducer)
                {
                    exactProducerCountsByBaseline[baselineIndex]++;
                    exactProducerCountsByCandidate[candidateIndex]++;
                }

                var candidateNode = baselineFindings.Length + candidateIndex;
                completeGraphSets.Union(baselineIndex, candidateNode);
                activeNodes[baselineIndex] = true;
                activeNodes[candidateNode] = true;
            }
        }

        var overflowBaselineNodes = admissibleEdgeCountsByBaseline
            .Select((count, index) => (count, index))
            .Where(item => item.count > configuration.Limits.MaximumCandidateEdgesPerFinding)
            .Select(item => item.index)
            .ToImmutableArray();
        var overflowCandidateIndexes = admissibleEdgeCountsByCandidate
            .Select((count, index) => (count, index))
            .Where(item => item.count > configuration.Limits.MaximumCandidateEdgesPerFinding)
            .Select(item => item.index)
            .ToImmutableArray();
        var retainedEdges = RetainBoundedEdges(
            allAdmissibleEdges,
            baselineFindings,
            candidateFindings,
            exactProducerCountsByBaseline,
            exactProducerCountsByCandidate,
            configuration.Limits.MaximumCandidateEdgesPerFinding);

        var completeGraphSummary = SummarizeCompleteGraph(
            completeGraphSets,
            activeNodes,
            baselineFindings.Length,
            overflowBaselineNodes,
            overflowCandidateIndexes);

        var diagnostics = new List<Diagnostic>();

        var reportedEdgeCount = candidateEdgeCount > int.MaxValue
            ? int.MaxValue
            : (int)candidateEdgeCount;
        if (candidateEdgeCount > int.MaxValue)
        {
            diagnostics.Add(new Diagnostic(
                "MATCH0006",
                DiagnosticSeverity.Warning,
                DiagnosticStage.Match,
                "The candidate-edge operation count exceeded the report contract and was "
                + "saturated at 2147483647."));
        }

        return new CandidateGraph(
            retainedEdges,
            completeGraphSummary.ForcedAmbiguousComponents,
            overflowBaselineNodes,
            overflowCandidateIndexes,
            exactProducerCountsByBaseline.ToImmutableArray(),
            exactProducerCountsByCandidate.ToImmutableArray(),
            completeGraphSummary.ComponentCount,
            reportedEdgeCount,
            Diagnostic.Sort(diagnostics),
            PreflightRefusal: null);
    }

    private static ImmutableArray<MatchEdge> RetainBoundedEdges(
        IEnumerable<MatchEdge> allEdges,
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        IReadOnlyList<int> exactProducerCountsByBaseline,
        IReadOnlyList<int> exactProducerCountsByCandidate,
        int maximumEdgesPerFinding)
    {
        var baselineIndexByKey = baselineFindings
            .Select((finding, index) => (finding.FindingKey, index))
            .ToDictionary(item => item.FindingKey, item => item.index, StringComparer.Ordinal);
        var candidateIndexByKey = candidateFindings
            .Select((finding, index) => (finding.FindingKey, index))
            .ToDictionary(item => item.FindingKey, item => item.index, StringComparer.Ordinal);
        var retainedCountsByBaseline = new int[baselineFindings.Length];
        var retainedCountsByCandidate = new int[candidateFindings.Length];
        var retained = ImmutableArray.CreateBuilder<MatchEdge>();

        foreach (var edge in allEdges
            .OrderByDescending(edge => IsIndisputableExactProducerEdge(
                edge,
                baselineIndexByKey,
                candidateIndexByKey,
                exactProducerCountsByBaseline,
                exactProducerCountsByCandidate))
            .ThenBy(edge => edge, MatchEdgePreferenceComparer.Instance))
        {
            var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
            var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
            if (retainedCountsByBaseline[baselineIndex] >= maximumEdgesPerFinding
                || retainedCountsByCandidate[candidateIndex] >= maximumEdgesPerFinding)
            {
                continue;
            }

            retained.Add(edge);
            retainedCountsByBaseline[baselineIndex]++;
            retainedCountsByCandidate[candidateIndex]++;
        }

        return retained.ToImmutable();
    }

    private static bool IsIndisputableExactProducerEdge(
        MatchEdge edge,
        IReadOnlyDictionary<string, int> baselineIndexByKey,
        IReadOnlyDictionary<string, int> candidateIndexByKey,
        IReadOnlyList<int> exactProducerCountsByBaseline,
        IReadOnlyList<int> exactProducerCountsByCandidate)
    {
        if (edge.DecisionVector.PrecedenceTier != PrecedenceTier.ExactProducer)
        {
            return false;
        }

        var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
        var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
        return exactProducerCountsByBaseline[baselineIndex] == 1
            && exactProducerCountsByCandidate[candidateIndex] == 1;
    }

    /// <summary>
    /// Plans all coarse candidate pairs before creating an edge. Work stops as soon as a
    /// per-finding, incoming, or comparison-wide pair budget would be exceeded.
    /// </summary>
    // Time: O(B × S + min(P, G)), Space: O(min(P, G) + B + C), where P is the number
    // of coarse pairs, S is the per-finding selection bound, and G is the global pair budget.
    private static CandidatePairPreflight PreflightCandidatePairs(
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        SarifRegressConfiguration configuration,
        CandidateBucketIndex candidateBuckets)
    {
        var limitPerFinding =
            configuration.Limits.MaximumCandidatePairEvaluationsPerFinding;
        var globalLimit = configuration.Limits.MaximumCandidatePairEvaluations;
        var candidateIncomingCounts = new int[candidateFindings.Length];
        var plannedPairCount = 0L;
        var selections = ImmutableArray.CreateBuilder<ImmutableArray<int>>(
            baselineFindings.Length);

        for (var baselineIndex = 0; baselineIndex < baselineFindings.Length; baselineIndex++)
        {
            var remainingGlobalPairs = globalLimit - plannedPairCount;
            var globalSelectionBound = remainingGlobalPairs >= int.MaxValue
                ? int.MaxValue
                : (int)remainingGlobalPairs + 1;
            var effectiveSelectionLimit = Math.Min(
                limitPerFinding,
                globalSelectionBound);
            var selection = candidateBuckets.FindCandidatesBounded(
                baselineFindings[baselineIndex],
                effectiveSelectionLimit);
            if (selection.ExceededLimit)
            {
                if (effectiveSelectionLimit < limitPerFinding)
                {
                    return CandidatePairPreflight.Refused(
                        CreateGlobalPairRefusal(globalLimit));
                }

                return CandidatePairPreflight.Refused(new CandidatePreflightRefusal(
                    "MATCH0007",
                    $"Finding '{baselineFindings[baselineIndex].FindingKey}' exceeds "
                    + $"the candidate-selection evaluation limit of {limitPerFinding}; "
                    + "candidate scoring was not started and all unresolved findings "
                    + "were refused.",
                    "Narrow rule aliases or add more specific producer and rule identities."));
            }

            if (plannedPairCount > globalLimit - selection.CandidateIndexes.Length)
            {
                return CandidatePairPreflight.Refused(
                    CreateGlobalPairRefusal(globalLimit));
            }

            foreach (var candidateIndex in selection.CandidateIndexes)
            {
                candidateIncomingCounts[candidateIndex]++;
                if (candidateIncomingCounts[candidateIndex] > limitPerFinding)
                {
                    return CandidatePairPreflight.Refused(new CandidatePreflightRefusal(
                        "MATCH0009",
                        $"Finding '{candidateFindings[candidateIndex].FindingKey}' has more than "
                        + $"{limitPerFinding} incoming coarse candidate pairs; candidate scoring "
                        + "was not started and all unresolved findings were refused.",
                        "Narrow rule aliases or add more specific producer and rule identities."));
                }
            }

            plannedPairCount += selection.CandidateIndexes.Length;
            selections.Add(selection.CandidateIndexes);
        }

        return new CandidatePairPreflight(selections.MoveToImmutable(), Refusal: null);
    }

    private static CandidatePreflightRefusal CreateGlobalPairRefusal(long globalLimit) =>
        new(
            "MATCH0008",
            $"The comparison requires more than {globalLimit} coarse candidate-pair "
            + "evaluations; candidate scoring was not started and all unresolved "
            + "findings were refused.",
            "Split the comparison or improve producer and rule bucketing.");

    /// <summary>
    /// Groups active bipartite graph nodes by disjoint-set root without relying on hash
    /// enumeration order.
    /// </summary>
    // Time: O((B + C) α(B + C)); Space: O(B + C).
    private static SortedDictionary<int, GraphComponent> BuildComponents(
        DisjointSet sets,
        IReadOnlyList<bool> activeNodes,
        int baselineCount)
    {
        var builders = new SortedDictionary<int, GraphComponentBuilder>();
        for (var node = 0; node < activeNodes.Count; node++)
        {
            if (!activeNodes[node])
            {
                continue;
            }

            var root = sets.Find(node);
            if (!builders.TryGetValue(root, out var builder))
            {
                builder = new GraphComponentBuilder();
                builders.Add(root, builder);
            }

            if (node < baselineCount)
            {
                builder.BaselineIndexes.Add(node);
            }
            else
            {
                builder.CandidateIndexes.Add(node - baselineCount);
            }
        }

        return new SortedDictionary<int, GraphComponent>(
            builders.ToDictionary(
                item => item.Key,
                item => item.Value.Build(baselineCount)));
    }

    /// <summary>
    /// Counts every complete component while materializing only components whose edge cap
    /// overflowed. Most comparisons contain many independent complete pairs and no overflow,
    /// so building a component object for every root would retain redundant per-pair arrays.
    /// </summary>
    // Time: O((B + C) α(B + C)); Space: O(B + C + O), where O is the number of
    // nodes in overflowed components.
    private static CompleteGraphSummary SummarizeCompleteGraph(
        DisjointSet sets,
        IReadOnlyList<bool> activeNodes,
        int baselineCount,
        ImmutableArray<int> overflowBaselineIndexes,
        ImmutableArray<int> overflowCandidateIndexes)
    {
        bool[]? overflowRoots = null;
        if (!overflowBaselineIndexes.IsEmpty || !overflowCandidateIndexes.IsEmpty)
        {
            overflowRoots = new bool[activeNodes.Count];
            foreach (var baselineIndex in overflowBaselineIndexes)
            {
                overflowRoots[sets.Find(baselineIndex)] = true;
            }

            foreach (var candidateIndex in overflowCandidateIndexes)
            {
                overflowRoots[sets.Find(baselineCount + candidateIndex)] = true;
            }
        }

        var seenRoots = new bool[activeNodes.Count];
        SortedDictionary<int, GraphComponentBuilder>? overflowBuilders = null;
        var componentCount = 0;
        for (var node = 0; node < activeNodes.Count; node++)
        {
            if (!activeNodes[node])
            {
                continue;
            }

            var root = sets.Find(node);
            if (!seenRoots[root])
            {
                seenRoots[root] = true;
                componentCount++;
            }

            if (overflowRoots is null || !overflowRoots[root])
            {
                continue;
            }

            overflowBuilders ??= new SortedDictionary<int, GraphComponentBuilder>();
            if (!overflowBuilders.TryGetValue(root, out var builder))
            {
                builder = new GraphComponentBuilder();
                overflowBuilders.Add(root, builder);
            }

            if (node < baselineCount)
            {
                builder.BaselineIndexes.Add(node);
            }
            else
            {
                builder.CandidateIndexes.Add(node - baselineCount);
            }
        }

        var forcedAmbiguousComponents = overflowBuilders is null
            ? ImmutableArray<GraphComponent>.Empty
            : overflowBuilders
                .Select(item => item.Value.Build(baselineCount))
                .ToImmutableArray();
        return new CompleteGraphSummary(componentCount, forcedAmbiguousComponents);
    }

    private static MatchResult ResolveGraph(
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        SarifRegressConfiguration configuration,
        CandidateGraph graph,
        ImmutableArray<Diagnostic> fingerprintDiagnostics)
    {
        if (graph.PreflightRefusal is not null)
        {
            return CreatePreflightRefusalResult(
                baselineFindings,
                candidateFindings,
                graph,
                fingerprintDiagnostics);
        }

        var baselineIndexByKey = baselineFindings
            .Select((finding, index) => (finding.FindingKey, index))
            .ToDictionary(item => item.FindingKey, item => item.index, StringComparer.Ordinal);
        var candidateIndexByKey = candidateFindings
            .Select((finding, index) => (finding.FindingKey, index))
            .ToDictionary(item => item.FindingKey, item => item.index, StringComparer.Ordinal);
        var selectedByBaseline = new Dictionary<int, MatchEdge>();
        var selectedByCandidate = new Dictionary<int, MatchEdge>();
        var ambiguousBaselineIndexes = new HashSet<int>();
        var ambiguousCandidateIndexes = new HashSet<int>();
        var diagnosticsByNode = new Dictionary<int, List<Diagnostic>>();
        var resultDiagnostics = fingerprintDiagnostics
            .Concat(graph.Diagnostics)
            .ToList();
        var ambiguousOriginalComponents = new HashSet<string>(StringComparer.Ordinal);

        CommitIndisputableProducerMatches(
            graph,
            baselineIndexByKey,
            candidateIndexByKey,
            ambiguousBaselineIndexes,
            ambiguousCandidateIndexes,
            selectedByBaseline,
            selectedByCandidate);

        if (!graph.ForcedAmbiguousComponents.IsEmpty)
        {
            MarkForcedAmbiguity(
                baselineFindings,
                candidateFindings,
                configuration,
                graph,
                selectedByBaseline,
                selectedByCandidate,
                ambiguousBaselineIndexes,
                ambiguousCandidateIndexes,
                diagnosticsByNode,
                ambiguousOriginalComponents,
                resultDiagnostics);
        }

        var residualGraph = BuildResidualGraph(
            baselineFindings.Length,
            candidateFindings.Length,
            graph.RetainedEdges,
            baselineIndexByKey,
            candidateIndexByKey,
            selectedByBaseline,
            selectedByCandidate,
            ambiguousBaselineIndexes,
            ambiguousCandidateIndexes);

        foreach (var residualComponent in residualGraph.Components)
        {
            var component = residualComponent.Component;
            var componentEdges = residualComponent.Edges;
            var componentIdentity = CreateComponentIdentity(
                component,
                baselineFindings,
                candidateFindings);

            if (component.BaselineIndexes.Length
                    > configuration.Limits.MaximumAssignmentSideSize
                || component.CandidateIndexes.Length
                    > configuration.Limits.MaximumAssignmentSideSize)
            {
                var diagnostic = new Diagnostic(
                    "MATCH0002",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Match,
                    $"Assignment component '{componentIdentity}' contains "
                    + $"{component.BaselineIndexes.Length} baseline and "
                    + $"{component.CandidateIndexes.Length} candidate findings, exceeding "
                    + $"the configured exact-solver side limit of "
                    + $"{configuration.Limits.MaximumAssignmentSideSize}; the component "
                    + "was refused.",
                    help: "Narrow aliases or improve canonical evidence to split the component.");
                MarkComponentAmbiguous(
                    component,
                    diagnostic,
                    baselineFindings.Length,
                    ambiguousBaselineIndexes,
                    ambiguousCandidateIndexes,
                    diagnosticsByNode);
                resultDiagnostics.Add(diagnostic);
                ambiguousOriginalComponents.Add(componentIdentity);
                continue;
            }

            var solver = new BoundedAssignmentSolver(
                component.BaselineIndexes,
                component.CandidateIndexes,
                componentEdges,
                baselineIndexByKey,
                candidateIndexByKey);
            var solution = solver.Solve();
            if (solution.HasEqualOptimum)
            {
                var diagnostic = new Diagnostic(
                    "MATCH0001",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Match,
                    $"Assignment component '{componentIdentity}' has multiple equal-optimal "
                    + "semantic assignments; the component was refused rather than ordered "
                    + "by a stable key.");
                MarkComponentAmbiguous(
                    component,
                    diagnostic,
                    baselineFindings.Length,
                    ambiguousBaselineIndexes,
                    ambiguousCandidateIndexes,
                    diagnosticsByNode);
                resultDiagnostics.Add(diagnostic);
                ambiguousOriginalComponents.Add(componentIdentity);
                continue;
            }

            foreach (var edge in solution.Edges)
            {
                var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
                var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
                selectedByBaseline.Add(baselineIndex, edge);
                selectedByCandidate.Add(candidateIndex, edge);
            }
        }

        var decisions = BuildDecisions(
            baselineFindings,
            candidateFindings,
            configuration,
            graph.RetainedEdges,
            baselineIndexByKey,
            candidateIndexByKey,
            selectedByBaseline,
            selectedByCandidate,
            ambiguousBaselineIndexes,
            ambiguousCandidateIndexes,
            diagnosticsByNode);

        return new MatchResult(
            decisions,
            graph.CandidateEdgeCount,
            graph.ComponentCount,
            ambiguousOriginalComponents.Count,
            Diagnostic.Sort(resultDiagnostics));
    }

    private static MatchResult CreatePreflightRefusalResult(
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        CandidateGraph graph,
        ImmutableArray<Diagnostic> fingerprintDiagnostics)
    {
        var refusal = graph.PreflightRefusal!;
        var diagnostic = new Diagnostic(
            refusal.Code,
            DiagnosticSeverity.Warning,
            DiagnosticStage.Match,
            refusal.Message,
            help: refusal.Help);
        var trace = new DecisionTrace(
            PrecedenceTier.Refuse,
            DisplayConfidence.Low,
            Ambiguous: true,
            MatchingAlgorithms.MatcherVersion,
            ImmutableArray<EvidenceRecord>.Empty,
            ImmutableArray<RejectedAlternative>.Empty,
            ImmutableArray<TransformationRecord>.Empty,
            ImmutableArray<Diagnostic>.Empty);
        var decisions = baselineFindings
            .Select(finding => new FindingDecision(
                FindingClassification.Ambiguous,
                finding,
                Candidate: null,
                trace))
            .Concat(candidateFindings.Select(finding => new FindingDecision(
                FindingClassification.Ambiguous,
                Baseline: null,
                finding,
                trace)))
            .OrderBy(
                decision => decision.Baseline?.FindingKey
                    ?? decision.Candidate?.FindingKey
                    ?? string.Empty,
                StringComparer.Ordinal)
            .ThenBy(decision => decision.Baseline is null ? 1 : 0)
            .ThenBy(
                decision => decision.Candidate?.FindingKey ?? string.Empty,
                StringComparer.Ordinal)
            .ToImmutableArray();
        return new MatchResult(
            decisions,
            graph.CandidateEdgeCount,
            graph.ComponentCount,
            graph.ComponentCount,
            Diagnostic.Sort(
                fingerprintDiagnostics
                    .Concat(graph.Diagnostics)
                    .Append(diagnostic)));
    }

    private static void MarkForcedAmbiguity(
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        SarifRegressConfiguration configuration,
        CandidateGraph graph,
        IReadOnlyDictionary<int, MatchEdge> committedBaselineIndexes,
        IReadOnlyDictionary<int, MatchEdge> committedCandidateIndexes,
        ISet<int> ambiguousBaselineIndexes,
        ISet<int> ambiguousCandidateIndexes,
        IDictionary<int, List<Diagnostic>> diagnosticsByNode,
        ISet<string> ambiguousOriginalComponents,
        ICollection<Diagnostic> resultDiagnostics)
    {
        var overflowBaselineIndexes = graph.OverflowBaselineIndexes.ToHashSet();
        var overflowCandidateIndexes = graph.OverflowCandidateIndexes.ToHashSet();
        foreach (var component in graph.ForcedAmbiguousComponents)
        {
            var unresolvedOverflowBaselines = component.BaselineIndexes
                .Where(index =>
                    overflowBaselineIndexes.Contains(index)
                    && !committedBaselineIndexes.ContainsKey(index))
                .ToImmutableArray();
            var unresolvedOverflowCandidates = component.CandidateIndexes
                .Where(index =>
                    overflowCandidateIndexes.Contains(index)
                    && !committedCandidateIndexes.ContainsKey(index))
                .ToImmutableArray();
            if (unresolvedOverflowBaselines.IsEmpty
                && unresolvedOverflowCandidates.IsEmpty)
            {
                continue;
            }

            ambiguousOriginalComponents.Add(
                CreateComponentIdentity(component, baselineFindings, candidateFindings));
            foreach (var overflowBaselineIndex in unresolvedOverflowBaselines)
            {
                var diagnostic = new Diagnostic(
                    "MATCH0003",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Match,
                    $"Finding '{baselineFindings[overflowBaselineIndex].FindingKey}' has more "
                    + $"than {configuration.Limits.MaximumCandidateEdgesPerFinding} "
                    + "admissible candidate edges; its residual connected component was "
                    + "refused.",
                    baselineFindings[overflowBaselineIndex].SourceReference,
                    help: "Narrow aliases or improve canonical evidence to reduce the "
                    + "candidate bucket.");
                resultDiagnostics.Add(diagnostic);
            }

            foreach (var overflowCandidateIndex in unresolvedOverflowCandidates)
            {
                var diagnostic = new Diagnostic(
                    "MATCH0010",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Match,
                    $"Finding '{candidateFindings[overflowCandidateIndex].FindingKey}' has more "
                    + $"than {configuration.Limits.MaximumCandidateEdgesPerFinding} incoming "
                    + "admissible candidate edges; its residual connected component was refused.",
                    candidateFindings[overflowCandidateIndex].SourceReference,
                    help: "Narrow aliases or improve canonical evidence to reduce incoming "
                    + "candidate pressure.");
                resultDiagnostics.Add(diagnostic);
            }

            foreach (var node in component.AllNodes)
            {
                var isBaseline = node < baselineFindings.Length;
                var sideIndex = isBaseline ? node : node - baselineFindings.Length;
                if ((isBaseline && committedBaselineIndexes.ContainsKey(sideIndex))
                    || (!isBaseline && committedCandidateIndexes.ContainsKey(sideIndex)))
                {
                    continue;
                }

                var finding = isBaseline
                    ? baselineFindings[node]
                    : candidateFindings[sideIndex];
                var diagnostic = new Diagnostic(
                    "MATCH0003",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Match,
                    "The finding belongs to a component whose candidate-edge cap was exceeded; "
                    + "no arbitrary bounded assignment was accepted.",
                    finding.SourceReference);
                AddNodeDiagnostic(diagnosticsByNode, node, diagnostic);

                if (isBaseline)
                {
                    ambiguousBaselineIndexes.Add(node);
                }
                else
                {
                    ambiguousCandidateIndexes.Add(sideIndex);
                }
            }
        }
    }

    private static void CommitIndisputableProducerMatches(
        CandidateGraph graph,
        IReadOnlyDictionary<string, int> baselineIndexByKey,
        IReadOnlyDictionary<string, int> candidateIndexByKey,
        IReadOnlySet<int> ambiguousBaselineIndexes,
        IReadOnlySet<int> ambiguousCandidateIndexes,
        IDictionary<int, MatchEdge> selectedByBaseline,
        IDictionary<int, MatchEdge> selectedByCandidate)
    {
        foreach (var edge in graph.RetainedEdges)
        {
            if (edge.DecisionVector.PrecedenceTier != PrecedenceTier.ExactProducer)
            {
                continue;
            }

            var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
            var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
            if (ambiguousBaselineIndexes.Contains(baselineIndex)
                || ambiguousCandidateIndexes.Contains(candidateIndex)
                || graph.ExactProducerCountsByBaseline[baselineIndex] != 1
                || graph.ExactProducerCountsByCandidate[candidateIndex] != 1
                || selectedByBaseline.ContainsKey(baselineIndex)
                || selectedByCandidate.ContainsKey(candidateIndex))
            {
                continue;
            }

            selectedByBaseline.Add(baselineIndex, edge);
            selectedByCandidate.Add(candidateIndex, edge);
        }
    }

    private static ResidualGraph BuildResidualGraph(
        int baselineCount,
        int candidateCount,
        ImmutableArray<MatchEdge> retainedEdges,
        IReadOnlyDictionary<string, int> baselineIndexByKey,
        IReadOnlyDictionary<string, int> candidateIndexByKey,
        IReadOnlyDictionary<int, MatchEdge> committedBaselineIndexes,
        IReadOnlyDictionary<int, MatchEdge> committedCandidateIndexes,
        IReadOnlySet<int> ambiguousBaselineIndexes,
        IReadOnlySet<int> ambiguousCandidateIndexes)
    {
        if (retainedEdges.IsEmpty
            || committedBaselineIndexes.Count == baselineCount
            || committedCandidateIndexes.Count == candidateCount)
        {
            return ResidualGraph.Empty;
        }

        var residualEdges = retainedEdges
            .Where(edge =>
            {
                var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
                var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
                return !committedBaselineIndexes.ContainsKey(baselineIndex)
                    && !committedCandidateIndexes.ContainsKey(candidateIndex)
                    && !ambiguousBaselineIndexes.Contains(baselineIndex)
                    && !ambiguousCandidateIndexes.Contains(candidateIndex);
            })
            .ToImmutableArray();
        if (residualEdges.IsEmpty)
        {
            return ResidualGraph.Empty;
        }

        if (residualEdges.Length == 1)
        {
            var edge = residualEdges[0];
            var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
            var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
            return new ResidualGraph(
            [
                new ResidualComponent(
                    new GraphComponent(
                        [baselineIndex],
                        [candidateIndex],
                        [baselineIndex, baselineCount + candidateIndex]),
                    residualEdges),
            ]);
        }

        var sets = new DisjointSet(baselineCount + candidateCount);
        var active = new bool[baselineCount + candidateCount];
        foreach (var edge in residualEdges)
        {
            var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
            var candidateNode = baselineCount + candidateIndexByKey[edge.Candidate.FindingKey];
            sets.Union(baselineIndex, candidateNode);
            active[baselineIndex] = true;
            active[candidateNode] = true;
        }

        var components = BuildComponents(sets, active, baselineCount);
        var edgeBuilders = components.Keys.ToDictionary(
            root => root,
            _ => new List<MatchEdge>());
        foreach (var edge in residualEdges)
        {
            var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
            edgeBuilders[sets.Find(baselineIndex)].Add(edge);
        }

        return new ResidualGraph(
            components
                .Select(item => new ResidualComponent(
                    item.Value,
                    edgeBuilders[item.Key]
                        .Order(MatchEdgePreferenceComparer.Instance)
                        .ToImmutableArray()))
                .ToImmutableArray());
    }

    private static void MarkComponentAmbiguous(
        GraphComponent component,
        Diagnostic diagnostic,
        int baselineCount,
        ISet<int> ambiguousBaselineIndexes,
        ISet<int> ambiguousCandidateIndexes,
        IDictionary<int, List<Diagnostic>> diagnosticsByNode)
    {
        foreach (var baselineIndex in component.BaselineIndexes)
        {
            ambiguousBaselineIndexes.Add(baselineIndex);
            AddNodeDiagnostic(diagnosticsByNode, baselineIndex, diagnostic);
        }

        foreach (var candidateIndex in component.CandidateIndexes)
        {
            ambiguousCandidateIndexes.Add(candidateIndex);
            AddNodeDiagnostic(diagnosticsByNode, baselineCount + candidateIndex, diagnostic);
        }
    }

    private static void AddNodeDiagnostic(
        IDictionary<int, List<Diagnostic>> diagnosticsByNode,
        int node,
        Diagnostic diagnostic)
    {
        if (!diagnosticsByNode.TryGetValue(node, out var diagnostics))
        {
            diagnostics = [];
            diagnosticsByNode.Add(node, diagnostics);
        }

        diagnostics.Add(diagnostic);
    }

    private static string CreateComponentIdentity(
        GraphComponent component,
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings)
    {
        var firstBaseline = component.BaselineIndexes
            .Select(index => baselineFindings[index].FindingKey)
            .Order(StringComparer.Ordinal)
            .FirstOrDefault();
        var firstCandidate = component.CandidateIndexes
            .Select(index => candidateFindings[index].FindingKey)
            .Order(StringComparer.Ordinal)
            .FirstOrDefault();
        return $"{firstBaseline ?? "-"}|{firstCandidate ?? "-"}";
    }

    private static ImmutableArray<FindingDecision> BuildDecisions(
        ImmutableArray<Finding> baselineFindings,
        ImmutableArray<Finding> candidateFindings,
        SarifRegressConfiguration configuration,
        ImmutableArray<MatchEdge> edges,
        IReadOnlyDictionary<string, int> baselineIndexByKey,
        IReadOnlyDictionary<string, int> candidateIndexByKey,
        IReadOnlyDictionary<int, MatchEdge> selectedByBaseline,
        IReadOnlyDictionary<int, MatchEdge> selectedByCandidate,
        IReadOnlySet<int> ambiguousBaselineIndexes,
        IReadOnlySet<int> ambiguousCandidateIndexes,
        IReadOnlyDictionary<int, List<Diagnostic>> diagnosticsByNode)
    {
        var allRetainedEdgesWereSelected =
            ambiguousBaselineIndexes.Count == 0
            && ambiguousCandidateIndexes.Count == 0
            && selectedByBaseline.Count == edges.Length
            && selectedByCandidate.Count == edges.Length;
        var incidentEdgeIndex = allRetainedEdgesWereSelected
            ? null
            : IncidentEdgeIndex.Create(
                baselineFindings.Length,
                candidateFindings.Length,
                edges,
                baselineIndexByKey,
                candidateIndexByKey);
        var decisions = new List<FindingDecision>(
            baselineFindings.Length + candidateFindings.Length);
        for (var baselineIndex = 0; baselineIndex < baselineFindings.Length; baselineIndex++)
        {
            var baseline = baselineFindings[baselineIndex];
            if (ambiguousBaselineIndexes.Contains(baselineIndex))
            {
                decisions.Add(CreateAmbiguousDecision(
                    baseline,
                    candidate: null,
                    baselineIndex,
                    configuration,
                    incidentEdgeIndex?.ForBaseline(baselineIndex)
                        ?? ImmutableArray<MatchEdge>.Empty,
                    diagnosticsByNode));
                continue;
            }

            if (selectedByBaseline.TryGetValue(baselineIndex, out var selectedEdge))
            {
                var candidateIndex = candidateIndexByKey[selectedEdge.Candidate.FindingKey];
                decisions.Add(CreateMatchedDecision(
                    selectedEdge,
                    baselineIndex,
                    candidateIndex,
                    configuration,
                    incidentEdgeIndex?.ForMatch(baselineIndex, candidateIndex)
                        ?? ImmutableArray<MatchEdge>.Empty,
                    diagnosticsByNode));
                continue;
            }

            decisions.Add(CreateUnmatchedDecision(
                FindingClassification.Resolved,
                baseline,
                candidate: null,
                baselineIndex,
                configuration,
                incidentEdgeIndex?.ForBaseline(baselineIndex)
                    ?? ImmutableArray<MatchEdge>.Empty,
                diagnosticsByNode));
        }

        for (var candidateIndex = 0; candidateIndex < candidateFindings.Length; candidateIndex++)
        {
            if (selectedByCandidate.ContainsKey(candidateIndex))
            {
                continue;
            }

            var candidate = candidateFindings[candidateIndex];
            var node = baselineFindings.Length + candidateIndex;
            decisions.Add(ambiguousCandidateIndexes.Contains(candidateIndex)
                ? CreateAmbiguousDecision(
                    baseline: null,
                    candidate,
                    node,
                    configuration,
                    incidentEdgeIndex?.ForCandidate(candidateIndex)
                        ?? ImmutableArray<MatchEdge>.Empty,
                    diagnosticsByNode)
                : CreateUnmatchedDecision(
                    FindingClassification.New,
                    baseline: null,
                    candidate,
                    node,
                    configuration,
                    incidentEdgeIndex?.ForCandidate(candidateIndex)
                        ?? ImmutableArray<MatchEdge>.Empty,
                    diagnosticsByNode));
        }

        return decisions
            .OrderBy(
                decision => decision.Baseline?.FindingKey
                    ?? decision.Candidate?.FindingKey
                    ?? string.Empty,
                StringComparer.Ordinal)
            .ThenBy(decision => decision.Baseline is null ? 1 : 0)
            .ThenBy(decision => decision.Candidate?.FindingKey ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(decision => decision.Classification)
            .ToImmutableArray();
    }

    private static FindingDecision CreateMatchedDecision(
        MatchEdge selectedEdge,
        int baselineIndex,
        int candidateIndex,
        SarifRegressConfiguration configuration,
        ImmutableArray<MatchEdge> incidentEdges,
        IReadOnlyDictionary<int, List<Diagnostic>> diagnosticsByNode)
    {
        var alternatives =
            incidentEdges.Length == 1
            && ReferenceEquals(incidentEdges[0], selectedEdge)
                ? ImmutableArray<MatchEdge>.Empty
                : incidentEdges
                    .Where(edge => !ReferenceEquals(edge, selectedEdge))
                    .ToImmutableArray();
        var trace = CreateTrace(
            selectedEdge.DecisionVector.PrecedenceTier,
            GetDisplayConfidence(selectedEdge.DecisionVector.PrecedenceTier),
            ambiguous: false,
            selectedEdge.Evidence,
            CreateRejectedAlternatives(
                alternatives,
                selectedEdge.Baseline,
                selectedEdge.Candidate,
                "A stronger maximum-cardinality assignment was selected."),
            selectedEdge.Transformations,
            GetNodeDiagnostics(
                diagnosticsByNode,
                baselineIndex,
                selectedEdge.Baseline.SourceReference),
            configuration.Limits.MaximumRejectedAlternatives,
            selectedEdge.Baseline.SourceReference);
        return new FindingDecision(
            Classify(
                selectedEdge,
                configuration.Matching.PathCaseSensitivity),
            selectedEdge.Baseline,
            selectedEdge.Candidate,
            trace);
    }

    private static FindingDecision CreateAmbiguousDecision(
        Finding? baseline,
        Finding? candidate,
        int node,
        SarifRegressConfiguration configuration,
        ImmutableArray<MatchEdge> incidentEdges,
        IReadOnlyDictionary<int, List<Diagnostic>> diagnosticsByNode)
    {
        var sourceReference = (baseline ?? candidate)!.SourceReference;
        var evidence = incidentEdges
            .SelectMany(edge => edge.Evidence)
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.BaselineValue, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateValue, StringComparer.Ordinal)
            .ThenBy(item => item.Origin)
            .ThenBy(item => item.PrecedenceTier)
            .ThenBy(item => item.Lossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
        var transformations = incidentEdges
            .SelectMany(edge => edge.Transformations)
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.OriginalValue, StringComparer.Ordinal)
            .ThenBy(item => item.TransformedValue, StringComparer.Ordinal)
            .ThenBy(item => item.IsLossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
        var trace = CreateTrace(
            PrecedenceTier.Refuse,
            DisplayConfidence.Low,
            ambiguous: true,
            evidence,
            CreateRejectedAlternatives(
                incidentEdges,
                baseline,
                candidate,
                "The connected component was refused without choosing a semantic tie."),
            transformations,
            GetNodeDiagnostics(diagnosticsByNode, node, sourceReference),
            configuration.Limits.MaximumRejectedAlternatives,
            sourceReference);
        return new FindingDecision(
            FindingClassification.Ambiguous,
            baseline,
            candidate,
            trace);
    }

    private static FindingDecision CreateUnmatchedDecision(
        FindingClassification classification,
        Finding? baseline,
        Finding? candidate,
        int node,
        SarifRegressConfiguration configuration,
        ImmutableArray<MatchEdge> incidentEdges,
        IReadOnlyDictionary<int, List<Diagnostic>> diagnosticsByNode)
    {
        var sourceReference = (baseline ?? candidate)!.SourceReference;
        var outcome = incidentEdges.IsEmpty
            ? baseline is null
                ? "no-admissible-baseline"
                : "no-admissible-candidate"
            : "not-selected-after-one-to-one-assignment";
        var evidence = incidentEdges
            .SelectMany(edge => edge.Evidence)
            .Append(new EvidenceRecord(
                "assignment-outcome",
                baseline is null ? null : outcome,
                candidate is null ? null : outcome,
                EvidenceOrigin.System,
                PrecedenceTier.Refuse,
                Lossy: false,
                MatchingAlgorithms.AssignmentOutcomeVersion))
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.BaselineValue, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateValue, StringComparer.Ordinal)
            .ThenBy(item => item.Origin)
            .ThenBy(item => item.PrecedenceTier)
            .ThenBy(item => item.Lossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
        var transformations = incidentEdges
            .SelectMany(edge => edge.Transformations)
            .Concat(GetFindingTransformations(baseline))
            .Concat(GetFindingTransformations(candidate))
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.OriginalValue, StringComparer.Ordinal)
            .ThenBy(item => item.TransformedValue, StringComparer.Ordinal)
            .ThenBy(item => item.IsLossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
        var trace = CreateTrace(
            PrecedenceTier.Refuse,
            DisplayConfidence.Low,
            ambiguous: false,
            evidence,
            CreateRejectedAlternatives(
                incidentEdges,
                baseline,
                candidate,
                "The alternative was consumed by a lexicographically better "
                + "maximum-cardinality assignment."),
            transformations,
            GetNodeDiagnostics(diagnosticsByNode, node, sourceReference),
            configuration.Limits.MaximumRejectedAlternatives,
            sourceReference);
        return new FindingDecision(classification, baseline, candidate, trace);
    }

    private static ImmutableArray<TransformationRecord> GetFindingTransformations(
        Finding? finding) =>
        finding?.PrimaryLocation?.Path.Transformations
        ?? ImmutableArray<TransformationRecord>.Empty;

    private static ImmutableArray<RejectedAlternative> CreateRejectedAlternatives(
        ImmutableArray<MatchEdge> alternatives,
        Finding? decisionBaseline,
        Finding? decisionCandidate,
        string reason)
    {
        return alternatives.IsEmpty
            ? ImmutableArray<RejectedAlternative>.Empty
            : alternatives
                .Select(edge => new RejectedAlternative(
                    GetAlternativeKey(edge, decisionBaseline, decisionCandidate),
                    reason,
                    edge.DecisionVector.PrecedenceTier,
                    edge.DecisionVector))
                .OrderByDescending(
                    item => item.DecisionVector,
                    DecisionVectorComparer.Instance)
                .ThenBy(item => item.FindingKey, StringComparer.Ordinal)
                .ToImmutableArray();
    }

    private static string GetAlternativeKey(
        MatchEdge edge,
        Finding? decisionBaseline,
        Finding? decisionCandidate)
    {
        if (decisionBaseline is not null
            && string.Equals(
                edge.Baseline.FindingKey,
                decisionBaseline.FindingKey,
                StringComparison.Ordinal))
        {
            return edge.Candidate.FindingKey;
        }

        if (decisionCandidate is not null
            && string.Equals(
                edge.Candidate.FindingKey,
                decisionCandidate.FindingKey,
                StringComparison.Ordinal))
        {
            return edge.Baseline.FindingKey;
        }

        return edge.StableIdentityKey;
    }

    private static DecisionTrace CreateTrace(
        PrecedenceTier precedenceTier,
        DisplayConfidence displayConfidence,
        bool ambiguous,
        ImmutableArray<EvidenceRecord> evidence,
        ImmutableArray<RejectedAlternative> rejectedAlternatives,
        ImmutableArray<TransformationRecord> transformations,
        ImmutableArray<Diagnostic> diagnostics,
        int maximumItems,
        SourceReference sourceReference)
    {
        var wasTruncated =
            evidence.Length > maximumItems
            || rejectedAlternatives.Length > maximumItems
            || transformations.Length > maximumItems;
        if (wasTruncated)
        {
            diagnostics = Diagnostic.Sort(
                diagnostics.Append(new Diagnostic(
                    "MATCH0004",
                    DiagnosticSeverity.Note,
                    DiagnosticStage.Match,
                    $"Decision explanation collections were capped at {maximumItems} items.",
                    sourceReference)));
        }

        return new DecisionTrace(
            precedenceTier,
            displayConfidence,
            ambiguous,
            MatchingAlgorithms.MatcherVersion,
            TakeAtMost(evidence, maximumItems),
            TakeAtMost(rejectedAlternatives, maximumItems),
            TakeAtMost(transformations, maximumItems),
            diagnostics);
    }

    private static ImmutableArray<T> TakeAtMost<T>(
        ImmutableArray<T> values,
        int maximumItems) =>
        values.Length <= maximumItems
            ? values
            : values.Take(maximumItems).ToImmutableArray();

    private static ImmutableArray<Diagnostic> GetNodeDiagnostics(
        IReadOnlyDictionary<int, List<Diagnostic>> diagnosticsByNode,
        int node,
        SourceReference sourceReference)
    {
        if (!diagnosticsByNode.TryGetValue(node, out var diagnostics))
        {
            return ImmutableArray<Diagnostic>.Empty;
        }

        return Diagnostic.Sort(
            diagnostics.Select(item =>
                item.SourceReference is null
                    ? new Diagnostic(
                        item.Code,
                        item.Severity,
                        item.Stage,
                        item.Message,
                        sourceReference,
                        item.StandardBasis,
                        item.Help)
                    : item));
    }

    private static FindingClassification Classify(
        MatchEdge edge,
        PathCaseSensitivity pathCaseSensitivity)
    {
        var messageChanged = edge.DecisionVector.MessageAgreement == AgreementBand.None;
        var contextChanged = HasChangedMaterialContext(edge.Baseline, edge.Candidate);
        var codeFlowChanged = HasChangedCodeFlow(
            edge.Baseline,
            edge.Candidate,
            pathCaseSensitivity);
        if (messageChanged || contextChanged || codeFlowChanged)
        {
            return FindingClassification.Modified;
        }

        var baselineLocation = edge.Baseline.PrimaryLocation;
        var candidateLocation = edge.Candidate.PrimaryLocation;
        var pathMoved =
            (baselineLocation is null) != (candidateLocation is null)
            || (baselineLocation is not null
                && candidateLocation is not null
                && edge.DecisionVector.PathMatchKind != PathMatchKind.Exact);
        var regionMoved = !Equals(
            baselineLocation?.Region,
            candidateLocation?.Region);
        return pathMoved || regionMoved
            ? FindingClassification.Moved
            : FindingClassification.Unchanged;
    }

    private static bool HasChangedMaterialContext(Finding baseline, Finding candidate)
    {
        if (baseline.Context is null || candidate.Context is null)
        {
            return false;
        }

        return ValuesConflict(
                baseline.Context.SnippetHash,
                candidate.Context.SnippetHash)
            || ValuesConflict(
                baseline.Context.TokenWindowHash,
                candidate.Context.TokenWindowHash);
    }

    private static bool HasChangedCodeFlow(
        Finding baseline,
        Finding candidate,
        PathCaseSensitivity pathCaseSensitivity)
    {
        var baselineHasFlow =
            baseline.CodeFlow is not null
            && !baseline.CodeFlow.Anchors.IsDefaultOrEmpty;
        var candidateHasFlow =
            candidate.CodeFlow is not null
            && !candidate.CodeFlow.Anchors.IsDefaultOrEmpty;
        if (!baselineHasFlow || !candidateHasFlow)
        {
            return false;
        }

        var baselineAnchors = baseline.CodeFlow!.Anchors
            .Select(anchor => (
                CanonicalPath: NormalizePathForComparison(
                    anchor.CanonicalPath,
                    pathCaseSensitivity),
                anchor.ContextHash))
            .ToHashSet();
        var candidateAnchors = candidate.CodeFlow!.Anchors
            .Select(anchor => (
                CanonicalPath: NormalizePathForComparison(
                    anchor.CanonicalPath,
                    pathCaseSensitivity),
                anchor.ContextHash))
            .ToHashSet();
        return !baselineAnchors.SetEquals(candidateAnchors);
    }

    private static bool ValuesConflict(string? baseline, string? candidate) =>
        baseline is not null
        && candidate is not null
        && !string.Equals(baseline, candidate, StringComparison.Ordinal);

    private static string NormalizePathForComparison(
        string path,
        PathCaseSensitivity pathCaseSensitivity)
    {
        if (pathCaseSensitivity == PathCaseSensitivity.Sensitive)
        {
            return path;
        }

        return string.Create(
            path.Length,
            path,
            static (destination, source) =>
            {
                for (var index = 0; index < source.Length; index++)
                {
                    var value = source[index];
                    destination[index] = value is >= 'A' and <= 'Z'
                        ? (char)(value + ('a' - 'A'))
                        : value;
                }
            });
    }

    private static DisplayConfidence GetDisplayConfidence(PrecedenceTier precedenceTier) =>
        precedenceTier switch
        {
            PrecedenceTier.Override
                or PrecedenceTier.ExactProducer
                or PrecedenceTier.ExactCanonical
                or PrecedenceTier.StrongMoved => DisplayConfidence.High,
            PrecedenceTier.PathProblem => DisplayConfidence.Medium,
            _ => DisplayConfidence.Low,
        };

    private sealed class IncidentEdgeIndex
    {
        private readonly ImmutableArray<MatchEdge>[] baselineEdges;
        private readonly ImmutableArray<MatchEdge>[] candidateEdges;

        private IncidentEdgeIndex(
            ImmutableArray<MatchEdge>[] baselineEdges,
            ImmutableArray<MatchEdge>[] candidateEdges)
        {
            this.baselineEdges = baselineEdges;
            this.candidateEdges = candidateEdges;
        }

        public static IncidentEdgeIndex Create(
            int baselineCount,
            int candidateCount,
            ImmutableArray<MatchEdge> edges,
            IReadOnlyDictionary<string, int> baselineIndexByKey,
            IReadOnlyDictionary<string, int> candidateIndexByKey)
        {
            var baselineBuilders = new List<MatchEdge>?[baselineCount];
            var candidateBuilders = new List<MatchEdge>?[candidateCount];
            foreach (var edge in edges)
            {
                var baselineIndex = baselineIndexByKey[edge.Baseline.FindingKey];
                var candidateIndex = candidateIndexByKey[edge.Candidate.FindingKey];
                (baselineBuilders[baselineIndex] ??= []).Add(edge);
                (candidateBuilders[candidateIndex] ??= []).Add(edge);
            }

            return new IncidentEdgeIndex(
                Freeze(baselineBuilders),
                Freeze(candidateBuilders));
        }

        public ImmutableArray<MatchEdge> ForBaseline(int baselineIndex) =>
            baselineEdges[baselineIndex];

        public ImmutableArray<MatchEdge> ForCandidate(int candidateIndex) =>
            candidateEdges[candidateIndex];

        public ImmutableArray<MatchEdge> ForMatch(
            int baselineIndex,
            int candidateIndex)
        {
            var baseline = ForBaseline(baselineIndex);
            var candidate = ForCandidate(candidateIndex);
            if (baseline.IsEmpty)
            {
                return candidate;
            }

            if (candidate.IsEmpty
                || (baseline.Length == 1
                    && candidate.Length == 1
                    && ReferenceEquals(baseline[0], candidate[0])))
            {
                return baseline;
            }

            return baseline
                .Concat(candidate)
                .DistinctBy(edge => edge.StableIdentityKey, StringComparer.Ordinal)
                .Order(MatchEdgePreferenceComparer.Instance)
                .ToImmutableArray();
        }

        private static ImmutableArray<MatchEdge>[] Freeze(
            List<MatchEdge>?[] builders)
        {
            var result = new ImmutableArray<MatchEdge>[builders.Length];
            for (var index = 0; index < builders.Length; index++)
            {
                var builder = builders[index];
                if (builder is null)
                {
                    result[index] = ImmutableArray<MatchEdge>.Empty;
                    continue;
                }

                if (builder.Count > 1)
                {
                    builder.Sort(MatchEdgePreferenceComparer.Instance);
                }

                result[index] = builder.ToImmutableArray();
            }

            return result;
        }
    }

    private sealed record CandidateGraph(
        ImmutableArray<MatchEdge> RetainedEdges,
        ImmutableArray<GraphComponent> ForcedAmbiguousComponents,
        ImmutableArray<int> OverflowBaselineIndexes,
        ImmutableArray<int> OverflowCandidateIndexes,
        ImmutableArray<int> ExactProducerCountsByBaseline,
        ImmutableArray<int> ExactProducerCountsByCandidate,
        int ComponentCount,
        int CandidateEdgeCount,
        ImmutableArray<Diagnostic> Diagnostics,
        CandidatePreflightRefusal? PreflightRefusal);

    private sealed record CandidatePairPreflight(
        ImmutableArray<ImmutableArray<int>> CandidateIndexesByBaseline,
        CandidatePreflightRefusal? Refusal)
    {
        public static CandidatePairPreflight Refused(CandidatePreflightRefusal refusal) =>
            new(ImmutableArray<ImmutableArray<int>>.Empty, refusal);
    }

    private sealed record CandidatePreflightRefusal(
        string Code,
        string Message,
        string Help);

    private sealed record ResidualGraph(
        ImmutableArray<ResidualComponent> Components)
    {
        public static ResidualGraph Empty { get; } =
            new(ImmutableArray<ResidualComponent>.Empty);
    }

    private sealed record ResidualComponent(
        GraphComponent Component,
        ImmutableArray<MatchEdge> Edges);

    private sealed record CompleteGraphSummary(
        int ComponentCount,
        ImmutableArray<GraphComponent> ForcedAmbiguousComponents);

    private sealed record GraphComponent(
        ImmutableArray<int> BaselineIndexes,
        ImmutableArray<int> CandidateIndexes,
        ImmutableArray<int> AllNodes);

    private sealed class GraphComponentBuilder
    {
        public List<int> BaselineIndexes { get; } = [];

        public List<int> CandidateIndexes { get; } = [];

        public GraphComponent Build(int baselineCount)
        {
            var baselines = BaselineIndexes.Order().ToImmutableArray();
            var candidates = CandidateIndexes.Order().ToImmutableArray();
            return new GraphComponent(
                baselines,
                candidates,
                baselines
                    .Concat(candidates.Select(index => baselineCount + index))
                    .Order()
                    .ToImmutableArray());
        }
    }
}

internal sealed class CandidateBucketIndex
{
    private readonly ImmutableArray<Finding> candidates;
    private readonly Dictionary<DefaultRuleBucket, ImmutableArray<int>> defaultBuckets;
    private readonly Dictionary<AliasLookupBucket, ImmutableArray<int>> aliasBuckets;
    private readonly Dictionary<AliasLookupBucket, ImmutableArray<AliasLookupBucket>>
        aliasTargetsByBaseline;

    private CandidateBucketIndex(
        ImmutableArray<Finding> candidates,
        Dictionary<DefaultRuleBucket, ImmutableArray<int>> defaultBuckets,
        Dictionary<AliasLookupBucket, ImmutableArray<int>> aliasBuckets,
        Dictionary<AliasLookupBucket, ImmutableArray<AliasLookupBucket>>
            aliasTargetsByBaseline)
    {
        this.candidates = candidates;
        this.defaultBuckets = defaultBuckets;
        this.aliasBuckets = aliasBuckets;
        this.aliasTargetsByBaseline = aliasTargetsByBaseline;
    }

    public static CandidateBucketIndex Create(
        ImmutableArray<Finding> candidates,
        ImmutableArray<RuleAlias> aliases)
    {
        var defaultBuilders = new Dictionary<DefaultRuleBucket, List<int>>();
        var aliasBuilders = new Dictionary<AliasLookupBucket, List<int>>();
        var hasAliases = !aliases.IsEmpty;
        for (var candidateIndex = 0; candidateIndex < candidates.Length; candidateIndex++)
        {
            var candidate = candidates[candidateIndex];
            Add(
                defaultBuilders,
                new DefaultRuleBucket(
                    candidate.Producer.Family,
                    candidate.Rule.CanonicalId),
                candidateIndex);

            if (!hasAliases)
            {
                continue;
            }

            var producerTokens = new[]
            {
                candidate.Producer.Family,
                candidate.Producer.ToolName,
            }.Distinct(StringComparer.Ordinal);
            var ruleTokens = new[]
            {
                candidate.Rule.CanonicalId,
                candidate.Rule.OriginalId,
            }.Distinct(StringComparer.Ordinal);
            foreach (var producer in producerTokens)
            {
                foreach (var rule in ruleTokens)
                {
                    Add(
                        aliasBuilders,
                        new AliasLookupBucket(producer, rule),
                        candidateIndex);
                }
            }
        }

        var aliasTargetBuilders =
            new Dictionary<AliasLookupBucket, List<AliasLookupBucket>>();
        foreach (var alias in aliases)
        {
            Add(
                aliasTargetBuilders,
                new AliasLookupBucket(alias.BaselineProducer, alias.BaselineRule),
                new AliasLookupBucket(alias.CandidateProducer, alias.CandidateRule));
        }

        return new CandidateBucketIndex(
            candidates,
            defaultBuilders.ToDictionary(
                item => item.Key,
                item => item.Value.Distinct().Order().ToImmutableArray()),
            aliasBuilders.ToDictionary(
                item => item.Key,
                item => item.Value.Distinct().Order().ToImmutableArray()),
            aliasTargetBuilders.ToDictionary(
                item => item.Key,
                item => item.Value
                    .Distinct()
                    .OrderBy(target => target.Producer, StringComparer.Ordinal)
                    .ThenBy(target => target.Rule, StringComparer.Ordinal)
                    .ToImmutableArray()));
    }

    public BoundedCandidateSelection FindCandidatesBounded(
        Finding baseline,
        int maximumCandidateCount)
    {
        if (aliasTargetsByBaseline.Count == 0)
        {
            if (!defaultBuckets.TryGetValue(
                    new DefaultRuleBucket(
                        baseline.Producer.Family,
                        baseline.Rule.CanonicalId),
                    out var directCandidates))
            {
                return BoundedCandidateSelection.Empty;
            }

            return directCandidates.Length > maximumCandidateCount
                ? BoundedCandidateSelection.Overflow
                : new BoundedCandidateSelection(
                    directCandidates,
                    ExceededLimit: false);
        }

        var candidateIndexes = new HashSet<int>();
        var selectionWorkCount = 0;
        if (defaultBuckets.TryGetValue(
            new DefaultRuleBucket(
                baseline.Producer.Family,
                baseline.Rule.CanonicalId),
            out var defaultCandidates))
        {
            if (!TryAddCandidates(
                defaultCandidates,
                maximumCandidateCount,
                candidateIndexes,
                ref selectionWorkCount))
            {
                return BoundedCandidateSelection.Overflow;
            }
        }

        var targetBuckets = new HashSet<AliasLookupBucket>();
        foreach (var baselineBucket in BaselineAliasBuckets(baseline))
        {
            if (!aliasTargetsByBaseline.TryGetValue(
                baselineBucket,
                out var configuredTargets))
            {
                continue;
            }

            foreach (var configuredTarget in configuredTargets)
            {
                targetBuckets.Add(configuredTarget);
                if (targetBuckets.Count > maximumCandidateCount)
                {
                    return BoundedCandidateSelection.Overflow;
                }
            }
        }

        foreach (var targetBucket in targetBuckets
            .OrderBy(item => item.Producer, StringComparer.Ordinal)
            .ThenBy(item => item.Rule, StringComparer.Ordinal))
        {
            if (!aliasBuckets.TryGetValue(targetBucket, out var aliasedCandidates))
            {
                continue;
            }

            if (!TryAddCandidates(
                aliasedCandidates,
                maximumCandidateCount,
                candidateIndexes,
                ref selectionWorkCount))
            {
                return BoundedCandidateSelection.Overflow;
            }
        }

        return new BoundedCandidateSelection(
            candidateIndexes
                .OrderBy(index => candidates[index].FindingKey, StringComparer.Ordinal)
                .ThenBy(index => index)
                .ToImmutableArray(),
            ExceededLimit: false);
    }

    private static bool TryAddCandidates(
        ImmutableArray<int> source,
        int maximumCandidateCount,
        ISet<int> target,
        ref int selectionWorkCount)
    {
        foreach (var candidateIndex in source)
        {
            selectionWorkCount++;
            if (selectionWorkCount > maximumCandidateCount)
            {
                return false;
            }

            target.Add(candidateIndex);
            if (target.Count > maximumCandidateCount)
            {
                return false;
            }
        }

        return true;
    }

    private static IEnumerable<AliasLookupBucket> BaselineAliasBuckets(Finding baseline)
    {
        var producerTokens = new[]
        {
            baseline.Producer.Family,
            baseline.Producer.ToolName,
        }.Distinct(StringComparer.Ordinal);
        var ruleTokens = new[]
        {
            baseline.Rule.CanonicalId,
            baseline.Rule.OriginalId,
        }.Distinct(StringComparer.Ordinal);

        return producerTokens
            .SelectMany(producer => ruleTokens.Select(rule =>
                new AliasLookupBucket(producer, rule)))
            .OrderBy(item => item.Producer, StringComparer.Ordinal)
            .ThenBy(item => item.Rule, StringComparer.Ordinal);
    }

    private static void Add<TKey, TValue>(
        IDictionary<TKey, List<TValue>> target,
        TKey key,
        TValue value)
        where TKey : notnull
    {
        if (!target.TryGetValue(key, out var values))
        {
            values = [];
            target.Add(key, values);
        }

        values.Add(value);
    }

    public sealed record BoundedCandidateSelection(
        ImmutableArray<int> CandidateIndexes,
        bool ExceededLimit)
    {
        public static BoundedCandidateSelection Empty { get; } =
            new(ImmutableArray<int>.Empty, ExceededLimit: false);

        public static BoundedCandidateSelection Overflow { get; } =
            new(ImmutableArray<int>.Empty, ExceededLimit: true);
    }

    private readonly record struct DefaultRuleBucket(
        string ProducerFamily,
        string CanonicalRule);

    private readonly record struct AliasLookupBucket(
        string Producer,
        string Rule);
}
