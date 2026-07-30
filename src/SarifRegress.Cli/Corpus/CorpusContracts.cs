using System.Collections.Immutable;
using SarifRegress.Core.Matching;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Defines one labelled baseline/candidate identity pair.
/// </summary>
public sealed record LabelledPair(
    string BaselineKey,
    string CandidateKey,
    FindingClassification Classification);

/// <summary>
/// Defines the complete pairing graph and expected refusals for one corpus case.
/// </summary>
public sealed record CorpusLabels(
    string SchemaVersion,
    ImmutableArray<LabelledPair> Pairs,
    ImmutableHashSet<string> ExpectedAmbiguous,
    ImmutableHashSet<string> ExpectedResolved,
    ImmutableHashSet<string> ExpectedNew);

/// <summary>
/// Reports exact corpus quality counts and derived metrics.
/// </summary>
public sealed record CorpusMetrics(
    int LabelledPairs,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    int ExpectedAmbiguous,
    int SilentAmbiguousMatches,
    decimal Precision,
    decimal Recall,
    decimal F1);

/// <summary>
/// Reports one case-level corpus evaluation.
/// </summary>
public sealed record CorpusCaseEvaluation(
    string CaseName,
    CorpusMetrics Metrics);

/// <summary>
/// Reports an aggregate corpus evaluation in stable case-name order.
/// </summary>
public sealed record CorpusEvaluation(
    ImmutableArray<CorpusCaseEvaluation> Cases,
    CorpusMetrics Aggregate);
