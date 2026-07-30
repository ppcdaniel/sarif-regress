using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
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
    ImmutableHashSet<string> ExpectedNew)
{
    /// <summary>
    /// Gets inputs that are intentionally malformed and must be rejected by ingestion.
    /// </summary>
    public ImmutableHashSet<InputKind> ExpectedInvalidInputs { get; init; } =
        ImmutableHashSet<InputKind>.Empty;
}

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
    decimal F1)
{
    /// <summary>
    /// Gets accepted labelled pairs whose classification differs from ground truth.
    /// </summary>
    public int ClassificationMismatches { get; init; }

    /// <summary>
    /// Gets expected ambiguous finding identities emitted as ambiguous.
    /// </summary>
    public int CorrectAmbiguous { get; init; }

    /// <summary>
    /// Gets expected ambiguous identities not emitted as ambiguous.
    /// </summary>
    public int MissingAmbiguous { get; init; }

    /// <summary>
    /// Gets emitted ambiguous identities absent from ground truth.
    /// </summary>
    public int UnexpectedAmbiguous { get; init; }

    /// <summary>
    /// Gets the number of baseline identities labelled resolved.
    /// </summary>
    public int ExpectedResolved { get; init; }

    /// <summary>
    /// Gets expected resolved baseline identities emitted as resolved.
    /// </summary>
    public int CorrectResolved { get; init; }

    /// <summary>
    /// Gets expected resolved baseline identities not emitted as resolved.
    /// </summary>
    public int MissingResolved { get; init; }

    /// <summary>
    /// Gets emitted resolved identities absent from ground truth.
    /// </summary>
    public int UnexpectedResolved { get; init; }

    /// <summary>
    /// Gets the number of candidate identities labelled new.
    /// </summary>
    public int ExpectedNew { get; init; }

    /// <summary>
    /// Gets expected new candidate identities emitted as new.
    /// </summary>
    public int CorrectNew { get; init; }

    /// <summary>
    /// Gets expected new candidate identities not emitted as new.
    /// </summary>
    public int MissingNew { get; init; }

    /// <summary>
    /// Gets emitted new identities absent from ground truth.
    /// </summary>
    public int UnexpectedNew { get; init; }

    /// <summary>
    /// Gets whether every classification and expected unmatched/refused set agrees exactly.
    /// </summary>
    public bool ExpectationsSatisfied =>
        ClassificationMismatches == 0
        && MissingAmbiguous == 0
        && UnexpectedAmbiguous == 0
        && MissingResolved == 0
        && UnexpectedResolved == 0
        && MissingNew == 0
        && UnexpectedNew == 0
        && SilentAmbiguousMatches == 0;
}

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

/// <summary>
/// Defines fixed quality gates for one corpus run.
/// </summary>
public sealed record CorpusThresholds(
    decimal MinimumPrecision,
    decimal MinimumRecall,
    int MaximumSilentAmbiguousMatches)
{
    /// <summary>
    /// Gets the published MVP corpus gates.
    /// </summary>
    public static CorpusThresholds Mvp { get; } = new(
        MinimumPrecision: 0.95m,
        MinimumRecall: 0.90m,
        MaximumSilentAmbiguousMatches: 0);

    /// <summary>
    /// Validates the threshold contract.
    /// </summary>
    public void Validate()
    {
        if (MinimumPrecision is < 0 or > 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MinimumPrecision),
                MinimumPrecision,
                "Minimum precision must be between zero and one.");
        }

        if (MinimumRecall is < 0 or > 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MinimumRecall),
                MinimumRecall,
                "Minimum recall must be between zero and one.");
        }

        if (MaximumSilentAmbiguousMatches < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumSilentAmbiguousMatches),
                MaximumSilentAmbiguousMatches,
                "The silent-ambiguity limit cannot be negative.");
        }
    }
}

/// <summary>
/// Reports one fully executed corpus case.
/// </summary>
public sealed record CorpusCaseRun(
    string CaseName,
    ImmutableArray<InputKind> ExpectedInvalidInputs,
    ImmutableArray<InputKind> ObservedInvalidInputs,
    CorpusMetrics Metrics,
    bool Passed);

/// <summary>
/// Reports one deterministic corpus execution and its quality-gate outcome.
/// </summary>
public sealed record CorpusRunResult(
    string SchemaVersion,
    CorpusThresholds Thresholds,
    ImmutableArray<CorpusCaseRun> Cases,
    CorpusMetrics Aggregate,
    ImmutableArray<string> Failures)
{
    /// <summary>
    /// Gets whether all labels, input expectations, and published quality gates passed.
    /// </summary>
    public bool Passed => Failures.IsEmpty;
}
