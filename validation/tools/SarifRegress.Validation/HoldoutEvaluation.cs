using System.Collections.Immutable;
using System.Text.Json;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;

namespace SarifRegress.Validation;

/// <summary>Defines stable metric fields shared by case, producer, and aggregate reports.</summary>
public sealed record HoldoutMetrics(
    int GroundTruthUnits,
    int LabelledRelationships,
    int LabelledMatches,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    int ClassificationMismatches,
    int NewClassifications,
    int ResolvedClassifications,
    int AmbiguousClassifications,
    int CorrectNewClassifications,
    int CorrectResolvedClassifications,
    int CorrectAmbiguityRefusals,
    int UnexpectedAmbiguityRefusals,
    int IncorrectlyAutoMatchedAmbiguousCases,
    int IngestionFailures,
    int StructuralFailures,
    decimal Precision,
    decimal Recall,
    decimal F1);

/// <summary>Defines one ground-truth relationship independent of matcher output.</summary>
public sealed record GroundTruthRelationship(
    string Kind,
    string? BaselineKey,
    string? CandidateKey,
    string ExpectedClassification);

/// <summary>Defines the matcher projection observed for one ground-truth relationship.</summary>
public sealed record ActualRelationship(
    string State,
    string? BaselineKey,
    string? CandidateKey);

/// <summary>Reports one exact ground-truth relationship outcome.</summary>
public sealed record RelationshipResult(
    string RelationshipId,
    GroundTruthRelationship GroundTruth,
    ActualRelationship Actual,
    string Outcome);

/// <summary>References one relationship without duplicating producer-controlled content.</summary>
public sealed record RelationshipReference(string RelationshipId);

/// <summary>Reports whether one observed ambiguity refusal was expected.</summary>
public sealed record AmbiguityRefusal(string RelationshipId, bool Expected);

/// <summary>Reports one bounded ingestion failure and its stable diagnostic code.</summary>
public sealed record IngestionFailure(string Input, string DiagnosticCode);

/// <summary>Reports one structural failure without an ambient path.</summary>
public sealed record StructuralFailure(string Code, string RelativePath);

/// <summary>Separates failure modes that must not be collapsed into generic errors.</summary>
public sealed record OutcomeDetails(
    ImmutableArray<RelationshipReference> FalseMatches,
    ImmutableArray<RelationshipReference> MissedMatches,
    ImmutableArray<RelationshipReference> ClassificationMismatches,
    ImmutableArray<AmbiguityRefusal> AmbiguityRefusals,
    ImmutableArray<RelationshipReference> IncorrectAmbiguityMatches,
    ImmutableArray<IngestionFailure> IngestionFailures,
    ImmutableArray<StructuralFailure> StructuralFailures);

/// <summary>Counts one stable diagnostic code.</summary>
public sealed record DiagnosticCount(string Code, int Count);

/// <summary>Reports one fully normalized SarifRegress case evaluation.</summary>
public sealed record SarifRegressCaseResult(
    string CaseId,
    string ProducerId,
    string Status,
    CaseInputHashes InputHashes,
    string? EngineReportSha256,
    HoldoutMetrics Metrics,
    ImmutableArray<RelationshipResult> RelationshipResults,
    OutcomeDetails Outcomes,
    ImmutableArray<DiagnosticCount> DiagnosticCounts);

/// <summary>Associates aggregate metrics with one producer family.</summary>
public sealed record ProducerHoldoutMetrics(
    string ProducerId,
    HoldoutMetrics Metrics);

/// <summary>Reports the complete normalized frozen-engine evaluation.</summary>
public sealed record SarifRegressHoldoutReport(
    EvaluationIdentity Evaluation,
    HoldoutMetrics Aggregate,
    ImmutableArray<ProducerHoldoutMetrics> Producers,
    ImmutableArray<SarifRegressCaseResult> Cases,
    ImmutableArray<DiagnosticCount> DiagnosticCounts);

/// <summary>Creates exact counts and ratios without averaging rounded case values.</summary>
public static class HoldoutMetricsCalculator
{
    /// <summary>Projects existing corpus metrics plus lifecycle/refusal details.</summary>
    public static HoldoutMetrics FromCase(
        CorpusMetrics metrics,
        int groundTruthUnits,
        int ambiguousClassifications,
        int correctAmbiguityRefusals,
        int unexpectedAmbiguityRefusals,
        int incorrectlyAutoMatchedAmbiguousCases,
        int ingestionFailures,
        int structuralFailures) => new(
        groundTruthUnits,
        metrics.LabelledPairs,
        metrics.TruePositives + metrics.FalsePositives,
        metrics.TruePositives,
        metrics.FalsePositives,
        metrics.FalseNegatives,
        metrics.ClassificationMismatches,
        metrics.CorrectNew + metrics.UnexpectedNew,
        metrics.CorrectResolved + metrics.UnexpectedResolved,
        ambiguousClassifications,
        metrics.CorrectNew,
        metrics.CorrectResolved,
        correctAmbiguityRefusals,
        unexpectedAmbiguityRefusals,
        incorrectlyAutoMatchedAmbiguousCases,
        ingestionFailures,
        structuralFailures,
        metrics.Precision,
        metrics.Recall,
        metrics.F1);

    /// <summary>Aggregates raw counts and recomputes precision, recall, and F1.</summary>
    public static HoldoutMetrics Aggregate(IEnumerable<HoldoutMetrics> metrics)
    {
        ArgumentNullException.ThrowIfNull(metrics);
        HoldoutMetrics[] values = metrics.ToArray();
        int truePositives = values.Sum(item => item.TruePositives);
        int falsePositives = values.Sum(item => item.FalsePositives);
        int falseNegatives = values.Sum(item => item.FalseNegatives);
        decimal precision = Divide(truePositives, truePositives + falsePositives);
        decimal recall = Divide(truePositives, truePositives + falseNegatives);
        decimal f1 = precision + recall == 0
            ? 0
            : decimal.Round(
                2 * precision * recall / (precision + recall),
                6,
                MidpointRounding.ToEven);
        return new HoldoutMetrics(
            values.Sum(item => item.GroundTruthUnits),
            values.Sum(item => item.LabelledRelationships),
            values.Sum(item => item.LabelledMatches),
            truePositives,
            falsePositives,
            falseNegatives,
            values.Sum(item => item.ClassificationMismatches),
            values.Sum(item => item.NewClassifications),
            values.Sum(item => item.ResolvedClassifications),
            values.Sum(item => item.AmbiguousClassifications),
            values.Sum(item => item.CorrectNewClassifications),
            values.Sum(item => item.CorrectResolvedClassifications),
            values.Sum(item => item.CorrectAmbiguityRefusals),
            values.Sum(item => item.UnexpectedAmbiguityRefusals),
            values.Sum(item => item.IncorrectlyAutoMatchedAmbiguousCases),
            values.Sum(item => item.IngestionFailures),
            values.Sum(item => item.StructuralFailures),
            precision,
            recall,
            f1);
    }

    private static decimal Divide(int numerator, int denominator) => denominator == 0
        ? 1
        : decimal.Round(
            (decimal)numerator / denominator,
            6,
            MidpointRounding.ToEven);
}

/// <summary>
/// Converts the existing <see cref="CorpusRunner"/> result into an explicit holdout failure taxonomy.
/// </summary>
public static class HoldoutOutcomeClassifier
{
    /// <summary>
    /// Time: O(r log r); Space: O(r), where r is labelled plus observed relationships.
    /// </summary>
    public static SarifRegressCaseResult Classify(
        ValidatedHoldoutCase holdoutCase,
        CorpusCaseRun caseRun)
    {
        ArgumentNullException.ThrowIfNull(holdoutCase);
        ArgumentNullException.ThrowIfNull(caseRun);
        if (!string.Equals(
            holdoutCase.Plan.Id,
            caseRun.CaseName,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The corpus result case name does not match the holdout plan.");
        }

        ObservedCase observed = ParseObservedCase(caseRun.Artifact.Json.AsSpan());
        ImmutableArray<IngestionFailure> ingestionFailures =
            CreateIngestionFailures(caseRun, observed);
        string status = ingestionFailures.IsEmpty
            ? "evaluated"
            : "ingestion-failure";
        ImmutableArray<RelationshipResult> relationships = ingestionFailures.IsEmpty
            ? ClassifyRelationships(holdoutCase.Plan.Id, holdoutCase.Labels, observed)
            : CreateFailedRelationships(
                holdoutCase.Plan.Id,
                holdoutCase.Labels,
                "ingestion-failure",
                "ingestion-failure");
        OutcomeDetails outcomes = CreateOutcomeDetails(
            relationships,
            ingestionFailures,
            []);
        int correctAmbiguities = outcomes.AmbiguityRefusals.Count(item => item.Expected);
        int unexpectedAmbiguities = outcomes.AmbiguityRefusals.Length
            - correctAmbiguities;
        HoldoutMetrics metrics = HoldoutMetricsCalculator.FromCase(
            caseRun.Metrics,
            relationships.Length,
            observed.Decisions.Count(item =>
                item.Classification == FindingClassification.Ambiguous),
            correctAmbiguities,
            unexpectedAmbiguities,
            outcomes.IncorrectAmbiguityMatches.Length,
            ingestionFailures.Length,
            structuralFailures: 0);
        return new SarifRegressCaseResult(
            holdoutCase.Plan.Id,
            holdoutCase.Plan.ProducerId,
            status,
            holdoutCase.InputHashes,
            caseRun.Artifact.Sha256,
            metrics,
            relationships,
            outcomes,
            observed.DiagnosticCounts);
    }

    private static ImmutableArray<RelationshipResult> ClassifyRelationships(
        string caseId,
        CorpusLabels labels,
        ObservedCase observed)
    {
        LabelledPair[] expectedPairs = labels.Pairs
            .OrderBy(item => item.BaselineKey, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey, StringComparer.Ordinal)
            .ToArray();
        Dictionary<string, LabelledPair> expectedPairKeys = expectedPairs.ToDictionary(
            item => PairKey(item.BaselineKey, item.CandidateKey),
            StringComparer.Ordinal);
        ObservedDecision[] unexpectedAccepted = observed.Decisions
            .Where(item => item.IsAccepted
                && !labels.ExpectedAmbiguous.Contains(item.BaselineKey!)
                && !labels.ExpectedAmbiguous.Contains(item.CandidateKey!)
                && !labels.ExpectedResolved.Contains(item.BaselineKey!)
                && !labels.ExpectedNew.Contains(item.CandidateKey!)
                && !expectedPairKeys.ContainsKey(PairKey(
                    item.BaselineKey!,
                    item.CandidateKey!)))
            .OrderBy(item => item.BaselineKey, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey, StringComparer.Ordinal)
            .ToArray();
        Dictionary<string, ObservedDecision> assignedFalseMatches =
            AssignFalseMatches(caseId, expectedPairs, unexpectedAccepted);

        var results = ImmutableArray.CreateBuilder<RelationshipResult>();
        for (var index = 0; index < expectedPairs.Length; index++)
        {
            LabelledPair expected = expectedPairs[index];
            string id = RelationshipId(caseId, "match", index);
            if (assignedFalseMatches.TryGetValue(id, out ObservedDecision? falseMatch))
            {
                results.Add(new RelationshipResult(
                    id,
                    GroundTruth(expected),
                    Actual(falseMatch),
                    "false-match"));
                continue;
            }

            ObservedDecision? exact = observed.Decisions.FirstOrDefault(item =>
                item.IsAccepted
                && item.BaselineKey == expected.BaselineKey
                && item.CandidateKey == expected.CandidateKey);
            if (exact is not null)
            {
                string expectedClassification = Classification(expected.Classification);
                string actualClassification = Classification(exact.Classification);
                results.Add(new RelationshipResult(
                    id,
                    GroundTruth(expected),
                    Actual(exact),
                    expectedClassification == actualClassification
                        ? "true-positive"
                        : "classification-mismatch"));
                continue;
            }

            ObservedDecision? ambiguity = observed.Decisions.FirstOrDefault(item =>
                item.Classification == FindingClassification.Ambiguous
                && (item.BaselineKey == expected.BaselineKey
                    || item.CandidateKey == expected.CandidateKey));
            results.Add(new RelationshipResult(
                id,
                GroundTruth(expected),
                ambiguity is null
                    ? new ActualRelationship("not-reported", null, null)
                    : Actual(ambiguity),
                ambiguity is null
                    ? "missed-match"
                    : "unexpected-ambiguity-refusal"));
        }

        AddLifecycleRelationships(
            results,
            caseId,
            "new",
            labels.ExpectedNew,
            observed,
            isBaseline: false);
        AddLifecycleRelationships(
            results,
            caseId,
            "resolved",
            labels.ExpectedResolved,
            observed,
            isBaseline: true);
        AddAmbiguousRelationships(results, caseId, labels, observed);
        return results
            .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static Dictionary<string, ObservedDecision> AssignFalseMatches(
        string caseId,
        IReadOnlyList<LabelledPair> expectedPairs,
        IEnumerable<ObservedDecision> falseMatches)
    {
        var assignments = new Dictionary<string, ObservedDecision>(
            StringComparer.Ordinal);
        foreach (ObservedDecision falseMatch in falseMatches)
        {
            int index = Enumerable.Range(0, expectedPairs.Count)
                .Where(candidateIndex =>
                    expectedPairs[candidateIndex].BaselineKey == falseMatch.BaselineKey
                    || expectedPairs[candidateIndex].CandidateKey == falseMatch.CandidateKey)
                .Order()
                .FirstOrDefault(
                    candidateIndex => !assignments.ContainsKey(
                        RelationshipId(caseId, "match", candidateIndex)),
                    defaultValue: -1);
            if (index < 0)
            {
                throw new InvalidDataException(
                    "An accepted false match could not be associated with labelled endpoints.");
            }

            assignments.Add(RelationshipId(caseId, "match", index), falseMatch);
        }

        return assignments;
    }

    private static void AddLifecycleRelationships(
        ImmutableArray<RelationshipResult>.Builder results,
        string caseId,
        string kind,
        IEnumerable<string> keys,
        ObservedCase observed,
        bool isBaseline)
    {
        string expectedState = kind;
        string correctOutcome = kind == "new" ? "correct-new" : "correct-resolved";
        string incorrectOutcome = kind == "new" ? "incorrect-new" : "incorrect-resolved";
        string[] ordered = keys.Order(StringComparer.Ordinal).ToArray();
        for (var index = 0; index < ordered.Length; index++)
        {
            string key = ordered[index];
            ObservedDecision? actual = observed.Decisions.FirstOrDefault(item =>
                isBaseline ? item.BaselineKey == key : item.CandidateKey == key);
            bool correct = actual is not null
                && Classification(actual.Classification) == expectedState;
            string outcome = actual?.IsAccepted == true
                ? "false-match"
                : correct
                    ? correctOutcome
                    : incorrectOutcome;
            results.Add(new RelationshipResult(
                RelationshipId(caseId, kind, index),
                new GroundTruthRelationship(
                    kind,
                    isBaseline ? key : null,
                    isBaseline ? null : key,
                    expectedState),
                actual is null
                    ? new ActualRelationship("not-reported", null, null)
                    : Actual(actual),
                outcome));
        }
    }

    private static void AddAmbiguousRelationships(
        ImmutableArray<RelationshipResult>.Builder results,
        string caseId,
        CorpusLabels labels,
        ObservedCase observed)
    {
        string[] baseline = labels.ExpectedAmbiguous
            .Where(item => item.StartsWith("baseline:", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] candidate = labels.ExpectedAmbiguous
            .Where(item => item.StartsWith("candidate:", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (baseline.Length != candidate.Length)
        {
            throw new InvalidDataException(
                "Expected ambiguity labels must be balanced across baseline and candidate.");
        }

        HashSet<string> ambiguousKeys = baseline.Concat(candidate)
            .ToHashSet(StringComparer.Ordinal);
        ObservedDecision[] acceptedDecisions = observed.Decisions
            .Where(item => item.IsAccepted
                && (ambiguousKeys.Contains(item.BaselineKey!)
                    || ambiguousKeys.Contains(item.CandidateKey!)))
            .OrderBy(item => item.BaselineKey, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey, StringComparer.Ordinal)
            .ToArray();
        var assignedAccepted = new Dictionary<int, ObservedDecision>();
        foreach (ObservedDecision decision in acceptedDecisions)
        {
            int assignedIndex = Enumerable.Range(0, baseline.Length)
                .Where(index => !assignedAccepted.ContainsKey(index)
                    && (decision.BaselineKey == baseline[index]
                        || decision.CandidateKey == candidate[index]))
                .OrderBy(index => decision.BaselineKey == baseline[index]
                    && decision.CandidateKey == candidate[index]
                        ? 0
                        : 1)
                .ThenBy(index => index)
                .FirstOrDefault(defaultValue: -1);
            if (assignedIndex < 0)
            {
                throw new InvalidDataException(
                    "An accepted ambiguity decision could not be assigned exactly once.");
            }

            assignedAccepted.Add(assignedIndex, decision);
        }

        for (var index = 0; index < baseline.Length; index++)
        {
            ObservedDecision? baselineDecision = observed.Decisions.FirstOrDefault(
                item => item.BaselineKey == baseline[index]);
            ObservedDecision? candidateDecision = observed.Decisions.FirstOrDefault(
                item => item.CandidateKey == candidate[index]);
            bool accepted = assignedAccepted.TryGetValue(
                index,
                out ObservedDecision? acceptedDecision);
            bool refused = baselineDecision?.Classification
                    == FindingClassification.Ambiguous
                && candidateDecision?.Classification
                    == FindingClassification.Ambiguous;
            ActualRelationship actual = accepted
                ? Actual(acceptedDecision!)
                : new ActualRelationship(
                    refused ? "ambiguous" : "not-reported",
                    refused ? baseline[index] : null,
                    refused ? candidate[index] : null);
            string outcome = accepted
                ? "incorrect-ambiguity-match"
                : refused
                    ? "correct-ambiguity-refusal"
                    : "missed-match";
            results.Add(new RelationshipResult(
                RelationshipId(caseId, "ambiguous", index),
                new GroundTruthRelationship(
                    "ambiguous",
                    baseline[index],
                    candidate[index],
                    "ambiguous"),
                actual,
                outcome));
        }
    }

    private static ImmutableArray<RelationshipResult> CreateFailedRelationships(
        string caseId,
        CorpusLabels labels,
        string actualState,
        string outcome)
    {
        var relationships = CreateGroundTruthRelationships(caseId, labels);
        return relationships.Select(item => item with
            {
                Actual = new ActualRelationship(actualState, null, null),
                Outcome = outcome,
            })
            .ToImmutableArray();
    }

    private static ImmutableArray<RelationshipResult> CreateGroundTruthRelationships(
        string caseId,
        CorpusLabels labels)
    {
        var emptyObserved = new ObservedCase(
            [],
            [],
            ImmutableSortedDictionary<string, string>.Empty
                .WithComparers(StringComparer.Ordinal));
        return ClassifyRelationships(caseId, labels, emptyObserved);
    }

    private static OutcomeDetails CreateOutcomeDetails(
        ImmutableArray<RelationshipResult> relationships,
        ImmutableArray<IngestionFailure> ingestionFailures,
        ImmutableArray<StructuralFailure> structuralFailures) => new(
        References(relationships, "false-match"),
        References(relationships, "missed-match"),
        References(relationships, "classification-mismatch"),
        relationships
            .Where(item => item.Outcome is
                "correct-ambiguity-refusal" or "unexpected-ambiguity-refusal")
            .Select(item => new AmbiguityRefusal(
                item.RelationshipId,
                item.Outcome == "correct-ambiguity-refusal"))
            .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray(),
        References(relationships, "incorrect-ambiguity-match"),
        ingestionFailures,
        structuralFailures);

    private static ImmutableArray<RelationshipReference> References(
        IEnumerable<RelationshipResult> relationships,
        string outcome) => relationships
        .Where(item => item.Outcome == outcome)
        .Select(item => new RelationshipReference(item.RelationshipId))
        .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
        .ToImmutableArray();

    private static ImmutableArray<IngestionFailure> CreateIngestionFailures(
        CorpusCaseRun caseRun,
        ObservedCase observed) => caseRun.ObservedInvalidInputs
        .Order()
        .Select(input => new IngestionFailure(
            input == InputKind.Baseline ? "baseline" : "candidate",
            observed.IngestionDiagnosticCodes.GetValueOrDefault(
                input == InputKind.Baseline ? "baseline" : "candidate")
                ?? observed.DiagnosticCounts.FirstOrDefault()?.Code
                ?? "INGESTION_FAILURE"))
        .ToImmutableArray();

    private static ObservedCase ParseObservedCase(ReadOnlySpan<byte> artifact)
    {
        using JsonDocument document = JsonDocument.Parse(artifact);
        var decisions = ImmutableArray.CreateBuilder<ObservedDecision>();
        if (document.RootElement.TryGetProperty("findings", out JsonElement findings))
        {
            foreach (JsonElement finding in findings.EnumerateArray())
            {
                FindingClassification classification = ParseClassification(
                    finding.GetProperty("classification").GetString());
                decisions.Add(new ObservedDecision(
                    GetFindingKey(finding, "baseline"),
                    GetFindingKey(finding, "candidate"),
                    classification));
            }
        }

        ImmutableArray<ObservedDecision> ordered = decisions
            .OrderBy(item => item.BaselineKey ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.Classification)
            .ToImmutableArray();
        EnsureDecisionKeysUnique(ordered);
        return new ObservedCase(
            ordered,
            CountDiagnostics(document.RootElement),
            ReadIngestionDiagnosticCodes(document.RootElement));
    }

    private static ImmutableSortedDictionary<string, string>
        ReadIngestionDiagnosticCodes(JsonElement root)
    {
        var values = ImmutableSortedDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        if (!root.TryGetProperty("inputs", out JsonElement inputs))
        {
            return values.ToImmutable();
        }

        foreach (JsonElement input in inputs.EnumerateArray())
        {
            if (!input.TryGetProperty("valid", out JsonElement valid)
                || valid.GetBoolean()
                || !input.TryGetProperty("input", out JsonElement inputName)
                || !input.TryGetProperty("diagnostics", out JsonElement diagnostics))
            {
                continue;
            }

            string name = inputName.GetString()
                ?? throw new InvalidDataException("An invalid input name is null.");
            JsonElement.ArrayEnumerator enumerator = diagnostics.EnumerateArray();
            if (enumerator.MoveNext())
            {
                string code = enumerator.Current.GetProperty("code").GetString()
                    ?? throw new InvalidDataException(
                        "An ingestion diagnostic code is null.");
                values[name] = code;
            }
        }

        return values.ToImmutable();
    }

    private static string? GetFindingKey(JsonElement finding, string propertyName)
    {
        if (!finding.TryGetProperty(propertyName, out JsonElement snapshot)
            || snapshot.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return snapshot.GetProperty("findingKey").GetString()
            ?? throw new InvalidDataException("A report finding key is null.");
    }

    private static ImmutableArray<DiagnosticCount> CountDiagnostics(
        JsonElement root)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        Visit(root, counts);
        return counts.OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(item => new DiagnosticCount(item.Key, item.Value))
            .ToImmutableArray();

        static void Visit(JsonElement element, IDictionary<string, int> values)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                if (element.TryGetProperty("code", out JsonElement codeElement)
                    && element.TryGetProperty("severity", out _)
                    && element.TryGetProperty("stage", out _))
                {
                    string code = codeElement.GetString()
                        ?? throw new InvalidDataException("A diagnostic code is null.");
                    values[code] = values.TryGetValue(code, out int count)
                        ? checked(count + 1)
                        : 1;
                }

                foreach (JsonProperty property in element.EnumerateObject())
                {
                    Visit(property.Value, values);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in element.EnumerateArray())
                {
                    Visit(item, values);
                }
            }
        }
    }

    private static void EnsureDecisionKeysUnique(
        IEnumerable<ObservedDecision> decisions)
    {
        var baseline = new HashSet<string>(StringComparer.Ordinal);
        var candidate = new HashSet<string>(StringComparer.Ordinal);
        foreach (ObservedDecision decision in decisions)
        {
            if (decision.BaselineKey is not null
                && !baseline.Add(decision.BaselineKey))
            {
                throw new InvalidDataException(
                    $"Engine report repeats baseline finding '{decision.BaselineKey}'.");
            }

            if (decision.CandidateKey is not null
                && !candidate.Add(decision.CandidateKey))
            {
                throw new InvalidDataException(
                    $"Engine report repeats candidate finding '{decision.CandidateKey}'.");
            }
        }
    }

    private static GroundTruthRelationship GroundTruth(LabelledPair pair) => new(
        "match",
        pair.BaselineKey,
        pair.CandidateKey,
        Classification(pair.Classification));

    private static ActualRelationship Actual(ObservedDecision decision) => new(
        Classification(decision.Classification),
        decision.BaselineKey,
        decision.CandidateKey);

    private static string RelationshipId(
        string caseId,
        string kind,
        int zeroBasedIndex) =>
        $"{caseId}-{kind}-{zeroBasedIndex + 1:D3}";

    private static string PairKey(string baselineKey, string candidateKey) =>
        $"{baselineKey.Length}:{baselineKey}{candidateKey.Length}:{candidateKey}";

    private static FindingClassification ParseClassification(string? value) => value switch
    {
        "unchanged" => FindingClassification.Unchanged,
        "moved" => FindingClassification.Moved,
        "modified" => FindingClassification.Modified,
        "new" => FindingClassification.New,
        "resolved" => FindingClassification.Resolved,
        "ambiguous" => FindingClassification.Ambiguous,
        _ => throw new InvalidDataException(
            $"Engine report contains unsupported classification '{value ?? "<null>"}'."),
    };

    private static string Classification(FindingClassification value) => value switch
    {
        FindingClassification.Unchanged => "unchanged",
        FindingClassification.Moved => "moved",
        FindingClassification.Modified => "modified",
        FindingClassification.New => "new",
        FindingClassification.Resolved => "resolved",
        FindingClassification.Ambiguous => "ambiguous",
        _ => throw new InvalidDataException(
            $"Unsupported finding classification '{value}'."),
    };

    private sealed record ObservedDecision(
        string? BaselineKey,
        string? CandidateKey,
        FindingClassification Classification)
    {
        public bool IsAccepted => BaselineKey is not null
            && CandidateKey is not null
            && Classification != FindingClassification.Ambiguous;
    }

    private sealed record ObservedCase(
        ImmutableArray<ObservedDecision> Decisions,
        ImmutableArray<DiagnosticCount> DiagnosticCounts,
        ImmutableSortedDictionary<string, string> IngestionDiagnosticCodes);
}
