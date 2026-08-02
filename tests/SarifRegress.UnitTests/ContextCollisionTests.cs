using System.Text.Json;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Match;
using SarifRegress.Sarif.Configuration;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.UnitTests;

public sealed class ContextCollisionTests
{
    private const string SharedContext = "opaque-context-hash-7f3a";

    private readonly FindingMatcher matcher = new();

    [Fact]
    public async Task Authentic_repeated_context_holdout_recovers_only_labelled_pairs()
    {
        var caseRoot = Path.Combine(
            RepositoryLayout.Root,
            "validation",
            "holdout",
            "cases",
            "gitleaks");
        await using var configStream = File.OpenRead(Path.Combine(caseRoot, "config.json"));
        var configResult = await new SarifConfigurationReader().ReadAsync(
            configStream,
            TestContext.Current.CancellationToken);
        Assert.True(configResult.IsValid);
        var configuration = Assert.IsType<
            SarifRegress.Core.Configuration.SarifRegressConfiguration>(
                configResult.Configuration);

        var baseline = await IngestHoldoutAsync(
            caseRoot,
            "baseline.sarif",
            InputKind.Baseline,
            configuration);
        var candidate = await IngestHoldoutAsync(
            caseRoot,
            "candidate.sarif",
            InputKind.Candidate,
            configuration);
        var result = matcher.Match(baseline, candidate, configuration);

        using var labels = JsonDocument.Parse(
            File.ReadAllBytes(Path.Combine(caseRoot, "labels.json")));
        var expectedPairs = labels.RootElement
            .GetProperty("pairs")
            .EnumerateArray()
            .ToDictionary(
                item => item.GetProperty("baselineKey").GetString()!,
                item => new ExpectedPair(
                    item.GetProperty("candidateKey").GetString()!,
                    Enum.Parse<FindingClassification>(
                        item.GetProperty("classification").GetString()!,
                        ignoreCase: true)),
                StringComparer.Ordinal);
        var matched = result.Decisions
            .Where(decision => decision.Baseline is not null && decision.Candidate is not null)
            .ToArray();

        Assert.Equal(25, matched.Length);
        Assert.All(
            matched,
            decision =>
            {
                var expected = expectedPairs[decision.Baseline!.FindingKey];
                Assert.Equal(expected.CandidateKey, decision.Candidate!.FindingKey);
                Assert.Equal(expected.Classification, decision.Classification);
            });
        Assert.Equal(expectedPairs.Keys.Order(StringComparer.Ordinal), matched
            .Select(decision => decision.Baseline!.FindingKey)
            .Order(StringComparer.Ordinal));

        var expectedAmbiguous = labels.RootElement
            .GetProperty("expectedAmbiguous")
            .EnumerateArray()
            .Select(item => item.GetString()!)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var actualAmbiguous = result.Decisions
            .Where(decision => decision.Classification == FindingClassification.Ambiguous)
            .Select(decision => decision.Baseline?.FindingKey ?? decision.Candidate!.FindingKey)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expectedAmbiguous, actualAmbiguous);
        Assert.Equal(
            3,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.Equal(
            3,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0002");
        Assert.All(
            result.Decisions,
            decision => Assert.Contains(
                decision.Decision.Evidence,
                evidence => evidence.Kind == "context-collision"));

        var pathTemplatedMoves = matched
            .Where(decision => decision.Baseline!.PrimaryLocation?.Path
                .RepositoryRelativePath is string path
                && path.StartsWith(
                    "src/renamed-old/",
                    StringComparison.Ordinal))
            .OrderBy(decision => decision.Baseline!.FindingKey, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(5, pathTemplatedMoves.Length);
        Assert.Equal(
            [
                "baseline:0:22",
                "baseline:0:23",
                "baseline:0:24",
                "baseline:0:25",
                "baseline:0:26",
            ],
            pathTemplatedMoves.Select(decision => decision.Baseline!.FindingKey));
        Assert.Equal(
            [
                "candidate:0:25",
                "candidate:0:26",
                "candidate:0:27",
                "candidate:0:28",
                "candidate:0:29",
            ],
            pathTemplatedMoves.Select(decision => decision.Candidate!.FindingKey));
        Assert.All(
            pathTemplatedMoves,
            decision =>
            {
                Assert.Equal(FindingClassification.Moved, decision.Classification);
                Assert.Equal(
                    PrecedenceTier.WeakContextual,
                    decision.Decision.PrecedenceTier);
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "context-collision");
                var transformation = Assert.Single(
                    decision.Decision.Transformations,
                    item => item.Kind ==
                        "classification-message-location-template");
                Assert.Equal(
                    "sarifregress/message-location-template/v1",
                    transformation.AlgorithmVersion);
                var originalValue = Assert.IsType<string>(
                    transformation.OriginalValue);
                var transformedValue = Assert.IsType<string>(
                    transformation.TransformedValue);
                Assert.StartsWith(
                    "sha256:",
                    originalValue,
                    StringComparison.Ordinal);
                Assert.StartsWith(
                    "sha256:",
                    transformedValue,
                    StringComparison.Ordinal);
                Assert.Equal(71, originalValue.Length);
                Assert.Equal(71, transformedValue.Length);
                Assert.NotEqual(originalValue, transformedValue);
                Assert.True(transformation.IsLossy);
            });
    }

    [Fact]
    public void Thirteen_by_thirteen_repeated_context_reproduction_preserves_diagonals()
    {
        var (baseline, candidate) = CreateMirroredFindings(
            count: 13,
            contextHash: SharedContext,
            includeUniqueDerivedFingerprints: true);

        var result = Match(baseline, candidate);

        AssertMirroredMatches(result, count: 13, PrecedenceTier.ExactCanonical);
        Assert.Equal(13, result.CandidateEdgeCount);
        Assert.DoesNotContain(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0002");
    }

    [Fact]
    public void Thirty_by_thirty_repeated_context_stays_decomposed_and_bounded()
    {
        var (baseline, candidate) = CreateMirroredFindings(
            count: 30,
            contextHash: SharedContext,
            includeUniqueDerivedFingerprints: true);

        var result = Match(baseline, candidate);

        AssertMirroredMatches(result, count: 30, PrecedenceTier.ExactCanonical);
        Assert.Equal(30, result.CandidateEdgeCount);
        Assert.Equal(30, result.ComponentCount);
        Assert.Equal(0, result.AmbiguousComponentCount);
        Assert.DoesNotContain(
            result.Diagnostics,
            diagnostic => diagnostic.Code is "MATCH0002" or "MATCH0003"
                or "MATCH0007" or "MATCH0008" or "MATCH0009" or "MATCH0010");
    }

    [Fact]
    public void Unique_exact_path_diagonals_survive_shared_context_without_derived_identity()
    {
        var (baseline, candidate) = CreateMirroredFindings(
            count: 4,
            contextHash: SharedContext,
            includeUniqueDerivedFingerprints: false);

        var result = Match(baseline, candidate);

        AssertMirroredMatches(result, count: 4, PrecedenceTier.WeakContextual);
        Assert.Equal(4, result.CandidateEdgeCount);
    }

    [Fact]
    public void Repeated_context_alone_across_different_paths_creates_no_false_match()
    {
        var baseline = Enumerable.Range(0, 3)
            .Select(index => RepeatedContextFinding(
                InputKind.Baseline,
                $"baseline:{index:D2}",
                $"src/baseline-{index:D2}.txt",
                SharedContext))
            .ToArray();
        var candidate = Enumerable.Range(0, 3)
            .Select(index => RepeatedContextFinding(
                InputKind.Candidate,
                $"candidate:{index:D2}",
                $"src/candidate-{index:D2}.txt",
                SharedContext))
            .ToArray();

        var result = Match(baseline, candidate);

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(6, result.Decisions.Length);
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Baseline is not null && decision.Candidate is not null);
        Assert.Equal(
            3,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.Equal(
            3,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Classification == FindingClassification.Ambiguous);
    }

    [Fact]
    public void Duplicated_raw_context_on_exact_paths_refuses_incompatible_messages()
    {
        var baseline = Enumerable.Range(0, 2)
            .Select(index => RepeatedContextFinding(
                InputKind.Baseline,
                $"baseline:{index}",
                $"src/message-guard-{index}.txt",
                SharedContext,
                message: $"Baseline message {index}."))
            .ToArray();
        var candidate = Enumerable.Range(0, 2)
            .Select(index => RepeatedContextFinding(
                InputKind.Candidate,
                $"candidate:{index}",
                $"src/message-guard-{index}.txt",
                SharedContext,
                message: $"Candidate message {index}."))
            .ToArray();

        var result = Match(baseline, candidate);

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
        Assert.DoesNotContain(
            result.Decisions,
            decision => decision.Baseline is not null && decision.Candidate is not null);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public void Collided_context_cannot_hide_a_conflicting_available_channel(
        bool snippetIsCollided,
        bool pathIsAliased)
    {
        const string baselineTargetPath = "src/old/replacement.txt";
        var candidateTargetPath = pathIsAliased
            ? "src/new/replacement.txt"
            : baselineTargetPath;
        var baseline = new[]
        {
            MixedContextFinding(
                InputKind.Baseline,
                "baseline:target",
                baselineTargetPath,
                "Replacement finding.",
                snippetIsCollided,
                conflictingValue: "baseline-target"),
            MixedContextFinding(
                InputKind.Baseline,
                "baseline:collider",
                "src/colliders/baseline.txt",
                "Unrelated baseline collider.",
                snippetIsCollided,
                conflictingValue: "baseline-collider"),
        };
        var candidate = new[]
        {
            MixedContextFinding(
                InputKind.Candidate,
                "candidate:target",
                candidateTargetPath,
                "Replacement finding.",
                snippetIsCollided,
                conflictingValue: "candidate-target"),
            MixedContextFinding(
                InputKind.Candidate,
                "candidate:collider",
                "src/colliders/candidate.txt",
                "Unrelated candidate collider.",
                snippetIsCollided,
                conflictingValue: "candidate-collider"),
        };
        PathAlias[]? aliases = pathIsAliased
            ? [new PathAlias("src/old/", "src/new/")]
            : null;
        var configuration = MatchingTestData.Configuration(
            allowWeakMessageSimilarity: true,
            pathAliases: aliases);

        var ordered = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration);
        var reversed = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline.Reverse().ToArray()),
            MatchingTestData.Input(InputKind.Candidate, candidate.Reverse().ToArray()),
            configuration);

        Assert.Equal(ProjectResult(ordered), ProjectResult(reversed));
        Assert.Equal(0, ordered.CandidateEdgeCount);
        Assert.Equal(
            2,
            ordered.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.Equal(
            2,
            ordered.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.DoesNotContain(
            ordered.Decisions,
            decision => decision.Baseline is not null && decision.Candidate is not null);

        var targetDecisions = ordered.Decisions
            .Where(decision =>
                (decision.Baseline?.FindingKey ?? decision.Candidate?.FindingKey)!
                    .EndsWith(":target", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(2, targetDecisions.Length);
        Assert.All(
            targetDecisions,
            decision =>
            {
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "context-collision"
                        && evidence.AlgorithmVersion
                            == "sarifregress/evidence-occurrence/v1");
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "assignment-outcome"
                        && evidence.PrecedenceTier == PrecedenceTier.Refuse);
            });
    }

    [Fact]
    public void Collided_derived_fingerprint_cannot_hide_conflicting_raw_context()
    {
        var duplicate = MatchingTestData.DerivedFingerprint("collided-derived-context");
        var baseline = new[]
        {
            MatchingTestData.Finding(
                InputKind.Baseline,
                "baseline:target",
                path: "src/replacement.txt",
                message: "Replacement target.",
                derivedFingerprints: [duplicate],
                contextHash: "baseline-context"),
            MatchingTestData.Finding(
                InputKind.Baseline,
                "baseline:collider",
                path: "src/baseline-collider.txt",
                derivedFingerprints: [duplicate],
                contextHash: "baseline-collider-context"),
        };
        var candidate = new[]
        {
            MatchingTestData.Finding(
                InputKind.Candidate,
                "candidate:target",
                path: "src/replacement.txt",
                message: "Replacement target.",
                derivedFingerprints: [duplicate],
                contextHash: "candidate-context"),
            MatchingTestData.Finding(
                InputKind.Candidate,
                "candidate:collider",
                path: "src/candidate-collider.txt",
                derivedFingerprints: [duplicate],
                contextHash: "candidate-collider-context"),
        };

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(allowWeakMessageSimilarity: true));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Equal(
            2,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.Resolved));
        Assert.Equal(
            2,
            result.Decisions.Count(
                decision => decision.Classification == FindingClassification.New));
        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "derived-fingerprint-collision");
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "assignment-outcome");
            });
    }

    [Fact]
    public void Genuinely_indistinguishable_two_by_two_findings_remain_ambiguous()
    {
        var result = Match(
            [
                IndistinguishableFinding(InputKind.Baseline, "baseline:one"),
                IndistinguishableFinding(InputKind.Baseline, "baseline:two"),
            ],
            [
                IndistinguishableFinding(InputKind.Candidate, "candidate:one"),
                IndistinguishableFinding(InputKind.Candidate, "candidate:two"),
            ]);

        AssertAmbiguous(result, decisionCount: 4, candidateEdgeCount: 4);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0001");
    }

    [Fact]
    public void Duplicated_derived_fingerprint_does_not_use_asymmetric_line_distance()
    {
        var duplicate = MatchingTestData.DerivedFingerprint("duplicate-derived-value");
        var result = Match(
            [
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:near-first",
                    path: "src/derived/shared.txt",
                    startLine: 10,
                    derivedFingerprints: [duplicate]),
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:near-second",
                    path: "src/derived/shared.txt",
                    startLine: 100,
                    derivedFingerprints: [duplicate]),
            ],
            [
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:near-first",
                    path: "src/derived/shared.txt",
                    startLine: 11,
                    derivedFingerprints: [duplicate]),
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:near-second",
                    path: "src/derived/shared.txt",
                    startLine: 99,
                    derivedFingerprints: [duplicate]),
            ]);

        AssertAmbiguous(result, decisionCount: 4, candidateEdgeCount: 4);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0001");
        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "derived-fingerprint"
                        && evidence.AlgorithmVersion
                            == "sarifregress/derived-fingerprint-compare/v2");
                Assert.Contains(
                    decision.Decision.Evidence,
                    evidence => evidence.Kind == "derived-fingerprint-collision"
                        && evidence.AlgorithmVersion
                            == "sarifregress/evidence-occurrence/v1");
            });
    }

    [Fact]
    public void One_to_many_repeated_context_is_refused_as_ambiguous()
    {
        var result = Match(
            [IndistinguishableFinding(InputKind.Baseline, "baseline:one")],
            [
                IndistinguishableFinding(InputKind.Candidate, "candidate:one"),
                IndistinguishableFinding(InputKind.Candidate, "candidate:two"),
            ]);

        AssertAmbiguous(result, decisionCount: 3, candidateEdgeCount: 2);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0001");
    }

    [Fact]
    public void Many_to_one_repeated_context_is_refused_as_ambiguous()
    {
        var result = Match(
            [
                IndistinguishableFinding(InputKind.Baseline, "baseline:one"),
                IndistinguishableFinding(InputKind.Baseline, "baseline:two"),
            ],
            [IndistinguishableFinding(InputKind.Candidate, "candidate:one")]);

        AssertAmbiguous(result, decisionCount: 3, candidateEdgeCount: 2);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0001");
    }

    [Fact]
    public void Repeated_context_results_are_independent_of_input_order()
    {
        var (baseline, candidate) = CreateMirroredFindings(
            count: 13,
            contextHash: SharedContext,
            includeUniqueDerivedFingerprints: true);
        var ordered = Match(baseline, candidate);
        var shuffled = Match(
            baseline.Reverse().ToArray(),
            candidate.OrderByDescending(item => item.FindingKey).ToArray());

        Assert.Equal(ProjectResult(ordered), ProjectResult(shuffled));
        Assert.Equal(ordered.CandidateEdgeCount, shuffled.CandidateEdgeCount);
        Assert.Equal(ordered.ComponentCount, shuffled.ComponentCount);
        Assert.Equal(
            ordered.AmbiguousComponentCount,
            shuffled.AmbiguousComponentCount);
    }

    [Fact]
    public void Assignment_side_limit_still_refuses_an_indistinguishable_thirteen_by_thirteen()
    {
        var baseline = Enumerable.Range(0, 13)
            .Select(index => IndistinguishableFinding(
                InputKind.Baseline,
                $"baseline:{index:D2}"))
            .ToArray();
        var candidate = Enumerable.Range(0, 13)
            .Select(index => IndistinguishableFinding(
                InputKind.Candidate,
                $"candidate:{index:D2}"))
            .ToArray();

        var result = Match(baseline, candidate);

        AssertAmbiguous(result, decisionCount: 26, candidateEdgeCount: 169);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "MATCH0002");
    }

    [Fact]
    public void A_unique_context_fingerprint_retains_strong_moved_evidence()
    {
        var result = Match(
            [
                RepeatedContextFinding(
                    InputKind.Baseline,
                    "baseline:one",
                    "src/old/location.txt",
                    "unique-context-hash",
                    startLine: 10),
            ],
            [
                RepeatedContextFinding(
                    InputKind.Candidate,
                    "candidate:one",
                    "src/new/location.txt",
                    "unique-context-hash",
                    startLine: 40),
            ]);

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.Equal(PrecedenceTier.StrongMoved, decision.Decision.PrecedenceTier);
        Assert.DoesNotContain(
            decision.Decision.Evidence,
            evidence => IsCollisionOrDegradation(evidence.Kind));
    }

    [Fact]
    public void Duplicated_context_is_degraded_and_explained_with_occurrence_counts()
    {
        var (baseline, candidate) = CreateMirroredFindings(
            count: 2,
            contextHash: SharedContext,
            includeUniqueDerivedFingerprints: false);

        var result = Match(baseline, candidate);

        AssertMirroredMatches(result, count: 2, PrecedenceTier.WeakContextual);
        var occurrenceEvidence = result.Decisions
            .SelectMany(decision => decision.Decision.Evidence)
            .Where(evidence => IsCollisionOrDegradation(evidence.Kind))
            .ToArray();
        Assert.NotEmpty(occurrenceEvidence);
        Assert.All(
            occurrenceEvidence,
            evidence => Assert.Equal(
                "sarifregress/evidence-occurrence/v1",
                evidence.AlgorithmVersion));
        Assert.Contains(
            occurrenceEvidence,
            evidence => ContainsOccurrenceCount(evidence, count: 2));
    }

    [Fact]
    public void Explanation_cap_retains_occurrence_evidence_for_a_collision_match()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRejectedAlternatives = 1,
        };
        var (baseline, candidate) = CreateMirroredFindings(
            count: 2,
            contextHash: SharedContext,
            includeUniqueDerivedFingerprints: false);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(limits: limits));

        AssertMirroredMatches(result, count: 2, PrecedenceTier.WeakContextual);
        Assert.All(
            result.Decisions,
            decision =>
            {
                var evidence = Assert.Single(decision.Decision.Evidence);
                Assert.Equal(
                    "sarifregress/evidence-occurrence/v1",
                    evidence.AlgorithmVersion);
                Assert.Contains("collision", evidence.Kind, StringComparison.Ordinal);
                Assert.Contains(
                    decision.Decision.Diagnostics,
                    diagnostic => diagnostic.Code == "MATCH0004");
            });
    }

    [Fact]
    public void Long_one_sided_occurrence_evidence_is_bounded_stable_and_capped()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRejectedAlternatives = 1,
        };
        var longContext = new string('x', 1_024);
        var baseline = Enumerable.Range(0, 2)
            .Select(index => RepeatedContextFinding(
                InputKind.Baseline,
                $"baseline:{index}",
                $"src/long-baseline-{index}.txt",
                longContext))
            .ToArray();
        var candidate = Enumerable.Range(0, 2)
            .Select(index => RepeatedContextFinding(
                InputKind.Candidate,
                $"candidate:{index}",
                $"src/long-candidate-{index}.txt",
                longContext))
            .ToArray();
        var configuration = MatchingTestData.Configuration(limits: limits);

        var ordered = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration);
        var shuffled = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline.Reverse().ToArray()),
            MatchingTestData.Input(InputKind.Candidate, candidate.Reverse().ToArray()),
            configuration);

        Assert.Equal(ProjectResult(ordered), ProjectResult(shuffled));
        Assert.Equal(0, ordered.CandidateEdgeCount);
        Assert.All(
            ordered.Decisions,
            decision =>
            {
                var evidence = Assert.Single(decision.Decision.Evidence);
                Assert.Equal("context-collision", evidence.Kind);
                Assert.Equal(
                    "sarifregress/evidence-occurrence/v1",
                    evidence.AlgorithmVersion);
                Assert.True(evidence.Lossy);
                var value = Assert.IsType<string>(
                    evidence.BaselineValue ?? evidence.CandidateValue);
                Assert.StartsWith("sha256:", value, StringComparison.Ordinal);
                Assert.Equal(71, value.Length);
                Assert.True(
                    (evidence.BaselineValue is null)
                    != (evidence.CandidateValue is null));
                Assert.Contains(
                    decision.Decision.Diagnostics,
                    diagnostic => diagnostic.Code == "MATCH0004");
            });
    }

    [Theory]
    [InlineData("opaque-a1b2c3", "Acme Audit", "acme-audit")]
    [InlineData("內容雜湊-甲乙丙", "Northwind Inspector", "northwind-inspector")]
    public void Collision_handling_is_independent_of_context_value_and_producer_name(
        string contextHash,
        string toolName,
        string producerFamily)
    {
        var baseline = Enumerable.Range(0, 2)
            .Select(index => RepeatedContextFinding(
                InputKind.Baseline,
                $"baseline:{index}",
                $"src/item-{index}.txt",
                contextHash,
                toolName: toolName,
                producerFamily: producerFamily))
            .ToArray();
        var candidate = Enumerable.Range(0, 2)
            .Select(index => RepeatedContextFinding(
                InputKind.Candidate,
                $"candidate:{index}",
                $"src/item-{index}.txt",
                contextHash,
                toolName: toolName,
                producerFamily: producerFamily))
            .ToArray();

        var result = Match(baseline, candidate);

        AssertMirroredMatches(result, count: 2, PrecedenceTier.WeakContextual);
        Assert.Contains(
            result.Decisions.SelectMany(decision => decision.Decision.Evidence),
            evidence => IsCollisionOrDegradation(evidence.Kind)
                && string.Equals(
                    evidence.AlgorithmVersion,
                    "sarifregress/evidence-occurrence/v1",
                    StringComparison.Ordinal));
    }

    private MatchResult Match(Finding[] baseline, Finding[] candidate) =>
        matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

    private static async Task<ComparisonInput> IngestHoldoutAsync(
        string caseRoot,
        string fileName,
        InputKind input,
        SarifRegress.Core.Configuration.SarifRegressConfiguration configuration)
    {
        await using var stream = File.OpenRead(Path.Combine(caseRoot, fileName));
        var result = await new SarifIngestor().IngestAsync(
            stream,
            new SarifIngestionRequest(input, fileName, configuration),
            TestContext.Current.CancellationToken);
        Assert.True(result.IsValid);
        Assert.Equal(30, result.ComparisonInput.Findings.Length);
        return result.ComparisonInput;
    }

    private static (Finding[] Baseline, Finding[] Candidate) CreateMirroredFindings(
        int count,
        string contextHash,
        bool includeUniqueDerivedFingerprints)
    {
        var baseline = Enumerable.Range(0, count)
            .Select(index => MirroredFinding(
                InputKind.Baseline,
                index,
                contextHash,
                includeUniqueDerivedFingerprints))
            .ToArray();
        var candidate = Enumerable.Range(0, count)
            .Select(index => MirroredFinding(
                InputKind.Candidate,
                index,
                contextHash,
                includeUniqueDerivedFingerprints))
            .ToArray();
        return (baseline, candidate);
    }

    private static Finding MirroredFinding(
        InputKind input,
        int index,
        string contextHash,
        bool includeUniqueDerivedFingerprint)
    {
        var derived = includeUniqueDerivedFingerprint
            ? new[]
            {
                MatchingTestData.DerivedFingerprint(
                    $"path-specific-derived-{index:D2}"),
            }
            : null;
        return RepeatedContextFinding(
            input,
            $"{InputPrefix(input)}:{index:D2}",
            $"src/exact/finding-{index:D2}.txt",
            contextHash,
            startLine: index + 10,
            derivedFingerprints: derived);
    }

    private static Finding IndistinguishableFinding(InputKind input, string key) =>
        RepeatedContextFinding(
            input,
            key,
            "src/collision/shared.txt",
            SharedContext,
            startLine: 20);

    private static Finding RepeatedContextFinding(
        InputKind input,
        string key,
        string path,
        string contextHash,
        string message = "Controlled credential-like finding.",
        int startLine = 10,
        string toolName = "Acme Audit",
        string producerFamily = "acme-audit",
        IEnumerable<DerivedFingerprint>? derivedFingerprints = null) =>
        MatchingTestData.Finding(
            input,
            key,
            path: path,
            message: message,
            producerFamily: producerFamily,
            toolName: toolName,
            ruleId: "audit/shared-rule",
            startLine: startLine,
            derivedFingerprints: derivedFingerprints,
            contextHash: contextHash);

    private static Finding MixedContextFinding(
        InputKind input,
        string key,
        string path,
        string message,
        bool snippetIsCollided,
        string conflictingValue) =>
        MatchingTestData.Finding(
            input,
            key,
            path: path,
            message: message,
            producerFamily: "acme-audit",
            toolName: "Acme Audit",
            ruleId: "audit/shared-rule",
            contextHash: snippetIsCollided ? SharedContext : conflictingValue,
            tokenWindowHash: snippetIsCollided ? conflictingValue : SharedContext);

    private static string InputPrefix(InputKind input) =>
        input == InputKind.Baseline ? "baseline" : "candidate";

    private static void AssertMirroredMatches(
        MatchResult result,
        int count,
        PrecedenceTier precedenceTier)
    {
        Assert.Equal(count, result.Decisions.Length);
        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Unchanged, decision.Classification);
                Assert.False(decision.Decision.Ambiguous);
                Assert.Equal(precedenceTier, decision.Decision.PrecedenceTier);
                var baseline = Assert.IsType<Finding>(decision.Baseline);
                var candidate = Assert.IsType<Finding>(decision.Candidate);
                Assert.Equal(
                    baseline.FindingKey["baseline:".Length..],
                    candidate.FindingKey["candidate:".Length..]);
            });
    }

    private static void AssertAmbiguous(
        MatchResult result,
        int decisionCount,
        int candidateEdgeCount)
    {
        Assert.Equal(decisionCount, result.Decisions.Length);
        Assert.Equal(candidateEdgeCount, result.CandidateEdgeCount);
        Assert.All(
            result.Decisions,
            decision =>
            {
                Assert.Equal(FindingClassification.Ambiguous, decision.Classification);
                Assert.True(decision.Decision.Ambiguous);
            });
    }

    private static string[] ProjectResult(MatchResult result) =>
        result.Decisions
            .Select(decision =>
                $"decision|{decision.Classification}|"
                + $"{decision.Baseline?.FindingKey}|{decision.Candidate?.FindingKey}|"
                + $"{decision.Decision.PrecedenceTier}|{decision.Decision.Ambiguous}|"
                + string.Join(
                    ";",
                    decision.Decision.Evidence.Select(evidence =>
                        $"{evidence.Kind}:{evidence.BaselineValue}:"
                        + $"{evidence.CandidateValue}:{evidence.AlgorithmVersion}:"
                        + $"{evidence.Lossy}"))
                + "|"
                + string.Join(
                    ";",
                    decision.Decision.Diagnostics.Select(diagnostic =>
                        $"{diagnostic.Code}:{diagnostic.Message}")))
            .Concat(result.Diagnostics.Select(diagnostic =>
                $"diagnostic|{diagnostic.Code}|{diagnostic.Message}"))
            .ToArray();

    private static bool IsCollisionOrDegradation(string kind) =>
        kind.Contains("collision", StringComparison.Ordinal)
        || kind.Contains("degrad", StringComparison.Ordinal);

    private static bool ContainsOccurrenceCount(
        EvidenceRecord evidence,
        int count) =>
        (evidence.BaselineValue?.Contains(
            $"occurrences={count}",
            StringComparison.Ordinal) ?? false)
        || (evidence.CandidateValue?.Contains(
            $"occurrences={count}",
            StringComparison.Ordinal) ?? false);

    private sealed record ExpectedPair(
        string CandidateKey,
        FindingClassification Classification);
}
