using System.Collections.Immutable;
using System.Security.Cryptography;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class MatcherV3ToV31DeltaReportTests
{
    private const string HoldoutManifestSha256 =
        "b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379";
    private const string ClassificationEvidenceKind =
        "classification-message-location-template";
    private const string ClassificationEvidenceVersion =
        "sarifregress/message-location-template/v1";

    [Fact]
    public void Reader_verifies_the_checksum_anchored_matcher_v3_history()
    {
        MatcherV3HistorySnapshot snapshot = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());

        Assert.Equal(
            MatcherV3HistoryReader.MatcherV3AlgorithmVersion,
            snapshot.Report.Evaluation.MatcherAlgorithmVersion);
        Assert.Equal(
            MatcherV3HistoryReader.MatcherV3HistoryChecksumManifestSha256,
            snapshot.HistoryChecksumManifestSha256);
        Assert.Equal(
            MatcherV3HistoryReader.MatcherV3ReportSha256,
            snapshot.ReportSha256);
        Assert.Equal(50, snapshot.Report.Aggregate.TruePositives);
        Assert.Equal(0, snapshot.Report.Aggregate.FalsePositives);
        Assert.Equal(25, snapshot.Report.Aggregate.FalseNegatives);
        Assert.Equal(5, snapshot.Report.Aggregate.ClassificationMismatches);
        Assert.Equal(99, snapshot.Report.Aggregate.GroundTruthUnits);
    }

    [Fact]
    public void Reader_rejects_a_rewritten_history_manifest()
    {
        string root = CopyHistory();
        try
        {
            string path = Path.Combine(
                root,
                "validation",
                "history",
                "matcher-v3",
                "checksums.sha256");
            string text = File.ReadAllText(path);
            char replacement = text[0] == '0' ? '1' : '0';
            File.WriteAllText(path, replacement + text[1..]);

            InvalidDataException exception = Assert.Throws<InvalidDataException>(
                () => new MatcherV3HistoryReader().Read(root));

            Assert.Contains("immutable anchor", exception.Message);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Builder_rejects_a_forged_matcher_v3_snapshot_payload()
    {
        MatcherV3HistorySnapshot matcherV3 = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        MatcherV3HistorySnapshot forged = matcherV3 with
        {
            Report = matcherV3.Report with
            {
                Evaluation = matcherV3.Report.Evaluation with
                {
                    RepositoryCommitSha = new string('f', 40),
                },
            },
        };
        SarifRegressHoldoutReport matcherV31 = CreateMatcherV31(matcherV3.Report);

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
            MatcherV3ToV31DeltaBuilder.Create(
                forged,
                matcherV31,
                InputHashes(forged, matcherV31)));

        Assert.Contains("payload differs", exception.Message);
    }

    [Fact]
    public void Builder_reports_the_expected_classification_only_transition()
    {
        MatcherV3HistorySnapshot matcherV3 = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        SarifRegressHoldoutReport matcherV31 = CreateMatcherV31(matcherV3.Report);

        MatcherV3ToV31DeltaReport delta = MatcherV3ToV31DeltaBuilder.Create(
            matcherV3,
            matcherV31,
            InputHashes(matcherV3, matcherV31));

        Assert.True(delta.CorrespondenceIdentity.Unchanged);
        Assert.Equal(
            new MatcherCorrespondenceIdentity(50, 0, 25),
            delta.CorrespondenceIdentity.MatcherV3);
        Assert.Equal(
            new MatcherCorrespondenceIdentity(50, 0, 25),
            delta.CorrespondenceIdentity.MatcherV31);
        Assert.Equal(5, delta.ClassificationMismatchChanges.MatcherV3Count);
        Assert.Equal(0, delta.ClassificationMismatchChanges.MatcherV31Count);
        Assert.Equal(
            ExpectedClassificationRepairs(),
            delta.ClassificationMismatchChanges.Fixed.Select(item =>
                item.RelationshipId));
        Assert.Empty(delta.ClassificationMismatchChanges.Introduced);
        Assert.Equal(
            ExpectedClassificationRepairs(),
            delta.Relationships.Fixed.Select(item => item.RelationshipId));
        Assert.Empty(delta.Relationships.Regressed);
        Assert.Equal(27, delta.Relationships.StillFailing.Length);
        Assert.Equal(27, delta.RemainingFailures.Length);
        Assert.Empty(delta.NewlyIntroducedFalseMatches);
        Assert.Equal(["gitleaks"], delta.Cases.Fixed.Select(item => item.CaseId));
        Assert.Empty(delta.Cases.Regressed);
        Assert.Equal(["pmd"], delta.Cases.StillFailing.Select(item => item.CaseId));
        Assert.Equal(5, delta.ChangedDecisionCount);
        Assert.Equal(5, delta.ChangedDecisionTraceCount);
        Assert.Equal(0, delta.ChangedDecisionWithoutTraceCount);
        Assert.Empty(delta.ChangedDecisionsWithoutTrace);
        Assert.True(delta.EveryChangedDecisionHasTrace);
        Assert.Equal(4, delta.AmbiguityChanges.MatcherV3CorrectRefusals);
        Assert.Equal(4, delta.AmbiguityChanges.MatcherV31CorrectRefusals);
        Assert.Equal(0, delta.AmbiguityChanges.MatcherV31IncorrectAutoMatches);
        Assert.Equal(2, delta.AmbiguityChanges.StillFailing.Length);
        Assert.Equal(0, delta.IngestionSuccessChanges.MatcherV3Failures);
        Assert.Equal(0, delta.IngestionSuccessChanges.MatcherV31Failures);

        MatcherV3ToV31AlgorithmVersionChange matcherChange = Assert.Single(
            delta.AlgorithmVersionChanges,
            item => item.Name == "matcher");
        Assert.Equal("sarifregress/matcher/v3", matcherChange.MatcherV3Version);
        Assert.Equal("sarifregress/matcher/v3.1", matcherChange.MatcherV31Version);
        Assert.True(matcherChange.Changed);
        MatcherV3ToV31AlgorithmVersionChange transformationChange = Assert.Single(
            delta.AlgorithmVersionChanges,
            item => item.Name
                == "decision-transformation.classification-message-location-template");
        Assert.Null(transformationChange.MatcherV3Version);
        Assert.Equal(
            ClassificationEvidenceVersion,
            transformationChange.MatcherV31Version);
        Assert.True(transformationChange.Changed);
    }

    [Fact]
    public void Builder_does_not_treat_an_old_nonempty_trace_as_the_new_explanation()
    {
        MatcherV3HistorySnapshot matcherV3 = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        SarifRegressHoldoutReport matcherV31 = RemoveClassificationTransformations(
            CreateMatcherV31(matcherV3.Report));

        MatcherV3ToV31DeltaReport delta = MatcherV3ToV31DeltaBuilder.Create(
            matcherV3,
            matcherV31,
            InputHashes(matcherV3, matcherV31));

        Assert.Equal(5, delta.ChangedDecisionCount);
        Assert.Equal(0, delta.ChangedDecisionTraceCount);
        Assert.Equal(5, delta.ChangedDecisionWithoutTraceCount);
        Assert.Equal(
            ExpectedClassificationRepairs(),
            delta.ChangedDecisionsWithoutTrace.Select(item => item.RelationshipId));
        Assert.False(delta.EveryChangedDecisionHasTrace);
    }

    [Fact]
    public void Builder_rejects_outcome_and_state_claims_that_contradict_the_graph()
    {
        MatcherV3HistorySnapshot matcherV3 = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        SarifRegressHoldoutReport matcherV31 = CreateMatcherV31(matcherV3.Report);
        SarifRegressHoldoutReport falseMatchClaim = ChangeOneTruePositive(
            matcherV31,
            relationship => relationship with { Outcome = "false-match" });

        InvalidDataException outcomeException = Assert.Throws<InvalidDataException>(
            () => MatcherV3ToV31DeltaBuilder.Create(
                matcherV3,
                falseMatchClaim,
                InputHashes(matcherV3, falseMatchClaim)));
        Assert.Contains("contradictory", outcomeException.Message);

        SarifRegressHoldoutReport wrongStateClaim = ChangeOneTruePositive(
            matcherV31,
            relationship => relationship with
            {
                Actual = relationship.Actual with
                {
                    State = relationship.GroundTruth.ExpectedClassification == "moved"
                        ? "modified"
                        : "moved",
                },
            });
        InvalidDataException stateException = Assert.Throws<InvalidDataException>(
            () => MatcherV3ToV31DeltaBuilder.Create(
                matcherV3,
                wrongStateClaim,
                InputHashes(matcherV3, wrongStateClaim)));
        Assert.Contains("contradictory", stateException.Message);
    }

    [Fact]
    public void Builder_is_input_order_invariant_and_binds_the_exact_graph_and_hashes()
    {
        MatcherV3HistorySnapshot matcherV3 = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        SarifRegressHoldoutReport matcherV31 = CreateMatcherV31(matcherV3.Report);
        MatcherV3ToV31DeltaReport expected = MatcherV3ToV31DeltaBuilder.Create(
            matcherV3,
            matcherV31,
            InputHashes(matcherV3, matcherV31));
        SarifRegressHoldoutReport reordered = Reorder(matcherV31);

        MatcherV3ToV31DeltaReport actual = MatcherV3ToV31DeltaBuilder.Create(
            matcherV3,
            reordered,
            InputHashes(matcherV3, reordered));

        Assert.Equal(
            expected.Relationships.Fixed.Select(item => item.RelationshipId),
            actual.Relationships.Fixed.Select(item => item.RelationshipId));
        Assert.Equal(
            expected.RemainingFailures.Select(item => item.RelationshipId),
            actual.RemainingFailures.Select(item => item.RelationshipId));
        Assert.Equal(
            expected.AlgorithmVersionChanges.Select(item => item.Name),
            actual.AlgorithmVersionChanges.Select(item => item.Name));

        MatcherV3ToV31InputHashes wrongHash = InputHashes(matcherV3, matcherV31)
            with
        {
            MatcherV31ReportSha256 = new string('f', 64),
        };
        Assert.Throws<InvalidDataException>(() =>
            MatcherV3ToV31DeltaBuilder.Create(matcherV3, matcherV31, wrongHash));

        SarifRegressHoldoutReport changedGraph = ChangeGroundTruth(matcherV31);
        Assert.Throws<InvalidDataException>(() =>
            MatcherV3ToV31DeltaBuilder.Create(
                matcherV3,
                changedGraph,
                InputHashes(matcherV3, changedGraph)));
    }

    [Fact]
    public void Builder_rejects_conflicting_or_unbounded_trace_algorithms()
    {
        MatcherV3HistorySnapshot matcherV3 = new MatcherV3HistoryReader().Read(
            ValidationTestRepository.FindRoot());
        SarifRegressHoldoutReport matcherV31 = CreateMatcherV31(matcherV3.Report);
        SarifRegressHoldoutReport conflicting = ChangeOneEvidenceVersion(matcherV31);

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
            MatcherV3ToV31DeltaBuilder.Create(
                matcherV3,
                conflicting,
                InputHashes(matcherV3, conflicting)));

        Assert.Contains("conflicting versions", exception.Message);

        SarifRegressHoldoutReport unbounded = AddTraceAlgorithms(
            matcherV31,
            count: 20);
        InvalidDataException boundedException = Assert.Throws<InvalidDataException>(() =>
            MatcherV3ToV31DeltaBuilder.Create(
                matcherV3,
                unbounded,
                InputHashes(matcherV3, unbounded)));
        Assert.Contains("too many algorithm versions", boundedException.Message);
    }

    private static SarifRegressHoldoutReport CreateMatcherV31(
        SarifRegressHoldoutReport matcherV3)
    {
        ImmutableArray<SarifRegressCaseResult> cases = matcherV3.Cases
            .Select(item => item.ProducerId == "gitleaks"
                ? RepairGitleaks(item)
                : UpdateTraceVersions(item))
            .ToImmutableArray();
        return Recalculate(
            matcherV3 with
            {
                Evaluation = matcherV3.Evaluation with
                {
                    RepositoryCommitSha = new string('1', 40),
                    SourceTreeSha256 = new string('2', 64),
                    MatcherAlgorithmVersion =
                        MatcherV3HistoryReader.MatcherV31AlgorithmVersion,
                },
                Cases = cases,
            });
    }

    private static SarifRegressCaseResult RepairGitleaks(
        SarifRegressCaseResult item)
    {
        ImmutableArray<RelationshipResult> relationships = item.RelationshipResults
            .Select(relationship =>
            {
                bool repair = relationship.Outcome == "classification-mismatch";
                ActualRelationship actual = relationship.Actual with
                {
                    State = repair ? "moved" : relationship.Actual.State,
                    DecisionTraces = relationship.Actual.DecisionTraces
                        .Select(trace => UpdateTrace(trace, repair))
                        .ToImmutableArray(),
                };
                return relationship with
                {
                    Actual = actual,
                    Outcome = repair ? "true-positive" : relationship.Outcome,
                };
            })
            .ToImmutableArray();
        return item with
        {
            Metrics = item.Metrics with { ClassificationMismatches = 0 },
            RelationshipResults = relationships,
            Outcomes = item.Outcomes with { ClassificationMismatches = [] },
        };
    }

    private static SarifRegressCaseResult UpdateTraceVersions(
        SarifRegressCaseResult item)
    {
        return item with
        {
            RelationshipResults = item.RelationshipResults
                .Select(relationship => relationship with
                {
                    Actual = relationship.Actual with
                    {
                        DecisionTraces = relationship.Actual.DecisionTraces
                            .Select(trace => UpdateTrace(trace, addEvidence: false))
                            .ToImmutableArray(),
                    },
                })
                .ToImmutableArray(),
        };
    }

    private static DecisionTraceProjection UpdateTrace(
        DecisionTraceProjection trace,
        bool addEvidence)
    {
        IEnumerable<DecisionTransformationProjection> transformations =
            trace.Transformations;
        if (addEvidence)
        {
            transformations = transformations.Append(
                new DecisionTransformationProjection(
                    ClassificationEvidenceKind,
                    Lossy: true,
                    AlgorithmVersion: ClassificationEvidenceVersion,
                    Count: 1));
        }

        return trace with
        {
            Classification = addEvidence ? "moved" : trace.Classification,
            MatcherAlgorithmVersion =
                MatcherV3HistoryReader.MatcherV31AlgorithmVersion,
            Transformations = transformations
                .OrderBy(item => item.Kind, StringComparer.Ordinal)
                .ThenBy(item => item.Lossy)
                .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
                .ToImmutableArray(),
        };
    }

    private static SarifRegressHoldoutReport RemoveClassificationTransformations(
        SarifRegressHoldoutReport report)
    {
        return report with
        {
            Cases = report.Cases
                .Select(caseResult => caseResult with
                {
                    RelationshipResults = caseResult.RelationshipResults
                        .Select(relationship => relationship with
                        {
                            Actual = relationship.Actual with
                            {
                                DecisionTraces = relationship.Actual.DecisionTraces
                                    .Select(trace => trace with
                                    {
                                        Transformations = trace.Transformations
                                            .Where(transformation =>
                                                transformation.Kind
                                                    != ClassificationEvidenceKind
                                                || transformation.AlgorithmVersion
                                                    != ClassificationEvidenceVersion)
                                            .ToImmutableArray(),
                                    })
                                    .ToImmutableArray(),
                            },
                        })
                        .ToImmutableArray(),
                })
                .ToImmutableArray(),
        };
    }

    private static SarifRegressHoldoutReport Recalculate(
        SarifRegressHoldoutReport report)
    {
        ImmutableArray<ProducerHoldoutMetrics> producers = report.Cases
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerHoldoutMetrics(
                group.Key,
                HoldoutMetricsCalculator.Aggregate(
                    group.Select(item => item.Metrics))))
            .ToImmutableArray();
        return report with
        {
            Aggregate = HoldoutMetricsCalculator.Aggregate(
                report.Cases.Select(item => item.Metrics)),
            Producers = producers,
        };
    }

    private static SarifRegressHoldoutReport Reorder(
        SarifRegressHoldoutReport report)
    {
        return report with
        {
            Producers = report.Producers.Reverse().ToImmutableArray(),
            Cases = report.Cases.Reverse()
                .Select(item => item with
                {
                    RelationshipResults = item.RelationshipResults.Reverse()
                        .ToImmutableArray(),
                })
                .ToImmutableArray(),
            DiagnosticCounts = report.DiagnosticCounts.Reverse().ToImmutableArray(),
        };
    }

    private static SarifRegressHoldoutReport ChangeGroundTruth(
        SarifRegressHoldoutReport report)
    {
        SarifRegressCaseResult firstCase = report.Cases[0];
        RelationshipResult firstRelationship = firstCase.RelationshipResults[0];
        SarifRegressCaseResult changedCase = firstCase with
        {
            RelationshipResults = firstCase.RelationshipResults.SetItem(
                0,
                firstRelationship with
                {
                    GroundTruth = firstRelationship.GroundTruth with
                    {
                        ExpectedClassification = "modified",
                    },
                }),
        };
        return report with { Cases = report.Cases.SetItem(0, changedCase) };
    }

    private static SarifRegressHoldoutReport ChangeOneTruePositive(
        SarifRegressHoldoutReport report,
        Func<RelationshipResult, RelationshipResult> change)
    {
        SarifRegressCaseResult caseResult = report.Cases.First(item =>
            item.RelationshipResults.Any(relationship =>
                relationship.Outcome == "true-positive"));
        RelationshipResult relationship = caseResult.RelationshipResults.First(item =>
            item.Outcome == "true-positive");
        SarifRegressCaseResult changedCase = caseResult with
        {
            RelationshipResults = caseResult.RelationshipResults
                .Select(item => item == relationship ? change(item) : item)
                .ToImmutableArray(),
        };
        return report with
        {
            Cases = report.Cases
                .Select(item => item == caseResult ? changedCase : item)
                .ToImmutableArray(),
        };
    }

    private static SarifRegressHoldoutReport ChangeOneEvidenceVersion(
        SarifRegressHoldoutReport report)
    {
        SarifRegressCaseResult item = report.Cases.First(caseValue =>
            caseValue.RelationshipResults.Any(relationship =>
                relationship.Actual.DecisionTraces.Any(trace =>
                    trace.Evidence.Any(evidence => evidence.Kind == "message"))));
        RelationshipResult relationship = item.RelationshipResults.First(value =>
            value.Actual.DecisionTraces.Any(trace =>
                trace.Evidence.Any(evidence => evidence.Kind == "message")));
        DecisionTraceProjection trace = relationship.Actual.DecisionTraces.First(value =>
            value.Evidence.Any(evidence => evidence.Kind == "message"));
        DecisionTraceProjection changedTrace = trace with
        {
            Evidence = trace.Evidence.Select(evidence => evidence.Kind == "message"
                    ? evidence with { AlgorithmVersion = "sarifregress/message-evidence/v9" }
                    : evidence)
                .ToImmutableArray(),
        };
        RelationshipResult changedRelationship = relationship with
        {
            Actual = relationship.Actual with
            {
                DecisionTraces = relationship.Actual.DecisionTraces
                    .Select(value => value == trace ? changedTrace : value)
                    .ToImmutableArray(),
            },
        };
        SarifRegressCaseResult changedCase = item with
        {
            RelationshipResults = item.RelationshipResults
                .Select(value => value == relationship ? changedRelationship : value)
                .ToImmutableArray(),
        };
        return report with
        {
            Cases = report.Cases
                .Select(value => value == item ? changedCase : value)
                .ToImmutableArray(),
        };
    }

    private static SarifRegressHoldoutReport AddTraceAlgorithms(
        SarifRegressHoldoutReport report,
        int count)
    {
        SarifRegressCaseResult item = report.Cases.First(caseValue =>
            caseValue.RelationshipResults.Any(relationship =>
                !relationship.Actual.DecisionTraces.IsEmpty));
        RelationshipResult relationship = item.RelationshipResults.First(value =>
            !value.Actual.DecisionTraces.IsEmpty);
        DecisionTraceProjection trace = relationship.Actual.DecisionTraces[0];
        ImmutableArray<DecisionEvidenceProjection> additions = Enumerable
            .Range(0, count)
            .Select(index => new DecisionEvidenceProjection(
                $"test-algorithm-{index:00}",
                "system",
                trace.PrecedenceTier,
                Lossy: false,
                AlgorithmVersion: "sarifregress/test-algorithm/v1",
                Count: 1))
            .ToImmutableArray();
        DecisionTraceProjection changedTrace = trace with
        {
            Evidence = trace.Evidence.AddRange(additions),
        };
        RelationshipResult changedRelationship = relationship with
        {
            Actual = relationship.Actual with
            {
                DecisionTraces = relationship.Actual.DecisionTraces.SetItem(
                    0,
                    changedTrace),
            },
        };
        SarifRegressCaseResult changedCase = item with
        {
            RelationshipResults = item.RelationshipResults
                .Select(value => value == relationship ? changedRelationship : value)
                .ToImmutableArray(),
        };
        return report with
        {
            Cases = report.Cases
                .Select(value => value == item ? changedCase : value)
                .ToImmutableArray(),
        };
    }

    private static MatcherV3ToV31InputHashes InputHashes(
        MatcherV3HistorySnapshot matcherV3,
        SarifRegressHoldoutReport matcherV31) => new(
        matcherV3.HistoryChecksumManifestSha256,
        matcherV3.ReportSha256,
        Sha256(StableReportSerializer.Serialize(matcherV31)),
        HoldoutManifestSha256);

    private static string[] ExpectedClassificationRepairs() =>
    [
        "gitleaks-match-014",
        "gitleaks-match-015",
        "gitleaks-match-016",
        "gitleaks-match-017",
        "gitleaks-match-018",
    ];

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string CopyHistory()
    {
        string sourceRoot = ValidationTestRepository.FindRoot();
        string destinationRoot = ValidationTestRepository.CreateTemporaryDirectory();
        CopyDirectory(
            Path.Combine(sourceRoot, "validation", "history", "matcher-v3"),
            Path.Combine(destinationRoot, "validation", "history", "matcher-v3"));
        CopyFile(
            sourceRoot,
            destinationRoot,
            "validation/history/v2-to-v3-delta.json");
        CopyFile(
            sourceRoot,
            destinationRoot,
            "validation/holdout/manifest.json");
        return destinationRoot;
    }

    private static void CopyFile(
        string sourceRoot,
        string destinationRoot,
        string relativePath)
    {
        string destination = Path.Combine(destinationRoot, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(Path.Combine(sourceRoot, relativePath), destination);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string path in Directory.EnumerateFiles(source))
        {
            File.Copy(path, Path.Combine(destination, Path.GetFileName(path)));
        }

        foreach (string path in Directory.EnumerateDirectories(source))
        {
            CopyDirectory(path, Path.Combine(destination, Path.GetFileName(path)));
        }
    }
}
