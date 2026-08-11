using System.Collections.Immutable;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Matching;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class MultitoolValidationTests
{
    [Fact]
    public void Parser_maps_all_supported_states_by_input_finding_identity()
    {
        string root = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string baseline = Path.Combine(root, "baseline.sarif");
            string candidate = Path.Combine(root, "candidate.sarif");
            string raw = Path.Combine(root, "raw.sarif");
            SarifResult matched = new(
                "RULE-MATCH",
                "matched",
                "src/matched.cs",
                10,
                "fingerprint-match");
            SarifResult resolved = new(
                "RULE-RESOLVED",
                "resolved",
                "src/resolved.cs",
                20,
                "fingerprint-resolved");
            SarifResult added = new(
                "RULE-NEW",
                "new",
                "src/new.cs",
                30,
                "fingerprint-new");
            WriteSarif(baseline, [(matched, null), (resolved, null)]);
            WriteSarif(candidate, [(matched, null), (added, null)]);
            WriteSarif(
                raw,
                [
                    (resolved, "absent"),
                    (added, "new"),
                    (matched, "unchanged"),
                ]);

            ParsedMultitoolOutput parsed = new MultitoolOutputParser().Parse(
                baseline,
                candidate,
                raw);

            Assert.Equal(
                MultitoolState.Unchanged,
                parsed.StatesByFindingKey["candidate:0:0"]);
            Assert.Equal(
                MultitoolState.New,
                parsed.StatesByFindingKey["candidate:0:1"]);
            Assert.Equal(
                MultitoolState.Absent,
                parsed.StatesByFindingKey["baseline:0:1"]);
            Assert.Empty(parsed.MissingCorrespondenceKeys);
            Assert.Equal(
                "src/matched.cs",
                parsed.LocationsByFindingKey["baseline:0:0"]);
            Assert.Equal(
                "baseline:0:0",
                parsed.PreviousKeysByCandidateKey["candidate:0:0"]);
            Assert.True(parsed.InstrumentationStateStable);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Parser_preserves_an_unknown_external_state_as_unsupported()
    {
        string root = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string baseline = Path.Combine(root, "baseline.sarif");
            string candidate = Path.Combine(root, "candidate.sarif");
            string raw = Path.Combine(root, "raw.sarif");
            SarifResult finding = new(
                "RULE",
                "message",
                "src/file.cs",
                1,
                "fingerprint");
            WriteSarif(baseline, [(finding, null)]);
            WriteSarif(candidate, [(finding, null)]);
            WriteSarif(raw, [(finding, "future-state")]);

            ParsedMultitoolOutput parsed = new MultitoolOutputParser().Parse(
                baseline,
                candidate,
                raw);

            Assert.Equal(
                MultitoolState.Unsupported,
                parsed.StatesByFindingKey["candidate:0:0"]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Normalizer_keeps_every_non_equivalent_state_explicitly_non_comparable()
    {
        CorpusLabels labels = new(
            "1",
            [
                Pair(0, FindingClassification.Unchanged),
                Pair(1, FindingClassification.Modified),
                Pair(2, FindingClassification.Moved),
                Pair(4, FindingClassification.Unchanged),
                Pair(5, FindingClassification.Unchanged),
            ],
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                "baseline:0:3",
                "candidate:0:3"),
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        var states = ImmutableSortedDictionary.CreateBuilder<string, MultitoolState>(
            StringComparer.Ordinal);
        states["candidate:0:0"] = MultitoolState.Unchanged;
        states["candidate:0:1"] = MultitoolState.Updated;
        states["candidate:0:2"] = MultitoolState.Updated;
        states["candidate:0:3"] = MultitoolState.Updated;
        states["candidate:0:5"] = MultitoolState.Unsupported;
        var missing = ImmutableHashSet.Create(
            StringComparer.Ordinal,
            "candidate:0:4");
        var locations = ImmutableSortedDictionary.CreateBuilder<string, string?>(
            StringComparer.Ordinal);
        locations["baseline:0:2"] = "/repository/src/file.cs";
        locations["candidate:0:2"] = "C:/repository/src/file.cs";
        var previous = ImmutableSortedDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        previous["candidate:0:0"] = "baseline:0:0";
        previous["candidate:0:1"] = "baseline:0:1";
        previous["candidate:0:2"] = "baseline:0:2";
        ParsedMultitoolOutput parsed = new(
            states.ToImmutable(),
            missing,
            locations.ToImmutable(),
            previous.ToImmutable(),
            InstrumentationStateStable: true);

        ImmutableArray<MultitoolRelationshipResult> results =
            MultitoolRelationshipNormalizer.Normalize(
                CreateHoldoutCase("multitool-taxonomy", labels),
                parsed);

        MultitoolRelationshipResult comparable = Assert.Single(
            results,
            item => item.RelationshipId == "multitool-taxonomy-match-001");
        Assert.True(comparable.Comparable);
        Assert.True(comparable.Correct is true);
        Assert.Equal("unchanged", comparable.MappedClassification);
        MultitoolRelationshipResult updatedIdentity = Assert.Single(
            results,
            item => item.RelationshipId == "multitool-taxonomy-match-002");
        Assert.True(updatedIdentity.Comparable);
        Assert.True(updatedIdentity.Correct is true);
        Assert.False(updatedIdentity.TaxonomyMapped);
        Assert.Null(updatedIdentity.MappedClassification);
        AssertNonComparable(
            results,
            "multitool-taxonomy-match-003",
            "path-rebase-configuration-not-supported");
        AssertNonComparable(
            results,
            "multitool-taxonomy-match-004",
            "missing-correspondence-data");
        AssertNonComparable(
            results,
            "multitool-taxonomy-match-005",
            "unsupported-sarif-shape");
        AssertNonComparable(
            results,
            "multitool-taxonomy-ambiguous-001",
            "multitool-does-not-express-ambiguity");

        MultitoolMetrics metrics = MultitoolMetricsCalculator.Create(
            labels.Pairs.Length,
            results);
        Assert.Equal(6, metrics.GroundTruthUnits);
        Assert.Equal(2, metrics.ComparableRelationships);
        Assert.Equal(3, metrics.NonComparableRelationships);
        Assert.Equal(2, metrics.TruePositives);
        Assert.Equal(0, metrics.FalsePositives);
        Assert.Equal(0, metrics.FalseNegatives);
        Assert.Equal(1m, metrics.Precision);
        Assert.Equal(1m, metrics.Recall);
        Assert.Equal(1m, metrics.F1);
    }

    [Fact]
    public void External_tool_evidence_hash_is_newline_invariant_across_platforms()
    {
        string windows = ToolOutputNormalizer.ComputeSha256(
            "version 5.5.0\r\n",
            "help\r\n--previous\r\n");
        string linux = ToolOutputNormalizer.ComputeSha256(
            "version 5.5.0\n",
            "help\n--previous\n");

        Assert.Equal(linux, windows);
    }

    [Fact]
    public void Help_evidence_hash_normalizes_the_observed_windows_console_banner()
    {
        string linux = ToolOutputNormalizer.ComputeHelpSha256(
            string.Empty,
            "© Microsoft Corporation. All rights reserved.\n--previous\n");
        string windows = ToolOutputNormalizer.ComputeHelpSha256(
            string.Empty,
            "c Microsoft Corporation. All rights reserved.\r\n--previous\r\n");

        Assert.Equal(linux, windows);
    }

    [Fact]
    public void Pinned_subcommand_help_validates_its_actual_syntax_without_repeating_name()
    {
        const string generatedHelp = """
            --previous          Path to the previous SARIF log.
            --output-file-path  Path to the annotated output log.
            <currentFiles>      Required current SARIF log paths.
            """;

        MultitoolRunner.ValidateGeneratedHelp(generatedHelp);
        InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
            MultitoolRunner.ValidateGeneratedHelp(
                generatedHelp.Replace(
                    "--previous",
                    "--different",
                    StringComparison.Ordinal)));
        Assert.Contains("--previous", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Tool_failure_preserves_every_ground_truth_unit_as_an_explicit_error()
    {
        CorpusLabels labels = new(
            "1",
            [Pair(0, FindingClassification.Unchanged)],
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                "baseline:0:3",
                "candidate:0:3"),
            ImmutableHashSet.Create(StringComparer.Ordinal, "baseline:0:1"),
            ImmutableHashSet.Create(StringComparer.Ordinal, "candidate:0:2"));

        ImmutableArray<MultitoolRelationshipResult> results =
            MultitoolRelationshipNormalizer.NormalizeToolError(
                CreateHoldoutCase("multitool-error", labels),
                "MULTITOOL_CASE_EVALUATION_FAILED");

        Assert.Equal(4, results.Length);
        Assert.Equal(
            [
                "multitool-error-ambiguous-001",
                "multitool-error-match-001",
                "multitool-error-new-001",
                "multitool-error-resolved-001",
            ],
            results.Select(result => result.RelationshipId));
        Assert.All(results, result =>
        {
            Assert.Equal("error", result.MultitoolState);
            Assert.False(result.Comparable);
            Assert.False(result.TaxonomyMapped);
            Assert.Null(result.MappedClassification);
            Assert.Null(result.Correct);
            Assert.Equal("tool-error", result.ComparabilityReason);
            Assert.Equal(
                "MULTITOOL_CASE_EVALUATION_FAILED",
                result.ErrorOrUnsupportedCode);
        });
        MultitoolMetrics metrics = MultitoolMetricsCalculator.Create(
            labels.Pairs.Length,
            results);
        Assert.Equal(4, metrics.GroundTruthUnits);
        Assert.Equal(4, metrics.Errors);
        Assert.Equal(4, metrics.States.Error);
        Assert.Equal(0, metrics.Unsupported);
        Assert.Equal(0, metrics.ComparableRelationships);
        Assert.Equal(1, metrics.NonComparableRelationships);
    }

    [Fact]
    public void Case_failure_adapter_preserves_stable_bounded_evidence_without_a_process()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            var runner = new MultitoolRunner();

            string relativePath = runner.PreserveCaseFailureEvidence(
                outputRoot,
                "multitool-error",
                "MULTITOOL_CASE_EVALUATION_FAILED");
            IReadOnlyDictionary<string, string> first =
                ValidationTestRepository.HashTree(outputRoot);

            Assert.Equal(
                "raw/multitool/multitool-error.failure-code.txt",
                relativePath);
            Assert.Equal(
                ValidationTestRepository.Utf8("MULTITOOL_CASE_EVALUATION_FAILED\n"),
                File.ReadAllBytes(Path.Combine(outputRoot, relativePath)));
            Assert.Equal(
                [
                    "raw/multitool/multitool-error.failure-code.txt",
                    "raw/multitool/multitool-error.instrumented.stderr.txt",
                    "raw/multitool/multitool-error.instrumented.stdout.txt",
                    "raw/multitool/multitool-error.uninstrumented.stderr.txt",
                    "raw/multitool/multitool-error.uninstrumented.stdout.txt",
                ],
                first.Keys.Order(StringComparer.Ordinal));
            foreach (string streamName in first.Keys.Where(
                         name => !name.EndsWith(
                             ".failure-code.txt",
                             StringComparison.Ordinal)))
            {
                Assert.Empty(File.ReadAllBytes(Path.Combine(outputRoot, streamName)));
            }

            string secondRelativePath = runner.PreserveCaseFailureEvidence(
                outputRoot,
                "multitool-error",
                "MULTITOOL_CASE_EVALUATION_FAILED");
            IReadOnlyDictionary<string, string> second =
                ValidationTestRepository.HashTree(outputRoot);

            Assert.Equal(relativePath, secondRelativePath);
            Assert.Equal(first.Count, second.Count);
            foreach ((string path, string hash) in first)
            {
                Assert.True(second.TryGetValue(path, out string? secondHash));
                Assert.Equal(hash, secondHash);
            }
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public void Multitool_metrics_use_only_semantically_comparable_relationships()
    {
        MultitoolRelationshipResult[] relationships =
        [
            MultitoolResult("match-001", "match", "unchanged", comparable: true),
            MultitoolResult("match-002", "match", "new", comparable: true),
            MultitoolResult("match-003", "match", "unsupported", comparable: false),
            MultitoolResult("new-001", "new", "unchanged", comparable: true),
            MultitoolResult("new-002", "new", "new", comparable: true),
        ];

        MultitoolMetrics metrics = MultitoolMetricsCalculator.Create(
            labelledMatchRelationships: 3,
            relationships);

        Assert.Equal(5, metrics.GroundTruthUnits);
        Assert.Equal(2, metrics.ComparableRelationships);
        Assert.Equal(1, metrics.NonComparableRelationships);
        Assert.Equal(1, metrics.TruePositives);
        Assert.Equal(1, metrics.FalsePositives);
        Assert.Equal(1, metrics.FalseNegatives);
        Assert.Equal(0.5m, metrics.Precision);
        Assert.Equal(0.5m, metrics.Recall);
        Assert.Equal(0.5m, metrics.F1);
    }

    [Fact]
    public void Wrong_updated_correspondence_is_both_false_positive_and_false_negative()
    {
        MultitoolRelationshipResult wrongIdentity = MultitoolResult(
            "match-001",
            "match",
            "updated",
            comparable: true) with
        {
            Correct = false,
        };

        MultitoolMetrics metrics = MultitoolMetricsCalculator.Create(
            labelledMatchRelationships: 1,
            [wrongIdentity]);

        Assert.Equal(0, metrics.TruePositives);
        Assert.Equal(1, metrics.FalsePositives);
        Assert.Equal(1, metrics.FalseNegatives);
        Assert.Equal(0m, metrics.Precision);
        Assert.Equal(0m, metrics.Recall);
        Assert.Equal(0m, metrics.F1);
    }

    [Fact]
    public void New_state_for_a_positive_match_is_false_negative_only()
    {
        MultitoolRelationshipResult unmatched = MultitoolResult(
            "match-001",
            "match",
            "new",
            comparable: true);

        MultitoolMetrics metrics = MultitoolMetricsCalculator.Create(
            labelledMatchRelationships: 1,
            [unmatched]);

        Assert.Equal(0, metrics.TruePositives);
        Assert.Equal(0, metrics.FalsePositives);
        Assert.Equal(1, metrics.FalseNegatives);
        Assert.Equal(1m, metrics.Precision);
        Assert.Equal(0m, metrics.Recall);
        Assert.Equal(0m, metrics.F1);
    }

    private static void AssertNonComparable(
        IEnumerable<MultitoolRelationshipResult> results,
        string relationshipId,
        string reason)
    {
        MultitoolRelationshipResult result = Assert.Single(
            results,
            item => item.RelationshipId == relationshipId);
        Assert.False(result.Comparable);
        Assert.False(result.TaxonomyMapped);
        Assert.Null(result.Correct);
        Assert.Equal(reason, result.ComparabilityReason);
    }

    private static LabelledPair Pair(
        int resultIndex,
        FindingClassification classification) => new(
        $"baseline:0:{resultIndex}",
        $"candidate:0:{resultIndex}",
        classification);

    private static MultitoolRelationshipResult MultitoolResult(
        string relationshipId,
        string kind,
        string state,
        bool comparable) => new(
        relationshipId,
        new GroundTruthRelationship(
            kind,
            kind == "new" ? null : $"baseline:{relationshipId}",
            kind == "resolved" ? null : $"candidate:{relationshipId}",
            kind),
        state,
        TaxonomyMapped: comparable,
        MappedClassification: comparable ? state : null,
        Comparable: comparable,
        comparable ? "equivalent-state-semantics" : "unsupported-sarif-shape",
        Correct: comparable
            ? kind == "match"
                ? state is "unchanged" or "updated"
                : state == kind
            : null,
        ErrorOrUnsupportedCode: comparable ? null : "MULTITOOL_STATE_UNSUPPORTED");

    private static ValidatedHoldoutCase CreateHoldoutCase(
        string caseId,
        CorpusLabels labels) => new(
        new HoldoutCasePlan(
            caseId,
            "producer",
            new HoldoutCasePaths(
                $"validation/holdout/cases/{caseId}",
                $"validation/holdout/cases/{caseId}/baseline.sarif",
                $"validation/holdout/cases/{caseId}/candidate.sarif",
                $"validation/holdout/cases/{caseId}/labels.json",
                $"validation/holdout/cases/{caseId}/notes.md",
                $"validation/holdout/cases/{caseId}/producer-input",
                Config: null),
            ["windows-posix-path-projection"],
            new HoldoutCaseCounts(
                BaselineFindings: 0,
                CandidateFindings: 0,
                GroundTruthUnits: labels.Pairs.Length
                    + labels.ExpectedNew.Count
                    + labels.ExpectedResolved.Count
                    + labels.ExpectedAmbiguous.Count / 2,
                LabelledRelationships: labels.Pairs.Length,
                SameFindingRelationships: labels.Pairs.Length,
                NewFindings: labels.ExpectedNew.Count,
                ResolvedFindings: labels.ExpectedResolved.Count,
                NewOrResolvedFindings: labels.ExpectedNew.Count
                    + labels.ExpectedResolved.Count,
                AmbiguousOrNearCollisionRelationships:
                    labels.ExpectedAmbiguous.Count / 2)),
        labels,
        new CaseInputHashes(
            Hash('a'),
            Hash('b'),
            Hash('c'),
            Hash('d'),
            Hash('e'),
            ConfigSha256: null));

    private static void WriteSarif(
        string path,
        IReadOnlyList<(SarifResult Result, string? BaselineState)> results)
    {
        byte[] bytes = StableJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("version", "2.1.0");
            writer.WriteStartArray("runs");
            writer.WriteStartObject();
            writer.WriteStartObject("tool");
            writer.WriteStartObject("driver");
            writer.WriteString("name", "Validation test producer");
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WriteStartArray("results");
            foreach ((SarifResult result, string? state) in results)
            {
                writer.WriteStartObject();
                writer.WriteString("ruleId", result.RuleId);
                if (state is not null)
                {
                    writer.WriteString("baselineState", state);
                }

                writer.WriteStartObject("message");
                writer.WriteString("text", result.Message);
                writer.WriteEndObject();
                writer.WriteStartObject("fingerprints");
                writer.WriteString("test/v1", result.Fingerprint);
                writer.WriteEndObject();
                writer.WriteStartArray("locations");
                writer.WriteStartObject();
                writer.WriteStartObject("physicalLocation");
                writer.WriteStartObject("artifactLocation");
                writer.WriteString("uri", result.Uri);
                writer.WriteEndObject();
                writer.WriteStartObject("region");
                writer.WriteNumber("startLine", result.Line);
                writer.WriteNumber("startColumn", 1);
                writer.WriteEndObject();
                writer.WriteEndObject();
                writer.WriteEndObject();
                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        });
        File.WriteAllBytes(path, bytes);
    }

    private static string Hash(char value) => new string(value, 64);

    private sealed record SarifResult(
        string RuleId,
        string Message,
        string Uri,
        int Line,
        string Fingerprint);
}
