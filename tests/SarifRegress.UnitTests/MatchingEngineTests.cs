using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Match;

namespace SarifRegress.UnitTests;

public sealed class MatchingEngineTests
{
    private readonly FindingMatcher matcher = new();

    [Fact]
    public void Reliable_common_version_producer_fingerprint_is_unchanged()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("producer-hash", version: 2);
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFingerprints: [fingerprint]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFingerprints: [fingerprint]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Unchanged, decision.Classification);
        Assert.Equal(
            "sarifregress/matcher/v3",
            decision.Decision.MatcherAlgorithmVersion);
        Assert.Contains(
            decision.Decision.Evidence,
            evidence =>
                evidence.Kind == "rule-identity" &&
                evidence.AlgorithmVersion ==
                    "sarifregress/rule-identity/v2");
        Assert.Equal(PrecedenceTier.ExactProducer, decision.Decision.PrecedenceTier);
        Assert.Equal("candidate:one", decision.Candidate?.FindingKey);
    }

    [Fact]
    public void Producer_fingerprint_comparison_does_not_fall_back_below_greatest_common_version()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src/baseline.cs",
            producerFingerprints:
            [
                MatchingTestData.ProducerFingerprint("shared-old", version: 1),
                MatchingTestData.ProducerFingerprint("baseline-new", version: 2),
            ]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/candidate.cs",
            producerFingerprints:
            [
                MatchingTestData.ProducerFingerprint("shared-old", version: 1),
                MatchingTestData.ProducerFingerprint("candidate-new", version: 2),
            ]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        Assert.Equal(2, result.Decisions.Length);
        Assert.Contains(
            result.Decisions,
            decision => decision.Classification == FindingClassification.Resolved);
        Assert.Contains(
            result.Decisions,
            decision => decision.Classification == FindingClassification.New);
        Assert.All(
            result.Decisions,
            decision => Assert.Contains(
                decision.Decision.Evidence,
                evidence =>
                    evidence.Kind == "assignment-outcome"
                    && evidence.PrecedenceTier == PrecedenceTier.Refuse));
        Assert.Equal(0, result.CandidateEdgeCount);
    }

    [Fact]
    public void Derived_fingerprint_and_canonical_path_use_exact_canonical_tier()
    {
        var derived = MatchingTestData.DerivedFingerprint("derived-hash");
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            derivedFingerprints: [derived]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            derivedFingerprints: [derived]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Unchanged, decision.Classification);
        Assert.Equal(PrecedenceTier.ExactCanonical, decision.Decision.PrecedenceTier);
    }

    [Fact]
    public void Canonical_evidence_marks_source_normalisation_as_lossy()
    {
        var derived = MatchingTestData.DerivedFingerprint("derived-hash");
        var pathTransformation = new TransformationRecord(
            "canonical-separators",
            @"src\example.cs",
            "src/example.cs",
            isLossy: true,
            "cross-platform-path/v1");
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            derivedFingerprints: [derived],
            messageNormalisationFlags: ["collapsed-whitespace"],
            metadata: new FindingMetadata(
                "warning",
                "fail",
                "unchanged"));
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            derivedFingerprints: [derived],
            pathTransformations: [pathTransformation],
            metadata: new FindingMetadata(
                "error",
                "review",
                "new"));

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Unchanged, decision.Classification);
        Assert.Contains(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "message" && evidence.Lossy);
        Assert.Contains(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "canonical-path" && evidence.Lossy);
        Assert.DoesNotContain(
            decision.Decision.Evidence,
            evidence => evidence.Kind.Contains(
                "baseline-state",
                StringComparison.Ordinal));
    }

    [Fact]
    public void Stable_context_across_a_path_and_region_change_is_moved()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src/old.cs",
            startLine: 10,
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/new.cs",
            startLine: 40,
            contextHash: "stable-context");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.Equal(PrecedenceTier.StrongMoved, decision.Decision.PrecedenceTier);
    }

    [Fact]
    public void Explicit_path_alias_preserves_suffix_and_classifies_the_match_as_moved()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src-old/security/check.cs",
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/security/check.cs",
            contextHash: "stable-context");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(
                pathAliases:
                [
                    new PathAlias("src-old/", "src/"),
                ]));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.Equal(PrecedenceTier.StrongMoved, decision.Decision.PrecedenceTier);
        Assert.Contains(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "path-alias");
    }

    [Fact]
    public void Path_alias_without_trailing_separator_matches_only_a_complete_segment()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var configuration = MatchingTestData.Configuration(
            pathAliases: [new PathAlias("src", "dst")]);
        var valid = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:valid",
                    path: "src/security/check.cs",
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:valid",
                    path: "dst/security/check.cs",
                    producerFingerprints: [fingerprint])),
            configuration);
        var partial = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:partial",
                    path: "src-old/security/check.cs",
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:partial",
                    path: "dst-old/security/check.cs",
                    producerFingerprints: [fingerprint])),
            configuration);

        Assert.Contains(
            Assert.Single(valid.Decisions).Decision.Evidence,
            evidence => evidence.Kind == "path-alias");
        Assert.DoesNotContain(
            Assert.Single(partial.Decisions).Decision.Evidence,
            evidence => evidence.Kind == "path-alias");
    }

    [Fact]
    public void Canonical_uri_path_alias_preserves_configured_evidence_values()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src-old/security/check.cs",
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/security/check.cs",
            contextHash: "stable-context");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(
                pathAliases:
                [
                    new PathAlias(
                        "repo://src-old/",
                        "repo://src/"),
                ]));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(
            FindingClassification.Moved,
            decision.Classification);
        var evidence = Assert.Single(
            decision.Decision.Evidence,
            item => item.Kind == "path-alias");
        Assert.Equal("repo://src-old/", evidence.BaselineValue);
        Assert.Equal("repo://src/", evidence.CandidateValue);
    }

    [Fact]
    public void Reliable_continuity_with_a_changed_message_is_modified()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            message: "Original message.",
            producerFingerprints: [fingerprint]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            message: "Changed message.",
            producerFingerprints: [fingerprint]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Modified, decision.Classification);
        Assert.Equal(PrecedenceTier.ExactProducer, decision.Decision.PrecedenceTier);
    }

    [Fact]
    public void Two_sided_conflicting_source_context_is_modified()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:one",
                    contextHash: "baseline-context",
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:one",
                    contextHash: "candidate-context",
                    producerFingerprints: [fingerprint])));

        Assert.Equal(
            FindingClassification.Modified,
            Assert.Single(result.Decisions).Classification);
    }

    [Fact]
    public void One_sided_context_and_code_flow_are_unavailable_not_contradictory()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:one",
                    contextHash: "baseline-context",
                    codeFlowPaths: ["src/helper.cs"],
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:one",
                    producerFingerprints: [fingerprint])));

        Assert.Equal(
            FindingClassification.Unchanged,
            Assert.Single(result.Decisions).Classification);
    }

    [Fact]
    public void Code_flow_classification_honours_ascii_case_insensitive_paths()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:one",
                    codeFlowPaths: ["SRC/Helper.cs"],
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:one",
                    codeFlowPaths: ["src/helper.cs"],
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Configuration(
                pathCaseSensitivity: PathCaseSensitivity.AsciiInsensitive));

        Assert.Equal(
            FindingClassification.Unchanged,
            Assert.Single(result.Decisions).Classification);
    }

    [Fact]
    public void Enclosing_symbol_is_deferred_and_does_not_affect_matching()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var result = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:one",
                    enclosingSymbol: "Baseline.Symbol",
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:one",
                    enclosingSymbol: "Candidate.Symbol",
                    producerFingerprints: [fingerprint])));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Unchanged, decision.Classification);
        Assert.DoesNotContain(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "context-enclosing-symbol");
    }

    [Fact]
    public void Two_absent_locations_are_stable_but_one_sided_location_is_moved()
    {
        var fingerprint = MatchingTestData.ProducerFingerprint("stable");
        var bothAbsent = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:absent",
                    path: null,
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:absent",
                    path: null,
                    producerFingerprints: [fingerprint])));
        var oneAbsent = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:missing",
                    path: null,
                    producerFingerprints: [fingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:present",
                    producerFingerprints: [fingerprint])));

        Assert.Equal(
            FindingClassification.Unchanged,
            Assert.Single(bothAbsent.Decisions).Classification);
        Assert.Equal(
            FindingClassification.Moved,
            Assert.Single(oneAbsent.Decisions).Classification);
    }

    [Fact]
    public void Code_flow_anchor_is_supporting_evidence_and_not_a_primary_identity()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src/old.cs",
            codeFlowPaths: ["src/shared-helper.cs"]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/new.cs",
            codeFlowPaths: ["src/shared-helper.cs"]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.Equal(PrecedenceTier.PathProblem, decision.Decision.PrecedenceTier);
        Assert.Contains(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "code-flow");
    }

    [Fact]
    public void Related_location_path_alone_cannot_create_a_match()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            path: "src/old.cs",
            relatedLocationPaths: ["src/shared-helper.cs"]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            path: "src/new.cs",
            relatedLocationPaths: ["src/shared-helper.cs"]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Collection(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Resolved,
                decision.Classification),
            decision => Assert.Equal(
                FindingClassification.New,
                decision.Classification));
    }

    [Fact]
    public void Explicit_rule_alias_enables_corroborated_cross_producer_match()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFamily: "semgrep",
            toolName: "Semgrep",
            ruleId: "python/eval",
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFamily: "internal",
            toolName: "InternalScanner",
            ruleId: "PY-EVAL-001",
            contextHash: "stable-context");

        var withoutAlias = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));
        var withAlias = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(
                ruleAliases:
                [
                    new RuleAlias(
                        "Semgrep",
                        "python/eval",
                        "InternalScanner",
                        "PY-EVAL-001"),
                ]));

        Assert.Equal(2, withoutAlias.Decisions.Length);
        var aliasedDecision = Assert.Single(withAlias.Decisions);
        Assert.Equal(PrecedenceTier.Override, aliasedDecision.Decision.PrecedenceTier);
        Assert.Equal(FindingClassification.Unchanged, aliasedDecision.Classification);
        Assert.Contains(
            aliasedDecision.Decision.Evidence,
            evidence => evidence.Kind == "rule-alias");
    }

    [Theory]
    [InlineData("Scanner.A", "Scanner A")]
    [InlineData("Scanner", "scanner")]
    [InlineData("掃描器甲", "掃描器乙")]
    [InlineData("CodeQL-Evil", "CodeQL")]
    [InlineData("CodeQL Scanner", "CodeQL")]
    [InlineData("CodeQLicious", "CodeQL")]
    public void Distinct_producer_names_do_not_enter_automatic_match_buckets(
        string baselineToolName,
        string candidateToolName)
    {
        var baselineResolution = ProducerIdentityResolver.Resolve(
            baselineToolName);
        var candidateResolution = ProducerIdentityResolver.Resolve(
            candidateToolName);
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFamily: baselineResolution.Family,
            toolName: baselineToolName,
            ruleId: "shared/rule",
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFamily: candidateResolution.Family,
            toolName: candidateToolName,
            ruleId: "shared/rule",
            contextHash: "stable-context");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        Assert.Equal(0, result.CandidateEdgeCount);
        Assert.Collection(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Resolved,
                decision.Classification),
            decision => Assert.Equal(
                FindingClassification.New,
                decision.Classification));
    }

    [Fact]
    public void Allowlisted_family_matches_across_tool_name_and_version_changes()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFamily: "codeql",
            toolName: "CodeQL command-line toolchain",
            toolVersion: "1.0.0",
            ruleId: "codeql/shared-rule",
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFamily: "codeql",
            toolName: "CodeQL",
            toolVersion: "2.0.0",
            ruleId: "codeql/shared-rule",
            contextHash: "stable-context");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate));

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(FindingClassification.Unchanged, decision.Classification);
    }

    [Fact]
    public void Explicit_alias_bridges_distinct_hashed_producer_identities()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFamily: "scanner-a",
            toolName: "Scanner.A",
            ruleId: "old-rule",
            contextHash: "stable-context");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFamily: "scanner-a",
            toolName: "Scanner A",
            ruleId: "new-rule",
            contextHash: "stable-context");
        var configuration = MatchingTestData.Configuration(
            ruleAliases:
            [
                new RuleAlias(
                    "Scanner.A",
                    "old-rule",
                    "Scanner A",
                    "new-rule"),
            ]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration);

        var decision = Assert.Single(result.Decisions);
        Assert.Equal(PrecedenceTier.Override, decision.Decision.PrecedenceTier);
        var aliasEvidence = Assert.Single(
            decision.Decision.Evidence,
            evidence => evidence.Kind == "rule-alias");
        Assert.Equal(
            "sarifregress/rule-alias/v2",
            aliasEvidence.AlgorithmVersion);
    }

    [Fact]
    public void Rule_alias_alone_does_not_guarantee_a_result_match()
    {
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            message: "Baseline message.",
            producerFamily: "first",
            toolName: "first",
            ruleId: "old-rule");
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            message: "Candidate message.",
            producerFamily: "second",
            toolName: "second",
            ruleId: "new-rule");
        var configuration = MatchingTestData.Configuration(
            ruleAliases:
            [
                new RuleAlias("first", "old-rule", "second", "new-rule"),
            ]);

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            configuration);

        Assert.Equal(2, result.Decisions.Length);
        Assert.Equal(0, result.CandidateEdgeCount);
    }

    [Fact]
    public void Cross_producer_alias_requires_real_path_and_context_corroboration()
    {
        var sharedFingerprint = MatchingTestData.ProducerFingerprint("shared");
        var alias = new RuleAlias("first", "old-rule", "second", "new-rule");
        var baseline = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFamily: "first",
            toolName: "first",
            ruleId: "old-rule",
            producerFingerprints: [sharedFingerprint]);
        var candidate = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFamily: "second",
            toolName: "second",
            ruleId: "new-rule",
            producerFingerprints: [sharedFingerprint]);

        var withFingerprint = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baseline),
            MatchingTestData.Input(InputKind.Candidate, candidate),
            MatchingTestData.Configuration(ruleAliases: [alias]));
        var withoutFingerprint = matcher.Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:no-fingerprint",
                    producerFamily: "first",
                    toolName: "first",
                    ruleId: "old-rule")),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:no-fingerprint",
                    producerFamily: "second",
                    toolName: "second",
                    ruleId: "new-rule")),
            MatchingTestData.Configuration(ruleAliases: [alias]));

        Assert.Equal(2, withFingerprint.Decisions.Length);
        Assert.Equal(0, withFingerprint.CandidateEdgeCount);
        Assert.Contains(
            withFingerprint.Decisions,
            decision => decision.Classification == FindingClassification.Resolved);
        Assert.Contains(
            withFingerprint.Decisions,
            decision => decision.Classification == FindingClassification.New);
        Assert.Equal(2, withoutFingerprint.Decisions.Length);
        Assert.Equal(0, withoutFingerprint.CandidateEdgeCount);
    }

    [Fact]
    public void Duplicate_producer_fingerprints_are_degraded_and_refused_as_ambiguous()
    {
        var duplicate = MatchingTestData.ProducerFingerprint("duplicate");
        var baselineOne = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:one",
            producerFingerprints: [duplicate],
            contextHash: "same");
        var baselineTwo = MatchingTestData.Finding(
            InputKind.Baseline,
            "baseline:two",
            producerFingerprints: [duplicate],
            contextHash: "same");
        var candidateOne = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:one",
            producerFingerprints: [duplicate],
            contextHash: "same");
        var candidateTwo = MatchingTestData.Finding(
            InputKind.Candidate,
            "candidate:two",
            producerFingerprints: [duplicate],
            contextHash: "same");

        var result = matcher.Match(
            MatchingTestData.Input(InputKind.Baseline, baselineOne, baselineTwo),
            MatchingTestData.Input(InputKind.Candidate, candidateOne, candidateTwo));

        Assert.Equal(4, result.Decisions.Length);
        Assert.All(
            result.Decisions,
            decision => Assert.Equal(
                FindingClassification.Ambiguous,
                decision.Classification));
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0005");
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == "MATCH0001");
    }
}
