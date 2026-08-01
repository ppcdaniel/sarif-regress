using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Matching;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class DecisionTraceProjectionTests
{
    [Fact]
    public void Projection_groups_safe_fields_and_omits_all_source_values()
    {
        const string producerSentinel = "producer-secret-value";
        const string pathSentinel = "/private/checkout/source.cs";
        DecisionTraceProjection projection = Project(
            CreateProducerRichFinding(
                producerSentinel,
                pathSentinel,
                reverseSafeOrder: false));

        DecisionEvidenceProjection collision = Assert.Single(
            projection.Evidence,
            item => item.Kind == "context-collision");
        Assert.Equal("system", collision.Origin);
        Assert.Equal("refuse", collision.PrecedenceTier);
        Assert.Equal("sarifregress/evidence-occurrence/v1", collision.AlgorithmVersion);
        Assert.Equal(2, collision.Count);
        DecisionTransformationProjection configuredBase = Assert.Single(
            projection.Transformations,
            item => item.Kind == "configured-uri-base");
        Assert.Equal("sarifregress/configured-uri-base/v1", configuredBase.AlgorithmVersion);
        Assert.Equal(2, configuredBase.Count);
        Assert.Equal(2, Assert.Single(projection.RejectedAlternatives).Count);
        Assert.Equal(2, Assert.Single(projection.Diagnostics).Count);

        string serialized = JsonSerializer.Serialize(projection);
        Assert.DoesNotContain(producerSentinel, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(pathSentinel, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("baselineValue", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("candidateValue", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("findingKey", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("reason", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("originalValue", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("transformedValue", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("diagnostic prose", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void Projection_is_order_invariant_when_source_values_and_array_order_change()
    {
        DecisionTraceProjection first = Project(CreateProducerRichFinding(
            "first-secret",
            "/first/path.cs",
            reverseSafeOrder: false));
        DecisionTraceProjection second = Project(CreateProducerRichFinding(
            "second-secret",
            "C:\\second\\path.cs",
            reverseSafeOrder: true));

        Assert.Equal(
            JsonSerializer.Serialize(first),
            JsonSerializer.Serialize(second));
    }

    [Fact]
    public void Projection_limits_are_enforced_before_trace_materialisation()
    {
        JsonObject finding = CreateProducerRichFinding(
            "secret",
            "/path.cs",
            reverseSafeOrder: false);
        ValidationLimits limits = ValidationLimits.Default with
        {
            MaximumDecisionTraceItems = 2,
        };
        using JsonDocument document = JsonDocument.Parse(finding.ToJsonString());

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
            DecisionTraceProjectionFactory.Create(document.RootElement, limits));

        Assert.Contains(
            "exceeds the configured projection limit",
            exception.Message,
            StringComparison.Ordinal);

        DecisionTraceProjection trace = Project(CreateFinding(
            "resolved",
            baselineKey: "baseline:0:0",
            candidateKey: null));
        Assert.Throws<InvalidDataException>(() =>
            DecisionTraceProjectionFactory.OrderAndValidate([trace, trace]));
        Assert.Throws<InvalidDataException>(() =>
            DecisionTraceProjectionFactory.OrderAndValidate(
                [trace, trace with { Side = "candidate" }, trace with { Side = "pair" }]));
    }

    [Fact]
    public void Classifier_retains_both_endpoint_traces_for_misses_and_refusals()
    {
        CorpusLabels labels = new(
            "1",
            [
                new LabelledPair(
                    "baseline:0:0",
                    "candidate:0:0",
                    FindingClassification.Unchanged),
                new LabelledPair(
                    "baseline:0:2",
                    "candidate:0:2",
                    FindingClassification.Unchanged),
            ],
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                "baseline:0:1",
                "candidate:0:1"),
            ImmutableHashSet<string>.Empty,
            ImmutableHashSet<string>.Empty);
        JsonObject artifact = new()
        {
            ["findings"] = new JsonArray(
                CreateFinding("resolved", "baseline:0:0", null),
                CreateFinding("new", null, "candidate:0:0"),
                CreateFinding("ambiguous", "baseline:0:1", null),
                CreateFinding("ambiguous", null, "candidate:0:1"),
                CreateFinding("unchanged", "baseline:0:2", "candidate:0:2")),
            ["diagnostics"] = new JsonArray(),
        };
        CorpusCaseRun run = new(
            "trace-case",
            [],
            [],
            new CorpusCaseArtifact(
                "comparison",
                ValidationTestRepository.Utf8(artifact.ToJsonString() + "\n")),
            new CorpusMetrics(2, 1, 0, 1, 2, 0, 1m, 0.5m, 0.666667m)
            {
                CorrectAmbiguous = 2,
                UnexpectedNew = 1,
                UnexpectedResolved = 1,
            },
            Passed: false);

        SarifRegressCaseResult result = HoldoutOutcomeClassifier.Classify(
            CreateHoldoutCase(labels),
            run);

        RelationshipResult missed = result.RelationshipResults.Single(item =>
            item.RelationshipId == "trace-case-match-001");
        Assert.Equal("missed-match", missed.Outcome);
        Assert.Equal(
            ["baseline", "candidate"],
            missed.Actual.DecisionTraces.Select(item => item.Side).ToArray());
        Assert.Equal(
            ["resolved", "new"],
            missed.Actual.DecisionTraces
                .Select(item => item.Classification)
                .ToArray());

        RelationshipResult ambiguous = result.RelationshipResults.Single(item =>
            item.RelationshipId == "trace-case-ambiguous-001");
        Assert.Equal("correct-ambiguity-refusal", ambiguous.Outcome);
        Assert.Equal(
            ["baseline", "candidate"],
            ambiguous.Actual.DecisionTraces.Select(item => item.Side).ToArray());
        Assert.All(
            ambiguous.Actual.DecisionTraces,
            item => Assert.True(item.Ambiguous));

        RelationshipResult observed = result.RelationshipResults.Single(item =>
            item.RelationshipId == "trace-case-match-002");
        Assert.Equal("true-positive", observed.Outcome);
        DecisionTraceProjection observedTrace = Assert.Single(
            observed.Actual.DecisionTraces);
        Assert.Equal("pair", observedTrace.Side);
        Assert.Equal("unchanged", observedTrace.Classification);
    }

    private static DecisionTraceProjection Project(JsonObject finding)
    {
        using JsonDocument document = JsonDocument.Parse(finding.ToJsonString());
        return DecisionTraceProjectionFactory.Create(document.RootElement);
    }

    private static JsonObject CreateProducerRichFinding(
        string producerValue,
        string pathValue,
        bool reverseSafeOrder)
    {
        JsonObject finding = CreateFinding(
            "unchanged",
            baselineKey: "baseline:0:0",
            candidateKey: "candidate:0:0");
        JsonObject collisionOne = Evidence(
            "context-collision",
            producerValue,
            pathValue,
            "system",
            "refuse",
            lossy: true,
            "sarifregress/evidence-occurrence/v1");
        JsonObject collisionTwo = Evidence(
            "context-collision",
            pathValue,
            producerValue,
            "system",
            "refuse",
            lossy: true,
            "sarifregress/evidence-occurrence/v1");
        JsonObject rule = Evidence(
            "rule-identity",
            producerValue,
            producerValue,
            "system",
            "exact-canonical",
            lossy: false,
            "sarifregress/rule-identity/v2");
        finding["evidence"] = reverseSafeOrder
            ? new JsonArray(rule, collisionTwo, collisionOne)
            : new JsonArray(collisionOne, rule, collisionTwo);

        JsonObject configuredOne = Transformation(
            "configured-uri-base",
            producerValue,
            pathValue,
            "sarifregress/configured-uri-base/v1");
        JsonObject configuredTwo = Transformation(
            "configured-uri-base",
            pathValue,
            producerValue,
            "sarifregress/configured-uri-base/v1");
        JsonObject pathRebase = Transformation(
            "configured-path-rebase",
            producerValue,
            pathValue,
            "sarifregress/path/v1");
        finding["transforms"] = reverseSafeOrder
            ? new JsonArray(configuredTwo, configuredOne, pathRebase)
            : new JsonArray(pathRebase, configuredOne, configuredTwo);

        finding["rejectedAlternatives"] = new JsonArray(
            Rejected(producerValue, "diagnostic prose " + pathValue),
            Rejected(pathValue, "diagnostic prose " + producerValue));
        finding["diagnostics"] = new JsonArray(
            Diagnostic(producerValue, pathValue),
            Diagnostic(pathValue, producerValue));
        return finding;
    }

    private static JsonObject CreateFinding(
        string classification,
        string? baselineKey,
        string? candidateKey) => new()
    {
        ["classification"] = classification,
        ["baseline"] = baselineKey is null
            ? null
            : new JsonObject { ["findingKey"] = baselineKey },
        ["candidate"] = candidateKey is null
            ? null
            : new JsonObject { ["findingKey"] = candidateKey },
        ["decision"] = new JsonObject
        {
            ["precedenceTier"] = classification == "ambiguous"
                ? "refuse"
                : "exact-canonical",
            ["displayConfidence"] = classification == "ambiguous"
                ? "low"
                : "high",
            ["ambiguous"] = classification == "ambiguous",
            ["matcherAlgorithmVersion"] = "sarifregress/matcher/v3",
        },
        ["evidence"] = new JsonArray(),
        ["rejectedAlternatives"] = new JsonArray(),
        ["transforms"] = new JsonArray(),
        ["diagnostics"] = new JsonArray(),
    };

    private static JsonObject Evidence(
        string kind,
        string baselineValue,
        string candidateValue,
        string origin,
        string precedenceTier,
        bool lossy,
        string algorithmVersion) => new()
    {
        ["kind"] = kind,
        ["baselineValue"] = baselineValue,
        ["candidateValue"] = candidateValue,
        ["origin"] = origin,
        ["precedenceTier"] = precedenceTier,
        ["lossy"] = lossy,
        ["algorithmVersion"] = algorithmVersion,
    };

    private static JsonObject Transformation(
        string kind,
        string originalValue,
        string transformedValue,
        string algorithmVersion) => new()
    {
        ["kind"] = kind,
        ["originalValue"] = originalValue,
        ["transformedValue"] = transformedValue,
        ["lossy"] = false,
        ["algorithmVersion"] = algorithmVersion,
    };

    private static JsonObject Rejected(string findingKey, string reason) => new()
    {
        ["findingKey"] = findingKey,
        ["reason"] = reason,
        ["precedenceTier"] = "exact-canonical",
        ["decisionVector"] = new JsonObject
        {
            ["precedenceTier"] = "exact-canonical",
            ["producerFingerprintStrength"] = 0,
            ["pathMatchKind"] = "exact",
            ["contextAgreement"] = "exact",
            ["codeFlowAgreement"] = "none",
            ["messageAgreement"] = "exact",
            ["regionDriftBand"] = 3,
        },
    };

    private static JsonObject Diagnostic(string message, string path) => new()
    {
        ["code"] = "MATCH0001",
        ["severity"] = "warning",
        ["stage"] = "match",
        ["message"] = "diagnostic prose " + message,
        ["sourceReference"] = new JsonObject
        {
            ["input"] = "baseline",
            ["runIndex"] = 0,
            ["resultIndex"] = 0,
            ["jsonPointer"] = path,
        },
        ["standardBasis"] = message,
        ["help"] = path,
    };

    private static ValidatedHoldoutCase CreateHoldoutCase(CorpusLabels labels) => new(
        new HoldoutCasePlan(
            "trace-case",
            "producer",
            new HoldoutCasePaths(
                "validation/holdout/cases/trace-case",
                "validation/holdout/cases/trace-case/baseline.sarif",
                "validation/holdout/cases/trace-case/candidate.sarif",
                "validation/holdout/cases/trace-case/labels.json",
                "validation/holdout/cases/trace-case/notes.md",
                "validation/holdout/cases/trace-case/producer-input",
                Config: null),
            [],
            new HoldoutCaseCounts(
                BaselineFindings: 3,
                CandidateFindings: 3,
                GroundTruthUnits: 3,
                LabelledRelationships: 2,
                SameFindingRelationships: 2,
                NewFindings: 0,
                ResolvedFindings: 0,
                NewOrResolvedFindings: 0,
                AmbiguousOrNearCollisionRelationships: 1)),
        labels,
        new CaseInputHashes(
            Hash('a'),
            Hash('b'),
            Hash('c'),
            Hash('d'),
            Hash('e'),
            ConfigSha256: null));

    private static string Hash(char value) => new(value, 64);
}
