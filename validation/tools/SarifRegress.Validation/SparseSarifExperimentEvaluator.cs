using System.Collections.Immutable;
using System.Text.Json.Nodes;

namespace SarifRegress.Validation;

/// <summary>
/// Scores a fixed label-neutral observation artifact. This is the only sparse
/// experiment component permitted to open ground-truth label files.
/// </summary>
public sealed class SparseSarifExperimentEvaluator
{
    public const string OutputFileName = "sparse-experiment-gate-evidence.json";
    public const string EvidenceKind = "sparse-experiment-gates/v1";

    private readonly ValidationLimits limits;

    /// <summary>Creates a bounded post-label evaluator.</summary>
    public SparseSarifExperimentEvaluator(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>Validates and independently scores one observation artifact.</summary>
    public SparseExperimentGateEvidence Evaluate(
        string repositoryRoot,
        string observationsPath)
    {
        string repository = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(repositoryRoot));
        string observation = Path.GetFullPath(observationsPath);
        string observationRoot = Path.GetDirectoryName(observation)
            ?? throw new InvalidDataException(
                "The sparse observation path must have a parent directory.");
        byte[] observationBytes = BoundedJsonFile.ReadBytes(
            observation,
            limits.MaximumSarifBytes,
            observationRoot);
        string observationSha256 = SparseSarifExperimentSerializer.Sha256(
            observationBytes);
        string observationsSchema = StablePath.Resolve(
            repository,
            SparseResearchManifestReader.SparseRootRelativePath
            + "/schemas/experiment-observations.schema.json");
        JsonNode observationNode = BoundedJsonFile.ParseNode(
            observationBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            Path.GetFileName(observation));
        _ = new JsonSchemaValidator(limits).ValidateNode(
            observationsSchema,
            observationNode,
            Path.GetFileName(observation),
            schemaApprovedRoot: repository);
        SparseExperimentObservations observations =
            SparseSarifExperimentSerializer.ReadObservations(
                observationBytes,
                limits);
        SparseResearchManifest manifest = SparseResearchManifestReader.Read(
            repository,
            limits);
        ValidateObservationBindings(repository, manifest, observations);

        // Scientific boundary: labels are not opened until the observations and
        // all provenance bindings above have passed independently.
        ImmutableArray<LabelFamily> labels = manifest.Families
            .Select(family => ReadLabels(repository, manifest, family))
            .ToImmutableArray();
        var scoredVariants = ImmutableArray.CreateBuilder<SparseVariantGateEvidence>(
            observations.Variants.Length);
        foreach (SparseVariantObservation variant in observations.Variants)
        {
            ImmutableArray<SparseFamilyMetrics> byFamily = variant.Families
                .Select(family => new SparseFamilyMetrics(
                    family.FamilyId,
                    ScoreFamily(
                        family.AcceptedPairs,
                        labels.Single(item => string.Equals(
                            item.FamilyId,
                            family.FamilyId,
                            StringComparison.Ordinal)))))
                .ToImmutableArray();
            SparseMetrics aggregate = Aggregate(byFamily.Select(item => item.Metrics));
            SparseClassificationMetrics classification = ScoreClassification(
                variant.Families,
                labels);
            SparseLifecycleMetrics lifecycle = ScoreLifecycle(
                variant.Families,
                labels);
            SparseAmbiguityMetrics ambiguity = ScoreAmbiguity(
                variant.Families,
                labels);
            ImmutableArray<SparseScenarioGateEvidence> scenarios = ScoreScenarios(
                variant.Scenarios,
                labels,
                trustedTreeHashes: true);
            ImmutableArray<SparseFamilyMetrics> productionByFamily =
                variant.ProductionApplicability.Families
                    .Select(family => new SparseFamilyMetrics(
                        family.FamilyId,
                        ScoreFamily(
                            family.AcceptedPairs,
                            labels.Single(item => string.Equals(
                                item.FamilyId,
                                family.FamilyId,
                                StringComparison.Ordinal)))))
                    .ToImmutableArray();
            SparseMetrics productionMetrics = Aggregate(
                productionByFamily.Select(item => item.Metrics));
            ImmutableArray<SparseScenarioGateEvidence> productionScenarios =
                ScoreScenarios(
                    variant.ProductionApplicability.ScenariosWithoutTrustedTreeHashes,
                    labels,
                    trustedTreeHashes: false);
            var production = new SparseProductionApplicabilityGateEvidence(
                TrustedTreeHashPreflightEnabled: false,
                productionMetrics,
                productionScenarios,
                CorpusSpecificPreflightRequired:
                    productionMetrics != aggregate
                    || productionScenarios.SelectMany(item => item.Families)
                        .Any(item => !item.AssertionsPassed));
            scoredVariants.Add(new SparseVariantGateEvidence(
                variant.Id,
                aggregate,
                byFamily,
                classification,
                lifecycle,
                ambiguity,
                variant.Ingestion,
                variant.Security,
                production,
                scenarios));
        }

        return new SparseExperimentGateEvidence(
            SchemaVersion: "1",
            Kind: EvidenceKind,
            manifest.Sha256,
            observationSha256,
            scoredVariants.MoveToImmutable());
    }

    private void ValidateObservationBindings(
        string repositoryRoot,
        SparseResearchManifest manifest,
        SparseExperimentObservations observations)
    {
        if (!string.Equals(observations.SchemaVersion, "1", StringComparison.Ordinal)
            || !string.Equals(observations.Kind, SparseSarifExperimentRunner.ObservationsKind, StringComparison.Ordinal)
            || !string.Equals(observations.CorpusManifestSha256, manifest.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Sparse observations do not bind the supported corpus manifest contract.");
        }

        string implementationSha256 =
            SparseResearchManifestReader.ValidateImplementationManifest(
                repositoryRoot,
                limits);
        if (!string.Equals(
                observations.ImplementationManifestSha256,
                implementationSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Sparse observations do not bind the committed implementation manifest.");
        }

        if (!observations.Variants.Select(item => item.Id)
                .SequenceEqual(SparseExperimentVariants.Ordered, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Sparse observations do not contain the five fixed variants in order.");
        }

        foreach (SparseVariantObservation variant in observations.Variants)
        {
            if (!string.Equals(
                    variant.AlgorithmVersion,
                    SparseSarifExperimentRunner.GetAlgorithmVersion(variant.Id),
                    StringComparison.Ordinal)
                || variant.Parameters != SparseSarifExperimentRunner.GetParameters(
                    variant.Id))
            {
                throw new InvalidDataException(
                    $"Sparse variant '{variant.Id}' does not use the preregistered algorithm and parameters.");
            }

            ValidateFamilies(variant.Families, manifest);
            ValidateFamilies(variant.ProductionApplicability.Families, manifest);
            ValidateScenarioOrder(variant.Scenarios, manifest);
            ValidateScenarioOrder(
                variant.ProductionApplicability.ScenariosWithoutTrustedTreeHashes,
                manifest);
            if (variant.ProductionApplicability.TrustedTreeHashPreflightEnabled)
            {
                throw new InvalidDataException(
                    "Production-applicability observations must disable corpus tree hashes.");
            }
        }
    }

    private static void ValidateFamilies(
        ImmutableArray<SparseFamilyObservation> observations,
        SparseResearchManifest manifest)
    {
        if (!observations.Select(item => item.FamilyId)
                .SequenceEqual(manifest.Families.Select(item => item.Id), StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Sparse observations do not contain the fixed families in order.");
        }

        foreach (SparseFamilyObservation observation in observations)
        {
            SparseFamilyManifest family = manifest.Families.Single(item =>
                string.Equals(item.Id, observation.FamilyId, StringComparison.Ordinal));
            if (!string.Equals(
                    observation.BaselineSarifSha256,
                    family.Baseline.ProjectedSarifSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    observation.CandidateSarifSha256,
                    family.Candidate.ProjectedSarifSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    observation.BaselineSourceTreeSha256,
                    family.Baseline.SourceTreeSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    observation.CandidateSourceTreeSha256,
                    family.Candidate.SourceTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Sparse family '{family.Id}' does not bind its manifest hashes.");
            }
        }
    }

    private static void ValidateScenarioOrder(
        ImmutableArray<SparseScenarioObservation> scenarios,
        SparseResearchManifest manifest)
    {
        if (!scenarios.Select(item => item.ScenarioId)
                .SequenceEqual(SparseExperimentScenarios.Ordered, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Sparse observations do not contain the ten fixed scenarios in order.");
        }

        foreach (SparseScenarioObservation scenario in scenarios)
        {
            if (!scenario.Families.Select(item => item.FamilyId)
                    .SequenceEqual(
                        manifest.Families.Select(item => item.Id),
                        StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    $"Sparse scenario '{scenario.ScenarioId}' does not contain the fixed families in order.");
            }
        }
    }

    private LabelFamily ReadLabels(
        string repositoryRoot,
        SparseResearchManifest manifest,
        SparseFamilyManifest family)
    {
        string path = SparseResearchManifestReader.ResolveSparsePath(
            repositoryRoot,
            family.LabelsPath);
        byte[] bytes = BoundedJsonFile.ReadBytes(
            path,
            limits.MaximumLabelBytes,
            repositoryRoot);
        if (!manifest.IntegritySha256.TryGetValue(
                family.LabelsPath,
                out string? expectedSha256)
            || !string.Equals(
                SparseSarifExperimentSerializer.Sha256(bytes),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Sparse labels for '{family.Id}' do not match the manifest integrity map.");
        }

        JsonNode labelNode = BoundedJsonFile.ParseNode(
            bytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            Path.GetFileName(path));
        string labelsSchema = StablePath.Resolve(
            repositoryRoot,
            SparseResearchManifestReader.SparseRootRelativePath
            + "/schemas/labels.schema.json");
        JsonObject root = new JsonSchemaValidator(limits).ValidateNode(
                labelsSchema,
                labelNode,
                Path.GetFileName(path),
                schemaApprovedRoot: repositoryRoot) as JsonObject
            ?? throw new InvalidDataException("A sparse label document must be an object.");
        if (!string.Equals(
                RequireString(root, "familyId"),
                family.Id,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("A sparse label family identifier does not match its manifest.");
        }

        ImmutableArray<LabelRelationship> relationships = RequireArray(root, "relationships")
            .Select((node, index) =>
            {
                JsonObject relationship = RequireObject(node, $"relationships[{index}]");
                return new LabelRelationship(
                    ReadSelector(relationship["baseline"], "relationship baseline"),
                    ReadSelector(relationship["candidate"], "relationship candidate"),
                    RequireString(relationship, "expectedClassification"),
                    RequireString(
                        RequireObject(
                            relationship["sourceTransformation"],
                            "relationship source transformation"),
                        "kind"));
            })
            .ToImmutableArray();
        ImmutableHashSet<SparseNaturalSelector> expectedNew = RequireArray(root, "new")
            .Select((node, index) => ReadSelector(
                RequireObject(node, $"new[{index}]")["candidate"],
                $"new[{index}].candidate"))
            .ToImmutableHashSet();
        ImmutableHashSet<SparseNaturalSelector> expectedResolved = RequireArray(root, "resolved")
            .Select((node, index) => ReadSelector(
                RequireObject(node, $"resolved[{index}]")["baseline"],
                $"resolved[{index}].baseline"))
            .ToImmutableHashSet();
        ImmutableArray<LabelAmbiguity> ambiguities = RequireArray(root, "ambiguities")
            .Select((node, index) =>
            {
                JsonObject ambiguity = RequireObject(node, $"ambiguities[{index}]");
                return new LabelAmbiguity(
                    RequireArray(ambiguity, "baseline")
                        .Select((selector, selectorIndex) => ReadSelector(
                            selector,
                            $"ambiguities[{index}].baseline[{selectorIndex}]"))
                        .ToImmutableHashSet(),
                    RequireArray(ambiguity, "candidate")
                        .Select((selector, selectorIndex) => ReadSelector(
                            selector,
                            $"ambiguities[{index}].candidate[{selectorIndex}]"))
                        .ToImmutableHashSet());
            })
            .ToImmutableArray();
        return new LabelFamily(
            family.Id,
            relationships,
            expectedNew,
            expectedResolved,
            ambiguities);
    }

    private static SparseMetrics ScoreFamily(
        ImmutableArray<SparseAcceptedPair> accepted,
        LabelFamily labels)
    {
        var expected = labels.Relationships
            .Select(item => new SelectorPair(item.Baseline, item.Candidate))
            .ToImmutableHashSet();
        int truePositives = accepted.Count(item => expected.Contains(
            new SelectorPair(item.Baseline, item.Candidate)));
        int falsePositives = accepted.Length - truePositives;
        int falseNegatives = expected.Count - truePositives;
        return CreateMetrics(
            accepted.Length,
            truePositives,
            falsePositives,
            falseNegatives);
    }

    private static SparseClassificationMetrics ScoreClassification(
        ImmutableArray<SparseFamilyObservation> families,
        ImmutableArray<LabelFamily> labels)
    {
        int matched = 0;
        int mismatches = 0;
        foreach (SparseFamilyObservation family in families)
        {
            LabelFamily label = labels.Single(item => string.Equals(
                item.FamilyId,
                family.FamilyId,
                StringComparison.Ordinal));
            var relationships = label.Relationships.ToDictionary(
                item => new SelectorPair(item.Baseline, item.Candidate));
            foreach (SparseAcceptedPair pair in family.AcceptedPairs)
            {
                if (!relationships.TryGetValue(
                        new SelectorPair(pair.Baseline, pair.Candidate),
                        out LabelRelationship? relationship))
                {
                    continue;
                }

                matched++;
                string actual = pair.Classification.ToString().ToLowerInvariant();
                if (!string.Equals(
                        actual,
                        relationship.ExpectedClassification,
                        StringComparison.Ordinal))
                {
                    mismatches++;
                }
            }
        }

        return new SparseClassificationMetrics(matched, mismatches);
    }

    private static SparseLifecycleMetrics ScoreLifecycle(
        ImmutableArray<SparseFamilyObservation> families,
        ImmutableArray<LabelFamily> labels)
    {
        int expectedNew = 0;
        int correctNew = 0;
        int expectedResolved = 0;
        int correctResolved = 0;
        foreach (SparseFamilyObservation family in families)
        {
            LabelFamily label = labels.Single(item => string.Equals(
                item.FamilyId,
                family.FamilyId,
                StringComparison.Ordinal));
            expectedNew += label.ExpectedNew.Count;
            expectedResolved += label.ExpectedResolved.Count;
            correctNew += family.NewFindings.Count(label.ExpectedNew.Contains);
            correctResolved += family.ResolvedFindings.Count(
                label.ExpectedResolved.Contains);
        }

        return new SparseLifecycleMetrics(
            expectedNew,
            correctNew,
            checked(expectedNew - correctNew),
            expectedResolved,
            correctResolved,
            checked(expectedResolved - correctResolved));
    }

    private static SparseMetrics Aggregate(IEnumerable<SparseMetrics> metrics)
    {
        SparseMetrics[] values = metrics.ToArray();
        return CreateMetrics(
            values.Sum(item => item.AcceptedPairs),
            values.Sum(item => item.TruePositives),
            values.Sum(item => item.FalsePositives),
            values.Sum(item => item.FalseNegatives));
    }

    private static SparseMetrics CreateMetrics(
        int acceptedPairs,
        int truePositives,
        int falsePositives,
        int falseNegatives)
    {
        decimal precision = acceptedPairs == 0
            ? 1m
            : Divide(truePositives, acceptedPairs);
        int labelledRelationships = truePositives + falseNegatives;
        decimal recall = labelledRelationships == 0
            ? 1m
            : Divide(truePositives, labelledRelationships);
        decimal f1 = precision + recall == 0m
            ? 0m
            : Math.Round(
                2m * precision * recall / (precision + recall),
                6,
                MidpointRounding.AwayFromZero);
        return new SparseMetrics(
            acceptedPairs,
            truePositives,
            falsePositives,
            falseNegatives,
            precision,
            recall,
            f1);
    }

    private static decimal Divide(int numerator, int denominator) => Math.Round(
        (decimal)numerator / denominator,
        6,
        MidpointRounding.AwayFromZero);

    private static SparseAmbiguityMetrics ScoreAmbiguity(
        ImmutableArray<SparseFamilyObservation> families,
        ImmutableArray<LabelFamily> labels)
    {
        int incorrect = 0;
        int units = 0;
        foreach (SparseFamilyObservation family in families)
        {
            LabelFamily label = labels.Single(item => string.Equals(
                item.FamilyId,
                family.FamilyId,
                StringComparison.Ordinal));
            units += label.Ambiguities.Length;
            incorrect += label.Ambiguities.Count(ambiguity =>
                family.AcceptedPairs.Any(pair =>
                    ambiguity.Baseline.Contains(pair.Baseline)
                    || ambiguity.Candidate.Contains(pair.Candidate)));
        }

        return new SparseAmbiguityMetrics(units, units - incorrect, incorrect);
    }

    private static ImmutableArray<SparseScenarioGateEvidence> ScoreScenarios(
        ImmutableArray<SparseScenarioObservation> scenarios,
        ImmutableArray<LabelFamily> labels,
        bool trustedTreeHashes)
    {
        return scenarios.Select(scenario => new SparseScenarioGateEvidence(
            scenario.ScenarioId,
            scenario.Families.Select(family => ScoreScenarioFamily(
                    scenario.ScenarioId,
                    family,
                    labels.Single(item => string.Equals(
                        item.FamilyId,
                        family.FamilyId,
                        StringComparison.Ordinal)),
                    trustedTreeHashes))
                .ToImmutableArray()))
            .ToImmutableArray();
    }

    private static SparseFamilyScenarioGateEvidence ScoreScenarioFamily(
        string scenarioId,
        SparseFamilyScenarioObservation scenario,
        LabelFamily labels,
        bool trustedTreeHashes)
    {
        ImmutableHashSet<SelectorPair> allRelationships = labels.Relationships
            .Select(item => new SelectorPair(item.Baseline, item.Candidate))
            .ToImmutableHashSet();
        IEnumerable<LabelRelationship> relevant = scenarioId switch
        {
            "exact-unchanged-source-location" => labels.Relationships.Where(item =>
                string.Equals(
                    item.ExpectedClassification,
                    "unchanged",
                    StringComparison.Ordinal)),
            "region-drift-equivalent-token-context" => labels.Relationships.Where(item =>
                item.TransformationKind is "line-shift" or "region-drift"),
            "file-method-movement-equivalent-token-context" =>
                labels.Relationships.Where(item =>
                    string.Equals(
                        item.ExpectedClassification,
                        "moved",
                        StringComparison.Ordinal)
                    && item.TransformationKind is not "line-shift" and not "region-drift"),
            "repeated-context-ambiguity" => [],
            _ => labels.Relationships,
        };
        ImmutableHashSet<SelectorPair> relevantRelationships = relevant
            .Select(item => new SelectorPair(item.Baseline, item.Candidate))
            .ToImmutableHashSet();
        int acceptedRelationships = scenario.AcceptedPairs.Count(pair =>
            relevantRelationships.Contains(new SelectorPair(pair.Baseline, pair.Candidate)));
        int affectedEndpointMatches = scenario.AcceptedPairs.Count(pair =>
            scenario.AffectedBaselineFindings.Contains(pair.Baseline)
            || scenario.AffectedCandidateFindings.Contains(pair.Candidate));
        bool falsePair = scenario.AcceptedPairs.Any(pair =>
            !allRelationships.Contains(new SelectorPair(pair.Baseline, pair.Candidate)));
        bool ambiguityMatched = scenario.AcceptedPairs.Any(pair =>
            labels.Ambiguities.Any(ambiguity =>
                ambiguity.Baseline.Contains(pair.Baseline)
                || ambiguity.Candidate.Contains(pair.Candidate)));
        bool securityScenario = scenarioId is "missing-source-file"
            or "mismatched-source-snapshot"
            or "baseline-root-bound-to-candidate"
            or "candidate-root-bound-to-baseline"
            or "both-roots-swapped";
        bool oppositeRootRead = scenario.BaselineReadsFromCandidateRoot > 0
            || scenario.CandidateReadsFromBaselineRoot > 0;
        bool preflightCorrect = trustedTreeHashes && securityScenario
            ? !scenario.PreflightAccepted
                && scenario.AcceptedPairs.IsEmpty
                && !oppositeRootRead
            : scenario.PreflightAccepted;
        bool assertionsPassed = preflightCorrect
            && !falsePair
            && !ambiguityMatched
            && affectedEndpointMatches == 0
            && (!oppositeRootRead || !securityScenario)
            && scenario.IngestionFailures == 0
            && scenario.StructuralFailures == 0
            && scenario.ContainmentViolations == 0;
        return new SparseFamilyScenarioGateEvidence(
            scenario.FamilyId,
            assertionsPassed,
            scenario.PreflightAccepted,
            acceptedRelationships,
            affectedEndpointMatches,
            scenario.BaselineReadsFromCandidateRoot,
            scenario.CandidateReadsFromBaselineRoot,
            scenario.ContainmentViolations,
            scenario.IngestionFailures,
            scenario.StructuralFailures);
    }

    private static SparseNaturalSelector ReadSelector(JsonNode? node, string name)
    {
        JsonObject value = RequireObject(node, name);
        JsonObject region = RequireObject(value["region"], name + ".region");
        return new SparseNaturalSelector(
            RequireString(value, "ruleId"),
            RequireString(value, "artifactUri"),
            new SparseRegionSelector(
                RequireInteger(region, "startLine"),
                RequireInteger(region, "startColumn"),
                RequireInteger(region, "endLine"),
                RequireInteger(region, "endColumn")),
            RequireString(value, "message"));
    }

    private static JsonObject RequireObject(JsonNode? node, string name) =>
        node as JsonObject
        ?? throw new InvalidDataException($"Sparse label value '{name}' must be an object.");

    private static JsonArray RequireArray(JsonObject value, string property) =>
        value[property] as JsonArray
        ?? throw new InvalidDataException($"Sparse label value '{property}' must be an array.");

    private static string RequireString(JsonObject value, string property) =>
        value[property]?.GetValue<string>()
        ?? throw new InvalidDataException($"Sparse label value '{property}' must be a string.");

    private static int RequireInteger(JsonObject value, string property) =>
        value[property]?.GetValue<int>()
        ?? throw new InvalidDataException($"Sparse label value '{property}' must be an integer.");

    private sealed record LabelRelationship(
        SparseNaturalSelector Baseline,
        SparseNaturalSelector Candidate,
        string ExpectedClassification,
        string TransformationKind);

    private sealed record LabelAmbiguity(
        ImmutableHashSet<SparseNaturalSelector> Baseline,
        ImmutableHashSet<SparseNaturalSelector> Candidate);

    private sealed record LabelFamily(
        string FamilyId,
        ImmutableArray<LabelRelationship> Relationships,
        ImmutableHashSet<SparseNaturalSelector> ExpectedNew,
        ImmutableHashSet<SparseNaturalSelector> ExpectedResolved,
        ImmutableArray<LabelAmbiguity> Ambiguities);

    private sealed record SelectorPair(
        SparseNaturalSelector Baseline,
        SparseNaturalSelector Candidate);
}
