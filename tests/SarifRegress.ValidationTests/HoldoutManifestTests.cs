using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class HoldoutManifestTests
{
    private static readonly string[] RequiredProducerProperties =
    [
        "id",
        "family",
        "displayName",
        "exactVersion",
        "sourceCommit",
        "projectUrl",
        "releaseUrl",
        "license",
        "captureDate",
        "commands",
        "downloads",
        "capturePolicy",
    ];

    [Fact]
    public void Tracked_manifest_satisfies_its_draft_2020_12_schema()
    {
        string root = ValidationTestRepository.FindRoot();
        string schemaPath = Path.Combine(
            root,
            "validation",
            "schemas",
            "holdout-manifest.schema.json");
        string manifestPath = Path.Combine(
            root,
            "validation",
            "holdout",
            "manifest.json");

        JsonNode instance = new JsonSchemaValidator().ValidateFile(
            schemaPath,
            manifestPath,
            ValidationLimits.Default.MaximumManifestBytes);

        Assert.Equal("1", instance["schemaVersion"]!.GetValue<string>());
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        Assert.Equal(
            "https://json-schema.org/draft/2020-12/schema",
            schema.RootElement.GetProperty("$schema").GetString());
    }

    [Fact]
    public void Schema_validation_is_repeatable_with_isolated_registries()
    {
        string root = ValidationTestRepository.FindRoot();
        string schemaPath = Path.Combine(
            root,
            "validation",
            "schemas",
            "holdout-manifest.schema.json");
        string manifestPath = Path.Combine(
            root,
            "validation",
            "holdout",
            "manifest.json");
        var validator = new JsonSchemaValidator();

        Parallel.For(
            0,
            8,
            _ => validator.ValidateFile(
                schemaPath,
                manifestPath,
                ValidationLimits.Default.MaximumManifestBytes));
    }

    [Fact]
    public void Schema_rejects_a_manifest_missing_required_provenance()
    {
        string root = ValidationTestRepository.FindRoot();
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string manifestPath = Path.Combine(
                root,
                "validation",
                "holdout",
                "manifest.json");
            JsonNode manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!;
            JsonObject firstProducer = manifest["producers"]![0]!.AsObject();
            Assert.True(firstProducer.Remove("releaseUrl"));
            string invalidPath = Path.Combine(temporaryRoot, "manifest.json");
            File.WriteAllText(invalidPath, manifest.ToJsonString());

            var exception = Assert.Throws<InvalidDataException>(() =>
                new JsonSchemaValidator().ValidateFile(
                    Path.Combine(
                        root,
                        "validation",
                        "schemas",
                        "holdout-manifest.schema.json"),
                    invalidPath,
                    ValidationLimits.Default.MaximumManifestBytes));

            Assert.Contains("does not satisfy", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Tracked_holdout_has_three_unique_real_producer_families()
    {
        ValidatedHoldout holdout = new HoldoutManifestReader().Read(
            ValidationTestRepository.FindRoot());

        Assert.Equal(3, holdout.Manifest.Producers.Length);
        Assert.Equal(
            3,
            holdout.Manifest.Producers
                .Select(producer => producer.Family)
                .Distinct(StringComparer.Ordinal)
                .Count());
        Assert.Equal(
            ["gitleaks", "pmd", "semgrep"],
            holdout.Manifest.Producers
                .Select(producer => producer.Family)
                .Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Producer_versions_downloads_commands_and_licenses_are_exactly_pinned()
    {
        JsonObject manifest = ReadTrackedManifest();
        JsonArray producers = manifest["producers"]!.AsArray();
        Assert.Equal(3, producers.Count);
        foreach (JsonObject producer in producers.Select(item => item!.AsObject()))
        {
            Assert.All(
                RequiredProducerProperties,
                property => Assert.True(
                    producer.ContainsKey(property),
                    $"Producer '{producer["id"]}' lacks '{property}'."));

            string version = producer["exactVersion"]!.GetValue<string>();
            Assert.True(
                Version.TryParse(version, out Version? parsed)
                && string.Equals(parsed.ToString(), version, StringComparison.Ordinal),
                $"Producer version '{version}' is not an exact numeric pin.");
            Assert.DoesNotContain("latest", version, StringComparison.OrdinalIgnoreCase);

            string releaseUrl = producer["releaseUrl"]!.GetValue<string>();
            Assert.StartsWith("https://", releaseUrl, StringComparison.Ordinal);
            Assert.DoesNotContain("/latest", releaseUrl, StringComparison.OrdinalIgnoreCase);
            Assert.True(
                DateOnly.TryParseExact(
                    producer["captureDate"]!.GetValue<string>(),
                    "yyyy-MM-dd",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.None,
                    out _));

            JsonObject license = producer["license"]!.AsObject();
            Assert.False(string.IsNullOrWhiteSpace(
                license["spdxIdentifier"]!.GetValue<string>()));
            Assert.StartsWith(
                "https://",
                license["url"]!.GetValue<string>(),
                StringComparison.Ordinal);

            JsonObject commands = producer["commands"]!.AsObject();
            JsonObject reproduction = commands["reproduction"]!.AsObject();
            Assert.Equal(
                "validation/tools/capture",
                reproduction["workingDirectory"]!.GetValue<string>());
            Assert.Equal(
                "./capture-holdout.sh",
                reproduction["executable"]!.GetValue<string>());
            Assert.Equal(
                new[]
                {
                    "--output-root",
                    "<new-staging-directory>",
                    "--producer",
                    producer["id"]!.GetValue<string>(),
                },
                reproduction["arguments"]!.AsArray()
                    .Select(argument => argument!.GetValue<string>()));
            Assert.NotEmpty(commands["install"]!.AsArray());
            Assert.NotEmpty(commands["capture"]!.AsArray());
            IEnumerable<JsonObject> recordedCommands = commands["install"]!
                .AsArray()
                .Concat(commands["capture"]!.AsArray())
                .Select(item => item!.AsObject())
                .Append(commands["reproduction"]!.AsObject());
            foreach (JsonObject command in recordedCommands)
            {
                string flattened = string.Join(
                    ' ',
                    command["arguments"]!.AsArray()
                        .Select(argument => argument!.GetValue<string>()));
                Assert.DoesNotContain("curl |", flattened, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("wget |", flattened, StringComparison.OrdinalIgnoreCase);
            }

            foreach (JsonObject download in producer["downloads"]!.AsArray()
                         .Select(item => item!.AsObject()))
            {
                Assert.Matches(
                    "^[0-9a-f]{64}$",
                    download["sha256"]!.GetValue<string>());
                Assert.True(download["sizeBytes"]!.GetValue<long>() > 0);
                Assert.True(download["immutable"]!.GetValue<bool>());
                string url = download["url"]!.GetValue<string>();
                Assert.StartsWith("https://", url, StringComparison.Ordinal);
                Assert.DoesNotContain("/latest", url, StringComparison.OrdinalIgnoreCase);
            }

            JsonObject policy = producer["capturePolicy"]!.AsObject();
            Assert.False(policy["downloadsRemoteRules"]!.GetValue<bool>());
            Assert.False(policy["executesFixtureCode"]!.GetValue<bool>());
            Assert.False(policy["followsSarifNetworkUris"]!.GetValue<bool>());
        }
    }

    [Fact]
    public void Every_case_records_source_and_raw_sarif_mutation_provenance()
    {
        JsonArray cases = ReadTrackedManifest()["cases"]!.AsArray();
        Assert.Equal(3, cases.Count);
        foreach (JsonObject holdoutCase in cases.Select(item => item!.AsObject()))
        {
            JsonObject input = holdoutCase["inputProvenance"]!.AsObject();
            Assert.Contains(
                input["origin"]!.GetValue<string>(),
                new[] { "created-for-repository", "clearly-redistributable" });
            Assert.False(input["containsRealSecrets"]!.GetValue<bool>());
            Assert.False(input["containsProprietaryCode"]!.GetValue<bool>());
            Assert.False(string.IsNullOrWhiteSpace(
                input["license"]!["spdxIdentifier"]!.GetValue<string>()));

            JsonArray sourceTransformations =
                holdoutCase["sourceTransformations"]!.AsArray();
            Assert.NotEmpty(sourceTransformations);
            Assert.All(
                sourceTransformations,
                item =>
                {
                    JsonObject transformation = item!.AsObject();
                    Assert.False(string.IsNullOrWhiteSpace(
                        transformation["script"]!.GetValue<string>()));
                    Assert.NotEmpty(transformation["inputPaths"]!.AsArray());
                    Assert.NotEmpty(transformation["outputPaths"]!.AsArray());
                    Assert.False(string.IsNullOrWhiteSpace(
                        transformation["description"]!.GetValue<string>()));
                });

            Assert.All(
                holdoutCase["rawSarifMutations"]!.AsArray(),
                item =>
                {
                    JsonObject mutation = item!.AsObject();
                    Assert.False(string.IsNullOrWhiteSpace(
                        mutation["originalCapture"]!.GetValue<string>()));
                    Assert.False(string.IsNullOrWhiteSpace(
                        mutation["script"]!.GetValue<string>()));
                    Assert.NotEmpty(mutation["changedFields"]!.AsArray());
                    Assert.Contains(
                        mutation["semanticIdentity"]!.GetValue<string>(),
                        new[] { "preserved", "changed" });
                    Assert.False(string.IsNullOrWhiteSpace(
                        mutation["rationale"]!.GetValue<string>()));
                });
        }
    }

    [Fact]
    public void Counts_meet_the_holdout_minimums_per_producer_and_in_aggregate()
    {
        ValidatedHoldout holdout = new HoldoutManifestReader().Read(
            ValidationTestRepository.FindRoot());
        JsonObject manifest = ReadTrackedManifest();
        JsonObject aggregateCounts = manifest["counts"]!.AsObject();

        Assert.True(holdout.Manifest.Counts.LabelledRelationships >= 75);
        Assert.Equal(99, holdout.Manifest.Counts.GroundTruthUnits);
        Assert.True(holdout.Manifest.Counts.SameFindingRelationships >= 30);
        Assert.True(holdout.Manifest.Counts.NewOrResolvedFindings >= 15);
        Assert.True(
            holdout.Manifest.Counts.AmbiguousOrNearCollisionRelationships >= 3);
        Assert.All(
            holdout.Manifest.Cases,
            item =>
            {
                Assert.Equal(33, item.Counts.GroundTruthUnits);
                Assert.True(item.Counts.LabelledRelationships >= 20);
                Assert.True(item.Counts.SameFindingRelationships >= 10);
                Assert.True(item.Counts.NewOrResolvedFindings >= 5);
                Assert.True(item.Counts.AmbiguousOrNearCollisionRelationships >= 1);
            });
        Assert.Equal(99, aggregateCounts["groundTruthUnits"]!.GetValue<int>());
        int caseGroundTruthUnits = 0;
        foreach (JsonObject holdoutCase in manifest["cases"]!.AsArray()
                     .Select(item => item!.AsObject()))
        {
            JsonObject counts = holdoutCase["counts"]!.AsObject();
            int expected = counts["labelledRelationships"]!.GetValue<int>()
                + counts["newFindings"]!.GetValue<int>()
                + counts["resolvedFindings"]!.GetValue<int>()
                + counts["ambiguousOrNearCollisionRelationships"]!.GetValue<int>();
            int actual = counts["groundTruthUnits"]!.GetValue<int>();
            Assert.Equal(33, actual);
            Assert.Equal(expected, actual);
            caseGroundTruthUnits += actual;
        }

        Assert.Equal(
            aggregateCounts["groundTruthUnits"]!.GetValue<int>(),
            caseGroundTruthUnits);
        string[] relationshipIds = holdout.Cases
            .SelectMany(item => GroundTruthRelationshipFactory.Create(
                item.Plan.Id,
                item.Labels))
            .Select(item => item.RelationshipId)
            .ToArray();
        Assert.Equal(99, relationshipIds.Length);
        Assert.Equal(
            relationshipIds.Length,
            relationshipIds.Distinct(StringComparer.Ordinal).Count());
        Assert.All(
            holdout.Cases,
            item => Assert.Equal(
                item.Plan.Counts.GroundTruthUnits,
                GroundTruthRelationshipFactory.Create(item.Plan.Id, item.Labels)
                    .Length));
    }

    [Fact]
    public void Holdout_ids_do_not_overlap_the_development_corpus()
    {
        string root = ValidationTestRepository.FindRoot();
        ValidatedHoldout holdout = new HoldoutManifestReader().Read(root);
        HashSet<string> developmentIds = Directory.EnumerateDirectories(
                Path.Combine(root, "corpus", "cases"))
            .Select(Path.GetFileName)
            .Where(name => name is not null)
            .Select(name => name!)
            .ToHashSet(StringComparer.Ordinal);

        Assert.DoesNotContain(
            holdout.Manifest.Cases.Select(item => item.Id),
            developmentIds.Contains);
    }

    [Fact]
    public void Undeclared_case_directory_is_rejected_instead_of_silently_omitted()
    {
        string temporaryRoot =
            ValidationTestRepository.CopyStructuralInputsToTemporaryRepository();
        try
        {
            Directory.CreateDirectory(Path.Combine(
                temporaryRoot,
                "validation",
                "holdout",
                "cases",
                "silently-omitted"));

            var exception = Assert.Throws<InvalidDataException>(() =>
                new HoldoutManifestReader().Read(temporaryRoot));

            Assert.Contains(
                "does not exactly match",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Case_child_path_outside_its_declared_directory_is_rejected()
    {
        string temporaryRoot =
            ValidationTestRepository.CopyStructuralInputsToTemporaryRepository();
        try
        {
            string manifestPath = Path.Combine(
                temporaryRoot,
                "validation",
                "holdout",
                "manifest.json");
            JsonObject manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!
                .AsObject();
            JsonObject firstCase = manifest["cases"]![0]!.AsObject();
            string firstId = firstCase["id"]!.GetValue<string>();
            string differentId = manifest["cases"]![1]!["id"]!.GetValue<string>();
            firstCase["paths"]!["candidateSarif"] =
                $"validation/holdout/cases/{differentId}/candidate.sarif";
            File.WriteAllText(manifestPath, manifest.ToJsonString());

            InvalidDataException exception = Assert.Throws<InvalidDataException>(
                () => new HoldoutManifestReader().Read(temporaryRoot));

            Assert.Contains(firstId, exception.Message, StringComparison.Ordinal);
            Assert.Contains(
                "outside its case directory",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Case_traversal_is_ordinal_even_when_manifest_order_is_reversed()
    {
        string temporaryRoot =
            ValidationTestRepository.CopyStructuralInputsToTemporaryRepository();
        try
        {
            string manifestPath = Path.Combine(
                temporaryRoot,
                "validation",
                "holdout",
                "manifest.json");
            JsonObject manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!
                .AsObject();
            JsonArray cases = manifest["cases"]!.AsArray();
            JsonNode?[] reversed = cases
                .Select(item => item!.DeepClone())
                .Reverse()
                .ToArray();
            cases.Clear();
            foreach (JsonNode? item in reversed)
            {
                cases.Add(item);
            }

            File.WriteAllText(manifestPath, manifest.ToJsonString());
            ValidatedHoldout holdout = new HoldoutManifestReader().Read(temporaryRoot);
            string[] ids = holdout.Cases.Select(item => item.Plan.Id).ToArray();

            Assert.Equal(ids.Order(StringComparer.Ordinal), ids);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Reading_structure_does_not_modify_any_holdout_fixture()
    {
        string holdoutRoot = Path.Combine(
            ValidationTestRepository.FindRoot(),
            "validation",
            "holdout");
        IReadOnlyDictionary<string, string> before =
            ValidationTestRepository.HashTree(holdoutRoot);

        _ = new HoldoutManifestReader().Read(ValidationTestRepository.FindRoot());

        IReadOnlyDictionary<string, string> after =
            ValidationTestRepository.HashTree(holdoutRoot);
        Assert.Equal(before, after);
    }

    private static JsonObject ReadTrackedManifest()
    {
        string path = Path.Combine(
            ValidationTestRepository.FindRoot(),
            "validation",
            "holdout",
            "manifest.json");
        return JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
    }
}
