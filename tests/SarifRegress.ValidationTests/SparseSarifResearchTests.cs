using System.Text.Json;
using System.Text.Json.Nodes;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class SparseSarifResearchTests
{
    [Fact]
    public void Authenticated_sparse_limitation_evidence_satisfies_its_schemas()
    {
        string root = ValidationTestRepository.FindRoot();
        string researchRoot = Path.Combine(
            root,
            "validation",
            "research",
            "sparse-sarif");
        string researchSchemaRoot = Path.Combine(researchRoot, "schemas");
        string expectedRoot = Path.Combine(researchRoot, "expected");
        string rootSchemaRoot = Path.Combine(root, "schemas");
        var validator = new JsonSchemaValidator();
        (string Schema, string Instance)[] checks =
        [
            (
                Path.Combine(researchSchemaRoot, "experiment-observations.schema.json"),
                Path.Combine(expectedRoot, "sparse-experiment-observations.json")),
            (
                Path.Combine(researchSchemaRoot, "experiment-gate-evidence.schema.json"),
                Path.Combine(expectedRoot, "sparse-experiment-gate-evidence.json")),
            (
                Path.Combine(researchSchemaRoot, "resource-observations.schema.json"),
                Path.Combine(expectedRoot, "sparse-experiment-resource-observations.json")),
            (
                Path.Combine(
                    rootSchemaRoot,
                    "sparse-experiment-workflow-provenance.schema.json"),
                Path.Combine(expectedRoot, "sparse-experiment-workflow-provenance.json")),
            (
                Path.Combine(rootSchemaRoot, "sparse-experiment-limitation.schema.json"),
                Path.Combine(expectedRoot, "sparse-experiment-limitation.json")),
        ];
        foreach ((string schema, string instance) in checks)
        {
            _ = validator.ValidateFile(
                schema,
                instance,
                ValidationLimits.Default.MaximumManifestBytes);
        }

        string projectionSchema = Path.Combine(
            rootSchemaRoot,
            "sparse-experiment-projection.schema.json");
        foreach (string role in new[] { "release", "determinism", "resource" })
        {
            _ = validator.ValidateFile(
                projectionSchema,
                Path.Combine(
                    expectedRoot,
                    "projections",
                    $"sparse-experiment-{role}-projection.json"),
                ValidationLimits.Default.MaximumManifestBytes);
        }
    }

    [Fact]
    public void Tracked_sparse_research_contracts_satisfy_their_schemas()
    {
        string root = ValidationTestRepository.FindRoot();
        string researchRoot = Path.Combine(
            root,
            "validation",
            "research",
            "sparse-sarif");
        string schemaRoot = Path.Combine(researchRoot, "schemas");
        var validator = new JsonSchemaValidator();

        JsonNode manifest = validator.ValidateFile(
            Path.Combine(schemaRoot, "manifest.schema.json"),
            Path.Combine(researchRoot, "manifest.json"),
            ValidationLimits.Default.MaximumManifestBytes);
        Assert.Equal("1", manifest["schemaVersion"]!.GetValue<string>());

        foreach (JsonNode? familyNode in manifest["families"]!.AsArray())
        {
            JsonObject family = familyNode!.AsObject();
            _ = validator.ValidateFile(
                Path.Combine(schemaRoot, "labels.schema.json"),
                ResolvePortable(researchRoot, family["labelsPath"]!.GetValue<string>()),
                ValidationLimits.Default.MaximumLabelBytes);

            foreach (string sideName in new[] { "baseline", "candidate" })
            {
                JsonObject side = family[sideName]!.AsObject();
                _ = validator.ValidateFile(
                    Path.Combine(schemaRoot, "projection-audit.schema.json"),
                    ResolvePortable(
                        researchRoot,
                        side["projectionAuditPath"]!.GetValue<string>()),
                    ValidationLimits.Default.MaximumManifestBytes);
                AssertAuthenticSparsePmdSarif(ResolvePortable(
                    researchRoot,
                    side["sarifPath"]!.GetValue<string>()));
            }
        }

        foreach (string schemaName in new[]
                 {
                     "manifest.schema.json",
                     "labels.schema.json",
                     "projection-audit.schema.json",
                     "experiment-report.schema.json",
                 })
        {
            using JsonDocument schema = JsonDocument.Parse(
                File.ReadAllBytes(Path.Combine(schemaRoot, schemaName)));
            Assert.Equal(
                "https://json-schema.org/draft/2020-12/schema",
                schema.RootElement.GetProperty("$schema").GetString());
        }
    }

    [Fact]
    public void Hosted_sparse_capture_authenticates_each_new_artifact()
    {
        string root = ValidationTestRepository.FindRoot();
        string researchRoot = Path.Combine(
            root,
            "validation",
            "research",
            "sparse-sarif");
        JsonObject manifest = JsonNode.Parse(
            File.ReadAllBytes(Path.Combine(researchRoot, "manifest.json")))!.AsObject();
        JsonObject capture = manifest["producer"]!["capture"]!.AsObject();
        JsonObject workflowEvidence = capture["workflow"]!.AsObject();
        string artifactName = workflowEvidence["artifactName"]!.GetValue<string>();
        string artifactDigest = workflowEvidence["artifactDigest"]!.GetValue<string>();
        string sourceHeadSha = capture["sourceHeadSha"]!.GetValue<string>();
        string workflow = File.ReadAllText(Path.Combine(
            root,
            ".github",
            "workflows",
            "holdout-validation.yml"));

        Assert.Contains("actions: read", workflow, StringComparison.Ordinal);
        Assert.Equal($"sparse-sarif-pmd-capture-{sourceHeadSha}", artifactName);
        Assert.Matches("^[0-9a-f]{64}$", artifactDigest);
        Assert.Contains(
            "needs.sparse-capture.outputs.artifact_id",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "needs.sparse-capture.outputs.artifact_digest",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            ".workflow_run.head_sha == $source_sha",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "promoted-capture-provenance:",
            workflow,
            StringComparison.Ordinal);
        Assert.Equal(
            2,
            workflow.Split("verify-promotion", StringSplitOptions.None).Length - 1);
    }

    private static void AssertAuthenticSparsePmdSarif(string path)
    {
        using JsonDocument document = JsonDocument.Parse(
            File.ReadAllBytes(path),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 128,
            });
        JsonElement root = document.RootElement;
        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        JsonElement run = Assert.Single(root.GetProperty("runs").EnumerateArray());
        JsonElement driver = run.GetProperty("tool").GetProperty("driver");
        Assert.Equal("PMD", driver.GetProperty("name").GetString());
        Assert.Equal("7.26.0", driver.GetProperty("version").GetString());
        JsonElement invocation = Assert.Single(run.GetProperty("invocations").EnumerateArray());
        Assert.True(invocation.GetProperty("executionSuccessful").GetBoolean());
        Assert.Empty(invocation.GetProperty("toolConfigurationNotifications").EnumerateArray());
        Assert.Empty(invocation.GetProperty("toolExecutionNotifications").EnumerateArray());
        Assert.NotEmpty(run.GetProperty("results").EnumerateArray());
    }

    private static string ResolvePortable(string root, string relative)
    {
        return relative
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Aggregate(root, static (current, segment) => Path.Combine(current, segment));
    }
}
