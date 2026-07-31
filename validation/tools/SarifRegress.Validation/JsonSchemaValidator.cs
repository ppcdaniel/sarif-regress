using Json.Schema;
using System.Text.Json.Nodes;

namespace SarifRegress.Validation;

/// <summary>
/// Evaluates repository JSON against a bounded local JSON Schema using JsonSchema.Net.
/// </summary>
public sealed class JsonSchemaValidator
{
    private readonly ValidationLimits limits;

    /// <summary>Creates a validator with explicit untrusted-input limits.</summary>
    public JsonSchemaValidator(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>
    /// Validates one JSON file and returns its parsed node for subsequent semantic checks.
    /// </summary>
    public JsonNode ValidateFile(
        string schemaPath,
        string instancePath,
        long maximumInstanceBytes,
        string? schemaApprovedRoot = null,
        string? instanceApprovedRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(instancePath);
        JsonNode schemaNode = BoundedJsonFile.ReadNode(
            schemaPath,
            limits.MaximumSchemaBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            schemaApprovedRoot);
        JsonNode instanceNode = BoundedJsonFile.ReadNode(
            instancePath,
            maximumInstanceBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            instanceApprovedRoot);

        JsonSchema schema;
        try
        {
            schema = JsonSchema.FromText(schemaNode.ToJsonString());
        }
        catch (Exception exception) when (
            exception is JsonException or SchemaException)
        {
            throw new InvalidDataException(
                $"Schema '{Path.GetFileName(schemaPath)}' is invalid.",
                exception);
        }

        EvaluationResults results = schema.Evaluate(
            instanceNode,
            new EvaluationOptions
            {
                OutputFormat = OutputFormat.List,
            });
        if (!results.IsValid)
        {
            throw new InvalidDataException(
                $"JSON file '{Path.GetFileName(instancePath)}' does not satisfy "
                + $"schema '{Path.GetFileName(schemaPath)}'.");
        }

        return instanceNode;
    }
}
