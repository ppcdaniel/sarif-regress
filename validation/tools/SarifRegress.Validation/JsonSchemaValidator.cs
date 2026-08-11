using System.Text.Json.Nodes;

namespace SarifRegress.Validation;

/// <summary>
/// Evaluates repository JSON against the bounded Draft 2020-12 vocabulary used by this repository.
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
        JsonNode instanceNode = BoundedJsonFile.ReadNode(
            instancePath,
            maximumInstanceBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            instanceApprovedRoot);

        return ValidateNode(
            schemaPath,
            instanceNode,
            Path.GetFileName(instancePath),
            schemaApprovedRoot);
    }

    /// <summary>Validates an already bounded and uniquely parsed JSON node.</summary>
    public JsonNode ValidateNode(
        string schemaPath,
        JsonNode instanceNode,
        string instanceName,
        string? schemaApprovedRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaPath);
        ArgumentNullException.ThrowIfNull(instanceNode);
        ArgumentException.ThrowIfNullOrWhiteSpace(instanceName);
        JsonNode schemaNode = BoundedJsonFile.ReadNode(
            schemaPath,
            limits.MaximumSchemaBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            schemaApprovedRoot);

        try
        {
            var evaluator = new BoundedJsonSchemaEvaluator(schemaNode, limits);
            if (!evaluator.IsValid(instanceNode))
            {
                throw new InvalidDataException(
                    $"JSON file '{instanceName}' does not satisfy "
                    + $"schema '{Path.GetFileName(schemaPath)}'.");
            }
        }
        catch (JsonSchemaDefinitionException exception)
        {
            throw new InvalidDataException(
                $"Schema '{Path.GetFileName(schemaPath)}' is invalid.",
                exception);
        }
        catch (JsonSchemaEvaluationException exception)
        {
            throw new InvalidDataException(
                $"JSON file '{instanceName}' could not be validated within the configured "
                + "schema evaluation limits.",
                exception);
        }

        return instanceNode;
    }
}
