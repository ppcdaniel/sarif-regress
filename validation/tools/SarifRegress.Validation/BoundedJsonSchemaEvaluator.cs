using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SarifRegress.Validation;

/// <summary>
/// Evaluates the deliberately small Draft 2020-12 vocabulary used by repository evidence schemas.
/// </summary>
/// <remarks>
/// The evaluator rejects unknown keywords and non-local references. This fail-closed contract keeps
/// future schema changes from silently weakening validation and prevents network-backed resolution.
/// </remarks>
internal sealed class BoundedJsonSchemaEvaluator
{
    private const string Draft202012Dialect =
        "https://json-schema.org/draft/2020-12/schema";

    private readonly JsonNode schemaRoot;
    private readonly ValidationLimits limits;
    private readonly Dictionary<string, JsonNode> resolvedReferences =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, Regex> regularExpressions =
        new(StringComparer.Ordinal);
    private readonly HashSet<JsonNode> validatedSchemaNodes =
        new(ReferenceEqualityComparer.Instance);
    private int remainingEvaluationSteps;

    /// <summary>Validates and prepares one bounded, local schema document.</summary>
    public BoundedJsonSchemaEvaluator(JsonNode schemaRoot, ValidationLimits limits)
    {
        ArgumentNullException.ThrowIfNull(schemaRoot);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        this.schemaRoot = schemaRoot;
        this.limits = limits;
        remainingEvaluationSteps = limits.MaximumSchemaEvaluationSteps;
        ValidateSchemaNode(schemaRoot, depth: 0, isDocumentRoot: true);
    }

    /// <summary>Returns whether an instance satisfies the prepared schema.</summary>
    public bool IsValid(JsonNode? instance)
    {
        remainingEvaluationSteps = limits.MaximumSchemaEvaluationSteps;
        var semanticComparer = new JsonSemanticComparer(this);
        return EvaluateSchema(schemaRoot, instance, depth: 0, semanticComparer);
    }

    // Time: O(S + R), where S is the structural schema size and R is resolved local references.
    // Space: O(S + R) for visited nodes, compiled expressions, and resolved-reference caches.
    private void ValidateSchemaNode(JsonNode? schema, int depth, bool isDocumentRoot = false)
    {
        SpendEvaluationStep();
        RequireAllowedDepth(depth);
        if (schema is null)
        {
            throw new JsonSchemaDefinitionException("A schema node cannot be JSON null.");
        }

        JsonValueKind schemaKind = schema.GetValueKind();
        if (schemaKind is JsonValueKind.True or JsonValueKind.False)
        {
            return;
        }

        if (schema is not JsonObject schemaObject)
        {
            throw new JsonSchemaDefinitionException(
                "A schema node must be an object or Boolean value.");
        }

        if (!validatedSchemaNodes.Add(schemaObject))
        {
            return;
        }

        foreach ((string keyword, _) in schemaObject)
        {
            SpendEvaluationStep();
            if (!IsSupportedKeyword(keyword))
            {
                throw new JsonSchemaDefinitionException(
                    $"Schema keyword '{keyword}' is not supported by the bounded validator.");
            }
        }

        ValidateDialectAndIdentifier(schemaObject, isDocumentRoot);
        ValidateTypeKeyword(schemaObject);
        ValidateSchemaMap(schemaObject, "$defs", depth);
        ValidateSchemaMap(schemaObject, "properties", depth);
        ValidateSchemaKeyword(schemaObject, "propertyNames", depth);
        ValidateDependentRequired(schemaObject);
        ValidateRequired(schemaObject);
        ValidateSchemaKeyword(schemaObject, "additionalProperties", depth);
        ValidateSchemaKeyword(schemaObject, "items", depth);
        ValidateSchemaKeyword(schemaObject, "contains", depth);
        ValidateSchemaKeyword(schemaObject, "not", depth);
        ValidateSchemaKeyword(schemaObject, "if", depth);
        ValidateSchemaKeyword(schemaObject, "then", depth);
        ValidateSchemaKeyword(schemaObject, "else", depth);
        ValidateSchemaArray(schemaObject, "prefixItems", depth);
        ValidateSchemaArray(schemaObject, "allOf", depth);
        ValidateSchemaArray(schemaObject, "anyOf", depth);
        ValidateSchemaArray(schemaObject, "oneOf", depth);
        ValidateNonNegativeIntegerKeyword(schemaObject, "minItems");
        ValidateNonNegativeIntegerKeyword(schemaObject, "maxItems");
        ValidateNonNegativeIntegerKeyword(schemaObject, "minLength");
        ValidateNonNegativeIntegerKeyword(schemaObject, "maxLength");
        ValidateNonNegativeIntegerKeyword(schemaObject, "minProperties");
        ValidateNonNegativeIntegerKeyword(schemaObject, "maxProperties");
        ValidateNonNegativeIntegerKeyword(schemaObject, "minContains");
        ValidateNumericKeyword(schemaObject, "minimum");
        ValidateNumericKeyword(schemaObject, "maximum");
        ValidateBooleanKeyword(schemaObject, "uniqueItems");
        ValidateStringKeyword(schemaObject, "title");
        ValidateStringKeyword(schemaObject, "description");
        ValidatePattern(schemaObject);
        ValidateEnum(schemaObject);

        if (schemaObject.TryGetPropertyValue("$ref", out JsonNode? referenceNode))
        {
            string reference = RequireString(referenceNode, "$ref");
            JsonNode target = ResolveLocalReference(reference);
            ValidateSchemaNode(target, checked(depth + 1));
        }
    }

    // Time: O(K + A + C), where K is the visited schema keywords, A the instance members, and
    // C the selected combinator branches. Space: O(D + U), for recursion depth D and unique items U.
    private bool EvaluateSchema(
        JsonNode schema,
        JsonNode? instance,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        SpendEvaluationStep();
        RequireAllowedDepth(depth);
        JsonValueKind schemaKind = schema.GetValueKind();
        if (schemaKind is JsonValueKind.True or JsonValueKind.False)
        {
            return schemaKind == JsonValueKind.True;
        }

        JsonObject schemaObject = schema.AsObject();
        if (schemaObject.TryGetPropertyValue("$ref", out JsonNode? referenceNode)
            && !EvaluateSchema(
                ResolveLocalReference(RequireString(referenceNode, "$ref")),
                instance,
                checked(depth + 1),
                semanticComparer))
        {
            return false;
        }

        if (!MatchesDeclaredType(schemaObject, instance)
            || !MatchesConstantAndEnumeration(schemaObject, instance, semanticComparer)
            || !MatchesStringKeywords(schemaObject, instance)
            || !MatchesNumberKeywords(schemaObject, instance)
            || !MatchesObjectKeywords(schemaObject, instance, depth, semanticComparer)
            || !MatchesArrayKeywords(schemaObject, instance, depth, semanticComparer)
            || !MatchesCombinators(schemaObject, instance, depth, semanticComparer))
        {
            return false;
        }

        return true;
    }

    private bool MatchesDeclaredType(JsonObject schema, JsonNode? instance)
    {
        if (!schema.TryGetPropertyValue("type", out JsonNode? typeNode))
        {
            return true;
        }

        if (typeNode is JsonArray declaredTypes)
        {
            foreach (JsonNode? declaredType in declaredTypes)
            {
                SpendEvaluationStep();
                if (MatchesType(RequireString(declaredType, "type"), instance))
                {
                    return true;
                }
            }

            return false;
        }

        return MatchesType(RequireString(typeNode, "type"), instance);
    }

    private bool MatchesType(string declaredType, JsonNode? instance)
    {
        JsonValueKind instanceKind = GetValueKind(instance);
        return declaredType switch
        {
            "null" => instanceKind == JsonValueKind.Null,
            "boolean" => instanceKind is JsonValueKind.True or JsonValueKind.False,
            "object" => instanceKind == JsonValueKind.Object,
            "array" => instanceKind == JsonValueKind.Array,
            "number" => instanceKind == JsonValueKind.Number,
            "integer" => instanceKind == JsonValueKind.Number
                && ParseNumber(instance!).IsInteger,
            "string" => instanceKind == JsonValueKind.String,
            _ => throw new JsonSchemaDefinitionException(
                $"Schema type '{declaredType}' is not supported."),
        };
    }

    private bool MatchesConstantAndEnumeration(
        JsonObject schema,
        JsonNode? instance,
        JsonSemanticComparer semanticComparer)
    {
        if (schema.TryGetPropertyValue("const", out JsonNode? constant)
            && !semanticComparer.Equals(constant, instance))
        {
            return false;
        }

        if (!schema.TryGetPropertyValue("enum", out JsonNode? enumNode))
        {
            return true;
        }

        foreach (JsonNode? allowedValue in enumNode!.AsArray())
        {
            SpendEvaluationStep();
            if (semanticComparer.Equals(allowedValue, instance))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesStringKeywords(JsonObject schema, JsonNode? instance)
    {
        if (GetValueKind(instance) != JsonValueKind.String)
        {
            return true;
        }

        string value = instance!.GetValue<string>();
        bool hasMinimum = TryGetNonNegativeInteger(schema, "minLength", out long minimum);
        bool hasMaximum = TryGetNonNegativeInteger(schema, "maxLength", out long maximum);
        if (hasMinimum || hasMaximum)
        {
            long scalarCount = CountUnicodeScalars(value);
            if ((hasMinimum && scalarCount < minimum)
                || (hasMaximum && scalarCount > maximum))
            {
                return false;
            }
        }

        if (!schema.TryGetPropertyValue("pattern", out JsonNode? patternNode))
        {
            return true;
        }

        string pattern = RequireString(patternNode, "pattern");
        try
        {
            return regularExpressions[pattern].IsMatch(value);
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw new JsonSchemaEvaluationException(
                "A schema regular expression exceeded its configured timeout.",
                exception);
        }
    }

    private bool MatchesNumberKeywords(JsonObject schema, JsonNode? instance)
    {
        if (GetValueKind(instance) != JsonValueKind.Number)
        {
            return true;
        }

        bool hasMinimum = schema.TryGetPropertyValue("minimum", out JsonNode? minimumNode);
        bool hasMaximum = schema.TryGetPropertyValue("maximum", out JsonNode? maximumNode);
        if (!hasMinimum && !hasMaximum)
        {
            return true;
        }

        NormalizedJsonNumber value = ParseNumber(instance!);
        return (!hasMinimum || value.CompareTo(ParseNumber(minimumNode!)) >= 0)
            && (!hasMaximum || value.CompareTo(ParseNumber(maximumNode!)) <= 0);
    }

    private bool MatchesObjectKeywords(
        JsonObject schema,
        JsonNode? instance,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        if (instance is not JsonObject instanceObject)
        {
            return true;
        }

        if ((TryGetNonNegativeInteger(schema, "minProperties", out long minimum)
                && instanceObject.Count < minimum)
            || (TryGetNonNegativeInteger(schema, "maxProperties", out long maximum)
                && instanceObject.Count > maximum))
        {
            return false;
        }

        if (schema.TryGetPropertyValue("required", out JsonNode? requiredNode))
        {
            foreach (JsonNode? requiredProperty in requiredNode!.AsArray())
            {
                SpendEvaluationStep();
                if (!instanceObject.ContainsKey(RequireString(requiredProperty, "required")))
                {
                    return false;
                }
            }
        }

        JsonObject? propertySchemas = schema["properties"] as JsonObject;
        if (schema.TryGetPropertyValue(
                "propertyNames",
                out JsonNode? propertyNameSchema))
        {
            foreach ((string propertyName, _) in instanceObject)
            {
                SpendEvaluationStep();
                if (!EvaluateSchema(
                    propertyNameSchema!,
                    JsonValue.Create(propertyName)!,
                    checked(depth + 1),
                    semanticComparer))
                {
                    return false;
                }
            }
        }

        if (propertySchemas is not null)
        {
            foreach ((string propertyName, JsonNode? propertySchema) in propertySchemas)
            {
                SpendEvaluationStep();
                if (instanceObject.TryGetPropertyValue(propertyName, out JsonNode? propertyValue)
                    && !EvaluateSchema(
                        propertySchema!,
                        propertyValue,
                        checked(depth + 1),
                        semanticComparer))
                {
                    return false;
                }
            }
        }

        if (schema.TryGetPropertyValue("dependentRequired", out JsonNode? dependenciesNode))
        {
            foreach ((string propertyName, JsonNode? dependencyNode)
                     in dependenciesNode!.AsObject())
            {
                SpendEvaluationStep();
                if (!instanceObject.ContainsKey(propertyName))
                {
                    continue;
                }

                foreach (JsonNode? requiredDependency in dependencyNode!.AsArray())
                {
                    SpendEvaluationStep();
                    if (!instanceObject.ContainsKey(
                        RequireString(requiredDependency, "dependentRequired")))
                    {
                        return false;
                    }
                }
            }
        }

        return MatchesAdditionalProperties(
            schema,
            instanceObject,
            propertySchemas,
            depth,
            semanticComparer);
    }

    private bool MatchesAdditionalProperties(
        JsonObject schema,
        JsonObject instance,
        JsonObject? propertySchemas,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        if (!schema.TryGetPropertyValue(
                "additionalProperties",
                out JsonNode? additionalProperties))
        {
            return true;
        }

        bool? allowed = GetBooleanSchemaValue(additionalProperties);
        foreach ((string propertyName, JsonNode? propertyValue) in instance)
        {
            SpendEvaluationStep();
            if (propertySchemas?.ContainsKey(propertyName) == true)
            {
                continue;
            }

            if (allowed.HasValue)
            {
                if (!allowed.Value)
                {
                    return false;
                }

                continue;
            }

            if (!EvaluateSchema(
                additionalProperties!,
                propertyValue,
                checked(depth + 1),
                semanticComparer))
            {
                return false;
            }
        }

        return true;
    }

    private bool MatchesArrayKeywords(
        JsonObject schema,
        JsonNode? instance,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        if (instance is not JsonArray instanceArray)
        {
            return true;
        }

        if ((TryGetNonNegativeInteger(schema, "minItems", out long minimum)
                && instanceArray.Count < minimum)
            || (TryGetNonNegativeInteger(schema, "maxItems", out long maximum)
                && instanceArray.Count > maximum))
        {
            return false;
        }

        int prefixCount = 0;
        if (schema.TryGetPropertyValue("prefixItems", out JsonNode? prefixItemsNode))
        {
            JsonArray prefixItems = prefixItemsNode!.AsArray();
            prefixCount = prefixItems.Count;
            int appliedPrefixCount = Math.Min(prefixCount, instanceArray.Count);
            for (var index = 0; index < appliedPrefixCount; index++)
            {
                SpendEvaluationStep();
                if (!EvaluateSchema(
                    prefixItems[index]!,
                    instanceArray[index],
                    checked(depth + 1),
                    semanticComparer))
                {
                    return false;
                }
            }
        }

        if (!MatchesRemainingItems(
            schema,
            instanceArray,
            prefixCount,
            depth,
            semanticComparer))
        {
            return false;
        }

        if (schema.TryGetPropertyValue("uniqueItems", out JsonNode? uniqueItemsNode)
            && RequireBoolean(uniqueItemsNode, "uniqueItems")
            && !HasUniqueItems(instanceArray, semanticComparer))
        {
            return false;
        }

        return MatchesContains(schema, instanceArray, depth, semanticComparer);
    }

    private bool MatchesRemainingItems(
        JsonObject schema,
        JsonArray instance,
        int prefixCount,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        if (!schema.TryGetPropertyValue("items", out JsonNode? itemsSchema))
        {
            return true;
        }

        bool? allowed = GetBooleanSchemaValue(itemsSchema);
        if (allowed == false)
        {
            return instance.Count <= prefixCount;
        }

        if (allowed == true)
        {
            return true;
        }

        for (var index = prefixCount; index < instance.Count; index++)
        {
            SpendEvaluationStep();
            if (!EvaluateSchema(
                itemsSchema!,
                instance[index],
                checked(depth + 1),
                semanticComparer))
            {
                return false;
            }
        }

        return true;
    }

    private bool MatchesContains(
        JsonObject schema,
        JsonArray instance,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        if (!schema.TryGetPropertyValue("contains", out JsonNode? containsSchema))
        {
            return true;
        }

        long minimumMatches = TryGetNonNegativeInteger(
            schema,
            "minContains",
            out long configuredMinimum)
            ? configuredMinimum
            : 1;
        if (minimumMatches == 0)
        {
            return true;
        }

        long matches = 0;
        foreach (JsonNode? item in instance)
        {
            SpendEvaluationStep();
            if (EvaluateSchema(
                containsSchema!,
                item,
                checked(depth + 1),
                semanticComparer))
            {
                matches++;
                if (matches >= minimumMatches)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool MatchesCombinators(
        JsonObject schema,
        JsonNode? instance,
        int depth,
        JsonSemanticComparer semanticComparer)
    {
        if (schema.TryGetPropertyValue("allOf", out JsonNode? allOfNode))
        {
            foreach (JsonNode? branch in allOfNode!.AsArray())
            {
                SpendEvaluationStep();
                if (!EvaluateSchema(
                    branch!,
                    instance,
                    checked(depth + 1),
                    semanticComparer))
                {
                    return false;
                }
            }
        }

        if (schema.TryGetPropertyValue("anyOf", out JsonNode? anyOfNode))
        {
            bool matched = false;
            foreach (JsonNode? branch in anyOfNode!.AsArray())
            {
                SpendEvaluationStep();
                if (EvaluateSchema(
                    branch!,
                    instance,
                    checked(depth + 1),
                    semanticComparer))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return false;
            }
        }

        if (schema.TryGetPropertyValue("oneOf", out JsonNode? oneOfNode))
        {
            var matches = 0;
            foreach (JsonNode? branch in oneOfNode!.AsArray())
            {
                SpendEvaluationStep();
                if (EvaluateSchema(
                    branch!,
                    instance,
                    checked(depth + 1),
                    semanticComparer)
                    && ++matches > 1)
                {
                    return false;
                }
            }

            if (matches != 1)
            {
                return false;
            }
        }

        if (schema.TryGetPropertyValue("not", out JsonNode? notNode)
            && EvaluateSchema(
                notNode!,
                instance,
                checked(depth + 1),
                semanticComparer))
        {
            return false;
        }

        if (!schema.TryGetPropertyValue("if", out JsonNode? ifNode))
        {
            return true;
        }

        string selectedKeyword = EvaluateSchema(
            ifNode!,
            instance,
            checked(depth + 1),
            semanticComparer)
            ? "then"
            : "else";
        return !schema.TryGetPropertyValue(selectedKeyword, out JsonNode? selectedSchema)
            || EvaluateSchema(
                selectedSchema!,
                instance,
                checked(depth + 1),
                semanticComparer);
    }

    // Time: expected O(N), Space: O(N), where N is the number of array items.
    private bool HasUniqueItems(JsonArray array, JsonSemanticComparer semanticComparer)
    {
        var seen = new HashSet<JsonNode?>(semanticComparer);
        foreach (JsonNode? item in array)
        {
            SpendEvaluationStep();
            if (!seen.Add(item))
            {
                return false;
            }
        }

        return true;
    }

    private void ValidateDialectAndIdentifier(JsonObject schema, bool isDocumentRoot)
    {
        if (schema.TryGetPropertyValue("$schema", out JsonNode? dialectNode))
        {
            if (!isDocumentRoot
                || !string.Equals(
                    RequireString(dialectNode, "$schema"),
                    Draft202012Dialect,
                    StringComparison.Ordinal))
            {
                throw new JsonSchemaDefinitionException(
                    "Only a root Draft 2020-12 '$schema' declaration is supported.");
            }
        }

        if (schema.TryGetPropertyValue("$id", out JsonNode? identifierNode))
        {
            _ = RequireString(identifierNode, "$id");
            if (!isDocumentRoot)
            {
                throw new JsonSchemaDefinitionException(
                    "Nested '$id' scopes are not supported by the local-only validator.");
            }
        }
    }

    private void ValidateTypeKeyword(JsonObject schema)
    {
        if (!schema.TryGetPropertyValue("type", out JsonNode? typeNode))
        {
            return;
        }

        if (typeNode is not JsonArray typeArray)
        {
            ValidateTypeName(RequireString(typeNode, "type"));
            return;
        }

        if (typeArray.Count == 0)
        {
            throw new JsonSchemaDefinitionException("Schema 'type' arrays cannot be empty.");
        }

        var distinctTypes = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonNode? typeNameNode in typeArray)
        {
            string typeName = RequireString(typeNameNode, "type");
            ValidateTypeName(typeName);
            if (!distinctTypes.Add(typeName))
            {
                throw new JsonSchemaDefinitionException(
                    "Schema 'type' arrays cannot repeat a type name.");
            }
        }
    }

    private static void ValidateTypeName(string typeName)
    {
        if (typeName is not (
            "null" or "boolean" or "object" or "array" or "number" or "integer" or "string"))
        {
            throw new JsonSchemaDefinitionException(
                $"Schema type '{typeName}' is not supported.");
        }
    }

    private void ValidateSchemaMap(JsonObject schema, string keyword, int depth)
    {
        if (!schema.TryGetPropertyValue(keyword, out JsonNode? mapNode))
        {
            return;
        }

        if (mapNode is not JsonObject schemaMap)
        {
            throw new JsonSchemaDefinitionException(
                $"Schema keyword '{keyword}' must be an object.");
        }

        foreach ((_, JsonNode? nestedSchema) in schemaMap)
        {
            ValidateSchemaNode(nestedSchema, checked(depth + 1));
        }
    }

    private void ValidateSchemaKeyword(JsonObject schema, string keyword, int depth)
    {
        if (schema.TryGetPropertyValue(keyword, out JsonNode? nestedSchema))
        {
            ValidateSchemaNode(nestedSchema, checked(depth + 1));
        }
    }

    private void ValidateSchemaArray(JsonObject schema, string keyword, int depth)
    {
        if (!schema.TryGetPropertyValue(keyword, out JsonNode? arrayNode))
        {
            return;
        }

        if (arrayNode is not JsonArray schemaArray || schemaArray.Count == 0)
        {
            throw new JsonSchemaDefinitionException(
                $"Schema keyword '{keyword}' must be a non-empty array.");
        }

        foreach (JsonNode? nestedSchema in schemaArray)
        {
            ValidateSchemaNode(nestedSchema, checked(depth + 1));
        }
    }

    private void ValidateRequired(JsonObject schema)
    {
        if (!schema.TryGetPropertyValue("required", out JsonNode? requiredNode))
        {
            return;
        }

        if (requiredNode is not JsonArray requiredArray)
        {
            throw new JsonSchemaDefinitionException(
                "Schema keyword 'required' must be an array.");
        }

        var distinctNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonNode? propertyNameNode in requiredArray)
        {
            string propertyName = RequireString(propertyNameNode, "required");
            if (!distinctNames.Add(propertyName))
            {
                throw new JsonSchemaDefinitionException(
                    "Schema keyword 'required' cannot repeat a property name.");
            }
        }
    }

    private void ValidateDependentRequired(JsonObject schema)
    {
        if (!schema.TryGetPropertyValue(
            "dependentRequired",
            out JsonNode? dependentRequiredNode))
        {
            return;
        }

        if (dependentRequiredNode is not JsonObject dependencies)
        {
            throw new JsonSchemaDefinitionException(
                "Schema keyword 'dependentRequired' must be an object.");
        }

        foreach ((_, JsonNode? dependencyNode) in dependencies)
        {
            if (dependencyNode is not JsonArray dependencyArray)
            {
                throw new JsonSchemaDefinitionException(
                    "Each 'dependentRequired' value must be an array.");
            }

            var distinctNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonNode? propertyNameNode in dependencyArray)
            {
                string propertyName = RequireString(propertyNameNode, "dependentRequired");
                if (!distinctNames.Add(propertyName))
                {
                    throw new JsonSchemaDefinitionException(
                        "A 'dependentRequired' array cannot repeat a property name.");
                }
            }
        }
    }

    private void ValidateEnum(JsonObject schema)
    {
        if (!schema.TryGetPropertyValue("enum", out JsonNode? enumNode))
        {
            return;
        }

        if (enumNode is not JsonArray enumArray || enumArray.Count == 0)
        {
            throw new JsonSchemaDefinitionException(
                "Schema keyword 'enum' must be a non-empty array.");
        }

        var comparer = new JsonSemanticComparer(this);
        var values = new HashSet<JsonNode?>(comparer);
        foreach (JsonNode? value in enumArray)
        {
            if (!values.Add(value))
            {
                throw new JsonSchemaDefinitionException(
                    "Schema keyword 'enum' cannot contain duplicate values.");
            }
        }
    }

    private void ValidatePattern(JsonObject schema)
    {
        if (!schema.TryGetPropertyValue("pattern", out JsonNode? patternNode))
        {
            return;
        }

        string pattern = RequireString(patternNode, "pattern");
        if (regularExpressions.ContainsKey(pattern))
        {
            return;
        }

        try
        {
            regularExpressions.Add(pattern, CreateRegularExpression(pattern));
        }
        catch (ArgumentException exception)
        {
            throw new JsonSchemaDefinitionException(
                "Schema keyword 'pattern' is not a valid regular expression.",
                exception);
        }
    }

    private Regex CreateRegularExpression(string pattern)
    {
        const RegexOptions sharedOptions = RegexOptions.CultureInvariant;
        string translatedPattern = Ecma262RegexTranslator.Translate(pattern);
        try
        {
            return new Regex(
                translatedPattern,
                sharedOptions | RegexOptions.NonBacktracking,
                limits.SchemaRegexTimeout);
        }
        catch (NotSupportedException)
        {
            return new Regex(
                translatedPattern,
                sharedOptions,
                limits.SchemaRegexTimeout);
        }
    }

    private void ValidateNonNegativeIntegerKeyword(JsonObject schema, string keyword)
    {
        if (schema.TryGetPropertyValue(keyword, out JsonNode? value)
            && !ParseNumber(value!).TryGetNonNegativeInt64(out _))
        {
            throw new JsonSchemaDefinitionException(
                $"Schema keyword '{keyword}' must be a non-negative 64-bit integer.");
        }
    }

    private void ValidateNumericKeyword(JsonObject schema, string keyword)
    {
        if (schema.TryGetPropertyValue(keyword, out JsonNode? value))
        {
            _ = ParseNumber(value!);
        }
    }

    private static void ValidateBooleanKeyword(JsonObject schema, string keyword)
    {
        if (schema.TryGetPropertyValue(keyword, out JsonNode? value))
        {
            _ = RequireBoolean(value, keyword);
        }
    }

    private static void ValidateStringKeyword(JsonObject schema, string keyword)
    {
        if (schema.TryGetPropertyValue(keyword, out JsonNode? value))
        {
            _ = RequireString(value, keyword);
        }
    }

    private bool TryGetNonNegativeInteger(
        JsonObject schema,
        string keyword,
        out long value)
    {
        if (!schema.TryGetPropertyValue(keyword, out JsonNode? valueNode))
        {
            value = default;
            return false;
        }

        if (!ParseNumber(valueNode!).TryGetNonNegativeInt64(out value))
        {
            throw new JsonSchemaDefinitionException(
                $"Schema keyword '{keyword}' must be a non-negative 64-bit integer.");
        }

        return true;
    }

    private long CountUnicodeScalars(string value)
    {
        long count = 0;
        foreach (Rune _ in value.EnumerateRunes())
        {
            SpendEvaluationStep();
            count++;
        }

        return count;
    }

    private JsonNode ResolveLocalReference(string reference)
    {
        if (resolvedReferences.TryGetValue(reference, out JsonNode? cachedTarget))
        {
            return cachedTarget;
        }

        if (!reference.StartsWith('#'))
        {
            throw new JsonSchemaDefinitionException(
                "Only document-local '$ref' values are supported.");
        }

        ValidatePercentEncoding(reference);
        string pointer;
        try
        {
            pointer = Uri.UnescapeDataString(reference[1..]);
        }
        catch (UriFormatException exception)
        {
            throw new JsonSchemaDefinitionException(
                "A schema '$ref' contains invalid URI escaping.",
                exception);
        }

        JsonNode? target = schemaRoot;
        if (pointer.Length > 0)
        {
            if (pointer[0] != '/')
            {
                throw new JsonSchemaDefinitionException(
                    "Only JSON Pointer fragments are supported in '$ref'.");
            }

            foreach (string encodedSegment in pointer[1..].Split('/'))
            {
                SpendEvaluationStep();
                string segment = DecodeJsonPointerSegment(encodedSegment);
                target = target switch
                {
                    JsonObject targetObject when targetObject.TryGetPropertyValue(
                        segment,
                        out JsonNode? propertyValue) => propertyValue,
                    JsonArray targetArray when TryParseArrayIndex(
                        segment,
                        targetArray.Count,
                        out int index) => targetArray[index],
                    _ => throw new JsonSchemaDefinitionException(
                        $"Schema reference '{reference}' does not resolve."),
                };
            }
        }

        if (target is null)
        {
            throw new JsonSchemaDefinitionException(
                $"Schema reference '{reference}' resolves to JSON null.");
        }

        resolvedReferences.Add(reference, target);
        return target;
    }

    private static void ValidatePercentEncoding(string reference)
    {
        for (var index = 0; index < reference.Length; index++)
        {
            if (reference[index] != '%')
            {
                continue;
            }

            if (index + 2 >= reference.Length
                || !Uri.IsHexDigit(reference[index + 1])
                || !Uri.IsHexDigit(reference[index + 2]))
            {
                throw new JsonSchemaDefinitionException(
                    "A schema '$ref' contains invalid percent encoding.");
            }

            index += 2;
        }
    }

    private static string DecodeJsonPointerSegment(string encodedSegment)
    {
        var decoded = new StringBuilder(encodedSegment.Length);
        for (var index = 0; index < encodedSegment.Length; index++)
        {
            char current = encodedSegment[index];
            if (current != '~')
            {
                decoded.Append(current);
                continue;
            }

            if (++index >= encodedSegment.Length)
            {
                throw new JsonSchemaDefinitionException(
                    "A schema '$ref' contains an invalid JSON Pointer escape.");
            }

            decoded.Append(encodedSegment[index] switch
            {
                '0' => '~',
                '1' => '/',
                _ => throw new JsonSchemaDefinitionException(
                    "A schema '$ref' contains an invalid JSON Pointer escape."),
            });
        }

        return decoded.ToString();
    }

    private static bool TryParseArrayIndex(string segment, int count, out int index)
    {
        index = default;
        bool canonical = segment.Length > 0
            && (segment.Length == 1 || segment[0] != '0');
        return canonical
            && int.TryParse(
                segment,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out index)
            && index >= 0
            && index < count;
    }

    private NormalizedJsonNumber ParseNumber(JsonNode numberNode) =>
        NormalizedJsonNumber.Parse(numberNode, limits.MaximumSchemaNumberCharacters);

    private void SpendEvaluationStep()
    {
        if (remainingEvaluationSteps-- <= 0)
        {
            throw new JsonSchemaEvaluationException(
                "The schema evaluation work budget was exhausted.");
        }
    }

    private void RequireAllowedDepth(int depth)
    {
        if (depth > limits.MaximumSchemaEvaluationDepth)
        {
            throw new JsonSchemaEvaluationException(
                "The schema evaluation depth limit was exceeded.");
        }
    }

    private static JsonValueKind GetValueKind(JsonNode? node) =>
        node?.GetValueKind() ?? JsonValueKind.Null;

    private static bool? GetBooleanSchemaValue(JsonNode? schema) =>
        GetValueKind(schema) switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null,
        };

    private static string RequireString(JsonNode? value, string keyword)
    {
        if (GetValueKind(value) != JsonValueKind.String)
        {
            throw new JsonSchemaDefinitionException(
                $"Schema keyword '{keyword}' must contain a string.");
        }

        return value!.GetValue<string>();
    }

    private static bool RequireBoolean(JsonNode? value, string keyword)
    {
        JsonValueKind kind = GetValueKind(value);
        return kind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new JsonSchemaDefinitionException(
                $"Schema keyword '{keyword}' must contain a Boolean value."),
        };
    }

    private static bool IsSupportedKeyword(string keyword) => keyword is
        "$schema"
        or "$id"
        or "$defs"
        or "$ref"
        or "title"
        or "description"
        or "default"
        or "type"
        or "const"
        or "enum"
        or "properties"
        or "propertyNames"
        or "required"
        or "additionalProperties"
        or "dependentRequired"
        or "minProperties"
        or "maxProperties"
        or "items"
        or "prefixItems"
        or "minItems"
        or "maxItems"
        or "uniqueItems"
        or "contains"
        or "minContains"
        or "minLength"
        or "maxLength"
        or "pattern"
        or "minimum"
        or "maximum"
        or "allOf"
        or "anyOf"
        or "oneOf"
        or "not"
        or "if"
        or "then"
        or "else";

    private readonly record struct NormalizedJsonNumber(
        int Sign,
        string SignificantDigits,
        long DecimalExponent) : IComparable<NormalizedJsonNumber>
    {
        /// <summary>Gets whether the finite decimal value is mathematically integral.</summary>
        public bool IsInteger => Sign == 0 || DecimalExponent >= 0;

        // Time: O(L), Space: O(L), where L is the bounded JSON number token length.
        public static NormalizedJsonNumber Parse(JsonNode node, int maximumCharacters)
        {
            if (node.GetValueKind() != JsonValueKind.Number)
            {
                throw new JsonSchemaDefinitionException(
                    "A numeric schema keyword must contain a JSON number.");
            }

            string text = node.ToJsonString();
            if (text.Length > maximumCharacters)
            {
                throw new JsonSchemaEvaluationException(
                    "A JSON number exceeds the configured schema number limit.");
            }

            var index = 0;
            int sign = 1;
            if (text[index] == '-')
            {
                sign = -1;
                index++;
            }

            int integerStart = index;
            while (index < text.Length && char.IsAsciiDigit(text[index]))
            {
                index++;
            }

            int integerLength = index - integerStart;
            int fractionStart = index;
            var fractionLength = 0;
            if (index < text.Length && text[index] == '.')
            {
                fractionStart = ++index;
                while (index < text.Length && char.IsAsciiDigit(text[index]))
                {
                    index++;
                }

                fractionLength = index - fractionStart;
            }

            long explicitExponent = 0;
            if (index < text.Length && text[index] is 'e' or 'E')
            {
                ReadOnlySpan<char> exponentSpan = text.AsSpan(index + 1);
                if (!long.TryParse(
                    exponentSpan,
                    NumberStyles.AllowLeadingSign,
                    CultureInfo.InvariantCulture,
                    out explicitExponent))
                {
                    throw new JsonSchemaEvaluationException(
                        "A JSON number exponent exceeds the bounded numeric representation.");
                }

                index = text.Length;
            }

            if (integerLength == 0 || index != text.Length)
            {
                throw new JsonSchemaEvaluationException(
                    "A JSON numeric value is not represented canonically.");
            }

            string combinedDigits = string.Concat(
                text.AsSpan(integerStart, integerLength),
                text.AsSpan(fractionStart, fractionLength));
            int firstSignificantDigit = 0;
            while (firstSignificantDigit < combinedDigits.Length
                && combinedDigits[firstSignificantDigit] == '0')
            {
                firstSignificantDigit++;
            }

            if (firstSignificantDigit == combinedDigits.Length)
            {
                return new NormalizedJsonNumber(0, "0", 0);
            }

            int lastSignificantDigit = combinedDigits.Length - 1;
            while (combinedDigits[lastSignificantDigit] == '0')
            {
                lastSignificantDigit--;
            }

            int removedTrailingZeros = combinedDigits.Length - lastSignificantDigit - 1;
            long decimalExponent;
            try
            {
                decimalExponent = checked(
                    explicitExponent - fractionLength + removedTrailingZeros);
            }
            catch (OverflowException exception)
            {
                throw new JsonSchemaEvaluationException(
                    "A JSON number exponent exceeds the bounded numeric representation.",
                    exception);
            }

            return new NormalizedJsonNumber(
                sign,
                combinedDigits[firstSignificantDigit..(lastSignificantDigit + 1)],
                decimalExponent);
        }

        public bool TryGetNonNegativeInt64(out long value)
        {
            value = default;
            if (Sign < 0 || !IsInteger)
            {
                return false;
            }

            if (Sign == 0)
            {
                return true;
            }

            if (!long.TryParse(
                SignificantDigits,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out value))
            {
                return false;
            }

            if (DecimalExponent > 18
                || SignificantDigits.Length + DecimalExponent > 19)
            {
                value = default;
                return false;
            }

            try
            {
                for (long index = 0; index < DecimalExponent; index++)
                {
                    value = checked(value * 10);
                }

                return true;
            }
            catch (OverflowException)
            {
                value = default;
                return false;
            }
        }

        // Time: O(L), Space: O(1), where L is the longer significant-digit sequence.
        public int CompareTo(NormalizedJsonNumber other)
        {
            if (Sign != other.Sign)
            {
                return Sign.CompareTo(other.Sign);
            }

            if (Sign == 0)
            {
                return 0;
            }

            int magnitudeComparison = CompareMagnitude(this, other);
            return Sign > 0 ? magnitudeComparison : -magnitudeComparison;
        }

        private static int CompareMagnitude(
            NormalizedJsonNumber left,
            NormalizedJsonNumber right)
        {
            long leftMagnitudeLength;
            long rightMagnitudeLength;
            try
            {
                leftMagnitudeLength = checked(
                    left.SignificantDigits.Length + left.DecimalExponent);
                rightMagnitudeLength = checked(
                    right.SignificantDigits.Length + right.DecimalExponent);
            }
            catch (OverflowException exception)
            {
                throw new JsonSchemaEvaluationException(
                    "A JSON number exponent exceeds the bounded numeric representation.",
                    exception);
            }

            int lengthComparison = leftMagnitudeLength.CompareTo(rightMagnitudeLength);
            if (lengthComparison != 0)
            {
                return lengthComparison;
            }

            int comparisonLength = Math.Max(
                left.SignificantDigits.Length,
                right.SignificantDigits.Length);
            for (var index = 0; index < comparisonLength; index++)
            {
                char leftDigit = index < left.SignificantDigits.Length
                    ? left.SignificantDigits[index]
                    : '0';
                char rightDigit = index < right.SignificantDigits.Length
                    ? right.SignificantDigits[index]
                    : '0';
                int digitComparison = leftDigit.CompareTo(rightDigit);
                if (digitComparison != 0)
                {
                    return digitComparison;
                }
            }

            return 0;
        }
    }

    private sealed class JsonSemanticComparer : IEqualityComparer<JsonNode?>
    {
        private const int HashSeed = unchecked((int)2166136261);
        private const int HashMultiplier = 16777619;
        private readonly BoundedJsonSchemaEvaluator evaluator;

        public JsonSemanticComparer(BoundedJsonSchemaEvaluator evaluator)
        {
            this.evaluator = evaluator;
        }

        // Time: O(V), Space: O(D), where V is compared JSON content and D is nesting depth.
        public bool Equals(JsonNode? left, JsonNode? right)
        {
            evaluator.SpendEvaluationStep();
            if (ReferenceEquals(left, right))
            {
                return true;
            }

            JsonValueKind leftKind = GetValueKind(left);
            JsonValueKind rightKind = GetValueKind(right);
            if (leftKind != rightKind)
            {
                return false;
            }

            return leftKind switch
            {
                JsonValueKind.Null => true,
                JsonValueKind.String => string.Equals(
                    left!.GetValue<string>(),
                    right!.GetValue<string>(),
                    StringComparison.Ordinal),
                JsonValueKind.Number => evaluator.ParseNumber(left!).CompareTo(
                    evaluator.ParseNumber(right!)) == 0,
                JsonValueKind.True or JsonValueKind.False =>
                    leftKind == rightKind,
                JsonValueKind.Array => ArraysEqual(left!.AsArray(), right!.AsArray()),
                JsonValueKind.Object => ObjectsEqual(left!.AsObject(), right!.AsObject()),
                _ => throw new JsonSchemaEvaluationException(
                    "A JSON value kind cannot be compared by the schema evaluator."),
            };
        }

        // Time: O(V), Space: O(D), where V is hashed JSON content and D is nesting depth.
        public int GetHashCode(JsonNode? value)
        {
            evaluator.SpendEvaluationStep();
            JsonValueKind kind = GetValueKind(value);
            int hash = Combine(HashSeed, (int)kind);
            return kind switch
            {
                JsonValueKind.Null => hash,
                JsonValueKind.String => Combine(hash, StableStringHash(value!.GetValue<string>())),
                JsonValueKind.Number => HashNumber(hash, evaluator.ParseNumber(value!)),
                JsonValueKind.True or JsonValueKind.False => hash,
                JsonValueKind.Array => HashArray(hash, value!.AsArray()),
                JsonValueKind.Object => HashObject(hash, value!.AsObject()),
                _ => throw new JsonSchemaEvaluationException(
                    "A JSON value kind cannot be hashed by the schema evaluator."),
            };
        }

        private bool ArraysEqual(JsonArray left, JsonArray right)
        {
            if (left.Count != right.Count)
            {
                return false;
            }

            for (var index = 0; index < left.Count; index++)
            {
                if (!Equals(left[index], right[index]))
                {
                    return false;
                }
            }

            return true;
        }

        private bool ObjectsEqual(JsonObject left, JsonObject right)
        {
            if (left.Count != right.Count)
            {
                return false;
            }

            foreach ((string propertyName, JsonNode? leftValue) in left)
            {
                evaluator.SpendEvaluationStep();
                if (!right.TryGetPropertyValue(propertyName, out JsonNode? rightValue)
                    || !Equals(leftValue, rightValue))
                {
                    return false;
                }
            }

            return true;
        }

        private int HashArray(int hash, JsonArray array)
        {
            int result = Combine(hash, array.Count);
            foreach (JsonNode? item in array)
            {
                result = Combine(result, GetHashCode(item));
            }

            return result;
        }

        private int HashObject(int hash, JsonObject value)
        {
            var unorderedPropertiesHash = 0;
            foreach ((string propertyName, JsonNode? propertyValue) in value)
            {
                evaluator.SpendEvaluationStep();
                int propertyHash = Combine(
                    StableStringHash(propertyName),
                    GetHashCode(propertyValue));
                unorderedPropertiesHash ^= propertyHash;
            }

            return Combine(Combine(hash, value.Count), unorderedPropertiesHash);
        }

        private static int HashNumber(int hash, NormalizedJsonNumber value) => Combine(
            Combine(
                Combine(hash, value.Sign),
                StableStringHash(value.SignificantDigits)),
            value.DecimalExponent.GetHashCode());

        private static int StableStringHash(string value)
        {
            int hash = HashSeed;
            foreach (char character in value)
            {
                hash = Combine(hash, character);
            }

            return hash;
        }

        private static int Combine(int hash, int value) =>
            unchecked((hash ^ value) * HashMultiplier);
    }
}

/// <summary>Identifies an unsupported or malformed repository schema.</summary>
internal sealed class JsonSchemaDefinitionException : Exception
{
    public JsonSchemaDefinitionException(string message)
        : base(message)
    {
    }

    public JsonSchemaDefinitionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Identifies a bounded schema evaluation that cannot safely complete.</summary>
internal sealed class JsonSchemaEvaluationException : Exception
{
    public JsonSchemaEvaluationException(string message)
        : base(message)
    {
    }

    public JsonSchemaEvaluationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
