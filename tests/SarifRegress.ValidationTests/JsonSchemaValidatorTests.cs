using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class JsonSchemaValidatorTests
{
    [Fact]
    public void Every_repository_schema_uses_the_supported_bounded_vocabulary()
    {
        string repositoryRoot = ValidationTestRepository.FindRoot();
        string[] schemaPaths = Directory
            .EnumerateFiles(repositoryRoot, "*.schema.json", SearchOption.AllDirectories)
            .Where(path => !ContainsGeneratedDirectory(path))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.NotEmpty(schemaPaths);
        foreach (string schemaPath in schemaPaths)
        {
            JsonNode schema = BoundedJsonFile.ReadNode(
                schemaPath,
                ValidationLimits.Default.MaximumSchemaBytes,
                ValidationLimits.Default.MaximumJsonDepth,
                ValidationLimits.Default.MaximumStringCharacters);

            _ = new BoundedJsonSchemaEvaluator(schema, ValidationLimits.Default);
        }
    }

    [Fact]
    public void Validator_supports_local_references_conditionals_and_tuple_arrays()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "$defs": {
                "identifier": {
                  "type": "string",
                  "minLength": 2,
                  "pattern": "^[a-z]+$"
                }
              },
              "type": "object",
              "additionalProperties": false,
              "required": ["kind", "id", "tuple", "values"],
              "dependentRequired": {
                "detail": ["kind"]
              },
              "properties": {
                "kind": { "enum": ["standard", "special"] },
                "id": { "$ref": "#/$defs/identifier" },
                "detail": { "type": "string", "minLength": 1 },
                "tuple": {
                  "type": "array",
                  "prefixItems": [
                    { "const": "left" },
                    { "type": "integer", "minimum": 1, "maximum": 3 }
                  ],
                  "items": false
                },
                "values": {
                  "type": "array",
                  "contains": { "const": 1 },
                  "minContains": 2
                }
              },
              "allOf": [
                {
                  "if": {
                    "properties": { "kind": { "const": "special" } },
                    "required": ["kind"]
                  },
                  "then": { "required": ["detail"] },
                  "else": { "not": { "required": ["detail"] } }
                }
              ]
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            JsonNode validInstance = JsonNode.Parse(
                """
                {
                  "kind": "special",
                  "id": "alpha",
                  "detail": "bound evidence",
                  "tuple": ["left", 2],
                  "values": [1, 0, 1.0]
                }
                """)!;

            JsonNode actual = new JsonSchemaValidator().ValidateNode(
                schemaPath,
                validInstance,
                "instance.json",
                temporaryRoot);

            Assert.Same(validInstance, actual);
            string[] invalidInstances =
            [
                """
                {
                  "kind": "special",
                  "id": "alpha",
                  "tuple": ["left", 2],
                  "values": [1, 1]
                }
                """,
                """
                {
                  "kind": "standard",
                  "id": "alpha",
                  "detail": "not permitted",
                  "tuple": ["left", 2],
                  "values": [1, 1]
                }
                """,
                """
                {
                  "kind": "standard",
                  "id": "alpha",
                  "tuple": ["left", 2, "extra"],
                  "values": [1, 1]
                }
                """,
                """
                {
                  "kind": "standard",
                  "id": "alpha",
                  "tuple": ["left", 2],
                  "values": [0, 1]
                }
                """,
                """
                {
                  "kind": "standard",
                  "id": "alpha",
                  "tuple": ["left", 2],
                  "values": [1, 1],
                  "unexpected": true
                }
                """,
            ];
            foreach (string invalidInstanceJson in invalidInstances)
            {
                JsonNode invalidInstance = JsonNode.Parse(invalidInstanceJson)!;
                _ = Assert.Throws<InvalidDataException>(() =>
                    new JsonSchemaValidator().ValidateNode(
                        schemaPath,
                        invalidInstance,
                        "invalid-instance.json",
                        temporaryRoot));
            }
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Property_names_apply_a_schema_to_every_object_member_name()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "object",
              "propertyNames": {
                "type": "string",
                "pattern": "^[a-z]+$"
              }
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            var validator = new JsonSchemaValidator();

            _ = validator.ValidateNode(
                schemaPath,
                JsonNode.Parse("{\"alpha\":1,\"beta\":2}")!,
                "valid-property-names.json",
                temporaryRoot);
            _ = Assert.Throws<InvalidDataException>(() =>
                validator.ValidateNode(
                    schemaPath,
                    JsonNode.Parse("{\"Alpha\":1}")!,
                    "invalid-property-name.json",
                    temporaryRoot));
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Theory]
    [InlineData("src/Worker.java", true)]
    [InlineData("src/nested/worker.cs", true)]
    [InlineData("../outside.cs", false)]
    [InlineData("src/../outside.cs", false)]
    [InlineData("src//worker.cs", false)]
    [InlineData("src/", false)]
    [InlineData(".", false)]
    [InlineData("src/./worker.cs", false)]
    [InlineData("/absolute.cs", false)]
    [InlineData("src\\worker.cs", false)]
    [InlineData("C:/worker.cs", false)]
    [InlineData("src/café.cs", false)]
    [InlineData("src/control\u001f.cs", false)]
    public void Snapshot_manifest_schema_matches_runtime_path_admission(
        string repositoryPath,
        bool expectedValid)
    {
        string repositoryRoot = ValidationTestRepository.FindRoot();
        string schemaPath = Path.Combine(
            repositoryRoot,
            "schemas",
            "repository-snapshot-manifest.schema.json");
        var instance = new JsonObject
        {
            ["schemaVersion"] = "1",
            ["files"] = new JsonObject
            {
                [repositoryPath] = new string('a', 64),
            },
        };

        Action validate = () => new JsonSchemaValidator().ValidateNode(
            schemaPath,
            instance,
            "snapshot.json",
            repositoryRoot);

        if (expectedValid)
        {
            validate();
        }
        else
        {
            _ = Assert.Throws<InvalidDataException>(validate);
        }
    }

    [Fact]
    public void Unique_items_uses_json_semantic_equality()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "array",
              "uniqueItems": true
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            JsonNode duplicateInstance = JsonNode.Parse(
                """
                [
                  { "left": 1, "right": 2 },
                  { "right": 2.0, "left": 1.0 }
                ]
                """)!;

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new JsonSchemaValidator().ValidateNode(
                    schemaPath,
                    duplicateInstance,
                    "duplicates.json",
                    temporaryRoot));

            Assert.Contains("does not satisfy", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Theory]
    [InlineData("{ \"$ref\": \"https://example.invalid/schema.json\" }")]
    [InlineData("{ \"unevaluatedProperties\": false }")]
    public void Validator_rejects_schema_semantics_it_cannot_enforce(string schemaJson)
    {
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new JsonSchemaValidator().ValidateNode(
                    schemaPath,
                    new JsonObject(),
                    "instance.json",
                    temporaryRoot));

            Assert.Contains("is invalid", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Validator_fails_closed_when_the_evaluation_work_budget_is_exhausted()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "array",
              "items": { "type": "integer" }
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            var instance = new JsonArray(
                Enumerable.Range(0, 100)
                    .Select(static value => JsonValue.Create(value))
                    .ToArray());
            ValidationLimits constrainedLimits = ValidationLimits.Default with
            {
                MaximumSchemaEvaluationSteps = 64,
            };

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new JsonSchemaValidator(constrainedLimits).ValidateNode(
                    schemaPath,
                    instance,
                    "large-array.json",
                    temporaryRoot));

            Assert.Contains(
                "configured schema evaluation limits",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Validator_fails_closed_when_the_schema_regex_timeout_is_exhausted()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "string",
              "pattern": "^(?=(a+)+$)"
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            ValidationLimits constrainedLimits = ValidationLimits.Default with
            {
                SchemaRegexTimeout = TimeSpan.FromTicks(1),
            };
            JsonNode instance = JsonValue.Create(
                new string('a', constrainedLimits.MaximumStringCharacters - 1) + "!")!;

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new JsonSchemaValidator(constrainedLimits).ValidateNode(
                    schemaPath,
                    instance,
                    "regex-timeout.json",
                    temporaryRoot));

            Assert.Contains(
                "configured schema evaluation limits",
                exception.Message,
                StringComparison.Ordinal);
            JsonSchemaEvaluationException evaluationException =
                Assert.IsType<JsonSchemaEvaluationException>(exception.InnerException);
            Assert.IsType<RegexMatchTimeoutException>(evaluationException.InnerException);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Sha256_pattern_rejects_a_trailing_line_feed()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "string",
              "pattern": "^[0-9a-f]{64}$"
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            string sha256 = new('a', 64);
            var validator = new JsonSchemaValidator();

            _ = validator.ValidateNode(
                schemaPath,
                JsonValue.Create(sha256)!,
                "sha256.json",
                temporaryRoot);
            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                validator.ValidateNode(
                    schemaPath,
                    JsonValue.Create(sha256 + "\n")!,
                    "sha256-with-newline.json",
                    temporaryRoot));

            Assert.Contains("does not satisfy", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void Regex_translator_rewrites_only_unescaped_end_anchors()
    {
        Assert.Equal(
            @"^[0-9a-f]{64}\z",
            Ecma262RegexTranslator.Translate(@"^[0-9a-f]{64}$"));
        Assert.Equal(
            @"^value\$\z",
            Ecma262RegexTranslator.Translate(@"^value\$$"));
        Assert.Equal(
            @"^[$]\z",
            Ecma262RegexTranslator.Translate(@"^[$]$"));
        Assert.Equal(
            @"^[^$]\z",
            Ecma262RegexTranslator.Translate(@"^[^$]$"));
    }

    [Fact]
    public void Regex_translator_tracks_escape_parity_and_escaped_character_class_members()
    {
        Regex evenBackslashes = CreateTranslatedRegex(@"^\\$");
        Assert.Matches(evenBackslashes, "\\");
        Assert.DoesNotMatch(evenBackslashes, "\\\n");

        Regex oddBackslashes = CreateTranslatedRegex(@"^\\\$$");
        Assert.Matches(oddBackslashes, "\\$");
        Assert.DoesNotMatch(oddBackslashes, "\\$\n");

        Regex escapedClassMembers = CreateTranslatedRegex(@"^[\]$]$");
        Assert.Matches(escapedClassMembers, "]");
        Assert.Matches(escapedClassMembers, "$");
        Assert.DoesNotMatch(escapedClassMembers, "\n");
    }

    [Fact]
    public void Regex_translator_preserves_ecma_dot_and_whitespace_semantics()
    {
        Regex singleCharacter = CreateTranslatedRegex("^.$");
        Assert.Matches(singleCharacter, "a");
        Assert.Matches(singleCharacter, "\u0085");
        Assert.DoesNotMatch(singleCharacter, "\r");
        Assert.DoesNotMatch(singleCharacter, "\n");
        Assert.DoesNotMatch(singleCharacter, "\u2028");
        Assert.DoesNotMatch(singleCharacter, "\u2029");

        Regex whitespace = CreateTranslatedRegex(@"^\s$");
        Regex nonWhitespace = CreateTranslatedRegex(@"^\S$");
        Assert.Matches(whitespace, "\uFEFF");
        Assert.DoesNotMatch(nonWhitespace, "\uFEFF");
        Assert.DoesNotMatch(whitespace, "\u0085");
        Assert.Matches(nonWhitespace, "\u0085");
    }

    [Theory]
    [InlineData(@"\bword\b")]
    [InlineData(@"(?i)value")]
    [InlineData(@"[\S]")]
    [InlineData(@"\Avalue")]
    public void Regex_translator_rejects_unpreserved_dialect_constructs(string pattern)
    {
        _ = Assert.Throws<JsonSchemaDefinitionException>(() =>
            Ecma262RegexTranslator.Translate(pattern));
    }

    [Fact]
    public void Validator_fails_closed_when_local_references_form_a_cycle()
    {
        const string schemaJson = """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "$defs": {
                "cycle": { "$ref": "#/$defs/cycle" }
              },
              "$ref": "#/$defs/cycle"
            }
            """;
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string schemaPath = WriteSchema(temporaryRoot, schemaJson);
            ValidationLimits constrainedLimits = ValidationLimits.Default with
            {
                MaximumSchemaEvaluationDepth = 8,
            };

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new JsonSchemaValidator(constrainedLimits).ValidateNode(
                    schemaPath,
                    new JsonObject(),
                    "cyclic-instance.json",
                    temporaryRoot));

            Assert.Contains(
                "configured schema evaluation limits",
                exception.Message,
                StringComparison.Ordinal);
            Assert.IsType<JsonSchemaEvaluationException>(exception.InnerException);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    private static string WriteSchema(string temporaryRoot, string schemaJson)
    {
        string path = Path.Combine(temporaryRoot, "schema.json");
        File.WriteAllText(path, schemaJson);
        return path;
    }

    private static bool ContainsGeneratedDirectory(string path)
    {
        string normalizedPath = path.Replace(Path.DirectorySeparatorChar, '/');
        return normalizedPath.Contains("/bin/", StringComparison.Ordinal)
            || normalizedPath.Contains("/obj/", StringComparison.Ordinal)
            || normalizedPath.Contains("/artifacts/", StringComparison.Ordinal);
    }

    private static Regex CreateTranslatedRegex(string pattern) => new(
        Ecma262RegexTranslator.Translate(pattern),
        RegexOptions.CultureInvariant,
        ValidationLimits.Default.SchemaRegexTimeout);
}
