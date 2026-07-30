using System.Text;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;

namespace SarifRegress.CorpusTests;

public sealed class CorpusLabelReaderSecurityTests
{
    [Fact]
    public void Optional_expectation_arrays_preserve_diagnostic_presence()
    {
        const string omittedJson =
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": []
            }
            """;
        const string presentJson =
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [],
              "expectedExplanations": []
            }
            """;

        var omitted = ReadValid(omittedJson, ResourceLimits.Default);
        var present = ReadValid(presentJson, ResourceLimits.Default);

        Assert.True(omitted.ExpectedDiagnostics.IsDefault);
        Assert.False(present.ExpectedDiagnostics.IsDefault);
        Assert.Empty(present.ExpectedDiagnostics);
        Assert.True(omitted.ExpectedExplanations.IsDefault);
        Assert.False(present.ExpectedExplanations.IsDefault);
        Assert.Empty(present.ExpectedExplanations);
    }

    [Fact]
    public void Diagnostic_and_explanation_expectations_use_stable_wire_names()
    {
        var labels = ReadValid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [{
                "input": "candidate",
                "code": "GHCS0013",
                "severity": "note",
                "stage": "github-compat",
                "message": "Expected diagnostic.",
                "runIndex": 2,
                "jsonPointer": "/runs/2",
                "standardBasis": "github-supported-subset-test",
                "help": "Review the documented subset."
              }],
              "expectedExplanations": [{
                "baselineKey": "baseline:0:0",
                "classification": "resolved",
                "precedenceTier": "refuse",
                "ambiguous": false,
                "evidenceKinds": ["rule-identity"]
              }]
            }
            """,
            ResourceLimits.Default);

        var diagnostic = Assert.Single(labels.ExpectedDiagnostics);
        Assert.Equal(InputKind.Candidate, diagnostic.Input);
        Assert.Equal(DiagnosticSeverity.Note, diagnostic.Severity);
        Assert.Equal(
            DiagnosticStage.GithubCompatibility,
            diagnostic.Stage);
        Assert.Equal(2, diagnostic.RunIndex);
        Assert.Null(diagnostic.ResultIndex);
        Assert.Equal(
            "github-supported-subset-test",
            diagnostic.StandardBasis);
        Assert.Equal(
            "Review the documented subset.",
            diagnostic.Help);
        var explanation = Assert.Single(labels.ExpectedExplanations);
        Assert.Equal(
            FindingClassification.Resolved,
            explanation.Classification);
        Assert.Equal(PrecedenceTier.Refuse, explanation.PrecedenceTier);
        Assert.False(explanation.Ambiguous);
        Assert.Equal(["rule-identity"], explanation.EvidenceKinds);
    }

    [Fact]
    public void Diagnostic_sources_support_all_inputs_and_source_less_values()
    {
        var labels = ReadValid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [
                {
                  "input": "baseline",
                  "code": "PARSE0100",
                  "severity": "error",
                  "stage": "parse",
                  "message": "Baseline.",
                  "jsonPointer": ""
                },
                {
                  "input": "candidate",
                  "code": "SCHEMA0100",
                  "severity": "error",
                  "stage": "schema",
                  "message": "Candidate.",
                  "jsonPointer": ""
                },
                {
                  "input": "configuration",
                  "code": "UNSUPPORTED0001",
                  "severity": "warning",
                  "stage": "unsupported",
                  "message": "Configuration.",
                  "jsonPointer": "/future"
                },
                {
                  "input": "corpus",
                  "code": "SCHEMA0001",
                  "severity": "error",
                  "stage": "schema",
                  "message": "Corpus.",
                  "jsonPointer": "/labels"
                },
                {
                  "code": "MATCH0001",
                  "severity": "warning",
                  "stage": "match",
                  "message": "Source-less."
                }
              ]
            }
            """,
            ResourceLimits.Default);

        Assert.Equal(
            [
                InputKind.Baseline,
                InputKind.Candidate,
                InputKind.Configuration,
                InputKind.Corpus,
            ],
            labels.ExpectedDiagnostics
                .Where(item => item.Input.HasValue)
                .Select(item => item.Input!.Value)
                .ToArray());
        var sourceLess = Assert.Single(
            labels.ExpectedDiagnostics,
            item => !item.Input.HasValue);
        Assert.Null(sourceLess.RunIndex);
        Assert.Null(sourceLess.ResultIndex);
        Assert.Null(sourceLess.JsonPointer);
        Assert.Null(sourceLess.StandardBasis);
        Assert.Null(sourceLess.Help);
    }

    [Fact]
    public void Diagnostic_source_fields_are_all_present_or_all_omitted()
    {
        var missingPointer = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [{
                "input": "configuration",
                "code": "UNSUPPORTED0001",
                "severity": "warning",
                "stage": "unsupported",
                "message": "Missing pointer."
              }]
            }
            """,
            ResourceLimits.Default);
        var orphanIndex = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [{
                "code": "MATCH0001",
                "severity": "warning",
                "stage": "match",
                "message": "Orphan index.",
                "runIndex": 0
              }]
            }
            """,
            ResourceLimits.Default);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            missingPointer.Message);
        Assert.Equal(missingPointer.Message, orphanIndex.Message);
        Assert.Contains(
            "source requires input and jsonPointer",
            missingPointer.InnerException?.Message,
            StringComparison.Ordinal);
        Assert.Equal(
            missingPointer.InnerException?.Message,
            orphanIndex.InnerException?.Message);
    }

    [Fact]
    public void Label_bytes_are_bounded_before_token_traversal()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumInputBytes = 16,
        };
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": []
            }
            """,
            limits);

        Assert.Equal(
            "The corpus label file exceeds the 16 byte limit.",
            exception.Message);
    }

    [Fact]
    public void Pair_array_is_bounded_before_all_pairs_are_materialised()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 3,
        };
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [
                { "baselineKey": "b1", "candidateKey": "c1", "classification": "unchanged" },
                { "baselineKey": "b2", "candidateKey": "c2", "classification": "unchanged" },
                { "baselineKey": "b3", "candidateKey": "c3", "classification": "unchanged" },
                { "baselineKey": "b4", "candidateKey": "c4", "classification": "unchanged" }
              ],
              "expectedAmbiguous": []
            }
            """,
            limits);

        Assert.Contains(
            "collection 'pairs' exceeds the 3-item limit",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Label_strings_are_bounded_during_token_traversal()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumStringCharacters = 20,
        };
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [{
                "baselineKey": "abcdefghijklmnopqrstu",
                "candidateKey": "candidate",
                "classification": "unchanged"
              }],
              "expectedAmbiguous": []
            }
            """,
            limits);

        Assert.Equal(
            "A corpus label string exceeds the configured character limit.",
            exception.Message);
    }

    [Fact]
    public void Label_depth_is_bounded_before_nested_collections_are_materialised()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumJsonDepth = 1,
        };
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": []
            }
            """,
            limits);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            exception.Message);
    }

    [Fact]
    public void Unknown_nested_label_subtrees_are_rejected_deterministically()
    {
        const string json =
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "future": { "items": [1, 2, 3] }
            }
            """;

        var first = ReadInvalid(json, ResourceLimits.Default);
        var second = ReadInvalid(json, ResourceLimits.Default);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            first.Message);
        Assert.Equal(first.Message, second.Message);
        Assert.Equal(
            first.InnerException?.Message,
            second.InnerException?.Message);
    }

    [Fact]
    public void Explanation_evidence_is_bounded_before_materialisation()
    {
        var limits = ResourceLimits.Default with
        {
            MaximumRunCollectionItems = 6,
        };
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedExplanations": [{
                "candidateKey": "candidate:0:0",
                "classification": "new",
                "precedenceTier": "refuse",
                "ambiguous": false,
                "evidenceKinds": ["a", "b", "c", "d", "e", "f", "g"]
              }]
            }
            """,
            limits);

        Assert.Contains(
            "collection 'evidenceKinds' exceeds the 6-item limit",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Diagnostic_coordinates_must_be_bounded_non_negative_integers()
    {
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [{
                "input": "baseline",
                "code": "PARSE0100",
                "severity": "error",
                "stage": "parse",
                "message": "Expected diagnostic.",
                "runIndex": 2147483648,
                "jsonPointer": ""
              }]
            }
            """,
            ResourceLimits.Default);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            exception.Message);
    }

    [Fact]
    public void Expectation_objects_reject_unsupported_fields_and_duplicate_evidence()
    {
        var unsupported = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [{
                "input": "baseline",
                "code": "PARSE0100",
                "severity": "error",
                "stage": "parse",
                "message": "Expected diagnostic.",
                "jsonPointer": "",
                "future": true
              }]
            }
            """,
            ResourceLimits.Default);
        var duplicateEvidence = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedExplanations": [{
                "candidateKey": "candidate:0:0",
                "classification": "new",
                "precedenceTier": "refuse",
                "ambiguous": false,
                "evidenceKinds": ["rule-identity", "rule-identity"]
              }]
            }
            """,
            ResourceLimits.Default);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            unsupported.Message);
        Assert.Equal(unsupported.Message, duplicateEvidence.Message);
    }

    [Fact]
    public void Diagnostic_expectations_reject_exact_duplicates()
    {
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedDiagnostics": [
                {
                  "input": "baseline",
                  "code": "PARSE0100",
                  "severity": "error",
                  "stage": "parse",
                  "message": "Expected diagnostic.",
                  "runIndex": 0,
                  "resultIndex": 0,
                  "jsonPointer": "/runs/0/results/0"
                },
                {
                  "input": "baseline",
                  "code": "PARSE0100",
                  "severity": "error",
                  "stage": "parse",
                  "message": "Expected diagnostic.",
                  "runIndex": 0,
                  "resultIndex": 0,
                  "jsonPointer": "/runs/0/results/0"
                }
              ]
            }
            """,
            ResourceLimits.Default);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            exception.Message);
        var inner = Assert.IsType<System.Text.Json.JsonException>(
            exception.InnerException);
        Assert.Contains(
            "diagnostic expectation array contains a duplicate",
            inner.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Explanation_expectations_reject_contradictory_duplicate_identities()
    {
        var exception = ReadInvalid(
            """
            {
              "schemaVersion": "1",
              "pairs": [],
              "expectedAmbiguous": [],
              "expectedExplanations": [
                {
                  "baselineKey": "baseline:0:0",
                  "candidateKey": "candidate:0:0",
                  "classification": "unchanged",
                  "precedenceTier": "exact-producer",
                  "ambiguous": false,
                  "evidenceKinds": ["producer-fingerprint"]
                },
                {
                  "baselineKey": "baseline:0:0",
                  "candidateKey": "candidate:0:0",
                  "classification": "unchanged",
                  "precedenceTier": "exact-canonical",
                  "ambiguous": false,
                  "evidenceKinds": ["derived-fingerprint"]
                }
              ]
            }
            """,
            ResourceLimits.Default);

        Assert.Equal(
            "The corpus label file is not valid label JSON.",
            exception.Message);
        var inner = Assert.IsType<System.Text.Json.JsonException>(
            exception.InnerException);
        Assert.Contains(
            "duplicate decision identity",
            inner.Message,
            StringComparison.Ordinal);
    }

    private static CorpusLabels ReadValid(
        string json,
        ResourceLimits limits)
    {
        var path = CreateLabelFile(json);
        try
        {
            return CorpusLabelReader.Read(path, limits);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static InvalidDataException ReadInvalid(
        string json,
        ResourceLimits limits)
    {
        var path = CreateLabelFile(json);
        try
        {
            return Assert.Throws<InvalidDataException>(
                () => CorpusLabelReader.Read(path, limits));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string CreateLabelFile(string json)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"sarif-regress-label-{Guid.NewGuid():N}.json");
        File.WriteAllText(
            path,
            json,
            new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false));
        return path;
    }
}
