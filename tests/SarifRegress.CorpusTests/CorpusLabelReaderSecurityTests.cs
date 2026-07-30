using System.Text;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Security;

namespace SarifRegress.CorpusTests;

public sealed class CorpusLabelReaderSecurityTests
{
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

    private static InvalidDataException ReadInvalid(
        string json,
        ResourceLimits limits)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"sarif-regress-label-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(
                path,
                json,
                new UTF8Encoding(
                    encoderShouldEmitUTF8Identifier: false));
            return Assert.Throws<InvalidDataException>(
                () => CorpusLabelReader.Read(path, limits));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
