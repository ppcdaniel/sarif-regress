using System.Text.Json;

namespace SarifRegress.UnitTests;

public sealed class OutputSchemaTests
{
    [Fact]
    public void SnapshotSchema_CoversEveryStableProducerAndFidelityField()
    {
        var schemaPath = Path.Combine(
            RepositoryLayout.Root,
            "schemas",
            "output.schema.json");
        using var schema = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        Assert.Equal(
            "1",
            schema.RootElement
                .GetProperty("properties")
                .GetProperty("outputSchemaVersion")
                .GetProperty("const")
                .GetString());
        var snapshot = schema.RootElement
            .GetProperty("$defs")
            .GetProperty("snapshot");
        string[] expectedProperties =
        [
            "findingKey",
            "producerFamily",
            "producerToolName",
            "producerToolVersion",
            "automaticProducerIdentity",
            "canonicalRule",
            "canonicalUri",
            "region",
            "canonicalMessage",
            "sourceMetadata",
            "messageNormalisationFlags",
            "lossiness",
            "derivedFingerprints",
        ];
        string[] expectedRequiredProperties =
        [
            "findingKey",
            "producerFamily",
            "producerToolName",
            "producerToolVersion",
            "automaticProducerIdentity",
            "canonicalRule",
            "canonicalUri",
            "region",
            "canonicalMessage",
        ];
        var actualProperties = snapshot
            .GetProperty("properties")
            .EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var requiredProperties = snapshot
            .GetProperty("required")
            .EnumerateArray()
            .Select(
                property => property.GetString()
                    ?? throw new InvalidDataException(
                        "A required schema property name cannot be null."))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var expectedSorted = expectedProperties
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expectedSorted, actualProperties);
        Assert.Equal(
            expectedRequiredProperties
                .Order(StringComparer.Ordinal)
                .ToArray(),
            requiredProperties);
    }
}
