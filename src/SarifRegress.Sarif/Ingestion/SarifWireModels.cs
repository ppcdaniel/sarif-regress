using System.Text.Json.Serialization;

namespace SarifRegress.Sarif.Ingestion;

// These private DTOs intentionally model only comparison-relevant fields and bounded facts used
// by the advisory GitHub profile. JsonSerializer consumes other properties incrementally without
// retaining their object graphs.
internal sealed class SarifLogWire
{
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    [JsonPropertyName("runs")]
    public List<SarifRunWire?>? Runs { get; init; }
}

internal sealed class SarifRunWire
{
    [JsonPropertyName("tool")]
    public SarifToolWire? Tool { get; init; }

    [JsonPropertyName("automationDetails")]
    public SarifAutomationDetailsWire? AutomationDetails { get; init; }

    [JsonPropertyName("originalUriBaseIds")]
    public Dictionary<string, SarifArtifactLocationWire?>? OriginalUriBaseIds { get; init; }

    [JsonPropertyName("artifacts")]
    public List<SarifArtifactWire?>? Artifacts { get; init; }

    [JsonPropertyName("results")]
    public List<SarifResultWire?>? Results { get; init; }

    [JsonPropertyName("invocations")]
    public List<SarifInvocationWire?>? Invocations { get; init; }

    [JsonPropertyName("graphs")]
    public UnsupportedJsonValue? UnsupportedGraphs { get; init; }
}

internal sealed class SarifToolWire
{
    [JsonPropertyName("driver")]
    public SarifToolComponentWire? Driver { get; init; }

    [JsonPropertyName("extensions")]
    public List<SarifToolComponentWire?>? Extensions { get; init; }
}

internal sealed class SarifToolComponentWire
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("version")]
    public string? Version { get; init; }

    [JsonPropertyName("semanticVersion")]
    public string? SemanticVersion { get; init; }

    [JsonPropertyName("rules")]
    public List<SarifRuleWire?>? Rules { get; init; }
}

internal sealed class SarifRuleWire
{
    [JsonPropertyName("id")]
    public string? Id { get; init; }

    [JsonPropertyName("properties")]
    public SarifPropertyBagWire? Properties { get; init; }
}

internal sealed class SarifPropertyBagWire
{
    [JsonPropertyName("tags")]
    public List<string?>? Tags { get; init; }
}

internal sealed class SarifAutomationDetailsWire
{
    [JsonPropertyName("id")]
    public string? Id { get; init; }
}

internal sealed class SarifInvocationWire
{
    [JsonPropertyName("workingDirectory")]
    public SarifArtifactLocationWire? WorkingDirectory { get; init; }
}

internal sealed class SarifArtifactWire
{
    [JsonPropertyName("location")]
    public SarifArtifactLocationWire? Location { get; init; }
}

internal sealed class SarifArtifactLocationWire
{
    [JsonPropertyName("uri")]
    public string? Uri { get; init; }

    [JsonPropertyName("uriBaseId")]
    public string? UriBaseId { get; init; }

    [JsonPropertyName("index")]
    public int? Index { get; init; }
}

internal sealed class SarifResultWire
{
    [JsonPropertyName("ruleId")]
    public string? RuleId { get; init; }

    [JsonPropertyName("ruleIndex")]
    public int? RuleIndex { get; init; }

    [JsonPropertyName("message")]
    public SarifMessageWire? Message { get; init; }

    [JsonPropertyName("level")]
    public string? Level { get; init; }

    [JsonPropertyName("kind")]
    public string? Kind { get; init; }

    [JsonPropertyName("fingerprints")]
    public Dictionary<string, string?>? Fingerprints { get; init; }

    [JsonPropertyName("partialFingerprints")]
    public Dictionary<string, string?>? PartialFingerprints { get; init; }

    [JsonPropertyName("locations")]
    public List<SarifLocationWire?>? Locations { get; init; }

    [JsonPropertyName("relatedLocations")]
    public List<SarifLocationWire?>? RelatedLocations { get; init; }

    [JsonPropertyName("codeFlows")]
    public List<SarifCodeFlowWire?>? CodeFlows { get; init; }

    [JsonPropertyName("baselineState")]
    public string? BaselineState { get; init; }

    [JsonPropertyName("logicalLocations")]
    public UnsupportedJsonValue? UnsupportedLogicalLocations { get; init; }

    [JsonPropertyName("stacks")]
    public UnsupportedJsonValue? UnsupportedStacks { get; init; }

    [JsonPropertyName("suppressions")]
    public UnsupportedJsonValue? UnsupportedSuppressions { get; init; }

    [JsonPropertyName("attachments")]
    public UnsupportedJsonValue? UnsupportedAttachments { get; init; }
}

internal sealed class SarifMessageWire
{
    [JsonPropertyName("text")]
    public string? Text { get; init; }

    [JsonPropertyName("markdown")]
    public string? Markdown { get; init; }
}

internal sealed class SarifLocationWire
{
    [JsonPropertyName("physicalLocation")]
    public SarifPhysicalLocationWire? PhysicalLocation { get; init; }

    [JsonPropertyName("message")]
    public SarifMessageWire? Message { get; init; }

    [JsonPropertyName("logicalLocations")]
    public UnsupportedJsonValue? UnsupportedLogicalLocations { get; init; }
}

internal sealed class SarifPhysicalLocationWire
{
    [JsonPropertyName("artifactLocation")]
    public SarifArtifactLocationWire? ArtifactLocation { get; init; }

    [JsonPropertyName("region")]
    public SarifRegionWire? Region { get; init; }
}

internal sealed class SarifRegionWire
{
    [JsonPropertyName("startLine")]
    public int? StartLine { get; init; }

    [JsonPropertyName("startColumn")]
    public int? StartColumn { get; init; }

    [JsonPropertyName("endLine")]
    public int? EndLine { get; init; }

    [JsonPropertyName("endColumn")]
    public int? EndColumn { get; init; }

    [JsonPropertyName("charOffset")]
    public int? CharOffset { get; init; }

    [JsonPropertyName("charLength")]
    public int? CharLength { get; init; }

    [JsonPropertyName("byteOffset")]
    public int? ByteOffset { get; init; }

    [JsonPropertyName("byteLength")]
    public int? ByteLength { get; init; }

    [JsonPropertyName("snippet")]
    public SarifMessageWire? Snippet { get; init; }
}

internal sealed class SarifCodeFlowWire
{
    [JsonPropertyName("threadFlows")]
    public List<SarifThreadFlowWire?>? ThreadFlows { get; init; }
}

internal sealed class SarifThreadFlowWire
{
    [JsonPropertyName("locations")]
    public List<SarifThreadFlowLocationWire?>? Locations { get; init; }
}

internal sealed class SarifThreadFlowLocationWire
{
    [JsonPropertyName("location")]
    public SarifLocationWire? Location { get; init; }
}
