using System.Text.Json.Serialization;

namespace SarifRegress.Report;

internal sealed class ReportDocumentDto
{
    [JsonPropertyName("outputSchemaVersion")]
    [JsonPropertyOrder(0)]
    public required string OutputSchemaVersion { get; init; }

    [JsonPropertyName("tool")]
    [JsonPropertyOrder(1)]
    public required ToolDto Tool { get; init; }

    [JsonPropertyName("inputs")]
    [JsonPropertyOrder(2)]
    public required InputsDto Inputs { get; init; }

    [JsonPropertyName("summary")]
    [JsonPropertyOrder(3)]
    public required SummaryDto Summary { get; init; }

    [JsonPropertyName("findings")]
    [JsonPropertyOrder(4)]
    public required FindingReportDto[] Findings { get; init; }

    [JsonPropertyName("diagnostics")]
    [JsonPropertyOrder(5)]
    public required DiagnosticDto[] Diagnostics { get; init; }

    [JsonPropertyName("metrics")]
    [JsonPropertyOrder(6)]
    public required MetricsDto Metrics { get; init; }

    [JsonPropertyName("determinism")]
    [JsonPropertyOrder(7)]
    public required DeterminismDto Determinism { get; init; }
}

internal sealed class ToolDto
{
    [JsonPropertyName("name")]
    [JsonPropertyOrder(0)]
    public required string Name { get; init; }

    [JsonPropertyName("version")]
    [JsonPropertyOrder(1)]
    public required string Version { get; init; }
}

internal sealed class InputsDto
{
    [JsonPropertyName("baseline")]
    [JsonPropertyOrder(0)]
    public required string Baseline { get; init; }

    [JsonPropertyName("candidate")]
    [JsonPropertyOrder(1)]
    public required string Candidate { get; init; }
}

internal sealed class SummaryDto
{
    [JsonPropertyName("baselineCount")]
    [JsonPropertyOrder(0)]
    public required int BaselineCount { get; init; }

    [JsonPropertyName("candidateCount")]
    [JsonPropertyOrder(1)]
    public required int CandidateCount { get; init; }

    [JsonPropertyName("new")]
    [JsonPropertyOrder(2)]
    public required int New { get; init; }

    [JsonPropertyName("unchanged")]
    [JsonPropertyOrder(3)]
    public required int Unchanged { get; init; }

    [JsonPropertyName("moved")]
    [JsonPropertyOrder(4)]
    public required int Moved { get; init; }

    [JsonPropertyName("modified")]
    [JsonPropertyOrder(5)]
    public required int Modified { get; init; }

    [JsonPropertyName("resolved")]
    [JsonPropertyOrder(6)]
    public required int Resolved { get; init; }

    [JsonPropertyName("ambiguous")]
    [JsonPropertyOrder(7)]
    public required int Ambiguous { get; init; }
}

internal sealed class FindingReportDto
{
    [JsonPropertyName("classification")]
    [JsonPropertyOrder(0)]
    public required string Classification { get; init; }

    [JsonPropertyName("baselineRef")]
    [JsonPropertyOrder(1)]
    public required SourceReferenceDto? BaselineReference { get; init; }

    [JsonPropertyName("candidateRef")]
    [JsonPropertyOrder(2)]
    public required SourceReferenceDto? CandidateReference { get; init; }

    [JsonPropertyName("baseline")]
    [JsonPropertyOrder(3)]
    public required FindingSnapshotDto? Baseline { get; init; }

    [JsonPropertyName("candidate")]
    [JsonPropertyOrder(4)]
    public required FindingSnapshotDto? Candidate { get; init; }

    [JsonPropertyName("decision")]
    [JsonPropertyOrder(5)]
    public required DecisionDto Decision { get; init; }

    [JsonPropertyName("evidence")]
    [JsonPropertyOrder(6)]
    public required EvidenceDto[] Evidence { get; init; }

    [JsonPropertyName("rejectedAlternatives")]
    [JsonPropertyOrder(7)]
    public required RejectedAlternativeDto[] RejectedAlternatives { get; init; }

    [JsonPropertyName("transforms")]
    [JsonPropertyOrder(8)]
    public required TransformationDto[] Transformations { get; init; }

    [JsonPropertyName("diagnostics")]
    [JsonPropertyOrder(9)]
    public required DiagnosticDto[] Diagnostics { get; init; }
}

internal sealed class SourceReferenceDto
{
    [JsonPropertyName("input")]
    [JsonPropertyOrder(0)]
    public required string Input { get; init; }

    [JsonPropertyName("runIndex")]
    [JsonPropertyOrder(1)]
    public required int? RunIndex { get; init; }

    [JsonPropertyName("resultIndex")]
    [JsonPropertyOrder(2)]
    public required int? ResultIndex { get; init; }

    [JsonPropertyName("jsonPointer")]
    [JsonPropertyOrder(3)]
    public required string JsonPointer { get; init; }
}

internal sealed class FindingSnapshotDto
{
    [JsonPropertyName("findingKey")]
    [JsonPropertyOrder(0)]
    public required string FindingKey { get; init; }

    [JsonPropertyName("producerFamily")]
    [JsonPropertyOrder(1)]
    public required string ProducerFamily { get; init; }

    [JsonPropertyName("producerToolName")]
    [JsonPropertyOrder(2)]
    public required string ProducerToolName { get; init; }

    [JsonPropertyName("producerToolVersion")]
    [JsonPropertyOrder(3)]
    public required string? ProducerToolVersion { get; init; }

    [JsonPropertyName("automaticProducerIdentity")]
    [JsonPropertyOrder(4)]
    public required string AutomaticProducerIdentity { get; init; }

    [JsonPropertyName("canonicalRule")]
    [JsonPropertyOrder(5)]
    public required string CanonicalRule { get; init; }

    [JsonPropertyName("canonicalUri")]
    [JsonPropertyOrder(6)]
    public required string? CanonicalUri { get; init; }

    [JsonPropertyName("region")]
    [JsonPropertyOrder(7)]
    public required RegionDto? Region { get; init; }

    [JsonPropertyName("canonicalMessage")]
    [JsonPropertyOrder(8)]
    public required string CanonicalMessage { get; init; }

    [JsonPropertyName("sourceMetadata")]
    [JsonPropertyOrder(9)]
    public SourceMetadataDto? SourceMetadata { get; init; }

    [JsonPropertyName("messageNormalisationFlags")]
    [JsonPropertyOrder(10)]
    public string[] MessageNormalisationFlags { get; init; } = [];

    [JsonPropertyName("lossiness")]
    [JsonPropertyOrder(11)]
    public string[] Lossiness { get; init; } = [];

    [JsonPropertyName("derivedFingerprints")]
    [JsonPropertyOrder(12)]
    public DerivedFingerprintDto[] DerivedFingerprints { get; init; } = [];
}

internal sealed class SourceMetadataDto
{
    [JsonPropertyName("level")]
    [JsonPropertyOrder(0)]
    public required string? Level { get; init; }

    [JsonPropertyName("kind")]
    [JsonPropertyOrder(1)]
    public required string? Kind { get; init; }

    [JsonPropertyName("baselineState")]
    [JsonPropertyOrder(2)]
    public required string? BaselineState { get; init; }
}

internal sealed class DerivedFingerprintDto
{
    [JsonPropertyName("name")]
    [JsonPropertyOrder(0)]
    public required string Name { get; init; }

    [JsonPropertyName("value")]
    [JsonPropertyOrder(1)]
    public required string Value { get; init; }

    [JsonPropertyName("algorithmVersion")]
    [JsonPropertyOrder(2)]
    public required string AlgorithmVersion { get; init; }
}

internal sealed class RegionDto
{
    [JsonPropertyName("startLine")]
    [JsonPropertyOrder(0)]
    public required int? StartLine { get; init; }

    [JsonPropertyName("startColumn")]
    [JsonPropertyOrder(1)]
    public required int? StartColumn { get; init; }

    [JsonPropertyName("endLine")]
    [JsonPropertyOrder(2)]
    public required int? EndLine { get; init; }

    [JsonPropertyName("endColumn")]
    [JsonPropertyOrder(3)]
    public required int? EndColumn { get; init; }
}

internal sealed class DecisionDto
{
    [JsonPropertyName("precedenceTier")]
    [JsonPropertyOrder(0)]
    public required string PrecedenceTier { get; init; }

    [JsonPropertyName("displayConfidence")]
    [JsonPropertyOrder(1)]
    public required string DisplayConfidence { get; init; }

    [JsonPropertyName("ambiguous")]
    [JsonPropertyOrder(2)]
    public required bool Ambiguous { get; init; }

    [JsonPropertyName("matcherAlgorithmVersion")]
    [JsonPropertyOrder(3)]
    public required string MatcherAlgorithmVersion { get; init; }
}

internal sealed class EvidenceDto
{
    [JsonPropertyName("kind")]
    [JsonPropertyOrder(0)]
    public required string Kind { get; init; }

    [JsonPropertyName("baselineValue")]
    [JsonPropertyOrder(1)]
    public required string? BaselineValue { get; init; }

    [JsonPropertyName("candidateValue")]
    [JsonPropertyOrder(2)]
    public required string? CandidateValue { get; init; }

    [JsonPropertyName("origin")]
    [JsonPropertyOrder(3)]
    public required string Origin { get; init; }

    [JsonPropertyName("precedenceTier")]
    [JsonPropertyOrder(4)]
    public required string PrecedenceTier { get; init; }

    [JsonPropertyName("lossy")]
    [JsonPropertyOrder(5)]
    public required bool Lossy { get; init; }

    [JsonPropertyName("algorithmVersion")]
    [JsonPropertyOrder(6)]
    public required string AlgorithmVersion { get; init; }
}

internal sealed class RejectedAlternativeDto
{
    [JsonPropertyName("findingKey")]
    [JsonPropertyOrder(0)]
    public required string FindingKey { get; init; }

    [JsonPropertyName("reason")]
    [JsonPropertyOrder(1)]
    public required string Reason { get; init; }

    [JsonPropertyName("precedenceTier")]
    [JsonPropertyOrder(2)]
    public required string PrecedenceTier { get; init; }

    [JsonPropertyName("decisionVector")]
    [JsonPropertyOrder(3)]
    public required DecisionVectorDto DecisionVector { get; init; }
}

internal sealed class DecisionVectorDto
{
    [JsonPropertyName("precedenceTier")]
    [JsonPropertyOrder(0)]
    public required string PrecedenceTier { get; init; }

    [JsonPropertyName("producerFingerprintStrength")]
    [JsonPropertyOrder(1)]
    public required int ProducerFingerprintStrength { get; init; }

    [JsonPropertyName("pathMatchKind")]
    [JsonPropertyOrder(2)]
    public required string PathMatchKind { get; init; }

    [JsonPropertyName("contextAgreement")]
    [JsonPropertyOrder(3)]
    public required string ContextAgreement { get; init; }

    [JsonPropertyName("codeFlowAgreement")]
    [JsonPropertyOrder(4)]
    public required string CodeFlowAgreement { get; init; }

    [JsonPropertyName("messageAgreement")]
    [JsonPropertyOrder(5)]
    public required string MessageAgreement { get; init; }

    [JsonPropertyName("regionDriftBand")]
    [JsonPropertyOrder(6)]
    public required int RegionDriftBand { get; init; }
}

internal sealed class TransformationDto
{
    [JsonPropertyName("kind")]
    [JsonPropertyOrder(0)]
    public required string Kind { get; init; }

    [JsonPropertyName("originalValue")]
    [JsonPropertyOrder(1)]
    public required string? OriginalValue { get; init; }

    [JsonPropertyName("transformedValue")]
    [JsonPropertyOrder(2)]
    public required string? TransformedValue { get; init; }

    [JsonPropertyName("lossy")]
    [JsonPropertyOrder(3)]
    public required bool Lossy { get; init; }

    [JsonPropertyName("algorithmVersion")]
    [JsonPropertyOrder(4)]
    public required string AlgorithmVersion { get; init; }
}

internal sealed class DiagnosticDto
{
    [JsonPropertyName("code")]
    [JsonPropertyOrder(0)]
    public required string Code { get; init; }

    [JsonPropertyName("severity")]
    [JsonPropertyOrder(1)]
    public required string Severity { get; init; }

    [JsonPropertyName("stage")]
    [JsonPropertyOrder(2)]
    public required string Stage { get; init; }

    [JsonPropertyName("message")]
    [JsonPropertyOrder(3)]
    public required string Message { get; init; }

    [JsonPropertyName("sourceRef")]
    [JsonPropertyOrder(4)]
    public required SourceReferenceDto? SourceReference { get; init; }

    [JsonPropertyName("standardBasis")]
    [JsonPropertyOrder(5)]
    public required string? StandardBasis { get; init; }

    [JsonPropertyName("help")]
    [JsonPropertyOrder(6)]
    public required string? Help { get; init; }
}

internal sealed class MetricsDto
{
    [JsonPropertyName("candidateEdges")]
    [JsonPropertyOrder(0)]
    public required int CandidateEdges { get; init; }

    [JsonPropertyName("assignmentComponents")]
    [JsonPropertyOrder(1)]
    public required int AssignmentComponents { get; init; }

    [JsonPropertyName("ambiguousComponents")]
    [JsonPropertyOrder(2)]
    public required int AmbiguousComponents { get; init; }

    [JsonPropertyName("diagnostics")]
    [JsonPropertyOrder(3)]
    public required int Diagnostics { get; init; }
}

internal sealed class DeterminismDto
{
    [JsonPropertyName("jsonCanonicalisation")]
    [JsonPropertyOrder(0)]
    public required string JsonCanonicalisation { get; init; }

    [JsonPropertyName("crossPlatformNormalisation")]
    [JsonPropertyOrder(1)]
    public required string CrossPlatformNormalisation { get; init; }

    [JsonPropertyName("matcherAlgorithm")]
    [JsonPropertyOrder(2)]
    public required string MatcherAlgorithm { get; init; }
}
