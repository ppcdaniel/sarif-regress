using System.Collections.Immutable;
using System.Text.Json;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Reporting;

namespace SarifRegress.Report;

internal static class StableJsonWireMapper
{
    public static ReportDocumentDto ToDto(ComparisonReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        return new ReportDocumentDto
        {
            OutputSchemaVersion = report.OutputSchemaVersion,
            Tool = new ToolDto
            {
                Name = report.ToolName,
                Version = report.ToolVersion,
            },
            Inputs = new InputsDto
            {
                Baseline = report.BaselineInputName,
                Candidate = report.CandidateInputName,
            },
            Summary = ToDto(report.Summary),
            Findings = report.Findings.Select(ToDto).ToArray(),
            Diagnostics = report.Diagnostics.Select(ToDto).ToArray(),
            Metrics = ToDto(report.Metrics),
            Determinism = ToDto(report.Determinism),
        };
    }

    public static ComparisonReport FromDto(ReportDocumentDto document)
    {
        ArgumentNullException.ThrowIfNull(document);
        EnsureSupportedSchema(document.OutputSchemaVersion);

        var findings = MapArray(
            document.Findings,
            "findings",
            item => FromDto(item));
        var diagnostics = MapArray(
            document.Diagnostics,
            "diagnostics",
            item => FromDto(item));
        var tool = Require(document.Tool, "tool");
        var inputs = Require(document.Inputs, "inputs");

        return new ComparisonReport(
            document.OutputSchemaVersion,
            tool.Name,
            tool.Version,
            inputs.Baseline,
            inputs.Candidate,
            FromDto(Require(document.Summary, "summary")),
            findings,
            diagnostics,
            FromDto(Require(document.Metrics, "metrics")),
            FromDto(Require(document.Determinism, "determinism")));
    }

    private static SummaryDto ToDto(ComparisonSummary summary) =>
        new()
        {
            BaselineCount = summary.BaselineCount,
            CandidateCount = summary.CandidateCount,
            New = summary.New,
            Unchanged = summary.Unchanged,
            Moved = summary.Moved,
            Modified = summary.Modified,
            Resolved = summary.Resolved,
            Ambiguous = summary.Ambiguous,
        };

    private static ComparisonSummary FromDto(SummaryDto summary)
    {
        EnsureNonNegative(summary.BaselineCount, "summary.baselineCount");
        EnsureNonNegative(summary.CandidateCount, "summary.candidateCount");
        EnsureNonNegative(summary.New, "summary.new");
        EnsureNonNegative(summary.Unchanged, "summary.unchanged");
        EnsureNonNegative(summary.Moved, "summary.moved");
        EnsureNonNegative(summary.Modified, "summary.modified");
        EnsureNonNegative(summary.Resolved, "summary.resolved");
        EnsureNonNegative(summary.Ambiguous, "summary.ambiguous");

        return new ComparisonSummary(
            summary.BaselineCount,
            summary.CandidateCount,
            summary.New,
            summary.Unchanged,
            summary.Moved,
            summary.Modified,
            summary.Resolved,
            summary.Ambiguous);
    }

    private static FindingReportDto ToDto(FindingReport finding) =>
        new()
        {
            Classification = StableJsonNames.Classification(finding.Classification),
            BaselineReference = finding.BaselineReference is null
                ? null
                : ToDto(finding.BaselineReference),
            CandidateReference = finding.CandidateReference is null
                ? null
                : ToDto(finding.CandidateReference),
            Baseline = finding.Baseline is null ? null : ToDto(finding.Baseline),
            Candidate = finding.Candidate is null ? null : ToDto(finding.Candidate),
            Decision = ToDto(finding.Decision),
            Evidence = finding.Decision.Evidence.Select(ToDto).ToArray(),
            RejectedAlternatives = finding.Decision.RejectedAlternatives
                .Select(ToDto)
                .ToArray(),
            Transformations = finding.Decision.Transformations.Select(ToDto).ToArray(),
            Diagnostics = finding.Decision.Diagnostics.Select(ToDto).ToArray(),
        };

    private static FindingReport FromDto(FindingReportDto finding)
    {
        var decision = Require(finding.Decision, "findings[].decision");
        return new FindingReport(
            StableJsonNames.ParseClassification(finding.Classification),
            finding.BaselineReference is null
                ? null
                : FromDto(finding.BaselineReference),
            finding.CandidateReference is null
                ? null
                : FromDto(finding.CandidateReference),
            finding.Baseline is null ? null : FromDto(finding.Baseline),
            finding.Candidate is null ? null : FromDto(finding.Candidate),
            new DecisionTrace(
                StableJsonNames.ParsePrecedence(decision.PrecedenceTier),
                StableJsonNames.ParseConfidence(decision.DisplayConfidence),
                decision.Ambiguous,
                decision.MatcherAlgorithmVersion,
                MapArray(
                    finding.Evidence,
                    "findings[].evidence",
                    item => FromDto(item)),
                MapArray(
                    finding.RejectedAlternatives,
                    "findings[].rejectedAlternatives",
                    item => FromDto(item)),
                MapArray(
                    finding.Transformations,
                    "findings[].transforms",
                    item => FromDto(item)),
                MapArray(
                    finding.Diagnostics,
                    "findings[].diagnostics",
                    item => FromDto(item))));
    }

    private static SourceReferenceDto ToDto(SourceReference sourceReference) =>
        new()
        {
            Input = StableJsonNames.Input(sourceReference.Input),
            RunIndex = sourceReference.RunIndex,
            ResultIndex = sourceReference.ResultIndex,
            JsonPointer = sourceReference.JsonPointer,
        };

    private static SourceReference FromDto(SourceReferenceDto sourceReference) =>
        new(
            StableJsonNames.ParseInput(sourceReference.Input),
            sourceReference.RunIndex,
            sourceReference.ResultIndex,
            sourceReference.JsonPointer);

    private static FindingSnapshotDto ToDto(FindingSnapshot snapshot) =>
        new()
        {
            FindingKey = snapshot.FindingKey,
            ProducerFamily = snapshot.ProducerFamily,
            CanonicalRule = snapshot.CanonicalRule,
            CanonicalUri = snapshot.CanonicalUri,
            Region = snapshot.Region is null ? null : ToDto(snapshot.Region),
            CanonicalMessage = snapshot.CanonicalMessage,
            DerivedFingerprints = snapshot.DerivedFingerprints.Select(ToDto).ToArray(),
        };

    private static FindingSnapshot FromDto(FindingSnapshotDto snapshot) =>
        new(
            snapshot.FindingKey,
            snapshot.ProducerFamily,
            snapshot.CanonicalRule,
            snapshot.CanonicalUri,
            snapshot.Region is null ? null : FromDto(snapshot.Region),
            snapshot.CanonicalMessage,
            MapArray(
                snapshot.DerivedFingerprints,
                "findings[].derivedFingerprints",
                item => FromDto(item)));

    private static DerivedFingerprintDto ToDto(
        DerivedFingerprint fingerprint) =>
        new()
        {
            Name = fingerprint.Name,
            Value = fingerprint.Value,
            AlgorithmVersion = fingerprint.AlgorithmVersion,
        };

    private static DerivedFingerprint FromDto(
        DerivedFingerprintDto fingerprint) =>
        new(
            fingerprint.Name,
            fingerprint.Value,
            fingerprint.AlgorithmVersion);

    private static RegionDto ToDto(Region region) =>
        new()
        {
            StartLine = region.StartLine,
            StartColumn = region.StartColumn,
            EndLine = region.EndLine,
            EndColumn = region.EndColumn,
        };

    private static Region FromDto(RegionDto region) =>
        new(
            region.StartLine,
            region.StartColumn,
            region.EndLine,
            region.EndColumn);

    private static DecisionDto ToDto(DecisionTrace decision) =>
        new()
        {
            PrecedenceTier = StableJsonNames.Precedence(decision.PrecedenceTier),
            DisplayConfidence = StableJsonNames.Confidence(decision.DisplayConfidence),
            Ambiguous = decision.Ambiguous,
            MatcherAlgorithmVersion = decision.MatcherAlgorithmVersion,
        };

    private static EvidenceDto ToDto(EvidenceRecord evidence) =>
        new()
        {
            Kind = evidence.Kind,
            BaselineValue = evidence.BaselineValue,
            CandidateValue = evidence.CandidateValue,
            Origin = StableJsonNames.Origin(evidence.Origin),
            PrecedenceTier = StableJsonNames.Precedence(evidence.PrecedenceTier),
            Lossy = evidence.Lossy,
            AlgorithmVersion = evidence.AlgorithmVersion,
        };

    private static EvidenceRecord FromDto(EvidenceDto evidence) =>
        new(
            evidence.Kind,
            evidence.BaselineValue,
            evidence.CandidateValue,
            StableJsonNames.ParseOrigin(evidence.Origin),
            StableJsonNames.ParsePrecedence(evidence.PrecedenceTier),
            evidence.Lossy,
            evidence.AlgorithmVersion);

    private static RejectedAlternativeDto ToDto(
        RejectedAlternative alternative) =>
        new()
        {
            FindingKey = alternative.FindingKey,
            Reason = alternative.Reason,
            PrecedenceTier = StableJsonNames.Precedence(alternative.PrecedenceTier),
            DecisionVector = ToDto(alternative.DecisionVector),
        };

    private static RejectedAlternative FromDto(
        RejectedAlternativeDto alternative) =>
        new(
            alternative.FindingKey,
            alternative.Reason,
            StableJsonNames.ParsePrecedence(alternative.PrecedenceTier),
            FromDto(Require(
                alternative.DecisionVector,
                "findings[].rejectedAlternatives[].decisionVector")));

    private static DecisionVectorDto ToDto(DecisionVector decisionVector) =>
        new()
        {
            PrecedenceTier = StableJsonNames.Precedence(
                decisionVector.PrecedenceTier),
            ProducerFingerprintStrength = decisionVector.ProducerFingerprintStrength,
            PathMatchKind = StableJsonNames.PathMatch(decisionVector.PathMatchKind),
            ContextAgreement = StableJsonNames.Agreement(
                decisionVector.ContextAgreement),
            CodeFlowAgreement = StableJsonNames.Agreement(
                decisionVector.CodeFlowAgreement),
            MessageAgreement = StableJsonNames.Agreement(
                decisionVector.MessageAgreement),
            RegionDriftBand = decisionVector.RegionDriftBand,
        };

    private static DecisionVector FromDto(DecisionVectorDto decisionVector) =>
        new(
            StableJsonNames.ParsePrecedence(decisionVector.PrecedenceTier),
            decisionVector.ProducerFingerprintStrength,
            StableJsonNames.ParsePathMatch(decisionVector.PathMatchKind),
            StableJsonNames.ParseAgreement(decisionVector.ContextAgreement),
            StableJsonNames.ParseAgreement(decisionVector.CodeFlowAgreement),
            StableJsonNames.ParseAgreement(decisionVector.MessageAgreement),
            decisionVector.RegionDriftBand);

    private static TransformationDto ToDto(
        TransformationRecord transformation) =>
        new()
        {
            Kind = transformation.Kind,
            OriginalValue = transformation.OriginalValue,
            TransformedValue = transformation.TransformedValue,
            Lossy = transformation.IsLossy,
            AlgorithmVersion = transformation.AlgorithmVersion,
        };

    private static TransformationRecord FromDto(
        TransformationDto transformation) =>
        new(
            transformation.Kind,
            transformation.OriginalValue,
            transformation.TransformedValue,
            transformation.Lossy,
            transformation.AlgorithmVersion);

    private static DiagnosticDto ToDto(Diagnostic diagnostic) =>
        new()
        {
            Code = diagnostic.Code,
            Severity = StableJsonNames.Severity(diagnostic.Severity),
            Stage = StableJsonNames.Stage(diagnostic.Stage),
            Message = diagnostic.Message,
            SourceReference = diagnostic.SourceReference is null
                ? null
                : ToDto(diagnostic.SourceReference),
            StandardBasis = diagnostic.StandardBasis,
            Help = diagnostic.Help,
        };

    private static Diagnostic FromDto(DiagnosticDto diagnostic) =>
        new(
            diagnostic.Code,
            StableJsonNames.ParseSeverity(diagnostic.Severity),
            StableJsonNames.ParseStage(diagnostic.Stage),
            diagnostic.Message,
            diagnostic.SourceReference is null
                ? null
                : FromDto(diagnostic.SourceReference),
            diagnostic.StandardBasis,
            diagnostic.Help);

    private static MetricsDto ToDto(ComparisonMetrics metrics) =>
        new()
        {
            CandidateEdges = metrics.CandidateEdges,
            AssignmentComponents = metrics.AssignmentComponents,
            AmbiguousComponents = metrics.AmbiguousComponents,
            Diagnostics = metrics.Diagnostics,
        };

    private static ComparisonMetrics FromDto(MetricsDto metrics)
    {
        EnsureNonNegative(metrics.CandidateEdges, "metrics.candidateEdges");
        EnsureNonNegative(
            metrics.AssignmentComponents,
            "metrics.assignmentComponents");
        EnsureNonNegative(
            metrics.AmbiguousComponents,
            "metrics.ambiguousComponents");
        EnsureNonNegative(metrics.Diagnostics, "metrics.diagnostics");

        return new ComparisonMetrics(
            metrics.CandidateEdges,
            metrics.AssignmentComponents,
            metrics.AmbiguousComponents,
            metrics.Diagnostics);
    }

    private static DeterminismDto ToDto(DeterminismDescriptor determinism) =>
        new()
        {
            JsonCanonicalisation = determinism.JsonCanonicalisation,
            CrossPlatformNormalisation = determinism.CrossPlatformNormalisation,
            MatcherAlgorithm = determinism.MatcherAlgorithm,
        };

    private static DeterminismDescriptor FromDto(DeterminismDto determinism) =>
        new(
            determinism.JsonCanonicalisation,
            determinism.CrossPlatformNormalisation,
            determinism.MatcherAlgorithm);

    private static void EnsureSupportedSchema(string outputSchemaVersion)
    {
        if (!string.Equals(
                outputSchemaVersion,
                ReportContractVersions.OutputSchema,
                StringComparison.Ordinal))
        {
            throw new JsonException(
                $"Unsupported output schema version '{outputSchemaVersion}'.");
        }
    }

    private static void EnsureNonNegative(int value, string propertyName)
    {
        if (value < 0)
        {
            throw new JsonException($"'{propertyName}' cannot be negative.");
        }
    }

    private static T Require<T>(T? value, string propertyName)
        where T : class =>
        value ?? throw new JsonException(
            $"The required '{propertyName}' property is null.");

    private static ImmutableArray<TTarget> MapArray<TSource, TTarget>(
        TSource[]? values,
        string propertyName,
        Func<TSource, TTarget> map)
        where TSource : class
    {
        if (values is null)
        {
            throw new JsonException(
                $"The required '{propertyName}' array is null.");
        }

        var builder = ImmutableArray.CreateBuilder<TTarget>(values.Length);
        for (var index = 0; index < values.Length; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new JsonException(
                    $"The '{propertyName}[{index}]' value is null.");
            }

            builder.Add(map(value));
        }

        return builder.MoveToImmutable();
    }
}
