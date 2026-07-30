using System.Collections.Immutable;
using System.Globalization;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Reporting;
using SarifRegress.Report;

namespace SarifRegress.DeterminismTests;

internal static class ReportTestData
{
    public const string DerivedFingerprintValue =
        "1111111111111111111111111111111111111111111111111111111111111111";
    public const string MatcherAlgorithmVersion = "matcher-v1";
    public const string NewDerivedFingerprintValue =
        "2222222222222222222222222222222222222222222222222222222222222222";
    public const string ToolVersion = "0.1.0-test";

    public static ComparisonReport CreateEmptyReport()
    {
        var result = new MatchResult(
            ImmutableArray<FindingDecision>.Empty,
            CandidateEdgeCount: 0,
            ComponentCount: 0,
            AmbiguousComponentCount: 0,
            ImmutableArray<Diagnostic>.Empty);
        return ComparisonReportFactory.Create(
            result,
            new ComparisonReportMetadata(
                ToolVersion,
                "baseline.sarif",
                "candidate.sarif",
                MatcherAlgorithmVersion));
    }

    public static ComparisonReport CreateRepresentativeReport(
        string? candidateMessage = null)
    {
        var baseline = CreateFinding(
            InputKind.Baseline,
            "baseline:0:2",
            resultIndex: 2,
            canonicalUri: "repo://src/old.cs",
            canonicalMessage: "unsafe input",
            derivedFingerprintValue: DerivedFingerprintValue);
        var candidate = CreateFinding(
            InputKind.Candidate,
            "candidate:0:7",
            resultIndex: 7,
            canonicalUri: "repo://src/new.cs",
            canonicalMessage: candidateMessage
                ?? "unsafe <script>alert(\"x\")</script> & 'quoted' input",
            derivedFingerprintValue: DerivedFingerprintValue);
        var newCandidate = CreateFinding(
            InputKind.Candidate,
            "candidate:0:3",
            resultIndex: 3,
            canonicalUri: "repo://src/alpha.cs",
            canonicalMessage: "new finding",
            derivedFingerprintValue: NewDerivedFingerprintValue);

        var modifiedDecision = new FindingDecision(
            FindingClassification.Modified,
            baseline,
            candidate,
            CreateTrace(
                PrecedenceTier.StrongMoved,
                [
                    new EvidenceRecord(
                        "z-message",
                        baseline.Message.CanonicalText,
                        candidate.Message.CanonicalText,
                        EvidenceOrigin.System,
                        PrecedenceTier.StrongMoved,
                        Lossy: false,
                        "message-v1"),
                    new EvidenceRecord(
                        "a-path",
                        baseline.PrimaryLocation!.Path.CanonicalUri,
                        candidate.PrimaryLocation!.Path.CanonicalUri,
                        EvidenceOrigin.Configuration,
                        PrecedenceTier.StrongMoved,
                        Lossy: false,
                        "path-alias-v1"),
                ],
                [
                    new RejectedAlternative(
                        "candidate:0:99",
                        "lower-precedence evidence",
                        PrecedenceTier.WeakContextual,
                        new DecisionVector(
                            PrecedenceTier.WeakContextual,
                            ProducerFingerprintStrength: 0,
                            PathMatchKind.None,
                            AgreementBand.Compatible,
                            AgreementBand.None,
                            AgreementBand.Compatible,
                            RegionDriftBand: 3)),
                ],
                [
                    new TransformationRecord(
                        "path-alias",
                        "repo://src/old.cs",
                        "repo://src/new.cs",
                        isLossy: false,
                        "path-alias-v1"),
                ],
                [
                    new Diagnostic(
                        "MATCH0002",
                        DiagnosticSeverity.Note,
                        DiagnosticStage.Match,
                        "Candidate message changed.",
                        candidate.SourceReference),
                ]));
        var newDecision = new FindingDecision(
            FindingClassification.New,
            Baseline: null,
            newCandidate,
            CreateTrace(
                PrecedenceTier.Refuse,
                [],
                [],
                [],
                []));

        var matchResult = new MatchResult(
            [newDecision, modifiedDecision],
            CandidateEdgeCount: 4,
            ComponentCount: 2,
            AmbiguousComponentCount: 0,
            [
                new Diagnostic(
                    "MATCH0009",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Match,
                    "A deterministic report-level warning.",
                    candidate.SourceReference,
                    standardBasis: "project-policy",
                    help: "Review the explanation."),
                new Diagnostic(
                    "IO0001",
                    DiagnosticSeverity.Note,
                    DiagnosticStage.Io,
                    "Inputs were read locally."),
            ]);

        return ComparisonReportFactory.Create(
            matchResult,
            new ComparisonReportMetadata(
                ToolVersion,
                "baseline <one>.sarif",
                "candidate & \"two\".sarif",
                MatcherAlgorithmVersion));
    }

    public static ComparisonReport CreateSingleCandidateReport(
        string canonicalUri,
        Region? region,
        bool includeDerivedFingerprint)
    {
        var candidate = CreateFinding(
            InputKind.Candidate,
            "candidate:0:0",
            resultIndex: 0,
            canonicalUri: canonicalUri,
            canonicalMessage: "candidate message",
            derivedFingerprintValue: includeDerivedFingerprint
                ? DerivedFingerprintValue
                : null,
            region: region);
        var decision = new FindingDecision(
            FindingClassification.New,
            Baseline: null,
            candidate,
            CreateTrace(
                PrecedenceTier.Refuse,
                [],
                [],
                [],
                []));
        return ComparisonReportFactory.Create(
            new MatchResult(
                [decision],
                CandidateEdgeCount: 0,
                ComponentCount: 0,
                AmbiguousComponentCount: 0,
                ImmutableArray<Diagnostic>.Empty),
            new ComparisonReportMetadata(
                ToolVersion,
                "baseline.sarif",
                "candidate.sarif",
                MatcherAlgorithmVersion));
    }

    private static Finding CreateFinding(
        InputKind input,
        string findingKey,
        int resultIndex,
        string canonicalUri,
        string canonicalMessage,
        string? derivedFingerprintValue,
        Region? region = null)
    {
        var sourceReference = new SourceReference(
            input,
            runIndex: 0,
            resultIndex,
            $"/runs/0/results/{resultIndex}");
        var path = new CanonicalPath(
            canonicalUri,
            canonicalUri,
            canonicalUri,
            canonicalUri["repo://".Length..],
            PathKind.RepositoryRelative);

        return new Finding(
            findingKey,
            sourceReference,
            new RunIdentity(0, AutomationCategory: null, StableRunKey: "run:0"),
            new ProducerIdentity(
                "Test scanner",
                ToolVersion: "4.2",
                Family: "test-scanner",
                AutomationCategory: null),
            new RuleIdentity(
                "RULE-001",
                "test-scanner/RULE-001",
                AliasApplied: false),
            new PrimaryLocation(
                path,
                region ?? new Region(12, 4, 12, 18),
                EmbeddedSnippet: null),
            new MessageIdentity(
                canonicalMessage,
                canonicalMessage,
                canonicalMessage,
                ImmutableArray<string>.Empty),
            derivedFingerprints: derivedFingerprintValue is null
                ? []
                : [
                    new DerivedFingerprint(
                        ReportContractVersions.SarifFingerprint,
                        derivedFingerprintValue,
                        ReportContractVersions.SarifFingerprintAlgorithm),
                ]);
    }

    private static DecisionTrace CreateTrace(
        PrecedenceTier precedenceTier,
        ImmutableArray<EvidenceRecord> evidence,
        ImmutableArray<RejectedAlternative> rejectedAlternatives,
        ImmutableArray<TransformationRecord> transformations,
        ImmutableArray<Diagnostic> diagnostics) =>
        new(
            precedenceTier,
            precedenceTier == PrecedenceTier.Refuse
                ? DisplayConfidence.Low
                : DisplayConfidence.High,
            Ambiguous: false,
            MatcherAlgorithmVersion,
            evidence,
            rejectedAlternatives,
            transformations,
            diagnostics);
}

internal sealed class CultureScope : IDisposable
{
    private readonly CultureInfo originalCulture;
    private readonly CultureInfo originalUiCulture;

    public CultureScope(string cultureName)
    {
        originalCulture = CultureInfo.CurrentCulture;
        originalUiCulture = CultureInfo.CurrentUICulture;
        var culture = CultureInfo.GetCultureInfo(cultureName);
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }

    public void Dispose()
    {
        CultureInfo.CurrentCulture = originalCulture;
        CultureInfo.CurrentUICulture = originalUiCulture;
    }
}
