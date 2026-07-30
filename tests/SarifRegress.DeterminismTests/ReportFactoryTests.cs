using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;

namespace SarifRegress.DeterminismTests;

public sealed class ReportFactoryTests
{
    [Fact]
    public void Create_RepresentativeResult_ComputesSummaryAndStableOrder()
    {
        var report = ReportTestData.CreateRepresentativeReport();

        Assert.Equal(1, report.Summary.BaselineCount);
        Assert.Equal(2, report.Summary.CandidateCount);
        Assert.Equal(1, report.Summary.New);
        Assert.Equal(1, report.Summary.Modified);
        Assert.Equal(
            [FindingClassification.Modified, FindingClassification.New],
            report.Findings.Select(item => item.Classification));
        Assert.Equal(
            ["a-path", "z-message"],
            report.Findings[0].Decision.Evidence.Select(item => item.Kind));
        Assert.Equal("IO0001", report.Diagnostics[0].Code);
        Assert.Equal("MATCH0009", report.Diagnostics[1].Code);
        Assert.Equal(
            ReportTestData.DerivedFingerprintValue,
            report.Findings[0].Candidate!.DerivedFingerprints[0].Value);
        Assert.Equal(
            "Test scanner",
            report.Findings[0].Candidate!.ProducerToolName);
        Assert.Equal(
            "4.2",
            report.Findings[0].Candidate!.ProducerToolVersion);
        Assert.Equal(
            "test-scanner",
            report.Findings[0].Candidate!.AutomaticProducerIdentity);
        Assert.Equal("error", report.Findings[0].Candidate!.SourceMetadata.Level);
        Assert.Equal("review", report.Findings[0].Candidate!.SourceMetadata.Kind);
        Assert.Equal(
            "updated",
            report.Findings[0].Candidate!.SourceMetadata.BaselineState);
        Assert.Equal(
            ["collapsed-whitespace", "invariant-case-fold"],
            report.Findings[0].Candidate!.MessageNormalisationFlags);
        Assert.Equal(
            ["collapsed-whitespace", "message-markdown-fallback"],
            report.Findings[0].Candidate!.Lossiness);
    }

    [Fact]
    public void WireMapper_PreservesProducerExplanation()
    {
        var report = ReportTestData.CreateRepresentativeReport();

        var document = StableJsonWireMapper.ToDto(report);
        var roundTripped = StableJsonWireMapper.FromDto(document);
        var snapshot = roundTripped.Findings[0].Candidate!;

        Assert.Equal("Test scanner", snapshot.ProducerToolName);
        Assert.Equal("4.2", snapshot.ProducerToolVersion);
        Assert.Equal("test-scanner", snapshot.ProducerFamily);
        Assert.Equal("test-scanner", snapshot.AutomaticProducerIdentity);
    }

    [Fact]
    public void DiagnosticSort_CompleteTieBreakers_AreInputOrderIndependent()
    {
        var baseline = new Diagnostic(
            "MATCH0001",
            DiagnosticSeverity.Warning,
            DiagnosticStage.Match,
            "same message",
            new SourceReference(
                InputKind.Baseline,
                runIndex: 0,
                resultIndex: 0,
                "/runs/0/results/0"),
            standardBasis: "basis-b",
            help: "help-b");
        var candidate = new Diagnostic(
            "MATCH0001",
            DiagnosticSeverity.Note,
            DiagnosticStage.Match,
            "same message",
            new SourceReference(
                InputKind.Candidate,
                runIndex: 0,
                resultIndex: 0,
                "/runs/0/results/0"),
            standardBasis: "basis-a",
            help: "help-a");

        var forward = Diagnostic.Sort([baseline, candidate]);
        var reverse = Diagnostic.Sort([candidate, baseline]);

        Assert.Equal(forward, reverse);
        Assert.Equal(InputKind.Baseline, forward[0].SourceReference!.Input);
    }
}
