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
