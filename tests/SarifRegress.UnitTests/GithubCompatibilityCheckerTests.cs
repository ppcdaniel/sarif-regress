using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Sarif.Compatibility;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.UnitTests;

public sealed class GithubCompatibilityCheckerTests
{
    [Fact]
    public void Supported_document_below_limits_has_no_advisories()
    {
        var summary = new SarifDocumentSummary(
            InputKind.Candidate,
            "2.1.0",
            InputBytes: 1_024,
            CompressedUploadBytes: 512,
            [
                new SarifRunSummary(
                    RunIndex: 0,
                    ResultCount: 1,
                    RuleCount: 1,
                    ExtensionCount: 0,
                    MaximumLocationsPerResult: 1,
                    MaximumThreadFlowLocationsPerResult: 0,
                    MaximumTagsPerRule: 1,
                    ResultsWithMultipleLocations: 0,
                    ResultsWithoutPrimaryLocationLineHash: 0,
                    NonRepositoryRelativePrimaryLocations: 0),
            ]);

        var diagnostics = new GithubCompatibilityChecker().Check(summary);

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void Injected_limits_make_checks_offline_and_testable()
    {
        var limits = new GithubCompatibilityLimits
        {
            MaximumCompressedUploadBytes = 10,
            MaximumRunsPerFile = 1,
            MaximumResultsPerRun = 2,
            SoftResultsPerRun = 1,
            MaximumRulesPerRun = 2,
            MaximumExtensionsPerRun = 1,
            MaximumThreadFlowLocationsPerResult = 2,
            SoftThreadFlowLocationsPerResult = 1,
            MaximumLocationsPerResult = 2,
            SoftLocationsPerResult = 1,
            MaximumTagsPerRule = 2,
            SoftTagsPerRule = 1,
            MaximumRepositoryAlerts = 2,
        };
        var summary = new SarifDocumentSummary(
            InputKind.Baseline,
            "2.0.0",
            InputBytes: 100,
            CompressedUploadBytes: 11,
            [
                CreateViolatingRun(0),
                CreateViolatingRun(1),
            ]);

        var diagnostics =
            new GithubCompatibilityChecker(limits).Check(summary);

        Assert.Contains(diagnostics, item => item.Code == "GHCS0001");
        Assert.Contains(diagnostics, item => item.Code == "GHCS0002");
        Assert.Contains(diagnostics, item => item.Code == "GHCS0003");
        Assert.Contains(diagnostics, item => item.Code == "GHCS0004");
        Assert.Contains(diagnostics, item => item.Code == "GHCS0012");
        Assert.Contains(diagnostics, item => item.Code == "GHCS0013");
        Assert.Contains(diagnostics, item => item.Code == "GHCS0017");
        Assert.All(
            diagnostics,
            item => Assert.Equal(
                "github-supported-subset-2026-07-30",
                item.StandardBasis));
        Assert.All(
            diagnostics,
            item => Assert.NotEqual(DiagnosticSeverity.Error, item.Severity));
    }

    [Fact]
    public void Compatibility_diagnostics_are_byte_order_independent()
    {
        var firstSummary = new SarifDocumentSummary(
            InputKind.Candidate,
            "2.1.0",
            100,
            null,
            [CreateViolatingRun(1), CreateViolatingRun(0)]);
        var secondSummary = firstSummary with
        {
            Runs = firstSummary.Runs.Reverse().ToImmutableArray(),
        };
        var checker = new GithubCompatibilityChecker(
            new GithubCompatibilityLimits
            {
                MaximumResultsPerRun = 2,
                SoftResultsPerRun = 1,
                MaximumRulesPerRun = 2,
                MaximumExtensionsPerRun = 1,
                MaximumThreadFlowLocationsPerResult = 2,
                SoftThreadFlowLocationsPerResult = 1,
                MaximumLocationsPerResult = 2,
                SoftLocationsPerResult = 1,
                MaximumTagsPerRule = 2,
                SoftTagsPerRule = 1,
                MaximumRepositoryAlerts = 2,
            });

        var first = checker.Check(firstSummary);
        var second = checker.Check(secondSummary);

        Assert.Equal(
            first.Select(ToStableDiagnosticTuple),
            second.Select(ToStableDiagnosticTuple));
    }

    private static SarifRunSummary CreateViolatingRun(int runIndex) =>
        new(
            runIndex,
            ResultCount: 3,
            RuleCount: 3,
            ExtensionCount: 2,
            MaximumLocationsPerResult: 3,
            MaximumThreadFlowLocationsPerResult: 3,
            MaximumTagsPerRule: 3,
            ResultsWithMultipleLocations: 1,
            ResultsWithoutPrimaryLocationLineHash: 1,
            NonRepositoryRelativePrimaryLocations: 1);

    private static (string Code, string Pointer, string Message)
        ToStableDiagnosticTuple(Diagnostic diagnostic) =>
        (
            diagnostic.Code,
            diagnostic.SourceReference?.JsonPointer ?? string.Empty,
            diagnostic.Message
        );
}
