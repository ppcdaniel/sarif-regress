using System.Text.Json;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Security;

namespace SarifRegress.CorpusTests;

public sealed class CorpusFixtureTests
{
    [Fact]
    public void Tracked_corpus_has_target_size_and_required_strata()
    {
        string corpusRoot = CorpusTestPaths.FindCorpusRoot();
        string[] cases = Directory
            .EnumerateDirectories(Path.Combine(corpusRoot, "cases"))
            .Select(Path.GetFileName)
            .Where(item => item is not null)
            .Select(item => item!)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var labels = cases
            .Select(caseName => CorpusLabelReader.Read(
                Path.Combine(corpusRoot, "cases", caseName, "labels.json"),
                ResourceLimits.Default))
            .ToArray();

        Assert.InRange(labels.Sum(item => item.Pairs.Length), 200, 500);
        Assert.Equal(
            [
                "assignment-ambiguity",
                "duplicate-fingerprints",
                "eslint-real-mutation",
                "explicit-renames",
                "github-supported-subset",
                "line-shifts",
                "malformed-json",
                "message-modifications",
                "missing-fingerprints",
                "new-and-resolved",
                "repository-root-changes",
                "stable-identities",
                "two-findings-one-line",
                "unsupported-offset-region",
            ],
            cases);
        Assert.Contains(labels, item => item.ExpectedAmbiguous.Count > 0);
        Assert.Contains(labels, item => item.ExpectedResolved.Count > 0);
        Assert.Contains(labels, item => item.ExpectedNew.Count > 0);
        Assert.Contains(labels, item => item.ExpectedInvalidInputs.Count > 0);
        Assert.Contains(
            labels,
            item =>
                !item.ExpectedDiagnostics.IsDefault
                && item.ExpectedDiagnostics.Length > 0);
        Assert.Contains(
            labels,
            item =>
                !item.ExpectedDiagnostics.IsDefault
                && item.ExpectedDiagnostics.IsEmpty);
        Assert.Contains(
            labels,
            item =>
                !item.ExpectedExplanations.IsDefault
                && item.ExpectedExplanations.Length > 0);

        string producerNotes = File.ReadAllText(
            Path.Combine(
                corpusRoot,
                "cases",
                "eslint-real-mutation",
                "notes.md"));
        Assert.Contains(
            "@microsoft/eslint-formatter-sarif",
            producerNotes,
            StringComparison.Ordinal);
        Assert.Contains("MIT", producerNotes, StringComparison.Ordinal);
        Assert.Contains(
            "--output-file output.sarif",
            producerNotes,
            StringComparison.Ordinal);
        Assert.True(
            File.Exists(
                Path.Combine(
                    corpusRoot,
                    "cases",
                    "eslint-real-mutation",
                    "producer-input",
                    "baseline.js")));
    }

    [Fact]
    public async Task Every_label_resolves_and_current_corpus_passes()
    {
        var result = await new CorpusRunner()
            .RunAsync(
                new CorpusRunRequest(CorpusTestPaths.FindCorpusRoot()),
                TestContext.Current.CancellationToken);

        Assert.True(
            result.Passed,
            string.Join(Environment.NewLine, result.Failures));
        Assert.Equal(224, result.Aggregate.LabelledPairs);
        Assert.Equal(224, result.Aggregate.TruePositives);
        Assert.Equal(0, result.Aggregate.FalsePositives);
        Assert.Equal(0, result.Aggregate.FalseNegatives);
        Assert.Equal(0, result.Aggregate.SilentAmbiguousMatches);
        Assert.Equal(1m, result.Aggregate.Precision);
        Assert.Equal(1m, result.Aggregate.Recall);
        Assert.All(result.Cases, item => Assert.True(item.Passed));
        Assert.All(result.Cases, item => Assert.Empty(item.ExpectationFailures));
        Assert.Contains(
            result.Cases,
            item =>
                item.DiagnosticExpectationsAsserted
                && item.ExpectedDiagnosticCount > 0);
        Assert.Contains(
            result.Cases,
            item =>
                item.DiagnosticExpectationsAsserted
                && item.ExpectedDiagnosticCount == 0);
        Assert.Contains(
            result.Cases,
            item =>
                item.ExplanationExpectationsAsserted
                && item.ExpectedExplanationCount > 0);
        Assert.All(
            result.Cases,
            item =>
            {
                Assert.Equal(64, item.Artifact.Sha256.Length);
                Assert.Equal((byte)'\n', item.Artifact.Json[^1]);
                using var artifact = JsonDocument.Parse(
                    item.Artifact.Json.ToArray());
                Assert.Equal(JsonValueKind.Object, artifact.RootElement.ValueKind);
            });
        Assert.Contains(
            result.Cases,
            item => item.Artifact.Kind == "comparison");
        Assert.Contains(
            result.Cases,
            item => item.Artifact.Kind == "invalid-input-diagnostics");
    }

    [Fact]
    public async Task Repeated_corpus_runs_produce_identical_utf8_bytes()
    {
        var request = new CorpusRunRequest(CorpusTestPaths.FindCorpusRoot());
        var runner = new CorpusRunner();
        var first = await runner.RunAsync(
            request,
            TestContext.Current.CancellationToken);
        var second = await runner.RunAsync(
            request,
            TestContext.Current.CancellationToken);
        byte[] firstBytes = CorpusRunReportSerializer.Serialize(first);
        byte[] secondBytes = CorpusRunReportSerializer.Serialize(second);

        Assert.True(firstBytes.AsSpan().SequenceEqual(secondBytes));
        Assert.NotEqual(0xEF, firstBytes[0]);
        Assert.DoesNotContain((byte)'\r', firstBytes);
        Assert.Equal((byte)'\n', firstBytes[^1]);
    }

    [Fact]
    public async Task Valid_configuration_diagnostics_are_asserted_and_retained()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            $"sarif-regress-corpus-{Guid.NewGuid():N}");
        string caseRoot = Path.Combine(root, "cases", "configuration-warning");
        Directory.CreateDirectory(caseRoot);
        try
        {
            const string sarif =
                """
                {
                  "version": "2.1.0",
                  "runs": [{
                    "tool": {
                      "driver": {
                        "name": "Configuration Corpus Test"
                      }
                    },
                    "results": []
                  }]
                }
                """;
            File.WriteAllText(
                Path.Combine(caseRoot, "baseline.sarif"),
                sarif);
            File.WriteAllText(
                Path.Combine(caseRoot, "candidate.sarif"),
                sarif);
            File.WriteAllText(
                Path.Combine(caseRoot, "config.json"),
                """
                {
                  "schemaVersion": "1",
                  "future": true
                }
                """);
            File.WriteAllText(
                Path.Combine(caseRoot, "labels.json"),
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
                    "message": "The configuration property \"future\" is not supported and was ignored.",
                    "jsonPointer": "/future"
                  }],
                  "expectedExplanations": []
                }
                """);

            var result = await new CorpusRunner().RunAsync(
                new CorpusRunRequest(root),
                TestContext.Current.CancellationToken);

            Assert.True(
                result.Passed,
                string.Join(Environment.NewLine, result.Failures));
            var caseRun = Assert.Single(result.Cases);
            Assert.True(caseRun.DiagnosticExpectationsAsserted);
            Assert.Equal(1, caseRun.ExpectedDiagnosticCount);
            using var artifact = JsonDocument.Parse(
                caseRun.Artifact.Json.ToArray());
            var diagnostic = Assert.Single(
                artifact.RootElement
                    .GetProperty("diagnostics")
                    .EnumerateArray()
                    .ToArray());
            Assert.Equal(
                "UNSUPPORTED0001",
                diagnostic.GetProperty("code").GetString());
            Assert.Equal(
                "configuration",
                diagnostic
                    .GetProperty("sourceRef")
                    .GetProperty("input")
                    .GetString());
            Assert.Equal(
                "/future",
                diagnostic
                    .GetProperty("sourceRef")
                    .GetProperty("jsonPointer")
                    .GetString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

internal static class CorpusTestPaths
{
    public static string FindCorpusRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(
                directory.FullName,
                "corpus",
                "schema",
                "labels.schema.json");
            if (File.Exists(candidate))
            {
                return Path.Combine(directory.FullName, "corpus");
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate the tracked corpus from the test output directory.");
    }
}
