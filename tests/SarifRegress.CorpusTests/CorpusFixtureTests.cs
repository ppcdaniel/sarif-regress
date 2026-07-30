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
                "explicit-renames",
                "line-shifts",
                "malformed-json",
                "message-modifications",
                "missing-fingerprints",
                "new-and-resolved",
                "repository-root-changes",
                "stable-identities",
                "two-findings-one-line",
            ],
            cases);
        Assert.Contains(labels, item => item.ExpectedAmbiguous.Count > 0);
        Assert.Contains(labels, item => item.ExpectedResolved.Count > 0);
        Assert.Contains(labels, item => item.ExpectedNew.Count > 0);
        Assert.Contains(labels, item => item.ExpectedInvalidInputs.Count > 0);
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
        Assert.Equal(220, result.Aggregate.LabelledPairs);
        Assert.Equal(220, result.Aggregate.TruePositives);
        Assert.Equal(0, result.Aggregate.FalsePositives);
        Assert.Equal(0, result.Aggregate.FalseNegatives);
        Assert.Equal(0, result.Aggregate.SilentAmbiguousMatches);
        Assert.Equal(1m, result.Aggregate.Precision);
        Assert.Equal(1m, result.Aggregate.Recall);
        Assert.All(result.Cases, item => Assert.True(item.Passed));
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
        Assert.Equal((byte)'\n', firstBytes[^1]);
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
