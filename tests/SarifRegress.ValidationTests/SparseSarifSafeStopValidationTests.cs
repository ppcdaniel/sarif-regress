using System.Collections.Immutable;
using System.Text.Json;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Configuration;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.ValidationTests;

public sealed class SparseSarifSafeStopValidationTests
{
    [Fact]
    public async Task Authentic_pmd_exact_signature_audit_exposes_full_fallback_failure()
    {
        string repositoryRoot = ValidationTestRepository.FindRoot();
        string caseRoot = PmdCaseRoot(repositoryRoot);
        SarifRegressConfiguration configuration = await ReadConfigurationAsync(caseRoot);
        ImmutableArray<SparseEndpoint> baseline = await ReadEndpointsAsync(
            caseRoot,
            "baseline.sarif",
            InputKind.Baseline,
            configuration);
        ImmutableArray<SparseEndpoint> candidate = await ReadEndpointsAsync(
            caseRoot,
            "candidate.sarif",
            InputKind.Candidate,
            configuration);
        CorpusLabels labels = CorpusLabelReader.Read(
            Path.Combine(caseRoot, "labels.json"),
            ResourceLimits.Default);

        SparseIntersection[] intersections = baseline
            .Join(
                candidate,
                item => item.Signature,
                item => item.Signature,
                (left, right) => new SparseIntersection(left, right))
            .OrderBy(item => item.Baseline.Key, StringComparer.Ordinal)
            .ThenBy(item => item.Candidate.Key, StringComparer.Ordinal)
            .ToArray();
        HashSet<string> labelledBaselineKeys = labels.Pairs
            .Select(item => item.BaselineKey)
            .ToHashSet(StringComparer.Ordinal);
        HashSet<string> labelledCandidateKeys = labels.Pairs
            .Select(item => item.CandidateKey)
            .ToHashSet(StringComparer.Ordinal);
        HashSet<PairKey> labelledPairs = labels.Pairs
            .Select(item => new PairKey(item.BaselineKey, item.CandidateKey))
            .ToHashSet();
        SparseIntersection[] labelledEndpointIntersections = intersections
            .Where(item => labelledBaselineKeys.Contains(item.Baseline.Key)
                && labelledCandidateKeys.Contains(item.Candidate.Key))
            .ToArray();
        SparseIntersection[] correct = labelledEndpointIntersections
            .Where(item => labelledPairs.Contains(new PairKey(
                item.Baseline.Key,
                item.Candidate.Key)))
            .ToArray();
        SparseIntersection[] falseIntersections = labelledEndpointIntersections
            .Except(correct)
            .ToArray();
        SparseIntersection[] ambiguous = intersections
            .Where(item => labels.ExpectedAmbiguous.Contains(item.Baseline.Key)
                && labels.ExpectedAmbiguous.Contains(item.Candidate.Key))
            .ToArray();

        Assert.Equal(10, intersections.Length);
        Assert.Equal(8, labelledEndpointIntersections.Length);
        Assert.Equal(
            [
                "baseline:0:5->candidate:0:5@4",
                "baseline:0:6->candidate:0:6@6",
                "baseline:0:7->candidate:0:7@8",
                "baseline:0:8->candidate:0:8@10",
                "baseline:0:9->candidate:0:9@12",
            ],
            correct.Select(FormatIntersection).ToArray());
        Assert.Equal(
            [
                "baseline:0:17->candidate:0:15@34",
                "baseline:0:18->candidate:0:16@36",
                "baseline:0:19->candidate:0:17@38",
            ],
            falseIntersections.Select(FormatIntersection).ToArray());
        Assert.Equal(
            [
                "baseline:0:0->candidate:0:0@4",
                "baseline:0:1->candidate:0:1@6",
            ],
            ambiguous.Select(FormatIntersection).ToArray());
        Assert.Equal(
            intersections.Length,
            correct.Length + falseIntersections.Length + ambiguous.Length);
        Assert.Equal(0.625m, (decimal)correct.Length / labelledEndpointIntersections.Length);
        Assert.All(
            intersections,
            intersection =>
            {
                Assert.Single(baseline, item => item.Signature == intersection.Baseline.Signature);
                Assert.Single(candidate, item => item.Signature == intersection.Candidate.Signature);
            });

        int truePositives = correct.Length;
        int falsePositives = intersections.Length - truePositives;
        int falseNegatives = labels.Pairs.Length - truePositives;
        int silentlyMatchedAmbiguousEndpoints = ambiguous
            .SelectMany(item => new[] { item.Baseline.Key, item.Candidate.Key })
            .Distinct(StringComparer.Ordinal)
            .Count();
        Assert.Equal(5, truePositives);
        Assert.Equal(5, falsePositives);
        Assert.Equal(20, falseNegatives);
        Assert.Equal(0.5m, (decimal)truePositives / intersections.Length);
        Assert.Equal(0.2m, (decimal)truePositives / labels.Pairs.Length);
        Assert.Equal(4, silentlyMatchedAmbiguousEndpoints);

        Dictionary<BucketKey, int> baselineBucketCounts = baseline
            .GroupBy(item => item.Bucket)
            .ToDictionary(group => group.Key, group => group.Count());
        Dictionary<BucketKey, int> candidateBucketCounts = candidate
            .GroupBy(item => item.Bucket)
            .ToDictionary(group => group.Key, group => group.Count());
        Assert.DoesNotContain(intersections, item =>
            baselineBucketCounts[item.Baseline.Bucket] == 1
            && candidateBucketCounts[item.Candidate.Bucket] == 1);
    }

    [Fact]
    public async Task Authentic_pmd_holdout_emits_zero_matches_and_no_sparse_tier()
    {
        string repositoryRoot = ValidationTestRepository.FindRoot();
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            CopyPmdCase(repositoryRoot, temporaryRoot);
            CorpusRunResult result = await new CorpusRunner().RunAsync(
                new CorpusRunRequest(
                    temporaryRoot,
                    CorpusThresholds.Mvp,
                    ResourceLimits.Default),
                TestContext.Current.CancellationToken);
            CorpusCaseRun caseRun = Assert.Single(result.Cases);

            Assert.Equal("pmd", caseRun.CaseName);
            Assert.Equal(0, caseRun.Metrics.TruePositives);
            Assert.Equal(0, caseRun.Metrics.FalsePositives);
            Assert.Equal(25, caseRun.Metrics.FalseNegatives);
            Assert.Equal(4, caseRun.Metrics.ExpectedAmbiguous);
            Assert.Equal(0, caseRun.Metrics.CorrectAmbiguous);
            Assert.Equal(0, caseRun.Metrics.SilentAmbiguousMatches);
            Assert.Equal(4, caseRun.Metrics.MissingAmbiguous);
            Assert.Equal(0, caseRun.Metrics.UnexpectedAmbiguous);
            Assert.False(caseRun.Passed);
            Assert.False(result.Passed);

            using JsonDocument document = JsonDocument.Parse(
                caseRun.Artifact.Json.ToArray());
            JsonElement[] findings = document.RootElement
                .GetProperty("findings")
                .EnumerateArray()
                .ToArray();
            Assert.Equal(60, findings.Length);
            Assert.DoesNotContain(findings, IsPairedDecision);
            Assert.All(
                findings,
                finding =>
                {
                    JsonElement decision = finding.GetProperty("decision");
                    Assert.Equal(
                        ProductInformation.MatcherAlgorithmVersion,
                        decision.GetProperty("matcherAlgorithmVersion").GetString());
                    Assert.False(ContainsSparseContinuity(
                        decision.GetProperty("precedenceTier").GetString()));
                });
            Assert.DoesNotContain(
                findings.SelectMany(finding =>
                    finding.GetProperty("evidence").EnumerateArray()),
                evidence => ContainsSparseContinuity(
                        evidence.GetProperty("kind").GetString())
                    || ContainsSparseContinuity(
                        evidence.GetProperty("algorithmVersion").GetString()));
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    private static async Task<SarifRegressConfiguration> ReadConfigurationAsync(
        string caseRoot)
    {
        await using FileStream stream = File.OpenRead(
            Path.Combine(caseRoot, "config.json"));
        ConfigurationReadResult result = await new SarifConfigurationReader().ReadAsync(
            stream,
            TestContext.Current.CancellationToken);
        Assert.True(result.IsValid);
        return Assert.IsType<SarifRegressConfiguration>(result.Configuration);
    }

    private static async Task<ImmutableArray<SparseEndpoint>> ReadEndpointsAsync(
        string caseRoot,
        string fileName,
        InputKind input,
        SarifRegressConfiguration configuration)
    {
        await using FileStream stream = File.OpenRead(Path.Combine(caseRoot, fileName));
        SarifIngestionResult result = await new SarifIngestor().IngestAsync(
            stream,
            new SarifIngestionRequest(input, fileName, configuration),
            TestContext.Current.CancellationToken);
        Assert.True(result.IsValid);
        Assert.Equal(30, result.ComparisonInput.Findings.Length);

        var endpoints = ImmutableArray.CreateBuilder<SparseEndpoint>(
            result.ComparisonInput.Findings.Length);
        foreach (Finding finding in result.ComparisonInput.Findings)
        {
            PrimaryLocation location = Assert.IsType<PrimaryLocation>(
                finding.PrimaryLocation);
            Assert.NotNull(location.Path.RepositoryRelativePath);
            Region region = Assert.IsType<Region>(location.Region);
            var signature = new SparseSignature(
                finding.Producer.AutomaticIdentity,
                finding.Rule.CanonicalId,
                location.Path.CanonicalUri,
                region,
                finding.Message.CanonicalText);
            endpoints.Add(new SparseEndpoint(
                finding.FindingKey,
                new BucketKey(
                    finding.Producer.AutomaticIdentity,
                    finding.Rule.CanonicalId),
                signature));
        }

        return endpoints.ToImmutable();
    }

    private static string PmdCaseRoot(string repositoryRoot) => Path.Combine(
        repositoryRoot,
        "validation",
        "holdout",
        "cases",
        "pmd");

    private static void CopyPmdCase(string repositoryRoot, string destinationRoot)
    {
        string source = Path.Combine(
            repositoryRoot,
            "validation",
            "holdout",
            "cases",
            "pmd");
        string destination = Path.Combine(destinationRoot, "cases", "pmd");
        Directory.CreateDirectory(destination);
        foreach (string name in new[]
        {
            "baseline.sarif",
            "candidate.sarif",
            "config.json",
            "labels.json",
        })
        {
            File.Copy(Path.Combine(source, name), Path.Combine(destination, name));
        }
    }

    private static bool IsPairedDecision(JsonElement finding) =>
        finding.GetProperty("baseline").ValueKind != JsonValueKind.Null
        && finding.GetProperty("candidate").ValueKind != JsonValueKind.Null;

    private static bool ContainsSparseContinuity(string? value) =>
        value?.Contains("sparse", StringComparison.OrdinalIgnoreCase) ?? false;

    private static string FormatIntersection(SparseIntersection intersection) =>
        $"{intersection.Baseline.Key}->{intersection.Candidate.Key}@"
        + intersection.Baseline.Signature.Region.StartLine;

    private readonly record struct BucketKey(string Producer, string Rule);

    private readonly record struct SparseSignature(
        string ProducerIdentity,
        string Rule,
        string CanonicalUri,
        Region Region,
        string Message);

    private readonly record struct SparseEndpoint(
        string Key,
        BucketKey Bucket,
        SparseSignature Signature);

    private readonly record struct SparseIntersection(
        SparseEndpoint Baseline,
        SparseEndpoint Candidate);

    private readonly record struct PairKey(string Baseline, string Candidate);
}
