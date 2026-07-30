using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Paths;
using SarifRegress.Sarif.Fingerprints;

namespace SarifRegress.UnitTests;

public sealed class FingerprintProcessorTests
{
    [Fact]
    public void Import_preserves_full_and_partial_values_with_the_same_name()
    {
        var result = FingerprintProcessor.Import(
            new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["primaryLocationLineHash/v2"] = "full",
            },
            new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["primaryLocationLineHash/v2"] = "partial",
            });

        Assert.Collection(
            result.Fingerprints,
            item => Assert.Equal(
                ProducerFingerprintSource.Fingerprint,
                item.Source),
            item => Assert.Equal(
                ProducerFingerprintSource.PartialFingerprint,
                item.Source));
        Assert.Contains(
            result.Fingerprints,
            item =>
                item.Source == ProducerFingerprintSource.Fingerprint &&
                item.Value == "full" &&
                item.Family == "primaryLocationLineHash" &&
                item.Version == 2);
        Assert.Contains(
            result.Fingerprints,
            item =>
                item.Source == ProducerFingerprintSource.PartialFingerprint &&
                item.Value == "partial");
        Assert.All(
            result.Fingerprints,
            item => Assert.Equal(
                FingerprintReliability.Unknown,
                item.Reliability));
        Assert.Empty(result.Diagnostics);
    }

    [Fact]
    public void Single_import_remains_unassessed_until_collision_analysis()
    {
        var result = FingerprintProcessor.Import(
            fingerprints: null,
            partialFingerprints: new Dictionary<string, string?>(
                StringComparer.Ordinal)
            {
                ["primaryLocationLineHash/v2"] = "partial",
            });

        var fingerprint = Assert.Single(result.Fingerprints);
        Assert.Equal(FingerprintReliability.Unknown, fingerprint.Reliability);
        Assert.Empty(result.Diagnostics);
    }

    [Fact]
    public void Invalid_single_import_emits_the_stable_diagnostic()
    {
        var result = FingerprintProcessor.Import(
            fingerprints: new Dictionary<string, string?>(
                StringComparer.Ordinal)
            {
                ["primaryLocationLineHash/v2"] = null,
            },
            partialFingerprints: null);

        Assert.Empty(result.Fingerprints);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal("CANON0020", diagnostic.Code);
    }

    [Fact]
    public void Duplicate_values_in_a_run_and_rule_bucket_are_degraded()
    {
        var first = CreateFinding("baseline:0:0", "same", startLine: 10);
        var second = CreateFinding("baseline:0:1", "same", startLine: 20);
        var unique = CreateFinding("baseline:0:2", "unique", startLine: 30);

        var assessed = FingerprintProcessor.AssessReliability(
            [first, second, unique]);

        Assert.Equal(
            FingerprintReliability.Degraded,
            assessed[0].ProducerFingerprints[0].Reliability);
        Assert.Equal(
            FingerprintReliability.Degraded,
            assessed[1].ProducerFingerprints[0].Reliability);
        Assert.Equal(
            FingerprintReliability.High,
            assessed[2].ProducerFingerprints[0].Reliability);
    }

    [Fact]
    public void Same_name_and_value_on_one_finding_is_not_a_collision()
    {
        var finding = CreateFinding(
            "baseline:0:0",
            "same",
            startLine: 10,
            duplicateAcrossSources: true);

        var assessed = Assert.Single(
            FingerprintProcessor.AssessReliability([finding]));

        Assert.Equal(2, assessed.ProducerFingerprints.Length);
        Assert.All(
            assessed.ProducerFingerprints,
            fingerprint => Assert.Equal(
                FingerprintReliability.High,
                fingerprint.Reliability));
    }

    [Fact]
    public void Derived_fingerprint_excludes_absolute_line_numbers()
    {
        var first = CreateFinding("baseline:0:0", "one", startLine: 10);
        var second = CreateFinding("baseline:0:1", "two", startLine: 300);

        var firstFingerprint =
            FingerprintProcessor.DeriveRulePathContext(first);
        var secondFingerprint =
            FingerprintProcessor.DeriveRulePathContext(second);

        Assert.NotNull(firstFingerprint);
        Assert.Equal(firstFingerprint?.Name, secondFingerprint?.Name);
        Assert.Equal(firstFingerprint?.Value, secondFingerprint?.Value);
        Assert.Equal(
            "sarifregress/rule-path-context/v2",
            firstFingerprint?.Name);
    }

    [Fact]
    public void Derived_fingerprint_requires_repository_path_and_context()
    {
        var finding = CreateFinding(
            "baseline:0:0",
            "value",
            startLine: 1,
            repositoryPath: null,
            contextHash: null);

        Assert.Null(FingerprintProcessor.DeriveRulePathContext(finding));
    }

    private static Finding CreateFinding(
        string key,
        string fingerprintValue,
        int startLine,
        string? repositoryPath = "src/a.cs",
        string? contextHash = "context",
        bool duplicateAcrossSources = false)
    {
        var sourceReference = new SourceReference(
            InputKind.Baseline,
            0,
            int.Parse(key.AsSpan(key.LastIndexOf(':') + 1), provider: null),
            $"/runs/0/results/{key[(key.LastIndexOf(':') + 1)..]}");
        var path = new CanonicalPath(
            repositoryPath ?? "/external/a.cs",
            repositoryPath,
            repositoryPath is null
                ? "file:///external/a.cs"
                : $"repo://{repositoryPath}",
            repositoryPath,
            repositoryPath is null
                ? PathKind.PosixAbsolute
                : PathKind.RepositoryRelative);
        return new Finding(
            key,
            sourceReference,
            new RunIdentity(0, null, "baseline:0"),
            new ProducerIdentity(
                "Tool",
                "1.0",
                "tool",
                AutomationCategory: null,
                AutomaticIdentity: "tool"),
            new RuleIdentity("R1", "tool/R1", false),
            new PrimaryLocation(
                path,
                new Region(startLine, 1, startLine, 2),
                EmbeddedSnippet: null),
            new MessageIdentity(
                "message",
                "message",
                "message",
                ImmutableArray<string>.Empty),
            duplicateAcrossSources
                ? [
                    new ProducerFingerprint(
                        "primaryLocationLineHash/v1",
                        "primaryLocationLineHash",
                        1,
                        fingerprintValue,
                        FingerprintReliability.Unknown,
                        ProducerFingerprintSource.Fingerprint),
                    new ProducerFingerprint(
                        "primaryLocationLineHash/v1",
                        "primaryLocationLineHash",
                        1,
                        fingerprintValue,
                        FingerprintReliability.Unknown,
                        ProducerFingerprintSource.PartialFingerprint),
                ]
                : [
                    new ProducerFingerprint(
                        "primaryLocationLineHash/v1",
                        "primaryLocationLineHash",
                        1,
                        fingerprintValue,
                        FingerprintReliability.Unknown,
                        ProducerFingerprintSource.PartialFingerprint),
                ],
            derivedFingerprints: [],
            contextHash is null
                ? null
                : new ContextEvidence(
                    contextHash,
                    null,
                    null,
                    startLine,
                    startLine));
    }
}
