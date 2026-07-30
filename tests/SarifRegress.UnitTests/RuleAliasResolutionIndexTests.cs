using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Utility;
using SarifRegress.Sarif.Ingestion;

namespace SarifRegress.UnitTests;

public sealed class RuleAliasResolutionIndexTests
{
    [Theory]
    [InlineData(InputKind.Baseline)]
    [InlineData(InputKind.Candidate)]
    public void Lookup_work_is_independent_of_alias_count_per_result(
        InputKind input)
    {
        const int aliasCount = 512;
        const int lookupCount = 4096;
        var aliases = Enumerable.Range(0, aliasCount)
            .Select(item => new RuleAlias(
                $"Baseline Scanner {item}",
                $"baseline/{item}",
                $"Candidate Scanner {item}",
                $"candidate/{item}"))
            .ToArray();
        var aliasIndex = RuleAliasResolutionIndex.Create(input, aliases);
        var unmatchedProducer = ProducerIdentityResolver.Resolve(
            "Unconfigured Scanner");

        for (var lookup = 0; lookup < lookupCount; lookup++)
        {
            _ = aliasIndex.Resolve(
                unmatchedProducer.AutomaticIdentity,
                $"missing/{lookup}");
        }

        Assert.Equal(aliasCount, aliasIndex.BuildAliasVisitCount);
        Assert.Equal((long)lookupCount, aliasIndex.LookupProbeCount);
        Assert.Equal(
            (long)aliasCount + lookupCount,
            aliasIndex.BuildAliasVisitCount + aliasIndex.LookupProbeCount);
    }

    [Fact]
    public void Conflicting_baseline_aliases_choose_first_configuration_entry()
    {
        var configuration = CreateConfiguration(
        [
            new RuleAlias(
                "Scanner",
                "R1",
                "Zed Candidate",
                "Z1"),
            new RuleAlias(
                "Scanner",
                "R1",
                "Alpha Candidate",
                "A1"),
        ]);
        var expectedAlias = configuration.RuleAliases[0];
        var producer = ProducerIdentityResolver.Resolve("Scanner");
        var aliasIndex = RuleAliasResolutionIndex.Create(
            InputKind.Baseline,
            configuration.RuleAliases);

        Assert.Equal("Alpha Candidate", expectedAlias.CandidateProducer);
        Assert.Equal(
            CreateCanonicalAliasId(expectedAlias),
            aliasIndex.Resolve(producer.AutomaticIdentity, "R1"));
        Assert.Equal(2, aliasIndex.BuildAliasVisitCount);
        Assert.Equal(1L, aliasIndex.LookupProbeCount);
    }

    [Fact]
    public void Conflicting_candidate_aliases_choose_first_configuration_entry()
    {
        var configuration = CreateConfiguration(
        [
            new RuleAlias(
                "Zed Baseline",
                "Z1",
                "Scanner",
                "R1"),
            new RuleAlias(
                "Alpha Baseline",
                "A1",
                "Scanner",
                "R1"),
        ]);
        var expectedAlias = configuration.RuleAliases[0];
        var producer = ProducerIdentityResolver.Resolve("Scanner");
        var aliasIndex = RuleAliasResolutionIndex.Create(
            InputKind.Candidate,
            configuration.RuleAliases);

        Assert.Equal("Alpha Baseline", expectedAlias.BaselineProducer);
        Assert.Equal(
            CreateCanonicalAliasId(expectedAlias),
            aliasIndex.Resolve(producer.AutomaticIdentity, "R1"));
        Assert.Equal(2, aliasIndex.BuildAliasVisitCount);
        Assert.Equal(1L, aliasIndex.LookupProbeCount);
    }

    [Fact]
    public void Exact_duplicate_aliases_preserve_the_same_resolution()
    {
        var alias = new RuleAlias(
            "Baseline Scanner",
            "B1",
            "Candidate Scanner",
            "C1");
        var aliasIndex = RuleAliasResolutionIndex.Create(
            InputKind.Baseline,
            new[] { alias, alias });
        var producer = ProducerIdentityResolver.Resolve(
            alias.BaselineProducer);

        Assert.Equal(
            CreateCanonicalAliasId(alias),
            aliasIndex.Resolve(
                producer.AutomaticIdentity,
                alias.BaselineRule));
        Assert.Equal(2, aliasIndex.BuildAliasVisitCount);
        Assert.Equal(1L, aliasIndex.LookupProbeCount);
    }

    private static SarifRegressConfiguration CreateConfiguration(
        IEnumerable<RuleAlias> ruleAliases)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            defaults.RepositoryRoot,
            defaults.PathRebases,
            defaults.PathAliases,
            ruleAliases,
            defaults.Matching,
            defaults.Policy,
            defaults.Reporting,
            defaults.Limits);
    }

    private static string CreateCanonicalAliasId(RuleAlias alias)
    {
        var baselineProducer = ProducerIdentityResolver.Resolve(
            alias.BaselineProducer);
        var candidateProducer = ProducerIdentityResolver.Resolve(
            alias.CandidateProducer);
        return "alias/" + VersionedHash.Compute(
            "rule-alias/v2",
            baselineProducer.AutomaticIdentity,
            alias.BaselineRule,
            candidateProducer.AutomaticIdentity,
            alias.CandidateRule);
    }
}
