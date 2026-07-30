using SarifRegress.Core.Configuration;
using SarifRegress.Core.Paths;
using SarifRegress.Match;
using SarifRegress.Sarif.Canonicalization;

namespace SarifRegress.UnitTests;

public sealed class PathConfigurationIndexTests
{
    [Fact]
    public void Rebase_lookup_work_is_independent_of_nonmatching_configuration_count()
    {
        var target = new PathRebase("src/", "repo:/");
        var small = CompletePrefixRebaseIndex.Create(
            [target],
            PathCaseSensitivity.Sensitive);
        var largeEntries = Enumerable
            .Range(0, 4096)
            .Select(index => new PathRebase(
                $"noise/{index:D4}/",
                $"external:/{index:D4}/"))
            .Append(target)
            .ToArray();
        var large = CompletePrefixRebaseIndex.Create(
            largeEntries,
            PathCaseSensitivity.Sensitive);

        var smallMatch = small.FindLongest(
            "src/file.cs",
            out var smallMetrics);
        var largeMatch = large.FindLongest(
            "src/file.cs",
            out var largeMetrics);

        Assert.Equal(target, smallMatch);
        Assert.Equal(target, largeMatch);
        Assert.Equal(smallMetrics, largeMetrics);
        Assert.Equal(2, largeMetrics.TransitionProbeCount);
        Assert.Equal(4, largeMetrics.CharacterComparisonCount);
        Assert.InRange(
            large.NodeCount,
            1,
            (2 * large.ConfiguredEntryCount) + 1);
        Assert.Equal(large.NodeCount - 1, large.EdgeCount);
    }

    [Fact]
    public void Compressed_rebase_structure_scales_with_entries_not_prefix_characters()
    {
        var longStem = new string('a', 4096);
        var entries = Enumerable
            .Range(0, 256)
            .Select(index => new PathRebase(
                $"{longStem}/{index:D3}/",
                $"repo:/{index:D3}/"))
            .ToArray();

        var index = CompletePrefixRebaseIndex.Create(
            entries,
            PathCaseSensitivity.Sensitive);

        Assert.Equal(entries.Length, index.ConfiguredEntryCount);
        Assert.InRange(
            index.NodeCount,
            1,
            (2 * entries.Length) + 1);
        Assert.True(
            index.BuildCharacterVisitCount
                > index.NodeCount * 1000);
    }

    [Fact]
    public void Rebase_index_preserves_longest_prefix_and_case_collision_precedence()
    {
        var configuration = CreateConfiguration(
            pathRebases:
            [
                new PathRebase("src/", "external:/short/"),
                new PathRebase("SRC/legacy/", "repo:/upper/"),
                new PathRebase("src/legacy/", "repo:/lower/"),
            ],
            pathAliases: [],
            PathCaseSensitivity.AsciiInsensitive);
        var index = CompletePrefixRebaseIndex.Create(
            configuration.PathRebases,
            configuration.Matching.PathCaseSensitivity);

        var match = index.FindLongest(
            "sRc/LeGaCy/file.cs",
            out var metrics);

        Assert.NotNull(match);
        Assert.Equal("SRC/legacy/", match.From);
        Assert.Equal("repo:/upper/", match.To);
        Assert.InRange(
            metrics.CharacterComparisonCount,
            1,
            "sRc/LeGaCy/file.cs".Length);
    }

    [Fact]
    public void Alias_lookup_work_is_independent_of_same_baseline_nonmatches()
    {
        var target = new PathAlias("src/", "target/");
        var small = PathAliasIndex.Create(
            [target],
            PathCaseSensitivity.Sensitive);
        var largeEntries = Enumerable
            .Range(0, 4096)
            .Select(index => new PathAlias(
                "src/",
                $"noise/{index:D4}/"))
            .Append(target)
            .OrderByDescending(alias => alias.Baseline.Length)
            .ThenBy(alias => alias.Baseline, StringComparer.Ordinal)
            .ThenBy(alias => alias.Candidate, StringComparer.Ordinal)
            .ToArray();
        var large = PathAliasIndex.Create(
            largeEntries,
            PathCaseSensitivity.Sensitive);

        var smallMatch = small.Find(
            "src/file.cs",
            "target/file.cs",
            out var smallMetrics);
        var largeMatch = large.Find(
            "src/file.cs",
            "target/file.cs",
            out var largeMetrics);

        Assert.Equal(target, smallMatch);
        Assert.Equal(target, largeMatch);
        Assert.Equal(smallMetrics, largeMetrics);
        Assert.Equal(1, largeMetrics.TerminalPairProbeCount);
        Assert.InRange(
            large.NodeCount,
            2,
            (4 * large.ConfiguredEntryCount) + 2);
        Assert.Equal(large.NodeCount - 2, large.EdgeCount);
    }

    [Fact]
    public void Alias_index_preserves_case_collision_configuration_precedence()
    {
        var configuration = CreateConfiguration(
            pathRebases: [],
            pathAliases:
            [
                new PathAlias("src/", "target/"),
                new PathAlias("SRC/", "TARGET/"),
            ],
            PathCaseSensitivity.AsciiInsensitive);
        var index = PathAliasIndex.Create(
            configuration.PathAliases,
            configuration.Matching.PathCaseSensitivity);

        var match = index.Find(
            "sRc/file.cs",
            "tArGeT/file.cs",
            out var metrics);

        Assert.NotNull(match);
        Assert.Equal("SRC/", match.Baseline);
        Assert.Equal("TARGET/", match.Candidate);
        Assert.Equal(1, metrics.TerminalPairProbeCount);
        Assert.Equal(2, index.ConfiguredEntryCount);
        Assert.InRange(index.NodeCount, 2, 10);
    }

    [Fact]
    public void Alias_index_preserves_longest_baseline_prefix_precedence()
    {
        var configuration = CreateConfiguration(
            pathRebases: [],
            pathAliases:
            [
                new PathAlias("src/", "dst/"),
                new PathAlias(
                    "src/legacy/",
                    "dst/legacy/"),
            ],
            PathCaseSensitivity.Sensitive);
        var index = PathAliasIndex.Create(
            configuration.PathAliases,
            configuration.Matching.PathCaseSensitivity);

        var match = index.Find(
            "src/legacy/file.cs",
            "dst/legacy/file.cs",
            out var metrics);

        Assert.NotNull(match);
        Assert.Equal("src/legacy/", match.Baseline);
        Assert.Equal("dst/legacy/", match.Candidate);
        Assert.Equal(2, metrics.TerminalPairProbeCount);
    }

    private static SarifRegressConfiguration CreateConfiguration(
        IEnumerable<PathRebase> pathRebases,
        IEnumerable<PathAlias> pathAliases,
        PathCaseSensitivity caseSensitivity)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            defaults.RepositoryRoot,
            pathRebases,
            pathAliases,
            defaults.RuleAliases,
            defaults.Matching with
            {
                PathCaseSensitivity = caseSensitivity,
            },
            defaults.Policy,
            defaults.Reporting,
            defaults.Limits);
    }
}
