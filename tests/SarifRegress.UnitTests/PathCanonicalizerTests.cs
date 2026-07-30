using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Paths;
using SarifRegress.Sarif.Canonicalization;

namespace SarifRegress.UnitTests;

public sealed class PathCanonicalizerTests
{
    [Theory]
    [InlineData(@"C:\repo\file.cs", PathKind.DriveAbsolute)]
    [InlineData(@"C:file.cs", PathKind.DriveRelative)]
    [InlineData(@"\repo\file.cs", PathKind.RootRelative)]
    [InlineData(@"\\server\share\file.cs", PathKind.Unc)]
    [InlineData(@"\\?\C:\repo\file.cs", PathKind.Device)]
    [InlineData(@"\\?\UNC\server\share\file.cs", PathKind.DeviceUnc)]
    [InlineData("file:///C:/repo/file.cs", PathKind.FileUri)]
    [InlineData("/repo/file.cs", PathKind.PosixAbsolute)]
    [InlineData("src/file.cs", PathKind.RepositoryRelative)]
    [InlineData("https://example.test/file.cs", PathKind.ExternalUri)]
    public void Classify_is_independent_of_the_host_operating_system(
        string value,
        PathKind expected)
    {
        Assert.Equal(expected, PathCanonicalizer.Classify(value));
    }

    [Fact]
    public void Drive_relative_and_drive_absolute_paths_remain_distinct()
    {
        var canonicalizer = new PathCanonicalizer();

        var driveRelative = canonicalizer.Canonicalize(@"C:file.cs");
        var driveAbsolute = canonicalizer.Canonicalize(@"C:\file.cs");

        Assert.Equal(PathKind.DriveRelative, driveRelative.Kind);
        Assert.Equal(PathKind.DriveAbsolute, driveAbsolute.Kind);
        Assert.NotEqual(driveRelative.CanonicalUri, driveAbsolute.CanonicalUri);
    }

    [Fact]
    public void Configured_rebase_produces_a_repository_uri()
    {
        var configuration = CreateConfiguration(
            repositoryRoot: null,
            pathRebases:
            [
                new PathRebase(
                    "file:///C:/agent/_work/1/s/",
                    "repo:/"),
            ]);
        var canonicalizer = new PathCanonicalizer(configuration);

        var path = canonicalizer.Canonicalize(
            "file:///C:/agent/_work/1/s/src/%41-File.cs");

        Assert.Equal("repo://src/A-File.cs", path.CanonicalUri);
        Assert.Equal("src/A-File.cs", path.RepositoryRelativePath);
        Assert.Contains(
            path.Transformations,
            item => item.Kind == "configured-path-rebase");
        Assert.Contains(
            path.Transformations,
            item => item.Kind == "safe-percent-decode");
    }

    [Fact]
    public void Reserved_percent_escapes_are_not_decoded()
    {
        var path = new PathCanonicalizer()
            .Canonicalize("src/A%20File%2FName.cs");

        Assert.Equal("repo://src/A%20File%2FName.cs", path.CanonicalUri);
        Assert.DoesNotContain(
            path.Transformations,
            item => item.Kind == "safe-percent-decode");
    }

    [Fact]
    public void Rebase_prefix_must_end_on_a_complete_path_segment()
    {
        var canonicalizer = new PathCanonicalizer(
            CreateConfiguration(
                repositoryRoot: null,
                pathRebases:
                [
                    new PathRebase("src", "repo:/"),
                ]));

        var path = canonicalizer.Canonicalize("src-old/file.cs");

        Assert.Equal("repo://src-old/file.cs", path.CanonicalUri);
        Assert.DoesNotContain(
            path.Transformations,
            item => item.Kind == "configured-path-rebase");
    }

    [Fact]
    public void Longest_complete_rebase_prefix_wins()
    {
        var canonicalizer = new PathCanonicalizer(
            CreateConfiguration(
                repositoryRoot: null,
                pathRebases:
                [
                    new PathRebase("file:///agent/", "external:/"),
                    new PathRebase("file:///agent/work/", "repo:/"),
                ]));

        var path = canonicalizer.Canonicalize(
            "file:///agent/work/src/a.cs");

        Assert.Equal("repo://src/a.cs", path.CanonicalUri);
    }

    [Fact]
    public void Resolved_logical_value_is_reclassified_before_namespacing()
    {
        var path = new PathCanonicalizer().Canonicalize(
            "src/a.cs",
            resolvedValue: "/outside/src/a.cs");

        Assert.Equal(PathKind.RepositoryRelative, path.Kind);
        Assert.Null(path.RepositoryRelativePath);
        Assert.Equal("file:///outside/src/a.cs", path.CanonicalUri);
    }

    [Fact]
    public void Repository_root_matching_is_lexical_and_cross_platform()
    {
        var canonicalizer = new PathCanonicalizer(
            CreateConfiguration(repositoryRoot: @"C:\work\repo"));

        var path = canonicalizer.Canonicalize(
            "file:///C:/work/repo/src/a.cs");

        Assert.Equal("repo://src/a.cs", path.CanonicalUri);
        Assert.Equal(PathKind.FileUri, path.Kind);
    }

    [Fact]
    public void Parent_traversal_above_repository_root_fails_closed()
    {
        var sourceReference = new SourceReference(
            InputKind.Baseline,
            0,
            0,
            "/runs/0/results/0/locations/0");

        var path = new PathCanonicalizer().Canonicalize(
            "../../secret.txt",
            sourceReference: sourceReference);

        var diagnostic = Assert.Single(path.Diagnostics);
        Assert.Equal("CANON0001", diagnostic.Code);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Null(path.RepositoryRelativePath);
        Assert.StartsWith(
            "unresolved://repository/",
            path.CanonicalUri,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Configured_ascii_case_semantics_are_explicit_and_recorded()
    {
        var configuration = CreateConfiguration(
            repositoryRoot: null,
            caseSensitivity: PathCaseSensitivity.AsciiInsensitive);

        var path = new PathCanonicalizer(configuration)
            .Canonicalize("SRC/File.CS");

        Assert.Equal("repo://src/file.cs", path.CanonicalUri);
        Assert.Contains(
            path.Transformations,
            item =>
                item.Kind == "configured-ascii-case-fold" &&
                item.IsLossy);
    }

    [Fact]
    public void Representation_changing_normalisations_are_marked_lossy()
    {
        var repositoryPath = new PathCanonicalizer()
            .Canonicalize(@"src\.\A%2Ecs");
        var absolutePath = new PathCanonicalizer()
            .Canonicalize(@"/repo/./src/../A.cs");
        var fileUri = new PathCanonicalizer()
            .Canonicalize("file://localhost/repo/A.cs");

        Assert.Equal("repo://src/A.cs", repositoryPath.CanonicalUri);
        Assert.Contains(
            repositoryPath.Transformations,
            item =>
                item.Kind == "safe-percent-decode" &&
                item.IsLossy);
        Assert.Contains(
            repositoryPath.Transformations,
            item =>
                item.Kind == "canonical-separators" &&
                item.IsLossy);
        Assert.Contains(
            repositoryPath.Transformations,
            item =>
                item.Kind == "collapsed-rooted-segments" &&
                item.IsLossy);
        Assert.Equal("file:///repo/A.cs", absolutePath.CanonicalUri);
        Assert.Contains(
            absolutePath.Transformations,
            item =>
                item.Kind == "collapsed-absolute-segments" &&
                item.IsLossy);
        Assert.Equal("file:///repo/A.cs", fileUri.CanonicalUri);
        Assert.Contains(
            fileUri.Transformations,
            item =>
                item.Kind == "canonical-file-uri" &&
                item.IsLossy);
    }

    [Fact]
    public void Reserved_windows_names_are_diagnosed_without_rewriting()
    {
        var path = new PathCanonicalizer()
            .Canonicalize(@"C:\repo\CON.cs");

        Assert.Equal("win-drive://C:/repo/CON.cs", path.CanonicalUri);
        Assert.Contains(
            path.Diagnostics,
            item => item.Code == "CANON0004");
    }

    [Fact]
    public void Already_canonical_repository_path_reuses_its_original_text()
    {
        var original = new string("src/folder/file.cs".ToCharArray());

        var path = new PathCanonicalizer().Canonicalize(original);

        Assert.Same(original, path.RepositoryRelativePath);
        Assert.Equal("repo://src/folder/file.cs", path.CanonicalUri);
        Assert.Empty(path.Transformations);
        Assert.Empty(path.Diagnostics);
    }

    [Theory]
    [InlineData(
        @"C:\repo\.\src\\nested\..\file.cs",
        PathKind.DriveAbsolute,
        "win-drive://C:/repo/src/file.cs",
        "canonical-separators,collapsed-absolute-segments")]
    [InlineData(
        @"\repo\.\src\\nested\..\file.cs",
        PathKind.RootRelative,
        "win-root:///repo/src/file.cs",
        "canonical-separators,collapsed-absolute-segments")]
    [InlineData(
        @"\\server\share\.\src\\nested\..\file.cs",
        PathKind.Unc,
        "unc://server/share/src/file.cs",
        "canonical-separators,collapsed-absolute-segments")]
    [InlineData(
        @"\\?\C:\repo\.\src\\nested\..\file.cs",
        PathKind.Device,
        "win-device://C:/repo/src/file.cs",
        "canonical-separators,collapsed-absolute-segments")]
    [InlineData(
        @"\\?\UNC\server\share\.\src\\nested\..\file.cs",
        PathKind.DeviceUnc,
        "win-device-unc://server/share/src/file.cs",
        "canonical-separators,collapsed-absolute-segments")]
    [InlineData(
        "/repo/./src//nested/../file.cs",
        PathKind.PosixAbsolute,
        "file:///repo/src/file.cs",
        "collapsed-absolute-segments")]
    [InlineData(
        "file:///C:/repo/./src//nested/../file.cs",
        PathKind.FileUri,
        "file:///C:/repo/src/file.cs",
        "collapsed-absolute-segments,canonical-file-uri")]
    [InlineData(
        "src//./nested/../file.cs/",
        PathKind.RepositoryRelative,
        "repo://src/file.cs",
        "collapsed-rooted-segments")]
    [InlineData(
        @"C:folder\.\nested\..\file.cs",
        PathKind.DriveRelative,
        "win-drive-relative://C:folder/./nested/../file.cs",
        "canonical-separators")]
    [InlineData(
        "https://example.test/a/./b/../file.cs",
        PathKind.ExternalUri,
        "https://example.test/a/./b/../file.cs",
        "")]
    public void Segment_normalization_preserves_each_path_kinds_semantics(
        string original,
        PathKind expectedKind,
        string expectedCanonicalUri,
        string expectedTransformationKinds)
    {
        var path = new PathCanonicalizer().Canonicalize(original);

        Assert.Equal(expectedKind, path.Kind);
        Assert.Equal(expectedCanonicalUri, path.CanonicalUri);
        Assert.Equal(
            expectedTransformationKinds,
            string.Join(
                ',',
                path.Transformations.Select(item => item.Kind)));
        Assert.Empty(path.Diagnostics);
    }

    private static SarifRegressConfiguration CreateConfiguration(
        string? repositoryRoot,
        IEnumerable<PathRebase>? pathRebases = null,
        PathCaseSensitivity caseSensitivity = PathCaseSensitivity.Sensitive)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            repositoryRoot,
            pathRebases ?? [],
            defaults.PathAliases,
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
