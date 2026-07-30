using System.Collections.Immutable;
using System.Xml.Linq;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;

namespace SarifRegress.UnitTests;

public sealed class CoreContractTests
{
    [Fact]
    public void Source_reference_escapes_rfc_6901_pointer_segments()
    {
        Assert.Equal(
            "rules~1by~0id",
            SourceReference.EscapePointerSegment("rules/by~id"));
    }

    [Fact]
    public void Source_reference_rejects_negative_indexes()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SourceReference(InputKind.Baseline, -1, null, "/runs"));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SourceReference(InputKind.Candidate, 0, -1, "/runs/0/results"));
    }

    [Fact]
    public void Diagnostic_rejects_unstable_code_shapes()
    {
        Assert.Throws<ArgumentException>(
            () => new Diagnostic(
                "parse-1",
                DiagnosticSeverity.Error,
                DiagnosticStage.Parse,
                "Invalid input."));
    }

    [Fact]
    public void Diagnostic_sorting_is_independent_of_input_order()
    {
        Diagnostic[] diagnostics =
        [
            new(
                "PARSE0002",
                DiagnosticSeverity.Error,
                DiagnosticStage.Parse,
                "Second."),
            new(
                "IO0001",
                DiagnosticSeverity.Error,
                DiagnosticStage.Io,
                "First."),
            new(
                "PARSE0001",
                DiagnosticSeverity.Warning,
                DiagnosticStage.Parse,
                "Middle."),
        ];

        var ascending = Diagnostic.Sort(diagnostics);
        var descending = Diagnostic.Sort(diagnostics.Reverse());

        Assert.Equal(ascending, descending);
        Assert.Equal(
            ["IO0001", "PARSE0001", "PARSE0002"],
            ascending.Select(item => item.Code));
    }

    [Fact]
    public void Diagnostic_sort_reuses_trivial_immutable_sequences()
    {
        var empty = ImmutableArray<Diagnostic>.Empty;
        var diagnostic = new Diagnostic(
            "IO0001",
            DiagnosticSeverity.Error,
            DiagnosticStage.Io,
            "Input failed.");
        var singleton = ImmutableArray.Create(diagnostic);

        Assert.True(empty.Equals(Diagnostic.Sort(empty)));
        Assert.True(singleton.Equals(Diagnostic.Sort(singleton)));
    }

    [Fact]
    public void Finding_collection_normalisation_reuses_trivial_immutable_sequences()
    {
        var producerFingerprints = ImmutableArray.Create(
            new ProducerFingerprint(
                "primary/v1",
                "primary",
                1,
                "producer-value",
                FingerprintReliability.High,
                ProducerFingerprintSource.PartialFingerprint));
        var derivedFingerprints = ImmutableArray.Create(
            new DerivedFingerprint(
                "sarifregress/test/v1",
                "derived-value",
                "test/v1"));
        var relatedLocations = ImmutableArray.Create(
            new RelatedLocation(
                Path: null,
                Region: null,
                StableKey: "related:0"));
        var lossiness = ImmutableArray.Create("collapsed-whitespace");
        var diagnostics = ImmutableArray.Create(
            new Diagnostic(
                "CANON0001",
                DiagnosticSeverity.Note,
                DiagnosticStage.Canonicalisation,
                "Canonicalised."));

        var finding = CreateFinding(
            producerFingerprints,
            derivedFingerprints,
            relatedLocations,
            lossiness,
            diagnostics);

        Assert.True(
            producerFingerprints.Equals(finding.ProducerFingerprints));
        Assert.True(derivedFingerprints.Equals(finding.DerivedFingerprints));
        Assert.True(relatedLocations.Equals(finding.RelatedLocations));
        Assert.True(lossiness.Equals(finding.Lossiness));
        Assert.True(diagnostics.Equals(finding.Diagnostics));

        var emptyFinding = CreateFinding();
        Assert.Empty(emptyFinding.ProducerFingerprints);
        Assert.Empty(emptyFinding.DerivedFingerprints);
        Assert.Empty(emptyFinding.RelatedLocations);
        Assert.Empty(emptyFinding.Lossiness);
        Assert.Empty(emptyFinding.Diagnostics);
    }

    [Fact]
    public void Finding_collection_normalisation_preserves_multi_item_ordering()
    {
        ProducerFingerprint[] producerFingerprints =
        [
            new(
                "zeta/v1",
                "zeta",
                1,
                "zeta-value",
                FingerprintReliability.High,
                ProducerFingerprintSource.PartialFingerprint),
            new(
                "alpha/v1",
                "alpha",
                1,
                "alpha-value",
                FingerprintReliability.High,
                ProducerFingerprintSource.PartialFingerprint),
        ];
        DerivedFingerprint[] derivedFingerprints =
        [
            new("zeta", "zeta-value", "test/v1"),
            new("alpha", "alpha-value", "test/v1"),
        ];
        RelatedLocation[] relatedLocations =
        [
            new(Path: null, Region: null, StableKey: "zeta"),
            new(Path: null, Region: null, StableKey: "alpha"),
        ];
        string[] lossiness = ["zeta", "alpha", "zeta"];
        Diagnostic[] diagnostics =
        [
            new(
                "PARSE0001",
                DiagnosticSeverity.Error,
                DiagnosticStage.Parse,
                "Parse failed."),
            new(
                "IO0001",
                DiagnosticSeverity.Error,
                DiagnosticStage.Io,
                "Input failed."),
        ];

        var finding = CreateFinding(
            producerFingerprints,
            derivedFingerprints,
            relatedLocations,
            lossiness,
            diagnostics);

        Assert.Equal(
            ["alpha", "zeta"],
            finding.ProducerFingerprints.Select(item => item.Family));
        Assert.Equal(
            ["alpha", "zeta"],
            finding.DerivedFingerprints.Select(item => item.Name));
        Assert.Equal(
            ["alpha", "zeta"],
            finding.RelatedLocations.Select(item => item.StableKey));
        Assert.Equal(["alpha", "zeta"], finding.Lossiness);
        Assert.Equal(
            ["IO0001", "PARSE0001"],
            finding.Diagnostics.Select(item => item.Code));
    }

    [Fact]
    public void Drive_relative_and_drive_absolute_paths_are_distinct_values()
    {
        CanonicalPath driveRelative = new(
            "C:file.cs",
            "C:file.cs",
            "win-drive-relative://C/file.cs",
            null,
            PathKind.DriveRelative);
        CanonicalPath driveAbsolute = new(
            @"C:\file.cs",
            @"C:\file.cs",
            "file:///C:/file.cs",
            null,
            PathKind.DriveAbsolute);

        Assert.NotEqual(driveRelative, driveAbsolute);
        Assert.NotEqual(driveRelative.Kind, driveAbsolute.Kind);
        Assert.NotEqual(driveRelative.CanonicalUri, driveAbsolute.CanonicalUri);
    }

    [Fact]
    public void Configuration_normalises_policy_and_mapping_order()
    {
        SarifRegressConfiguration configuration = new(
            SarifRegressConfiguration.SupportedSchemaVersion,
            null,
            [
                new PathRebase("file:///a/", "repo:/"),
                new PathRebase("file:///a/long/", "repo:/"),
            ],
            [],
            [],
            SarifRegressConfiguration.Default.Matching,
            new PolicyConfiguration(
                [
                    FindingClassification.New,
                    FindingClassification.Ambiguous,
                    FindingClassification.New,
                ],
                false),
            SarifRegressConfiguration.Default.Reporting,
            ResourceLimits.Default);

        Assert.Equal("file:///a/long/", configuration.PathRebases[0].From);
        Assert.Equal(
            [FindingClassification.New, FindingClassification.Ambiguous],
            configuration.Policy.FailOn);
    }

    [Fact]
    public void Resource_limits_fail_fast_when_a_bound_is_not_positive()
    {
        var invalidLimits = ResourceLimits.Default with
        {
            MaximumInputBytes = 0,
        };

        Assert.Throws<ArgumentOutOfRangeException>(invalidLimits.Validate);
    }

    [Fact]
    public void Line_regions_require_a_start_line()
    {
        Assert.Throws<ArgumentException>(
            () => new Region(null, 1, null, 2));
    }

    [Fact]
    public void Same_line_region_cannot_end_before_its_start_column()
    {
        Assert.Throws<ArgumentException>(
            () => new Region(1, 5, 1, 4));
        Assert.Equal(5, new Region(1, 5, 1, 5).EndColumn);
    }

    [Fact]
    public void Versioned_hash_is_stable_and_length_delimited()
    {
        var first = VersionedHash.Compute("algorithm/v1", "ab", "c");
        var repeated = VersionedHash.Compute("algorithm/v1", "ab", "c");
        var differentlyPartitioned = VersionedHash.Compute("algorithm/v1", "a", "bc");
        var nullField = VersionedHash.Compute("algorithm/v1", (string?)null);
        var emptyField = VersionedHash.Compute("algorithm/v1", string.Empty);

        Assert.Equal(first, repeated);
        Assert.NotEqual(first, differentlyPartitioned);
        Assert.NotEqual(nullField, emptyField);
        Assert.Equal(64, first.Length);
        Assert.Equal(first, first.ToLowerInvariant());
    }

    [Fact]
    public void Runtime_product_version_matches_the_build_version()
    {
        var buildPropertiesPath = Path.Combine(
            RepositoryLayout.Root,
            "Directory.Build.props");
        var buildProperties = XDocument.Load(buildPropertiesPath);
        var versionPrefix = buildProperties
            .Descendants("VersionPrefix")
            .Select(element => element.Value)
            .Single();

        Assert.Equal(ProductInformation.Version, versionPrefix);
    }

    private static Finding CreateFinding(
        IEnumerable<ProducerFingerprint>? producerFingerprints = null,
        IEnumerable<DerivedFingerprint>? derivedFingerprints = null,
        IEnumerable<RelatedLocation>? relatedLocations = null,
        IEnumerable<string>? lossiness = null,
        IEnumerable<Diagnostic>? diagnostics = null) =>
        new(
            "candidate:0:0",
            new SourceReference(
                InputKind.Candidate,
                runIndex: 0,
                resultIndex: 0,
                "/runs/0/results/0"),
            new RunIdentity(0, AutomationCategory: null, "candidate:0"),
            new ProducerIdentity(
                "Test tool",
                ToolVersion: "1.0.0",
                Family: "test",
                AutomationCategory: null),
            new RuleIdentity("TEST0001", "test/TEST0001", AliasApplied: false),
            primaryLocation: null,
            new MessageIdentity(
                "Message.",
                "Message.",
                "message.",
                ImmutableArray<string>.Empty),
            producerFingerprints,
            derivedFingerprints,
            context: null,
            relatedLocations,
            codeFlow: null,
            lossiness,
            diagnostics);
}
