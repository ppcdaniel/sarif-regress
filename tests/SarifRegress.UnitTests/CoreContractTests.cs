using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
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
}
