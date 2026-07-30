using SarifRegress.Core.Paths;
using SarifRegress.Sarif.Canonicalization;

namespace SarifRegress.PropertyTests;

public sealed class CanonicalizationPropertyTests
{
    [Fact]
    public void Path_kind_classification_is_host_independent_for_hostile_forms()
    {
        (string Id, string Value, PathKind Expected)[] cases =
        [
            ("empty", string.Empty, PathKind.Unknown),
            ("relative", "src/file.cs", PathKind.RepositoryRelative),
            ("posix", "/repo/file.cs", PathKind.PosixAbsolute),
            ("drive-absolute", @"C:\repo\file.cs", PathKind.DriveAbsolute),
            ("drive-relative", @"C:repo\file.cs", PathKind.DriveRelative),
            ("root-relative", @"\repo\file.cs", PathKind.RootRelative),
            ("unc", @"\\server\share\file.cs", PathKind.Unc),
            ("device", @"\\?\C:\repo\file.cs", PathKind.Device),
            ("device-unc", @"\\?\UNC\server\share\file.cs", PathKind.DeviceUnc),
            ("file-uri", "file:///repo/file.cs", PathKind.FileUri),
            ("external-uri", "https://example.invalid/a", PathKind.ExternalUri),
            ("repo-uri", "repo:/src/file.cs", PathKind.ExternalUri),
        ];

        foreach (var testCase in cases)
        {
            var actual = PathCanonicalizer.Classify(testCase.Value);
            Assert.True(
                actual == testCase.Expected,
                $"case={testCase.Id}; expected={testCase.Expected}; actual={actual}");
        }
    }

    [Fact]
    public void Path_canonicalization_is_idempotent_for_hostile_lexical_matrix()
    {
        string[] hostileValues =
        [
            string.Empty,
            ".",
            "src/file.cs",
            @"src\folder\..\file.cs",
            "src/./folder/../file.cs",
            "../escape.cs",
            "src/%7Euser/%41.cs",
            "src/%2F/%5c/%3F/%23/%25.cs",
            "src/%",
            "src/%G0/%F.cs",
            "/repo/./src/../file.cs",
            "/../escape.cs",
            @"C:\repo\src\..\file.cs",
            @"C:repo\file.cs",
            @"\repo\file.cs",
            @"\\server\share\dir\..\file.cs",
            @"\\?\C:\repo\file.cs",
            @"\\?\UNC\server\share\file.cs",
            "file:///C:/repo/src/../file.cs",
            "file://server/share/dir/../file.cs",
            @"https://EXAMPLE.invalid\a\%7Euser?q=%2F",
            "git+ssh://example.invalid/repo/%7Eowner",
            @"repo:/src\folder\..\file.cs",
            "repo://src/folder/../file.cs",
            "src/\0/file.cs",
            @"C:\CON\file.cs",
            "src/emoji-\U0001F642.cs",
            "src/e\u0301.cs",
        ];
        var canonicalizer = new PathCanonicalizer();

        for (var index = 0; index < hostileValues.Length; index++)
        {
            var caseId = $"path-{index:D2}";
            var first = canonicalizer.Canonicalize(hostileValues[index]);
            var second = canonicalizer.Canonicalize(first.CanonicalUri);
            var third = canonicalizer.Canonicalize(second.CanonicalUri);

            Assert.True(
                string.Equals(
                    first.CanonicalUri,
                    second.CanonicalUri,
                    StringComparison.Ordinal),
                $"case={caseId}; pass=first");
            Assert.True(
                string.Equals(
                    second.CanonicalUri,
                    third.CanonicalUri,
                    StringComparison.Ordinal),
                $"case={caseId}; pass=second");
            Assert.True(
                string.Equals(
                    first.RepositoryRelativePath,
                    second.RepositoryRelativePath,
                    StringComparison.Ordinal),
                $"case={caseId}; field=repository-relative");
            Assert.True(
                first.CanonicalUri.IndexOf('\\') < 0,
                $"case={caseId}; field=separator");
        }
    }

    [Fact]
    public void Equivalent_separators_and_safe_percent_escapes_converge()
    {
        (string Id, string Left, string Right)[] separatorPairs =
        [
            (
                "relative",
                @"src\a\.\b\..\file.cs",
                "src/a/./b/../file.cs"),
            (
                "drive",
                @"C:\repo\a\..\file.cs",
                "C:/repo/a/../file.cs"),
            (
                "unc",
                @"\\server\share\a\..\file.cs",
                "//server/share/a/../file.cs"),
            (
                "file-uri",
                @"file:///repo\a\..\file.cs",
                "file:///repo/a/../file.cs"),
            (
                "repo-uri",
                @"repo:/src\a\..\file.cs",
                "repo://src/a/../file.cs"),
            (
                "safe-percent",
                "src/%7euser/%41.cs",
                "src/~user/A.cs"),
        ];
        var canonicalizer = new PathCanonicalizer();

        foreach (var pair in separatorPairs)
        {
            var left = canonicalizer.Canonicalize(pair.Left);
            var right = canonicalizer.Canonicalize(pair.Right);
            Assert.True(
                string.Equals(
                    left.CanonicalUri,
                    right.CanonicalUri,
                    StringComparison.Ordinal),
                $"case={pair.Id}");
        }

        var reserved = canonicalizer.Canonicalize(
            "src/%2F/%5c/%3F/%23/%25.cs");
        Assert.True(
            string.Equals(
                "repo://src/%2F/%5c/%3F/%23/%25.cs",
                reserved.CanonicalUri,
                StringComparison.Ordinal),
            "case=reserved-percent");

        var dotSegments = canonicalizer.Canonicalize("src/%2E/tmp/%2e%2e/file.cs");
        Assert.True(
            string.Equals(
                "repo://src/file.cs",
                dotSegments.CanonicalUri,
                StringComparison.Ordinal),
            "case=percent-dot-segments");
    }

    [Fact]
    public void Message_canonicalization_is_idempotent_and_culture_independent()
    {
        string[] messages =
        [
            string.Empty,
            "plain",
            "  padded  ",
            "first\r\nsecond\rlast",
            "tabs\tand\nlines",
            "\u00A0non-breaking\u00A0space\u00A0",
            "İ I ı i",
            "e\u0301 \u00E9",
            "emoji \U0001F642 value",
            "null\0character",
            "line\u2028separator\u2029pair",
            " \t\r\n ",
        ];
        string[] cultures = ["en-US", "tr-TR", "ar-SA"];

        for (var index = 0; index < messages.Length; index++)
        {
            var caseId = $"message-{index:D2}";
            var first = MessageCanonicalizer.Canonicalize(messages[index]);
            var second = MessageCanonicalizer.Canonicalize(first.CanonicalText);

            Assert.True(
                string.Equals(
                    messages[index],
                    first.OriginalText,
                    StringComparison.Ordinal),
                $"case={caseId}; field=original");
            Assert.True(
                string.Equals(
                    first.CanonicalText,
                    second.CanonicalText,
                    StringComparison.Ordinal),
                $"case={caseId}; field=canonical");
            Assert.True(
                string.Equals(
                    first.ComparisonText,
                    second.ComparisonText,
                    StringComparison.Ordinal),
                $"case={caseId}; field=comparison");
            Assert.True(
                first.CanonicalText.IndexOf('\r') < 0,
                $"case={caseId}; field=line-endings");
            Assert.True(
                !first.CanonicalText.Contains("  ", StringComparison.Ordinal),
                $"case={caseId}; field=collapsed-whitespace");
            Assert.True(
                first.CanonicalText.All(
                    character => !char.IsWhiteSpace(character) || character == ' '),
                $"case={caseId}; field=whitespace-form");

            foreach (var culture in cultures)
            {
                using var scope = new CultureScope(culture);
                var cultureResult =
                    MessageCanonicalizer.Canonicalize(messages[index]);
                Assert.True(
                    string.Equals(
                        first.CanonicalText,
                        cultureResult.CanonicalText,
                        StringComparison.Ordinal),
                    $"case={caseId}; culture={culture}; field=canonical");
                Assert.True(
                    string.Equals(
                        first.ComparisonText,
                        cultureResult.ComparisonText,
                        StringComparison.Ordinal),
                    $"case={caseId}; culture={culture}; field=comparison");
                Assert.True(
                    first.NormalisationFlags.SequenceEqual(
                        cultureResult.NormalisationFlags,
                        StringComparer.Ordinal),
                    $"case={caseId}; culture={culture}; field=flags");
            }
        }
    }
}
