using System.Text;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.UnitTests;

public sealed class RepositoryContextTests
{
    [Fact]
    public async Task Read_returns_a_bounded_normalized_snippet_and_hash()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            var sourceDirectory = Directory.CreateDirectory(
                Path.Combine(root.FullName, "src"));
            await File.WriteAllTextAsync(
                Path.Combine(sourceDirectory.FullName, "a.cs"),
                "line one\r\nline two\r\nline three",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "src/a.cs",
                new Region(2, 1, 2, 4),
                lineRadius: 1,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Equal(
                "line one\nline two\nline three",
                result.Snippet);
            Assert.NotNull(result.Evidence?.SnippetHash);
            Assert.Equal(1, result.Evidence?.StartLine);
            Assert.Equal(3, result.Evidence?.EndLine);
            Assert.Empty(result.Diagnostics);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Parent_traversal_is_rejected_before_file_access()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "../outside.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.False(result.Exists);
            var diagnostic = Assert.Single(result.Diagnostics);
            Assert.Equal("SECURITY0001", diagnostic.Code);
            Assert.Equal(DiagnosticStage.Security, diagnostic.Stage);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Source_file_byte_limit_is_enforced()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "large.txt"),
                "12345",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var limits = ResourceLimits.Default with
            {
                MaximumRepositoryFileBytes = 4,
            };
            var context = new FileSystemRepositoryContext(
                root.FullName,
                limits);

            var result = await context.ReadAsync(
                "large.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Null(result.Evidence);
            Assert.Contains(
                result.Diagnostics,
                item =>
                    item.Code == "SECURITY0003" &&
                    item.Severity == DiagnosticSeverity.Error);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Invalid_utf8_is_reported_without_replacement_characters()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllBytesAsync(
                Path.Combine(root.FullName, "invalid.txt"),
                [0xC3, 0x28],
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "invalid.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Null(result.Snippet);
            Assert.Contains(
                result.Diagnostics,
                item => item.Code == "IO0004");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Two_reads_of_the_same_source_produce_identical_evidence()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "stable.txt"),
                "alpha\nbeta\ngamma",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);
            var region = new Region(2, null, null, null);

            var first = await context.ReadAsync(
                "stable.txt",
                region,
                lineRadius: 1,
                cancellationToken: TestContext.Current.CancellationToken);
            var second = await context.ReadAsync(
                "stable.txt",
                region,
                lineRadius: 1,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(first.Snippet, second.Snippet);
            Assert.Equal(
                first.Evidence?.SnippetHash,
                second.Evidence?.SnippetHash);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Maximum_region_coordinates_are_clamped_without_overflow()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "small.txt"),
                "only line",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "small.txt",
                new Region(1, 1, int.MaxValue, 1),
                lineRadius: ResourceLimits.Default.MaximumSnippetRadius,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal("only line", result.Snippet);
            Assert.Equal(1, result.Evidence?.EndLine);
            Assert.DoesNotContain(
                result.Diagnostics,
                item => item.Severity == DiagnosticSeverity.Error);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Symbolic_links_at_every_repository_level_are_rejected()
    {
        var parent = Directory.CreateTempSubdirectory("sarif-regress-links-");
        try
        {
            var root = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "root"));
            var outside = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "outside"));
            var outsideFile = Path.Combine(outside.FullName, "secret.txt");
            await File.WriteAllTextAsync(
                outsideFile,
                "secret",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);

            var fileLink = Path.Combine(root.FullName, "file-link.txt");
            var directoryLink = Path.Combine(root.FullName, "directory-link");
            var rootLink = Path.Combine(parent.FullName, "root-link");
            try
            {
                File.CreateSymbolicLink(fileLink, outsideFile);
                Directory.CreateSymbolicLink(directoryLink, outside.FullName);
                Directory.CreateSymbolicLink(rootLink, root.FullName);
            }
            catch (Exception exception)
                when (exception is IOException
                    or UnauthorizedAccessException
                    or PlatformNotSupportedException)
            {
                return;
            }

            var context = new FileSystemRepositoryContext(root.FullName);
            var fileResult = await context.ReadAsync(
                "file-link.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);
            var directoryResult = await context.ReadAsync(
                "directory-link/secret.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);
            var rootResult = await new FileSystemRepositoryContext(rootLink)
                .ReadAsync(
                    "file-link.txt",
                    new Region(1, null, null, null),
                    lineRadius: 0,
                    cancellationToken: TestContext.Current.CancellationToken);

            Assert.Contains(
                fileResult.Diagnostics,
                item => item.Code == "SECURITY0002");
            Assert.Contains(
                directoryResult.Diagnostics,
                item => item.Code == "SECURITY0002");
            Assert.Contains(
                rootResult.Diagnostics,
                item => item.Code == "SECURITY0002");
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }
}
