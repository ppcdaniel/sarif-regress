using System.Text;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.UnitTests;

public sealed class TokenWindowTests
{
    [Fact]
    public async Task Ingestion_only_emits_token_evidence_when_configuration_enables_it()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-token-");
        try
        {
            await WriteTextAsync(
                Path.Combine(root.FullName, "source.cs"),
                "before();\nTarget(value);\nafter();");
            var context = new FileSystemRepositoryContext(root.FullName);
            var ingestor = new SarifIngestor(context);

            var disabled = await IngestAsync(
                ingestor,
                enableTokenWindows: false);
            var enabled = await IngestAsync(
                ingestor,
                enableTokenWindows: true);

            var disabledFinding =
                Assert.Single(disabled.ComparisonInput.Findings);
            var enabledFinding =
                Assert.Single(enabled.ComparisonInput.Findings);
            Assert.NotNull(disabledFinding.Context?.SnippetHash);
            Assert.Null(disabledFinding.Context?.TokenWindowHash);
            Assert.NotNull(enabledFinding.Context?.TokenWindowHash);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Token_hash_ignores_blank_line_only_shifts()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-token-");
        try
        {
            await WriteTextAsync(
                Path.Combine(root.FullName, "baseline.cs"),
                "before();\nTarget(value);\nafter();");
            await WriteTextAsync(
                Path.Combine(root.FullName, "candidate.cs"),
                "before();\n\n\nTarget(value);\nafter();");
            var context = new FileSystemRepositoryContext(root.FullName);

            var baseline = await ReadTokenWindowAsync(
                context,
                "baseline.cs",
                startLine: 2);
            var candidate = await ReadTokenWindowAsync(
                context,
                "candidate.cs",
                startLine: 4);

            Assert.NotNull(baseline.Evidence?.TokenWindowHash);
            Assert.Equal(
                baseline.Evidence?.TokenWindowHash,
                candidate.Evidence?.TokenWindowHash);
            Assert.Equal(
                "5d2fa690d9b4d2137d53ff5acbd043b2a155cca50223fa59c3ef4b82684fe11c",
                baseline.Evidence?.TokenWindowHash);
            Assert.NotEqual(
                baseline.Evidence?.EndLine,
                candidate.Evidence?.EndLine);
            Assert.NotEqual(
                baseline.Evidence?.SnippetHash,
                candidate.Evidence?.SnippetHash);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Token_hash_changes_when_local_tokens_change_and_repeats_exactly()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-token-");
        try
        {
            await WriteTextAsync(
                Path.Combine(root.FullName, "first.cs"),
                "before();\nTarget(value);\nafter();");
            await WriteTextAsync(
                Path.Combine(root.FullName, "changed.cs"),
                "before();\nTarget(other);\nafter();");
            var context = new FileSystemRepositoryContext(root.FullName);

            var first = await ReadTokenWindowAsync(
                context,
                "first.cs",
                startLine: 2);
            var repeated = await ReadTokenWindowAsync(
                context,
                "first.cs",
                startLine: 2);
            var changed = await ReadTokenWindowAsync(
                context,
                "changed.cs",
                startLine: 2);

            Assert.Equal(
                first.Evidence?.TokenWindowHash,
                repeated.Evidence?.TokenWindowHash);
            Assert.NotEqual(
                first.Evidence?.TokenWindowHash,
                changed.Evidence?.TokenWindowHash);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Unsafe_or_unreadable_files_never_produce_token_evidence()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-token-");
        try
        {
            await File.WriteAllBytesAsync(
                Path.Combine(root.FullName, "binary.dat"),
                [0xC3, 0x28],
                TestContext.Current.CancellationToken);
            await WriteTextAsync(
                Path.Combine(root.FullName, "oversize.txt"),
                "123456789");
            var limits = ResourceLimits.Default with
            {
                MaximumRepositoryFileBytes = 8,
            };
            var context = new FileSystemRepositoryContext(
                root.FullName,
                limits);

            var missing = await ReadTokenWindowAsync(
                context,
                "missing.txt",
                startLine: 1);
            var outside = await ReadTokenWindowAsync(
                context,
                "../outside.txt",
                startLine: 1);
            var binary = await ReadTokenWindowAsync(
                context,
                "binary.dat",
                startLine: 1);
            var oversize = await ReadTokenWindowAsync(
                context,
                "oversize.txt",
                startLine: 1);

            Assert.Null(missing.Evidence);
            Assert.Null(outside.Evidence);
            Assert.Null(binary.Evidence);
            Assert.Null(oversize.Evidence);
            Assert.Contains(
                missing.Diagnostics,
                item => item.Code == "IO0001");
            Assert.Contains(
                outside.Diagnostics,
                item => item.Code == "SECURITY0001");
            Assert.Contains(
                binary.Diagnostics,
                item => item.Code == "IO0004");
            Assert.Contains(
                oversize.Diagnostics,
                item => item.Code == "SECURITY0003");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Token_and_string_limits_omit_only_token_evidence_with_stable_diagnostics()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-token-");
        try
        {
            await WriteTextAsync(
                Path.Combine(root.FullName, "many.txt"),
                "one two tri four");
            await WriteTextAsync(
                Path.Combine(root.FullName, "long.txt"),
                "alphabet");
            var limits = ResourceLimits.Default with
            {
                MaximumStringCharacters = 4,
                MaximumTokenWindowTerms = 3,
            };
            var context = new FileSystemRepositoryContext(
                root.FullName,
                limits);

            var many = await ReadTokenWindowAsync(
                context,
                "many.txt",
                startLine: 1);
            var longTerm = await ReadTokenWindowAsync(
                context,
                "long.txt",
                startLine: 1);

            Assert.NotNull(many.Evidence?.SnippetHash);
            Assert.Null(many.Evidence?.TokenWindowHash);
            Assert.Contains(
                many.Diagnostics,
                item =>
                    item.Code == "CANON0011" &&
                    item.Severity == DiagnosticSeverity.Warning);
            Assert.NotNull(longTerm.Evidence?.SnippetHash);
            Assert.Null(longTerm.Evidence?.TokenWindowHash);
            Assert.Contains(
                longTerm.Diagnostics,
                item =>
                    item.Code == "CANON0012" &&
                    item.Severity == DiagnosticSeverity.Warning);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Token_window_creation_observes_cancellation()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-token-");
        try
        {
            await WriteTextAsync(
                Path.Combine(root.FullName, "source.cs"),
                new string('a', 8 * 1024));
            var context = new FileSystemRepositoryContext(root.FullName);
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () =>
                {
                    _ = await context.ReadAsync(
                        "source.cs",
                        new Region(1, null, null, null),
                        lineRadius: 0,
                        includeTokenWindow: true,
                        cancellationToken: cancellation.Token);
                });
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    private static async Task<SarifIngestionResult> IngestAsync(
        SarifIngestor ingestor,
        bool enableTokenWindows)
    {
        const string sarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Tool" } },
                "results": [{
                  "ruleId": "R1",
                  "message": { "text": "message" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "uri": "source.cs" },
                      "region": { "startLine": 2 }
                    }
                  }]
                }]
              }]
            }
            """;
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(sarif),
            writable: false);
        return await ingestor.IngestAsync(
            stream,
            new SarifIngestionRequest(
                InputKind.Baseline,
                "input.sarif",
                CreateConfiguration(enableTokenWindows)),
            TestContext.Current.CancellationToken);
    }

    private static SarifRegressConfiguration CreateConfiguration(
        bool enableTokenWindows)
    {
        var defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            defaults.RepositoryRoot,
            defaults.PathRebases,
            defaults.PathAliases,
            defaults.RuleAliases,
            defaults.Matching with
            {
                EnableRepositoryContext = true,
                EnableTokenWindows = enableTokenWindows,
            },
            defaults.Policy,
            defaults.Reporting,
            defaults.Limits);
    }

    private static ValueTask<RepositoryContextResult> ReadTokenWindowAsync(
        FileSystemRepositoryContext context,
        string path,
        int startLine) =>
        context.ReadAsync(
            path,
            new Region(startLine, null, null, null),
            lineRadius: 3,
            includeTokenWindow: true,
            cancellationToken: TestContext.Current.CancellationToken);

    private static Task WriteTextAsync(
        string path,
        string contents) =>
        File.WriteAllTextAsync(
            path,
            contents,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            TestContext.Current.CancellationToken);
}
