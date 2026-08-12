using System.Security.Cryptography;
using System.Text;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Match;
using SarifRegress.Sarif.Fingerprints;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.UnitTests;

public sealed class TrustedRepositorySnapshotTests
{
    [Fact]
    public async Task Verified_file_derives_comment_blind_lexical_evidence()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void run() {\n"
            + "    // HOLDOUT:pmd-secret-one\n"
            + "    primaryFailure.getMessage(); // label one\n"
            + "  }\n"
            + "}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);

        var result = await context.ReadAsync(
            "src/Worker.java",
            new Region(4, 5, 4, 33),
            lineRadius: 1,
            cancellationToken: TestContext.Current.CancellationToken,
            includeTokenWindow: true);

        Assert.True(result.Exists);
        Assert.NotNull(result.TrustedLexicalContextHash);
        Assert.Null(result.Evidence?.SnippetHash);
        Assert.Null(result.Evidence?.TokenWindowHash);
        Assert.Empty(result.Diagnostics);
        var fingerprint = FingerprintProcessor.DeriveTrustedLexicalContext(
            "src/Worker.java",
            result.TrustedLexicalContextHash);
        Assert.Equal(
            FingerprintProcessor.TrustedLexicalFingerprintName,
            fingerprint?.Name);
    }

    [Fact]
    public async Task Ingestion_carries_trusted_lexical_atom_as_a_derived_fingerprint()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void run() {\n"
            + "    target.execute();\n"
            + "  }\n"
            + "}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);
        var defaults = SarifRegressConfiguration.Default;
        var configuration = new SarifRegressConfiguration(
            defaults.SchemaVersion,
            fixture.RepositoryRoot,
            defaults.PathRebases,
            defaults.PathAliases,
            defaults.RuleAliases,
            defaults.Matching,
            defaults.Policy,
            defaults.Reporting,
            defaults.Limits);
        const string sarif =
            "{\"version\":\"2.1.0\",\"runs\":[{"
            + "\"tool\":{\"driver\":{\"name\":\"Example\"}},"
            + "\"results\":[{\"ruleId\":\"R1\","
            + "\"message\":{\"text\":\"message\"},"
            + "\"locations\":[{\"physicalLocation\":{"
            + "\"artifactLocation\":{\"uri\":\"src/Worker.java\"},"
            + "\"region\":{\"startLine\":3,\"startColumn\":5,"
            + "\"endLine\":3,\"endColumn\":22}}}]}]}]}";
        await using var stream = new MemoryStream(
            Encoding.UTF8.GetBytes(sarif),
            writable: false);

        var result = await new SarifIngestor(context).IngestAsync(
            stream,
            new SarifIngestionRequest(
                InputKind.Baseline,
                "baseline.sarif",
                configuration),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
        var finding = Assert.Single(result.ComparisonInput.Findings);
        Assert.Equal(
            FingerprintProcessor.TrustedLexicalFingerprintName,
            Assert.Single(finding.DerivedFingerprints).Name);
    }

    [Fact]
    public async Task Comment_marker_mutations_do_not_change_lexical_atom()
    {
        const string firstSource =
            "class Worker {\n"
            + "  void run() {\n"
            + "    /* HOLDOUT:pmd-alpha */ target.execute(); // first\n"
            + "  }\n"
            + "}\n";
        const string secondSource =
            "class Worker {\n"
            + "  void run() {\n"
            + "    /* unrelated changed marker */ target.execute(); // second\n"
            + "  }\n"
            + "}\n";
        using var firstFixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            firstSource);
        using var secondFixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            secondSource);
        using var firstContext = new FileSystemRepositoryContext(
            firstFixture.RepositoryRoot,
            firstFixture.Manifest);
        using var secondContext = new FileSystemRepositoryContext(
            secondFixture.RepositoryRoot,
            secondFixture.Manifest);

        var first = await firstContext.ReadAsync(
            "src/Worker.java",
            new Region(3, 1, 3, 60),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var second = await secondContext.ReadAsync(
            "src/Worker.java",
            new Region(3, 1, 3, 70),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(first.TrustedLexicalContextHash);
        Assert.Equal(
            first.TrustedLexicalContextHash,
            second.TrustedLexicalContextHash);
        Assert.Equal(
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "src/Worker.java",
                first.TrustedLexicalContextHash)?.Value,
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "src/Worker.java",
                second.TrustedLexicalContextHash)?.Value);
    }

    [Fact]
    public async Task Repeated_sites_collide_in_the_same_scope()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void run() {\n"
            + "    target.execute();\n"
            + "    target.execute();\n"
            + "  }\n"
            + "}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);

        var first = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var second = await context.ReadAsync(
            "src/Worker.java",
            new Region(4, 5, 4, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(first.TrustedLexicalContextHash);
        Assert.Equal(
            first.TrustedLexicalContextHash,
            second.TrustedLexicalContextHash);
    }

    [Fact]
    public async Task Repeated_sites_in_control_blocks_collide_in_the_same_method()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void run(Exception error) {\n"
            + "    if (error.getCause() == null) {\n"
            + "      error.printStackTrace();\n"
            + "    } else {\n"
            + "      error.printStackTrace();\n"
            + "    }\n"
            + "  }\n"
            + "}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);

        var first = await context.ReadAsync(
            "src/Worker.java",
            new Region(4, 7, 4, 31),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var second = await context.ReadAsync(
            "src/Worker.java",
            new Region(6, 7, 6, 31),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(first.TrustedLexicalContextHash);
        Assert.Equal(
            first.TrustedLexicalContextHash,
            second.TrustedLexicalContextHash);
    }

    [Fact]
    public async Task Same_statement_in_different_method_headers_is_distinct()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void primary() {\n"
            + "    target.execute();\n"
            + "  }\n"
            + "  void secondary() {\n"
            + "    target.execute();\n"
            + "  }\n"
            + "}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);

        var primary = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var secondary = await context.ReadAsync(
            "src/Worker.java",
            new Region(6, 5, 6, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(primary.TrustedLexicalContextHash);
        Assert.NotNull(secondary.TrustedLexicalContextHash);
        Assert.NotEqual(
            primary.TrustedLexicalContextHash,
            secondary.TrustedLexicalContextHash);
    }

    [Fact]
    public void Same_file_name_across_directories_preserves_derived_identity()
    {
        const string trustedLexicalAtom = "trusted-lexical-atom";
        var baselineFingerprint =
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "archived/Worker.java",
                trustedLexicalAtom);
        var candidateFingerprint =
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "active/Worker.java",
                trustedLexicalAtom);
        var caseChangedFingerprint =
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "active/worker.java",
                trustedLexicalAtom);

        Assert.NotNull(baselineFingerprint);
        Assert.NotNull(candidateFingerprint);
        Assert.NotNull(caseChangedFingerprint);
        Assert.Equal(
            baselineFingerprint.Value,
            candidateFingerprint.Value);
        Assert.NotEqual(
            baselineFingerprint.Value,
            caseChangedFingerprint.Value);

        var matchResult = new FindingMatcher().Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:worker",
                    path: "archived/Worker.java",
                    derivedFingerprints: [baselineFingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:worker",
                    path: "active/Worker.java",
                    derivedFingerprints: [candidateFingerprint])));

        var decision = Assert.Single(matchResult.Decisions);
        Assert.Equal(FindingClassification.Moved, decision.Classification);
        Assert.Equal(
            PrecedenceTier.StrongMoved,
            decision.Decision.PrecedenceTier);
    }

    [Fact]
    public async Task Renamed_file_refuses_equal_lexical_atom()
    {
        const string baselineSource =
            "class PreviousWorker {\n"
            + "  void record() {\n"
            + "    audit.record();\n"
            + "  }\n"
            + "}\n";
        const string candidateSource =
            "class AuditTrail {\n"
            + "  void record() {\n"
            + "    // a source-only insertion must not affect identity\n"
            + "    audit.record();\n"
            + "  }\n"
            + "}\n";
        using var baselineFixture = await SnapshotFixture.CreateAsync(
            "old/PreviousWorker.java",
            baselineSource);
        using var candidateFixture = await SnapshotFixture.CreateAsync(
            "new/AuditTrail.java",
            candidateSource);
        using var baselineContext = new FileSystemRepositoryContext(
            baselineFixture.RepositoryRoot,
            baselineFixture.Manifest);
        using var candidateContext = new FileSystemRepositoryContext(
            candidateFixture.RepositoryRoot,
            candidateFixture.Manifest);

        var baseline = await baselineContext.ReadAsync(
            "old/PreviousWorker.java",
            new Region(3, 5, 3, 20),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var candidate = await candidateContext.ReadAsync(
            "new/AuditTrail.java",
            new Region(4, 5, 4, 20),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(baseline.TrustedLexicalContextHash);
        Assert.Equal(
            baseline.TrustedLexicalContextHash,
            candidate.TrustedLexicalContextHash);
        var baselineFingerprint =
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "old/PreviousWorker.java",
                baseline.TrustedLexicalContextHash);
        var candidateFingerprint =
            FingerprintProcessor.DeriveTrustedLexicalContext(
                "new/AuditTrail.java",
                candidate.TrustedLexicalContextHash);
        Assert.NotEqual(
            baselineFingerprint?.Value,
            candidateFingerprint?.Value);
        Assert.NotNull(baselineFingerprint);
        Assert.NotNull(candidateFingerprint);

        var matchResult = new FindingMatcher().Match(
            MatchingTestData.Input(
                InputKind.Baseline,
                MatchingTestData.Finding(
                    InputKind.Baseline,
                    "baseline:worker",
                    path: "old/PreviousWorker.java",
                    derivedFingerprints: [baselineFingerprint])),
            MatchingTestData.Input(
                InputKind.Candidate,
                MatchingTestData.Finding(
                    InputKind.Candidate,
                    "candidate:audit",
                    path: "new/AuditTrail.java",
                    derivedFingerprints: [candidateFingerprint])));

        Assert.Equal(0, matchResult.CandidateEdgeCount);
        Assert.Contains(
            matchResult.Decisions,
            decision => decision.Classification == FindingClassification.Resolved);
        Assert.Contains(
            matchResult.Decisions,
            decision => decision.Classification == FindingClassification.New);
    }

    [Fact]
    public async Task Excessive_nested_brace_scopes_refuse_boundedly()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void run() {\n"
            + "    if (ready) {\n"
            + "      target.execute();\n"
            + "    }\n"
            + "  }\n"
            + "}\n");
        var limits = ResourceLimits.Default with
        {
            MaximumJsonDepth = 2,
        };
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest,
            limits);

        var result = await context.ReadAsync(
            "src/Worker.java",
            new Region(4, 7, 4, 24),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(result.TrustedLexicalContextHash);
        Assert.Null(result.Evidence?.SnippetHash);
    }

    [Fact]
    public async Task Immutable_snapshot_cache_has_an_aggregate_byte_bound()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n  void run() {\n    target.execute();\n  }\n}\n");
        var limits = ResourceLimits.Default with
        {
            MaximumInputBytes = 16,
        };
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest,
            limits);

        var result = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var repeated = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(result.TrustedLexicalContextHash);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0014");
        Assert.Contains(
            repeated.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0014");
        Assert.Equal(1, context.TrustedSnapshotFileVerificationCount);
        Assert.Equal(0, context.TrustedSnapshotIndexBuildCount);
    }

    [Fact]
    public async Task Exhausted_snapshot_cache_refuses_later_paths_without_opening_them()
    {
        var directory = Directory.CreateTempSubdirectory(
            "sarif-regress-snapshot-cache-bound-");
        try
        {
            var repositoryRoot = Path.Combine(directory.FullName, "repository");
            Directory.CreateDirectory(Path.Combine(repositoryRoot, "src"));
            var sourceBytes = new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false).GetBytes(
                    "class Worker {\n  void run() {\n    target.execute();\n  }\n}\n");
            var digest = Convert
                .ToHexString(SHA256.HashData(sourceBytes))
                .ToLowerInvariant();
            foreach (var name in new[] { "First.java", "Second.java" })
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(repositoryRoot, "src", name),
                    sourceBytes,
                    TestContext.Current.CancellationToken);
            }

            var manifestPath = Path.Combine(directory.FullName, "snapshot.json");
            await File.WriteAllTextAsync(
                manifestPath,
                "{\"schemaVersion\":\"1\",\"files\":{"
                + $"\"src/First.java\":\"{digest}\","
                + $"\"src/Second.java\":\"{digest}\"}}}}",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                TestContext.Current.CancellationToken);
            var manifestResult = await RepositorySnapshotManifestReader.ReadAsync(
                manifestPath,
                cancellationToken: TestContext.Current.CancellationToken);
            using var context = new FileSystemRepositoryContext(
                repositoryRoot,
                Assert.IsType<RepositorySnapshotManifest>(manifestResult.Manifest),
                ResourceLimits.Default with { MaximumInputBytes = 16 });

            var first = await context.ReadAsync(
                "src/First.java",
                new Region(3, 5, 3, 22),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);
            var second = await context.ReadAsync(
                "src/Second.java",
                new Region(3, 5, 3, 22),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.All(
                new[] { first, second },
                result => Assert.Contains(
                    result.Diagnostics,
                    diagnostic => diagnostic.Code == "SECURITY0014"));
            Assert.Equal(1, context.TrustedSnapshotFileVerificationCount);
            Assert.Equal(0, context.TrustedSnapshotIndexBuildCount);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Repeated_near_eof_reads_build_one_bounded_lexical_index()
    {
        const int fillerLineCount = 20_000;
        var source = new StringBuilder(
            fillerLineCount * 112);
        source.Append("class Worker {\n  void run() {\n");
        for (var line = 0; line < fillerLineCount; line++)
        {
            source.Append(
                "    // bounded filler xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
        }

        source.Append("    target.execute();\n  }\n}\n");
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            source.ToString());
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);
        var targetLine = fillerLineCount + 3;
        string? expectedHash = null;

        for (var read = 0; read < 128; read++)
        {
            var result = await context.ReadAsync(
                "src/Worker.java",
                new Region(targetLine, 5, targetLine, 22),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal("    target.execute();", result.Snippet);
            Assert.NotNull(result.TrustedLexicalContextHash);
            expectedHash ??= result.TrustedLexicalContextHash;
            Assert.Equal(expectedHash, result.TrustedLexicalContextHash);
        }

        Assert.Equal(1, context.TrustedSnapshotFileVerificationCount);
        Assert.Equal(1, context.TrustedSnapshotIndexBuildCount);
    }

    [Fact]
    public async Task Later_unterminated_comment_does_not_poison_prior_lines()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n"
            + "  void run() {\n"
            + "    target.execute();\n"
            + "    /* unterminated\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);

        var prior = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 22),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var malformed = await context.ReadAsync(
            "src/Worker.java",
            new Region(4, 5, 4, 20),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(prior.TrustedLexicalContextHash);
        Assert.Null(malformed.TrustedLexicalContextHash);
        Assert.Equal(1, context.TrustedSnapshotFileVerificationCount);
        Assert.Equal(1, context.TrustedSnapshotIndexBuildCount);
    }

    [Fact]
    public async Task Successful_first_read_is_immutable_after_path_mutation()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n  void run() {\n    original();\n  }\n}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);
        var region = new Region(3, 5, 3, 16);

        var first = await context.ReadAsync(
            "src/Worker.java",
            region,
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            fixture.SourcePath,
            "class Worker {\n  void run() {\n    replaced();\n  }\n}\n",
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            TestContext.Current.CancellationToken);
        var second = await context.ReadAsync(
            "src/Worker.java",
            region,
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("    original();", first.Snippet);
        Assert.Equal(first.Snippet, second.Snippet);
        Assert.Equal(
            first.TrustedLexicalContextHash,
            second.TrustedLexicalContextHash);
    }

    [Fact]
    public async Task Missing_or_mismatched_source_fails_closed()
    {
        using var fixture = await SnapshotFixture.CreateAsync(
            "src/Worker.java",
            "class Worker {\n  void run() {\n    original();\n  }\n}\n");
        using var context = new FileSystemRepositoryContext(
            fixture.RepositoryRoot,
            fixture.Manifest);
        var missing = await context.ReadAsync(
            "src/Missing.java",
            new Region(1, 1, 1, 2),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        await File.AppendAllTextAsync(
            fixture.SourcePath,
            "mutation",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var mismatch = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 16),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var repeatedMismatch = await context.ReadAsync(
            "src/Worker.java",
            new Region(3, 5, 3, 16),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(missing.TrustedLexicalContextHash);
        Assert.Contains(
            missing.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0008");
        Assert.Null(mismatch.TrustedLexicalContextHash);
        Assert.Contains(
            mismatch.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0009");
        Assert.Contains(
            repeatedMismatch.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0009");
        Assert.Equal(1, context.TrustedSnapshotFileVerificationCount);
        Assert.Equal(0, context.TrustedSnapshotIndexBuildCount);
    }

    [Fact]
    public async Task Manifest_reader_rejects_duplicate_and_traversal_paths()
    {
        var directory = Directory.CreateTempSubdirectory(
            "sarif-regress-manifest-invalid-");
        try
        {
            var duplicatePath = Path.Combine(
                directory.FullName,
                "duplicate.json");
            var traversalPath = Path.Combine(
                directory.FullName,
                "traversal.json");
            var digest = new string('a', 64);
            await File.WriteAllTextAsync(
                duplicatePath,
                "{\"schemaVersion\":\"1\",\"files\":{"
                + $"\"src/a.cs\":\"{digest}\","
                + $"\"src/a.cs\":\"{digest}\"}}}}",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(
                traversalPath,
                "{\"schemaVersion\":\"1\",\"files\":{"
                + $"\"../outside.cs\":\"{digest}\"}}}}",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);

            var duplicate = await RepositorySnapshotManifestReader.ReadAsync(
                duplicatePath,
                cancellationToken: TestContext.Current.CancellationToken);
            var traversal = await RepositorySnapshotManifestReader.ReadAsync(
                traversalPath,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Null(duplicate.Manifest);
            Assert.Equal(
                "SCHEMA0021",
                Assert.Single(duplicate.Diagnostics).Code);
            Assert.Null(traversal.Manifest);
            Assert.Equal(
                "SCHEMA0022",
                Assert.Single(traversal.Diagnostics).Code);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Manifest_reader_requires_an_unambiguous_absolute_path()
    {
        var result = await RepositorySnapshotManifestReader.ReadAsync(
            "snapshot-manifest.json",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(result.Manifest);
        Assert.Equal("SECURITY0006", Assert.Single(result.Diagnostics).Code);
    }

    [Fact]
    public async Task Manifest_reader_reports_a_missing_absolute_file()
    {
        var missingPath = Path.Combine(
            Path.GetTempPath(),
            $"sarif-regress-missing-{Guid.NewGuid():N}.json");

        var result = await RepositorySnapshotManifestReader.ReadAsync(
            missingPath,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(result.Manifest);
        Assert.Equal("IO0005", Assert.Single(result.Diagnostics).Code);
    }

    private sealed class SnapshotFixture : IDisposable
    {
        private readonly DirectoryInfo directory;

        private SnapshotFixture(
            DirectoryInfo directory,
            string repositoryRoot,
            string sourcePath,
            RepositorySnapshotManifest manifest)
        {
            this.directory = directory;
            RepositoryRoot = repositoryRoot;
            SourcePath = sourcePath;
            Manifest = manifest;
        }

        public string RepositoryRoot { get; }

        public string SourcePath { get; }

        public RepositorySnapshotManifest Manifest { get; }

        public static async Task<SnapshotFixture> CreateAsync(
            string repositoryRelativePath,
            string sourceText)
        {
            var directory = Directory.CreateTempSubdirectory(
                "sarif-regress-snapshot-");
            try
            {
                var repositoryRoot = Path.Combine(
                    directory.FullName,
                    "repository");
                var manifestPath = Path.Combine(
                    directory.FullName,
                    "snapshot.json");
                var sourcePath = Path.Combine(
                    repositoryRoot,
                    repositoryRelativePath.Replace(
                        '/',
                        Path.DirectorySeparatorChar));
                Directory.CreateDirectory(
                    Path.GetDirectoryName(sourcePath)!);
                var sourceBytes = new UTF8Encoding(
                    encoderShouldEmitUTF8Identifier: false)
                    .GetBytes(sourceText);
                await File.WriteAllBytesAsync(
                    sourcePath,
                    sourceBytes,
                    TestContext.Current.CancellationToken);
                var digest = Convert
                    .ToHexString(SHA256.HashData(sourceBytes))
                    .ToLowerInvariant();
                await File.WriteAllTextAsync(
                    manifestPath,
                    "{\"schemaVersion\":\"1\",\"files\":{"
                    + $"\"{repositoryRelativePath}\":\"{digest}\"}}}}",
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                    TestContext.Current.CancellationToken);
                var manifestResult =
                    await RepositorySnapshotManifestReader.ReadAsync(
                        manifestPath,
                        cancellationToken:
                            TestContext.Current.CancellationToken);
                var manifest = Assert.IsType<RepositorySnapshotManifest>(
                    manifestResult.Manifest);
                Assert.Empty(manifestResult.Diagnostics);
                return new SnapshotFixture(
                    directory,
                    repositoryRoot,
                    sourcePath,
                    manifest);
            }
            catch
            {
                directory.Delete(recursive: true);
                throw;
            }
        }

        public void Dispose() => directory.Delete(recursive: true);
    }
}
