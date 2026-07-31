using System.Text.Json;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class DeterminismAndSafetyTests
{
    [Fact]
    public void Checksum_manifest_is_ordinal_exact_and_detects_corruption()
    {
        string root = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            var files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["z-report.json"] = ValidationTestRepository.Utf8("{\"z\":1}\n"),
                ["a-report.json"] = ValidationTestRepository.Utf8("{\"a\":1}\n"),
            };
            foreach ((string name, byte[] bytes) in files)
            {
                File.WriteAllBytes(Path.Combine(root, name), bytes);
            }

            byte[] manifest = ChecksumManifest.Create(files);
            Assert.StartsWith(
                "e346432021b04179518d9614f3560ccd71354a4ee101ddcb893d6959a9d6301c  a-report.json\n",
                System.Text.Encoding.UTF8.GetString(manifest),
                StringComparison.Ordinal);
            ChecksumManifest.VerifyFiles(root, manifest, files.Keys);

            File.AppendAllText(Path.Combine(root, "a-report.json"), " ");
            var exception = Assert.Throws<InvalidDataException>(() =>
                ChecksumManifest.VerifyFiles(root, manifest, files.Keys));
            Assert.Contains(
                "Checksum verification failed",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Corrupted_committed_expected_output_fails_exact_byte_comparison()
    {
        string root = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            const string name = "comparison-summary.json";
            byte[] generated = ValidationTestRepository.Utf8("{\"status\":\"ready\"}\n");
            byte[] corrupted = ValidationTestRepository.Utf8("{\"status\":\"blocked\"}\n");
            File.WriteAllBytes(Path.Combine(root, name), corrupted);

            var exception = Assert.Throws<InvalidDataException>(() =>
                ExpectedOutputVerifier.Verify(
                    root,
                    new Dictionary<string, byte[]>(StringComparer.Ordinal)
                    {
                        [name] = generated,
                    }));

            Assert.Contains("byte-for-byte", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Stable_json_is_byte_identical_across_repeated_serialization()
    {
        static byte[] Serialize() => StableJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "1");
            writer.WriteStartArray("cases");
            writer.WriteStringValue("gitleaks");
            writer.WriteStringValue("pmd");
            writer.WriteStringValue("semgrep");
            writer.WriteEndArray();
            writer.WriteEndObject();
        });

        byte[] first = Serialize();
        byte[] second = Serialize();

        Assert.True(first.AsSpan().SequenceEqual(second));
        Assert.Equal((byte)'\n', first[^1]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.NotEqual(0xEF, first[0]);
    }

    [Fact]
    public void Tree_hash_is_independent_of_absolute_checkout_root()
    {
        string firstRoot = ValidationTestRepository.CreateTemporaryDirectory();
        string secondRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            WritePortableTree(firstRoot);
            WritePortableTree(secondRoot);

            string first = TreeHasher.Compute(firstRoot, 1024, 8);
            string second = TreeHasher.Compute(secondRoot, 1024, 8);

            Assert.Equal(first, second);
        }
        finally
        {
            Directory.Delete(firstRoot, recursive: true);
            Directory.Delete(secondRoot, recursive: true);
        }
    }

    [Fact]
    public void Portable_paths_reject_windows_spelling_before_normalized_output()
    {
        Assert.Equal(
            "validation/holdout/cases/semgrep/baseline.sarif",
            StablePath.RequireRepositoryRelative(
                "validation/holdout/cases/semgrep/baseline.sarif",
                "fixture"));

        Assert.Throws<InvalidDataException>(() =>
            StablePath.RequireRepositoryRelative(
                "validation\\holdout\\cases\\semgrep\\baseline.sarif",
                "fixture"));
        Assert.Throws<InvalidDataException>(() =>
            StablePath.RequireRepositoryRelative(
                "C:\\checkout\\baseline.sarif",
                "fixture"));
    }

    [Theory]
    [InlineData("{\"path\":\"/home/runner/work/repository/report.json\"}\n")]
    [InlineData("{\"path\":\"C:\\\\work\\\\repository\\\\report.json\"}\n")]
    [InlineData("{\"generatedAt\":\"2026-08-01T12:34:56Z\"}\n")]
    [InlineData("{\"uri\":\"file:///tmp/report.json\"}\n")]
    public void Ambient_data_guard_rejects_paths_and_timestamps(string json)
    {
        Assert.Throws<InvalidDataException>(() => AmbientDataGuard.Validate(
            ValidationTestRepository.Utf8(json),
            ValidationTestRepository.FindRoot()));
    }

    [Fact]
    public void Ambient_data_guard_rejects_the_current_hostname()
    {
        byte[] bytes = ValidationTestRepository.Utf8(
            $"{{\"host\":{JsonSerializer.Serialize(Environment.MachineName)}}}\n");

        Assert.Throws<InvalidDataException>(() => AmbientDataGuard.Validate(
            bytes,
            ValidationTestRepository.FindRoot()));
    }

    [Fact]
    public void Ambient_data_guard_accepts_only_portable_stable_content()
    {
        byte[] bytes = ValidationTestRepository.Utf8(
            "{\"caseId\":\"semgrep\",\"path\":\"src/example.py\"}\n");

        AmbientDataGuard.Validate(bytes, ValidationTestRepository.FindRoot());
    }

    [Fact]
    public void Both_validation_scripts_enforce_fixture_snapshots()
    {
        string root = ValidationTestRepository.FindRoot();
        foreach (string relativePath in new[]
                 {
                     "scripts/validate-holdout.sh",
                     "scripts/validate-holdout.ps1",
                 })
        {
            string script = File.ReadAllText(Path.Combine(
                root,
                relativePath.Replace('/', Path.DirectorySeparatorChar)));

            Assert.Contains("holdout-before", script, StringComparison.Ordinal);
            Assert.Contains("holdout-after", script, StringComparison.Ordinal);
            Assert.Contains(
                "Holdout validation modified one or more committed fixture files.",
                script,
                StringComparison.Ordinal);
            Assert.Contains("holdout-final.sha256", script, StringComparison.Ordinal);
            Assert.Contains(
                "cross-platform-attestation.json",
                script,
                StringComparison.Ordinal);
            Assert.Contains(
                "Unattested candidate generation expected validation exit code 2",
                script,
                StringComparison.Ordinal);
            Assert.Contains(
                "crossPlatformByteIdentity",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "--cross-platform-byte-identity",
                script,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Hosted_coordinator_binds_real_artifacts_into_a_raw_attestation()
    {
        string workflow = File.ReadAllText(Path.Combine(
            ValidationTestRepository.FindRoot(),
            ".github",
            "workflows",
            "holdout-validation.yml"));

        Assert.Contains("artifact-id", workflow, StringComparison.Ordinal);
        Assert.Contains("artifact-digest", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "cross-platform-attestation.json",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("GITHUB_RUN_ID", workflow, StringComparison.Ordinal);
        Assert.Contains("GITHUB_RUN_ATTEMPT", workflow, StringComparison.Ordinal);
        Assert.Contains("GITHUB_SHA", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "Linux and Windows selected different attestation modes.",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--cross-platform-byte-identity",
            workflow,
            StringComparison.Ordinal);
    }

    private static void WritePortableTree(string root)
    {
        string nested = Path.Combine(root, "nested");
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(root, "a.txt"), "alpha\n");
        File.WriteAllText(Path.Combine(nested, "b.txt"), "beta\n");
    }
}
