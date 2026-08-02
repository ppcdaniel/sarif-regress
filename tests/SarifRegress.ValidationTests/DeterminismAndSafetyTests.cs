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
    public void Both_validation_scripts_are_strict_and_enforce_fixture_snapshots()
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
                "--expected-root",
                script,
                StringComparison.Ordinal);
            Assert.Contains(
                "--compare-expected",
                script,
                StringComparison.Ordinal);
            Assert.Contains(
                "v3-to-v3.1-delta.json",
                script,
                StringComparison.Ordinal);
            if (relativePath.EndsWith(".sh", StringComparison.Ordinal))
            {
                Assert.Contains(
                    "--compare-expected true",
                    script,
                    StringComparison.Ordinal);
                Assert.Contains(
                    "cd -- \"${repository_root}\"",
                    script,
                    StringComparison.Ordinal);
            }
            else
            {
                Assert.Contains(
                    "'--compare-expected',",
                    script,
                    StringComparison.Ordinal);
                Assert.Contains("'true',", script, StringComparison.Ordinal);
                Assert.Contains(
                    "Push-Location -LiteralPath $repositoryRoot",
                    script,
                    StringComparison.Ordinal);
            }
            Assert.DoesNotContain(
                "--cross-platform-byte-identity",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "--generate-cross-platform-attestation-candidate",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "--regenerate-attested-expected",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "GenerateCrossPlatformAttestationCandidate",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "RegenerateAttestedExpected",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                ".regenerate-expected",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "Unattested candidate",
                script,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "$global:LASTEXITCODE = 0",
                script,
                StringComparison.Ordinal);
        }

        Assert.False(File.Exists(Path.Combine(
            root,
            "validation",
            "holdout",
            ".regenerate-expected")));
    }

    [Fact]
    public void Hosted_workflow_is_strict_and_binds_real_artifact_evidence()
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
        Assert.Contains(
            "CHECKED_OUT_SOURCE_SHA",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "os.environ[\"GITHUB_SHA\"]",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "./scripts/verify.sh",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "${GITHUB_WORKSPACE}/scripts/validate-holdout.sh",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            ".\\scripts\\verify.ps1",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "Join-Path $env:GITHUB_WORKSPACE 'scripts/validate-holdout.ps1'",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "cd -- \"${RUNNER_TEMP}\"",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "Push-Location -LiteralPath $env:RUNNER_TEMP",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "v3-to-v3.1-delta.json",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "matcherV3HistoryChecksumManifestSha256",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("matcherV3ReportSha256", workflow, StringComparison.Ordinal);
        Assert.Contains("matcherV31ReportSha256", workflow, StringComparison.Ordinal);
        Assert.Contains("v3ToV31DeltaReportSha256", workflow, StringComparison.Ordinal);
        Assert.Contains("v3ToV31DeltaSha256", workflow, StringComparison.Ordinal);
        Assert.Contains("v3ToV31Delta", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "\"schemaVersion\": \"3\"",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "\"schemaVersion\": \"2\"",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--cross-platform-byte-identity",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            ".regenerate-expected",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--generate-cross-platform-attestation-candidate",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--regenerate-attested-expected",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Select attestation mode",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "attestation-mode",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "TrackedOutputTests",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain("LINUX_MODE", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("WINDOWS_MODE", workflow, StringComparison.Ordinal);
        Assert.Contains("  sparse-experiment-linux:\n", workflow, StringComparison.Ordinal);
        Assert.Contains("  sparse-experiment-windows:\n", workflow, StringComparison.Ordinal);
        Assert.Contains("  sparse-experiment-compare:\n", workflow, StringComparison.Ordinal);
        Assert.Contains("sparse-run", workflow, StringComparison.Ordinal);
        Assert.Contains("sparse-evaluate", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-observations.json",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-gate-evidence.json",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "artifact-ids: ${{ needs.sparse-experiment-linux.outputs.artifact_id }}",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "artifact-ids: ${{ needs.sparse-experiment-windows.outputs.artifact_id }}",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("digest-mismatch: error", workflow, StringComparison.Ordinal);
        Assert.Contains(
            ".workflow_run.head_sha == $source_sha",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "sparse-experiment-bootstrap",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "SPARSE_EXPERIMENT_MODE",
            workflow,
            StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(
            ValidationTestRepository.FindRoot(),
            ".github",
            "workflows",
            "holdout-bootstrap.yml")));

        string linuxExperiment = SliceWorkflowJob(
            workflow,
            "sparse-experiment-linux",
            "sparse-experiment-windows");
        string windowsExperiment = SliceWorkflowJob(
            workflow,
            "sparse-experiment-windows",
            "sparse-experiment-compare");
        string experimentCoordinator = SliceWorkflowJob(
            workflow,
            "sparse-experiment-compare",
            "linux");
        Assert.Contains("for run_id in 1 2", linuxExperiment, StringComparison.Ordinal);
        Assert.Contains("foreach ($runId in @(1, 2))", windowsExperiment, StringComparison.Ordinal);
        Assert.Contains("cmp --silent", linuxExperiment, StringComparison.Ordinal);
        Assert.Contains("Assert-ByteIdentical", windowsExperiment, StringComparison.Ordinal);
        Assert.Contains("permissions:\n      actions: read", experimentCoordinator, StringComparison.Ordinal);
        Assert.Contains("artifact-ids:", experimentCoordinator, StringComparison.Ordinal);
        Assert.Contains("digest-mismatch: error", experimentCoordinator, StringComparison.Ordinal);
        Assert.Contains("cmp --silent", experimentCoordinator, StringComparison.Ordinal);
        Assert.DoesNotContain("if: always()", linuxExperiment, StringComparison.Ordinal);
        Assert.DoesNotContain("if: always()", windowsExperiment, StringComparison.Ordinal);
        Assert.DoesNotContain("if: always()", experimentCoordinator, StringComparison.Ordinal);
        Assert.DoesNotContain("experiment-report.json", linuxExperiment, StringComparison.Ordinal);
        Assert.DoesNotContain("experiment-report.json", windowsExperiment, StringComparison.Ordinal);
        Assert.DoesNotContain("experiment-report.json", experimentCoordinator, StringComparison.Ordinal);

        string captureWorkflow = File.ReadAllText(Path.Combine(
            ValidationTestRepository.FindRoot(),
            ".github",
            "workflows",
            "holdout-capture.yml"));
        Assert.Contains("workflow_dispatch:", captureWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("pull_request:", captureWorkflow, StringComparison.Ordinal);
    }

    [Fact]
    public void Supporting_evidence_workflows_emit_exact_head_role_projections()
    {
        string workflowRoot = Path.Combine(
            ValidationTestRepository.FindRoot(),
            ".github",
            "workflows");
        string holdout = File.ReadAllText(Path.Combine(
            workflowRoot,
            "holdout-validation.yml"));
        string determinism = File.ReadAllText(Path.Combine(
            workflowRoot,
            "determinism.yml"));
        string benchmarks = File.ReadAllText(Path.Combine(
            workflowRoot,
            "benchmarks.yml"));

        Assert.Contains(
            "development-corpus-report.json",
            holdout,
            StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-release-projection.json",
            holdout,
            StringComparison.Ordinal);
        Assert.DoesNotContain("if-no-files-found: warn", holdout, StringComparison.Ordinal);
        Assert.Contains("for run_id in 1 2", determinism, StringComparison.Ordinal);
        Assert.Contains("foreach ($runId in @(1, 2))", determinism, StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-determinism-projection.json",
            determinism,
            StringComparison.Ordinal);
        Assert.Contains("          - 1000\n", benchmarks, StringComparison.Ordinal);
        Assert.Contains("          - 10000\n", benchmarks, StringComparison.Ordinal);
        Assert.Contains("          - 100000\n", benchmarks, StringComparison.Ordinal);
        Assert.Contains(
            "validation/research/sparse-sarif/**",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains(
            "validation/tools/SarifRegress.Validation/**",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-resource-projection.json",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-resource-values.json",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains("math.ceil(", benchmarks, StringComparison.Ordinal);
        Assert.Contains(
            "observedMaximumComponentFindingCount",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains(
            "maximumAdmittedAssignmentComponentSize",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains(
            "maximumAssignmentSideSize",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains("resource-limits", benchmarks, StringComparison.Ordinal);
        Assert.Contains("resource-limits.json", benchmarks, StringComparison.Ordinal);
        Assert.Contains(
            "sourceContextProjectionBenchmarked\": False",
            benchmarks,
            StringComparison.Ordinal);
        Assert.Contains("projection_evidence", benchmarks, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "copy.deepcopy(full_variants)",
            benchmarks,
            StringComparison.Ordinal);
        Assert.DoesNotContain("if-no-files-found: warn", benchmarks, StringComparison.Ordinal);

        string resourceProjection = File.ReadAllText(Path.Combine(
            ValidationTestRepository.FindRoot(),
            "validation",
            "research",
            "sparse-sarif",
            "expected",
            "projections",
            "sparse-experiment-resource-projection.json"));
        Assert.DoesNotContain(
            "elapsedMilliseconds",
            resourceProjection,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "peakWorkingSetBytes",
            resourceProjection,
            StringComparison.Ordinal);
        Assert.Contains(
            "sparse-experiment-resource-observations.json",
            resourceProjection,
            StringComparison.Ordinal);

        foreach (string workflow in new[] { holdout, determinism, benchmarks })
        {
            string[] actionReferences = workflow
                .Split('\n')
                .Select(line => line.Trim())
                .Where(line => line.StartsWith("uses: ", StringComparison.Ordinal))
                .Select(line => line["uses: ".Length..].Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries)[0])
                .ToArray();
            Assert.NotEmpty(actionReferences);
            Assert.All(actionReferences, reference =>
            {
                int separator = reference.LastIndexOf('@');
                Assert.True(separator > 0, $"Action is not pinned: {reference}");
                string revision = reference[(separator + 1)..];
                Assert.Equal(40, revision.Length);
                Assert.All(revision, character => Assert.True(Uri.IsHexDigit(character)));
            });
        }
    }

    [Theory]
    [InlineData("ci.yml")]
    [InlineData("holdout-validation.yml")]
    [InlineData("determinism.yml")]
    [InlineData("benchmarks.yml")]
    public void Pull_request_workflows_checkout_and_verify_the_exact_head(
        string workflowName)
    {
        string workflow = File.ReadAllText(Path.Combine(
            ValidationTestRepository.FindRoot(),
            ".github",
            "workflows",
            workflowName));
        const string exactHeadExpression =
            "${{ github.event.pull_request.head.sha || github.sha }}";

        int checkoutCount = CountOccurrences(
            workflow,
            "uses: actions/checkout@");
        Assert.True(checkoutCount > 0);
        Assert.Equal(
            checkoutCount,
            CountOccurrences(workflow, $"ref: {exactHeadExpression}"));
        Assert.Equal(
            checkoutCount,
            CountOccurrences(workflow, "- name: Verify exact source commit"));
        Assert.Contains(
            $"EXPECTED_SOURCE_SHA: {exactHeadExpression}",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "actual_source_sha=\"$(git rev-parse HEAD)\"",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "test \"${actual_source_sha}\" = \"${EXPECTED_SOURCE_SHA}\"",
            workflow,
            StringComparison.Ordinal);
    }

    private static int CountOccurrences(string value, string search)
    {
        int count = 0;
        int offset = 0;
        while (true)
        {
            int match = value.IndexOf(
                search,
                offset,
                StringComparison.Ordinal);
            if (match < 0)
            {
                return count;
            }

            count++;
            offset = match + search.Length;
        }
    }

    private static string SliceWorkflowJob(
        string workflow,
        string jobName,
        string nextJobName)
    {
        string startMarker = $"  {jobName}:\n";
        string endMarker = $"  {nextJobName}:\n";
        int start = workflow.IndexOf(startMarker, StringComparison.Ordinal);
        int end = workflow.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Workflow job '{jobName}' was not found.");
        Assert.True(end > start, $"Workflow job '{nextJobName}' was not found after '{jobName}'.");
        return workflow[start..end];
    }

    private static void WritePortableTree(string root)
    {
        string nested = Path.Combine(root, "nested");
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(root, "a.txt"), "alpha\n");
        File.WriteAllText(Path.Combine(nested, "b.txt"), "beta\n");
    }
}
