using System.Globalization;
using System.Text.Json;
using SarifRegress.Cli;

namespace SarifRegress.UnitTests;

public sealed class CliInvocationTests
{
    private const string SingleFindingSarif =
        """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "Example Analyzer" } },
            "results": [{
              "ruleId": "EXAMPLE001",
              "message": { "text": "Stable message" },
              "partialFingerprints": {
                "primaryLocationLineHash/v1": "stable-fingerprint"
              },
              "locations": [{
                "physicalLocation": {
                  "artifactLocation": { "uri": "src/example.cs" },
                  "region": { "startLine": 2, "startColumn": 1 }
                }
              }]
            }]
          }]
        }
        """;

    private const string ExternalBaseFindingSarif =
        """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "Example Analyzer" } },
            "results": [{
              "ruleId": "EXAMPLE001",
              "message": { "text": "Stable message" },
              "partialFingerprints": {
                "primaryLocationLineHash/v1": "stable-fingerprint"
              },
              "locations": [{
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "src/example.cs",
                    "uriBaseId": "EXPLICIT_ROOT"
                  },
                  "region": { "startLine": 2, "startColumn": 1 }
                }
              }]
            }]
          }]
        }
        """;

    [Fact]
    public void Compare_without_baseline_fails_with_an_actionable_error()
    {
        var invocation = Invoke(
            "compare",
            "--candidate",
            "candidate.sarif");

        Assert.NotEqual(0, invocation.ExitCode);
        Assert.Contains(
            "--baseline",
            invocation.StandardOutput + invocation.StandardError,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_without_candidate_fails_with_an_actionable_error()
    {
        var invocation = Invoke(
            "compare",
            "--baseline",
            "baseline.sarif");

        Assert.NotEqual(0, invocation.ExitCode);
        Assert.Contains(
            "--candidate",
            invocation.StandardOutput + invocation.StandardError,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("-?")]
    public void Compare_help_does_not_require_input_options(string helpOption)
    {
        var invocation = Invoke("compare", helpOption);
        var combinedOutput = invocation.StandardOutput + invocation.StandardError;

        Assert.Equal(0, invocation.ExitCode);
        Assert.Contains("--baseline", combinedOutput, StringComparison.Ordinal);
        Assert.Contains("--candidate", combinedOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("is missing", combinedOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Valid_compare_writes_stable_json_to_standard_output()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardError);
        using var report = JsonDocument.Parse(invocation.StandardOutput);
        var summary = report.RootElement.GetProperty("summary");
        Assert.Equal(1, summary.GetProperty("baselineCount").GetInt32());
        Assert.Equal(1, summary.GetProperty("candidateCount").GetInt32());
        Assert.Equal(1, summary.GetProperty("unchanged").GetInt32());
        Assert.DoesNotContain(
            workspace.Root,
            invocation.StandardOutput,
            StringComparison.Ordinal);
        Assert.EndsWith("\n", invocation.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_materializes_json_html_and_sarif_from_one_stable_report()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--json-out",
            "out/report.json",
            "--html-out",
            "out/report.html",
            "--sarif-out",
            "out/report.sarif");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Equal(string.Empty, invocation.StandardError);
        var json = workspace.Read("out/report.json");
        var html = workspace.Read("out/report.html");
        var sarif = workspace.Read("out/report.sarif");
        using var report = JsonDocument.Parse(json);
        using var sarifLog = JsonDocument.Parse(sarif);
        Assert.Equal("1", report.RootElement
            .GetProperty("outputSchemaVersion")
            .GetString());
        Assert.StartsWith("<!doctype html>\n", html, StringComparison.Ordinal);
        Assert.Equal(
            "2.1.0",
            sarifLog.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public void Config_relative_repository_root_is_resolved_from_the_config_directory()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);
        workspace.Write(
            "config/regress.json",
            """
            {
              "schemaVersion": "1",
              "repoRoot": "../repository",
              "policy": { "failOn": [] }
            }
            """);
        workspace.Write(
            "repository/src/example.cs",
            "namespace Example;\ninternal sealed class ExampleType { }\n");

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "config/regress.json");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Contains(
            "\"kind\": \"context-snippet\"",
            invocation.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            workspace.Root,
            invocation.StandardOutput,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Explicit_repository_root_overrides_the_configured_root()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);
        workspace.Write(
            "config/regress.json",
            """
            {
              "schemaVersion": "1",
              "repoRoot": "../missing",
              "policy": { "failOn": [] }
            }
            """);
        workspace.Write(
            "repository/src/example.cs",
            "namespace Example;\ninternal sealed class ExampleType { }\n");

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "config/regress.json",
            "--repo",
            "repository");

        Assert.Equal(0, invocation.ExitCode);
        Assert.Contains(
            "\"kind\": \"context-snippet\"",
            invocation.StandardOutput,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Explicit_repository_root_preserves_configured_uri_bases()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", ExternalBaseFindingSarif);
        workspace.Write("candidate.sarif", ExternalBaseFindingSarif);
        workspace.Write(
            "regress.json",
            """
            {
              "schemaVersion": "1",
              "uriBaseMappings": [
                { "id": "EXPLICIT_ROOT", "uri": "repo:/" }
              ],
              "policy": { "failOn": [] }
            }
            """);
        workspace.Write(
            "repository/src/example.cs",
            "namespace Example;\ninternal sealed class ExampleType { }\n");

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "regress.json",
            "--repo",
            "repository");

        Assert.Equal(0, invocation.ExitCode);
        Assert.DoesNotContain(
            "CANON0032",
            invocation.StandardOutput + invocation.StandardError,
            StringComparison.Ordinal);
        Assert.Contains(
            "configured-uri-base",
            invocation.StandardOutput,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Equivalent_local_uri_base_roots_produce_identical_stable_reports()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", ExternalBaseFindingSarif);
        workspace.Write("candidate.sarif", ExternalBaseFindingSarif);
        var firstRoot = workspace.PathOf("first-root");
        var secondRoot = workspace.PathOf("second-root");
        Directory.CreateDirectory(firstRoot);
        Directory.CreateDirectory(secondRoot);
        var firstUri = new Uri(
            firstRoot + Path.DirectorySeparatorChar).AbsoluteUri;
        var secondUri = new Uri(
            secondRoot + Path.DirectorySeparatorChar).AbsoluteUri;
        workspace.Write(
            "first.json",
            JsonSerializer.Serialize(
                new
                {
                    schemaVersion = "1",
                    repoRoot = firstRoot,
                    uriBaseMappings = new[]
                    {
                        new { id = "EXPLICIT_ROOT", uri = firstUri },
                    },
                    policy = new { failOn = Array.Empty<string>() },
                }));
        workspace.Write(
            "second.json",
            JsonSerializer.Serialize(
                new
                {
                    schemaVersion = "1",
                    repoRoot = secondRoot,
                    uriBaseMappings = new[]
                    {
                        new { id = "EXPLICIT_ROOT", uri = secondUri },
                    },
                    policy = new { failOn = Array.Empty<string>() },
                }));

        var first = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "first.json");
        var second = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "second.json");

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(0, second.ExitCode);
        Assert.Equal(first.StandardOutput, second.StandardOutput);
        Assert.DoesNotContain(
            firstRoot,
            first.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            secondRoot,
            second.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            firstUri,
            first.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            secondUri,
            second.StandardOutput,
            StringComparison.Ordinal);
        Assert.Contains(
            "configured-uri-base",
            first.StandardOutput,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Configured_regression_policy_returns_exit_code_three_after_reporting()
    {
        using var workspace = new TestWorkspace();
        workspace.Write(
            "baseline.sarif",
            """{ "version": "2.1.0", "runs": [] }""");
        workspace.Write("candidate.sarif", SingleFindingSarif);

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif");

        Assert.Equal(3, invocation.ExitCode);
        using var report = JsonDocument.Parse(invocation.StandardOutput);
        Assert.Equal(
            1,
            report.RootElement
                .GetProperty("summary")
                .GetProperty("new")
                .GetInt32());
    }

    [Fact]
    public void Empty_fail_on_policy_returns_zero_for_the_same_new_finding()
    {
        using var workspace = new TestWorkspace();
        workspace.Write(
            "baseline.sarif",
            """{ "version": "2.1.0", "runs": [] }""");
        workspace.Write("candidate.sarif", SingleFindingSarif);
        workspace.Write(
            "regress.json",
            """
            {
              "schemaVersion": "1",
              "policy": { "failOn": [] }
            }
            """);

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "regress.json");

        Assert.Equal(0, invocation.ExitCode);
        using var report = JsonDocument.Parse(invocation.StandardOutput);
        Assert.Equal(
            1,
            report.RootElement
                .GetProperty("summary")
                .GetProperty("new")
                .GetInt32());
    }

    [Fact]
    public void Github_incompatibility_policy_returns_three_for_a_warning()
    {
        using var workspace = new TestWorkspace();
        const string nonRepositorySarif =
            """
            {
              "version": "2.1.0",
              "runs": [{
                "tool": { "driver": { "name": "Example Analyzer" } },
                "results": [{
                  "ruleId": "EXAMPLE001",
                  "message": { "text": "Stable message" },
                  "partialFingerprints": {
                    "primaryLocationLineHash/v1": "stable-fingerprint"
                  },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "file:///outside/example.cs"
                      },
                      "region": { "startLine": 2 }
                    }
                  }]
                }]
              }]
            }
            """;
        workspace.Write("baseline.sarif", nonRepositorySarif);
        workspace.Write("candidate.sarif", nonRepositorySarif);
        workspace.Write(
            "regress.json",
            """
            {
              "schemaVersion": "1",
              "policy": {
                "failOn": [],
                "treatGithubIncompatibilityAsError": true
              }
            }
            """);

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "regress.json");

        Assert.Equal(3, invocation.ExitCode);
        Assert.Contains("GHCS0017 warning:", invocation.StandardError, StringComparison.Ordinal);
        Assert.Contains(
            "\"code\": \"GHCS0017\"",
            invocation.StandardOutput,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Malformed_input_returns_one_without_replacing_output_files()
    {
        using var workspace = new TestWorkspace();
        workspace.Write(
            "baseline.sarif",
            """{ "version": "2.1.0", "runs": [""");
        workspace.Write("candidate.sarif", SingleFindingSarif);
        workspace.Write("out/report.json", "existing-json");
        workspace.Write("out/report.html", "existing-html");
        workspace.Write("out/report.sarif", "existing-sarif");

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--json-out",
            "out/report.json",
            "--html-out",
            "out/report.html",
            "--sarif-out",
            "out/report.sarif");

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Contains("PARSE0100 error:", invocation.StandardError, StringComparison.Ordinal);
        Assert.DoesNotContain(
            workspace.Root,
            invocation.StandardError,
            StringComparison.Ordinal);
        Assert.Equal("existing-json", workspace.Read("out/report.json"));
        Assert.Equal("existing-html", workspace.Read("out/report.html"));
        Assert.Equal("existing-sarif", workspace.Read("out/report.sarif"));
    }

    [Fact]
    public void Output_path_cannot_overwrite_an_input()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--json-out",
            "baseline.sarif");

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Contains("CLI0006 error:", invocation.StandardError, StringComparison.Ordinal);
        Assert.Equal(SingleFindingSarif, workspace.Read("baseline.sarif"));
    }

    [Fact]
    public void Failed_multi_output_write_leaves_no_committed_output()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);
        workspace.Write("z-blocked", "not-a-directory");

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--json-out",
            "a-output/report.json",
            "--html-out",
            "z-blocked/report.html");

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Contains("CLI0002 error:", invocation.StandardError, StringComparison.Ordinal);
        Assert.False(File.Exists(workspace.PathOf("a-output/report.json")));
        Assert.Equal("not-a-directory", workspace.Read("z-blocked"));
        Assert.Empty(
            Directory.GetFiles(
                workspace.PathOf("a-output"),
                "*",
                SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public void Invalid_configuration_returns_one_with_a_stable_diagnostic()
    {
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);
        workspace.Write(
            "regress.json",
            """{ "schemaVersion": "future" }""");

        var invocation = InvokeFromDirectory(
            workspace.Root,
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--config",
            "regress.json");

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal(string.Empty, invocation.StandardOutput);
        Assert.Contains("SCHEMA0002 error:", invocation.StandardError, StringComparison.Ordinal);
        Assert.DoesNotContain(
            workspace.Root,
            invocation.StandardError,
            StringComparison.Ordinal);
    }

    private static CliInvocationResult Invoke(params string[] arguments)
    {
        return InvokeFromDirectory(Directory.GetCurrentDirectory(), arguments);
    }

    private static CliInvocationResult InvokeFromDirectory(
        string currentDirectory,
        params string[] arguments)
    {
        using var standardOutput = new StringWriter(CultureInfo.InvariantCulture);
        using var standardError = new StringWriter(CultureInfo.InvariantCulture);

        var exitCode = CliApplication.Run(
            arguments,
            standardOutput,
            standardError,
            currentDirectory);

        return new CliInvocationResult(
            exitCode,
            standardOutput.ToString(),
            standardError.ToString());
    }

    private sealed record CliInvocationResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private sealed class TestWorkspace : IDisposable
    {
        public TestWorkspace()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "sarif-regress-cli-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Write(string relativePath, string contents)
        {
            var path = Path.Combine(Root, relativePath);
            Directory.CreateDirectory(
                Path.GetDirectoryName(path)
                    ?? throw new InvalidOperationException(
                        "The test path has no containing directory."));
            File.WriteAllText(path, contents);
        }

        public string Read(string relativePath) =>
            File.ReadAllText(Path.Combine(Root, relativePath));

        public string PathOf(string relativePath) =>
            Path.Combine(Root, relativePath);

        public void Dispose()
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
