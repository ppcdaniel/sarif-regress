using System.Diagnostics;

namespace SarifRegress.IntegrationTests;

public sealed class BootstrapIntegrationTests
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

    [Fact]
    public async Task Real_cli_process_runs_the_complete_compare_pipeline()
    {
        var repositoryRoot = FindRepositoryRoot();
        var cliProject = Path.Combine(
            repositoryRoot,
            "src",
            "SarifRegress.Cli",
            "SarifRegress.Cli.csproj");
        using var workspace = new TestWorkspace();
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);
        var result = await RunDotnetAsync(
            repositoryRoot,
            "run",
            "--project",
            cliProject,
            "--configuration",
            "Release",
            "--no-build",
            "--",
            "compare",
            "--baseline",
            workspace.PathOf("baseline.sarif"),
            "--candidate",
            workspace.PathOf("candidate.sarif"),
            "--json-out",
            workspace.PathOf("report.json"),
            "--html-out",
            workspace.PathOf("report.html"),
            "--sarif-out",
            workspace.PathOf("report.sarif"));

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(string.Empty, result.StandardOutput);
        Assert.Equal(string.Empty, result.StandardError);
        Assert.Contains(
            "\"unchanged\": 1",
            workspace.Read("report.json"),
            StringComparison.Ordinal);
        Assert.StartsWith(
            "<!doctype html>\n",
            workspace.Read("report.html"),
            StringComparison.Ordinal);
        Assert.Contains(
            "\"version\": \"2.1.0\"",
            workspace.Read("report.sarif"),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            workspace.Root,
            workspace.Read("report.json"),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Real_cli_process_returns_one_for_malformed_sarif()
    {
        var repositoryRoot = FindRepositoryRoot();
        var cliProject = Path.Combine(
            repositoryRoot,
            "src",
            "SarifRegress.Cli",
            "SarifRegress.Cli.csproj");
        using var workspace = new TestWorkspace();
        workspace.Write(
            "baseline.sarif",
            """{ "version": "2.1.0", "runs": [""");
        workspace.Write("candidate.sarif", SingleFindingSarif);
        var result = await RunDotnetAsync(
            repositoryRoot,
            "run",
            "--project",
            cliProject,
            "--configuration",
            "Release",
            "--no-build",
            "--",
            "compare",
            "--baseline",
            workspace.PathOf("baseline.sarif"),
            "--candidate",
            workspace.PathOf("candidate.sarif"));

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(string.Empty, result.StandardOutput);
        Assert.Contains("PARSE0100 error:", result.StandardError, StringComparison.Ordinal);
        Assert.DoesNotContain(
            workspace.Root,
            result.StandardError,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Solution_builds_with_no_warnings()
    {
        var repositoryRoot = FindRepositoryRoot();
        var solutionPath = Path.Combine(repositoryRoot, "SarifRegress.slnx");
        var artifactsPath = Path.Combine(
            Path.GetTempPath(),
            "sarif-regress-build-verification",
            Guid.NewGuid().ToString("N"));
        var result = await RunDotnetAsync(
            repositoryRoot,
            "build",
            solutionPath,
            "--configuration",
            "Release",
            "--no-incremental",
            "--warnaserror",
            "--artifacts-path",
            artifactsPath,
            "--nologo",
            "-p:RestoreLockedMode=true");
        var combinedOutput = result.StandardOutput + result.StandardError;

        Assert.True(
            result.ExitCode == 0,
            "The clean Release build failed." + Environment.NewLine + combinedOutput);
        Assert.False(
            combinedOutput.Contains(": warning", StringComparison.OrdinalIgnoreCase),
            "The Release build emitted a warning." + Environment.NewLine + combinedOutput);
    }

    private static async Task<ProcessResult> RunDotnetAsync(
        string workingDirectory,
        params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet",
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        startInfo.Environment["DOTNET_NOLOGO"] = "1";

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start the dotnet process.");
        var standardOutputTask = process.StandardOutput.ReadToEndAsync();
        var standardErrorTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        return new ProcessResult(
            process.ExitCode,
            await standardOutputTask,
            await standardErrorTask);
    }

    private static string FindRepositoryRoot()
    {
        for (
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            directory is not null;
            directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SarifRegress.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException(
            "Could not locate the repository root containing SarifRegress.slnx.");
    }

    private sealed record ProcessResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private sealed class TestWorkspace : IDisposable
    {
        public TestWorkspace()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "sarif-regress-integration-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string PathOf(string relativePath) =>
            Path.Combine(Root, relativePath);

        public void Write(string relativePath, string contents)
        {
            File.WriteAllText(PathOf(relativePath), contents);
        }

        public string Read(string relativePath) =>
            File.ReadAllText(PathOf(relativePath));

        public void Dispose()
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
