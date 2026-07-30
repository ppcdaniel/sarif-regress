using System.Diagnostics;

namespace SarifRegress.IntegrationTests;

public sealed class BootstrapIntegrationTests
{
    private const string PlaceholderOutput =
        "SarifRegress comparison is not implemented yet.\n";

    [Fact]
    public async Task Real_cli_process_propagates_placeholder_exit_code_and_output()
    {
        var repositoryRoot = FindRepositoryRoot();
        var cliProject = Path.Combine(
            repositoryRoot,
            "src",
            "SarifRegress.Cli",
            "SarifRegress.Cli.csproj");
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
            "baseline.sarif",
            "--candidate",
            "candidate.sarif");

        Assert.Equal(2, result.ExitCode);
        Assert.Equal(PlaceholderOutput, result.StandardOutput);
        Assert.Equal(string.Empty, result.StandardError);
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
}
