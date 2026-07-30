using System.Globalization;
using SarifRegress.Cli;

namespace SarifRegress.UnitTests;

public sealed class CliInvocationTests
{
    private const string PlaceholderOutput =
        "SarifRegress comparison is not implemented yet.\n";

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

    [Fact]
    public void Valid_compare_returns_not_implemented_and_exact_output()
    {
        var invocation = Invoke(
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--repo",
            "repository",
            "--config",
            "sarif-regress.json",
            "--json-out",
            "comparison.json");

        Assert.Equal(2, invocation.ExitCode);
        Assert.Equal(PlaceholderOutput, invocation.StandardOutput);
        Assert.Equal(string.Empty, invocation.StandardError);
    }

    private static CliInvocationResult Invoke(params string[] arguments)
    {
        using var standardOutput = new StringWriter(CultureInfo.InvariantCulture);
        using var standardError = new StringWriter(CultureInfo.InvariantCulture);

        var exitCode = CliApplication.Run(arguments, standardOutput, standardError);

        return new CliInvocationResult(
            exitCode,
            standardOutput.ToString(),
            standardError.ToString());
    }

    private sealed record CliInvocationResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);
}
