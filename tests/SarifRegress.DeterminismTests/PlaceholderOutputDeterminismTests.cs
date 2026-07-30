using System.Globalization;
using System.Text;
using SarifRegress.Cli;

namespace SarifRegress.DeterminismTests;

public sealed class PlaceholderOutputDeterminismTests
{
    private static readonly UTF8Encoding StableUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    [Fact]
    public void Consecutive_valid_invocations_produce_byte_identical_output()
    {
        var firstInvocation = Invoke();
        var secondInvocation = Invoke();

        Assert.Equal(2, firstInvocation.ExitCode);
        Assert.Equal(2, secondInvocation.ExitCode);
        Assert.Equal(
            StableUtf8.GetBytes(firstInvocation.StandardOutput),
            StableUtf8.GetBytes(secondInvocation.StandardOutput));
    }

    private static CliInvocationResult Invoke()
    {
        using var standardOutput = new StringWriter(CultureInfo.InvariantCulture);
        using var standardError = new StringWriter(CultureInfo.InvariantCulture);
        var arguments = new[]
        {
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
        };

        var exitCode = CliApplication.Run(arguments, standardOutput, standardError);

        return new CliInvocationResult(exitCode, standardOutput.ToString());
    }

    private sealed record CliInvocationResult(int ExitCode, string StandardOutput);
}
