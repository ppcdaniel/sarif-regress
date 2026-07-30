using System.Globalization;
using System.Text;
using SarifRegress.Cli;

namespace SarifRegress.DeterminismTests;

public sealed class CompareOutputDeterminismTests
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

    private static readonly UTF8Encoding StableUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    [Fact]
    public void Consecutive_valid_invocations_produce_byte_identical_output()
    {
        using var firstWorkspace = new TestWorkspace();
        using var secondWorkspace = new TestWorkspace();
        var firstInvocation = Invoke(firstWorkspace);
        var secondInvocation = Invoke(secondWorkspace);

        Assert.Equal(0, firstInvocation.ExitCode);
        Assert.Equal(0, secondInvocation.ExitCode);
        Assert.Equal(string.Empty, firstInvocation.StandardOutput);
        Assert.Equal(string.Empty, secondInvocation.StandardOutput);
        Assert.Equal(string.Empty, firstInvocation.StandardError);
        Assert.Equal(string.Empty, secondInvocation.StandardError);
        Assert.Equal(
            StableUtf8.GetBytes(firstInvocation.StandardOutput),
            StableUtf8.GetBytes(secondInvocation.StandardOutput));
        Assert.Equal(
            StableUtf8.GetBytes(firstWorkspace.Read("report.json")),
            StableUtf8.GetBytes(secondWorkspace.Read("report.json")));
        Assert.Equal(
            StableUtf8.GetBytes(firstWorkspace.Read("report.html")),
            StableUtf8.GetBytes(secondWorkspace.Read("report.html")));
        Assert.Equal(
            StableUtf8.GetBytes(firstWorkspace.Read("report.sarif")),
            StableUtf8.GetBytes(secondWorkspace.Read("report.sarif")));
    }

    private static CliInvocationResult Invoke(TestWorkspace workspace)
    {
        workspace.Write("baseline.sarif", SingleFindingSarif);
        workspace.Write("candidate.sarif", SingleFindingSarif);
        using var standardOutput = new StringWriter(CultureInfo.InvariantCulture);
        using var standardError = new StringWriter(CultureInfo.InvariantCulture);
        var arguments = new[]
        {
            "compare",
            "--baseline",
            "baseline.sarif",
            "--candidate",
            "candidate.sarif",
            "--json-out",
            "report.json",
            "--html-out",
            "report.html",
            "--sarif-out",
            "report.sarif",
        };

        var exitCode = CliApplication.Run(
            arguments,
            standardOutput,
            standardError,
            workspace.Root);

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
                "sarif-regress-determinism-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Write(string relativePath, string contents)
        {
            File.WriteAllText(Path.Combine(Root, relativePath), contents);
        }

        public string Read(string relativePath) =>
            File.ReadAllText(Path.Combine(Root, relativePath));

        public void Dispose()
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
