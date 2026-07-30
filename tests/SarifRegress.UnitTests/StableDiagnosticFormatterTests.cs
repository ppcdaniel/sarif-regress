using SarifRegress.Cli.Diagnostics;
using SarifRegress.Core.Diagnostics;

namespace SarifRegress.UnitTests;

public sealed class StableDiagnosticFormatterTests
{
    [Fact]
    public void Diagnostics_use_stable_order_and_lf_line_endings()
    {
        Diagnostic[] diagnostics =
        [
            new(
                "PARSE0002",
                DiagnosticSeverity.Error,
                DiagnosticStage.Parse,
                "Second."),
            new(
                "IO0001",
                DiagnosticSeverity.Warning,
                DiagnosticStage.Io,
                "First.",
                new SourceReference(InputKind.Baseline, null, null, "/")),
        ];

        var formatted = StableDiagnosticFormatter.Format(diagnostics);

        Assert.Equal(
            "IO0001 warning: First. [/]\n" +
            "PARSE0002 error: Second.\n",
            formatted);
        Assert.DoesNotContain('\r', formatted);
    }
}
