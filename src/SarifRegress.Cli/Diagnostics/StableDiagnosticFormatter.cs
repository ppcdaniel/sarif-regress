using System.Text;
using SarifRegress.Core.Diagnostics;

namespace SarifRegress.Cli.Diagnostics;

/// <summary>
/// Formats deterministic single-line diagnostics for standard error.
/// </summary>
public static class StableDiagnosticFormatter
{
    /// <summary>
    /// Formats diagnostics in stable public order using LF line endings.
    /// </summary>
    /// <param name="diagnostics">The diagnostics to format.</param>
    /// <returns>The formatted text, or an empty string when no diagnostics exist.</returns>
    public static string Format(IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        var builder = new StringBuilder();

        foreach (var diagnostic in Diagnostic.Sort(diagnostics))
        {
            builder.Append(diagnostic.Code);
            builder.Append(' ');
            builder.Append(SeverityName(diagnostic.Severity));
            builder.Append(": ");
            builder.Append(diagnostic.Message);

            if (diagnostic.SourceReference is not null)
            {
                builder.Append(" [");
                builder.Append(diagnostic.SourceReference.JsonPointer);
                builder.Append(']');
            }

            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static string SeverityName(DiagnosticSeverity severity)
    {
        return severity switch
        {
            DiagnosticSeverity.Note => "note",
            DiagnosticSeverity.Warning => "warning",
            DiagnosticSeverity.Error => "error",
            _ => throw new ArgumentOutOfRangeException(
                nameof(severity),
                severity,
                "Unknown diagnostic severity."),
        };
    }
}
