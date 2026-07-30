using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Reporting;

namespace SarifRegress.Report;

/// <summary>
/// Renders a deterministic, offline-only HTML view from stable comparison JSON.
/// </summary>
public static class StaticHtmlReportRenderer
{
    private const int InitialHtmlCapacity = 8_192;

    private static readonly UTF8Encoding Utf8WithoutBom = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>
    /// Deserializes stable JSON and renders a self-contained static HTML document.
    /// </summary>
    /// <remarks>
    /// Accepting JSON rather than matching-domain objects keeps HTML a strict
    /// consumer of the stable machine-readable contract.
    /// </remarks>
    /// <param name="stableJson">Canonical comparison-report JSON.</param>
    /// <returns>UTF-8 HTML bytes without a byte-order mark and with LF endings.</returns>
    public static byte[] Render(ReadOnlySpan<byte> stableJson)
    {
        var report = StableJsonReportSerializer.Deserialize(stableJson);
        return Utf8WithoutBom.GetBytes(RenderReport(report));
    }

    /// <summary>
    /// Renders stable JSON to a static HTML file.
    /// </summary>
    /// <param name="path">The destination file path.</param>
    /// <param name="stableJson">Canonical comparison-report JSON.</param>
    public static void WriteFile(string path, ReadOnlySpan<byte> stableJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        File.WriteAllBytes(path, Render(stableJson));
    }

    private static string RenderReport(ComparisonReport report)
    {
        var html = new StringBuilder(capacity: InitialHtmlCapacity);
        AppendDocumentStart(html);
        AppendHeader(html, report);
        AppendSummary(html, report.Summary);
        AppendGlobalDiagnostics(html, report.Diagnostics);
        AppendFindings(html, report.Findings);
        AppendFooter(html, report);
        html.Append("</body>\n</html>\n");
        return html.ToString();
    }

    private static void AppendDocumentStart(StringBuilder html)
    {
        html.Append("<!doctype html>\n");
        html.Append("<html lang=\"en\">\n<head>\n");
        html.Append("  <meta charset=\"utf-8\">\n");
        html.Append(
            "  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">\n");
        html.Append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        html.Append("  <title>SarifRegress comparison</title>\n");
        html.Append("  <style>\n");
        html.Append(
            "    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }\n");
        html.Append(
            "    body { max-width: 80rem; margin: 0 auto; padding: 1.5rem; line-height: 1.45; }\n");
        html.Append(
            "    header, section, article, footer { margin-block: 1.5rem; }\n");
        html.Append(
            "    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(8rem, 1fr)); gap: .75rem; }\n");
        html.Append(
            "    .metric, article { border: 1px solid currentColor; border-radius: .35rem; padding: .75rem; }\n");
        html.Append(
            "    .metric strong { display: block; font-size: 1.4rem; }\n");
        html.Append(
            "    table { border-collapse: collapse; width: 100%; overflow-wrap: anywhere; }\n");
        html.Append(
            "    th, td { border: 1px solid currentColor; padding: .35rem .5rem; text-align: left; vertical-align: top; }\n");
        html.Append(
            "    code { white-space: pre-wrap; overflow-wrap: anywhere; }\n");
        html.Append(
            "    dt { font-weight: 700; } dd { margin: 0 0 .5rem; overflow-wrap: anywhere; }\n");
        html.Append(
            "    .classification { font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }\n");
        html.Append(
            "    .empty { font-style: italic; opacity: .75; }\n");
        html.Append("  </style>\n</head>\n<body>\n");
    }

    private static void AppendHeader(StringBuilder html, ComparisonReport report)
    {
        html.Append("<header>\n  <h1>SarifRegress comparison</h1>\n");
        html.Append("  <p><strong>Baseline:</strong> ");
        AppendText(html, report.BaselineInputName);
        html.Append("<br><strong>Candidate:</strong> ");
        AppendText(html, report.CandidateInputName);
        html.Append("</p>\n</header>\n");
    }

    private static void AppendSummary(
        StringBuilder html,
        ComparisonSummary summary)
    {
        html.Append("<section aria-labelledby=\"summary-heading\">\n");
        html.Append("  <h2 id=\"summary-heading\">Summary</h2>\n");
        html.Append("  <div class=\"summary\">\n");
        AppendMetric(html, "Baseline", summary.BaselineCount);
        AppendMetric(html, "Candidate", summary.CandidateCount);
        AppendMetric(html, "New", summary.New);
        AppendMetric(html, "Unchanged", summary.Unchanged);
        AppendMetric(html, "Moved", summary.Moved);
        AppendMetric(html, "Modified", summary.Modified);
        AppendMetric(html, "Resolved", summary.Resolved);
        AppendMetric(html, "Ambiguous", summary.Ambiguous);
        html.Append("  </div>\n</section>\n");
    }

    private static void AppendMetric(
        StringBuilder html,
        string label,
        int value)
    {
        html.Append("    <div class=\"metric\"><span>");
        html.Append(label);
        html.Append("</span><strong>");
        html.Append(value.ToString(CultureInfo.InvariantCulture));
        html.Append("</strong></div>\n");
    }

    private static void AppendGlobalDiagnostics(
        StringBuilder html,
        IEnumerable<Diagnostic> diagnostics)
    {
        html.Append("<section aria-labelledby=\"diagnostics-heading\">\n");
        html.Append("  <h2 id=\"diagnostics-heading\">Diagnostics</h2>\n");
        AppendDiagnostics(html, diagnostics);
        html.Append("</section>\n");
    }

    private static void AppendFindings(
        StringBuilder html,
        IEnumerable<FindingReport> findings)
    {
        html.Append("<section aria-labelledby=\"findings-heading\">\n");
        html.Append("  <h2 id=\"findings-heading\">Findings</h2>\n");

        var findingIndex = 0;
        foreach (var finding in findings)
        {
            AppendFinding(html, finding, findingIndex);
            findingIndex++;
        }

        if (findingIndex == 0)
        {
            html.Append("  <p class=\"empty\">No findings.</p>\n");
        }

        html.Append("</section>\n");
    }

    private static void AppendFinding(
        StringBuilder html,
        FindingReport finding,
        int index)
    {
        var headingId = string.Create(
            CultureInfo.InvariantCulture,
            $"finding-{index}");
        html.Append("  <article aria-labelledby=\"");
        html.Append(headingId);
        html.Append("\">\n    <h3 id=\"");
        html.Append(headingId);
        html.Append("\"><span class=\"classification\">");
        html.Append(StableJsonNames.Classification(finding.Classification));
        html.Append("</span>: ");
        AppendText(
            html,
            finding.Candidate?.FindingKey
                ?? finding.Baseline?.FindingKey
                ?? "unidentified");
        html.Append("</h3>\n");

        html.Append("    <dl>\n");
        AppendDefinition(
            html,
            "Decision tier",
            StableJsonNames.Precedence(finding.Decision.PrecedenceTier));
        AppendDefinition(
            html,
            "Confidence",
            StableJsonNames.Confidence(finding.Decision.DisplayConfidence));
        AppendDefinition(
            html,
            "Ambiguous",
            finding.Decision.Ambiguous ? "true" : "false");
        AppendDefinition(
            html,
            "Matcher",
            finding.Decision.MatcherAlgorithmVersion);
        AppendDefinition(
            html,
            "Baseline reference",
            FormatReference(finding.BaselineReference));
        AppendDefinition(
            html,
            "Candidate reference",
            FormatReference(finding.CandidateReference));
        html.Append("    </dl>\n");

        AppendSnapshot(html, "Baseline finding", finding.Baseline);
        AppendSnapshot(html, "Candidate finding", finding.Candidate);
        AppendEvidence(html, finding.Decision.Evidence);
        AppendRejectedAlternatives(html, finding.Decision.RejectedAlternatives);
        AppendTransformations(html, finding.Decision.Transformations);
        html.Append("    <h4>Finding diagnostics</h4>\n");
        AppendDiagnostics(html, finding.Decision.Diagnostics);
        html.Append("  </article>\n");
    }

    private static void AppendDefinition(
        StringBuilder html,
        string term,
        string value)
    {
        html.Append("      <dt>");
        html.Append(term);
        html.Append("</dt><dd>");
        AppendText(html, value);
        html.Append("</dd>\n");
    }

    private static void AppendSnapshot(
        StringBuilder html,
        string heading,
        FindingSnapshot? snapshot)
    {
        html.Append("    <h4>");
        html.Append(heading);
        html.Append("</h4>\n");
        if (snapshot is null)
        {
            html.Append("    <p class=\"empty\">Not available.</p>\n");
            return;
        }

        html.Append("    <dl>\n");
        AppendDefinition(html, "Key", snapshot.FindingKey);
        AppendDefinition(html, "Producer", snapshot.ProducerFamily);
        AppendDefinition(html, "Rule", snapshot.CanonicalRule);
        AppendDefinition(html, "URI", snapshot.CanonicalUri ?? "Not available");
        AppendDefinition(html, "Region", FormatRegion(snapshot));
        AppendDefinition(html, "Message", snapshot.CanonicalMessage);
        html.Append("    </dl>\n");
    }

    private static void AppendEvidence(
        StringBuilder html,
        IEnumerable<EvidenceRecord> evidence)
    {
        html.Append("    <h4>Evidence</h4>\n");
        html.Append(
            "    <table><thead><tr><th>Kind</th><th>Baseline</th><th>Candidate</th><th>Origin</th><th>Tier</th><th>Lossy</th><th>Algorithm</th></tr></thead><tbody>\n");
        var count = 0;
        foreach (var item in evidence)
        {
            html.Append("      <tr>");
            AppendCell(html, item.Kind);
            AppendCell(html, item.BaselineValue ?? "Not available");
            AppendCell(html, item.CandidateValue ?? "Not available");
            AppendCell(html, StableJsonNames.Origin(item.Origin));
            AppendCell(html, StableJsonNames.Precedence(item.PrecedenceTier));
            AppendCell(html, item.Lossy ? "true" : "false");
            AppendCell(html, item.AlgorithmVersion);
            html.Append("</tr>\n");
            count++;
        }

        if (count == 0)
        {
            html.Append(
                "      <tr><td colspan=\"7\" class=\"empty\">No evidence.</td></tr>\n");
        }

        html.Append("    </tbody></table>\n");
    }

    private static void AppendRejectedAlternatives(
        StringBuilder html,
        IEnumerable<RejectedAlternative> alternatives)
    {
        html.Append("    <h4>Rejected alternatives</h4>\n");
        html.Append(
            "    <table><thead><tr><th>Finding</th><th>Reason</th><th>Tier</th></tr></thead><tbody>\n");
        var count = 0;
        foreach (var alternative in alternatives)
        {
            html.Append("      <tr>");
            AppendCell(html, alternative.FindingKey);
            AppendCell(html, alternative.Reason);
            AppendCell(
                html,
                StableJsonNames.Precedence(alternative.PrecedenceTier));
            html.Append("</tr>\n");
            count++;
        }

        if (count == 0)
        {
            html.Append(
                "      <tr><td colspan=\"3\" class=\"empty\">No rejected alternatives.</td></tr>\n");
        }

        html.Append("    </tbody></table>\n");
    }

    private static void AppendTransformations(
        StringBuilder html,
        IEnumerable<TransformationRecord> transformations)
    {
        html.Append("    <h4>Transformations</h4>\n");
        html.Append(
            "    <table><thead><tr><th>Kind</th><th>Original</th><th>Transformed</th><th>Lossy</th><th>Algorithm</th></tr></thead><tbody>\n");
        var count = 0;
        foreach (var transformation in transformations)
        {
            html.Append("      <tr>");
            AppendCell(html, transformation.Kind);
            AppendCell(html, transformation.OriginalValue ?? "Not available");
            AppendCell(
                html,
                transformation.TransformedValue ?? "Not available");
            AppendCell(html, transformation.IsLossy ? "true" : "false");
            AppendCell(html, transformation.AlgorithmVersion);
            html.Append("</tr>\n");
            count++;
        }

        if (count == 0)
        {
            html.Append(
                "      <tr><td colspan=\"5\" class=\"empty\">No transformations.</td></tr>\n");
        }

        html.Append("    </tbody></table>\n");
    }

    private static void AppendDiagnostics(
        StringBuilder html,
        IEnumerable<Diagnostic> diagnostics)
    {
        html.Append(
            "  <table><thead><tr><th>Code</th><th>Severity</th><th>Stage</th><th>Message</th><th>Source</th><th>Basis</th><th>Help</th></tr></thead><tbody>\n");
        var count = 0;
        foreach (var diagnostic in diagnostics)
        {
            html.Append("    <tr>");
            AppendCell(html, diagnostic.Code);
            AppendCell(html, StableJsonNames.Severity(diagnostic.Severity));
            AppendCell(html, StableJsonNames.Stage(diagnostic.Stage));
            AppendCell(html, diagnostic.Message);
            AppendCell(html, FormatReference(diagnostic.SourceReference));
            AppendCell(html, diagnostic.StandardBasis ?? "Not available");
            AppendCell(html, diagnostic.Help ?? "Not available");
            html.Append("</tr>\n");
            count++;
        }

        if (count == 0)
        {
            html.Append(
                "    <tr><td colspan=\"7\" class=\"empty\">No diagnostics.</td></tr>\n");
        }

        html.Append("  </tbody></table>\n");
    }

    private static void AppendCell(StringBuilder html, string value)
    {
        html.Append("<td>");
        AppendText(html, value);
        html.Append("</td>");
    }

    private static void AppendFooter(StringBuilder html, ComparisonReport report)
    {
        html.Append("<footer>\n  <p>Schema ");
        AppendText(html, report.OutputSchemaVersion);
        html.Append(" · Generated by ");
        AppendText(html, report.ToolName);
        html.Append(' ');
        AppendText(html, report.ToolVersion);
        html.Append(" · JSON ");
        AppendText(html, report.Determinism.JsonCanonicalisation);
        html.Append(" · Matcher ");
        AppendText(html, report.Determinism.MatcherAlgorithm);
        html.Append("</p>\n</footer>\n");
    }

    private static string FormatReference(SourceReference? sourceReference)
    {
        if (sourceReference is null)
        {
            return "Not available";
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{StableJsonNames.Input(sourceReference.Input)} run={FormatNullable(sourceReference.RunIndex)} result={FormatNullable(sourceReference.ResultIndex)} {sourceReference.JsonPointer}");
    }

    private static string FormatRegion(FindingSnapshot snapshot)
    {
        if (snapshot.Region is null)
        {
            return "Not available";
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{FormatNullable(snapshot.Region.StartLine)}:{FormatNullable(snapshot.Region.StartColumn)}-{FormatNullable(snapshot.Region.EndLine)}:{FormatNullable(snapshot.Region.EndColumn)}");
    }

    private static string FormatNullable(int? value) =>
        value?.ToString(CultureInfo.InvariantCulture) ?? "n/a";

    private static void AppendText(StringBuilder html, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var normalized = value.Contains('\r')
            ? value
                .Replace("\r\n", "\n", StringComparison.Ordinal)
                .Replace('\r', '\n')
            : value;
        html.Append(HtmlEncoder.Default.Encode(normalized));
    }
}
