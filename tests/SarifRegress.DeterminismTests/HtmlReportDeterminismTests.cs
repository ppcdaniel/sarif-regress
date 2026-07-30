using System.Text;
using SarifRegress.Report;

namespace SarifRegress.DeterminismTests;

public sealed class HtmlReportDeterminismTests
{
    [Fact]
    public void Render_RepeatedAndAcrossCultures_ProducesIdenticalBytes()
    {
        var json = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());
        var first = StaticHtmlReportRenderer.Render(json);
        var second = StaticHtmlReportRenderer.Render(json);

        byte[] cultureSpecific;
        using (new CultureScope("tr-TR"))
        {
            cultureSpecific = StaticHtmlReportRenderer.Render(json);
        }

        Assert.Equal(first, second);
        Assert.Equal(first, cultureSpecific);
        Assert.Equal((byte)'\n', first[^1]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.False(
            first.Length >= 3
            && first[0] == 0xEF
            && first[1] == 0xBB
            && first[2] == 0xBF);
    }

    [Fact]
    public void Render_UntrustedValues_EscapesMarkupAndIncludesOfflineCsp()
    {
        var json = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport());

        var html = Encoding.UTF8.GetString(
            StaticHtmlReportRenderer.Render(json));

        Assert.Contains(
            "default-src 'none'; style-src 'unsafe-inline'",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "unsafe &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#x27;quoted&#x27; input",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "candidate &amp; &quot;two&quot;.sarif",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "<dt>SARIF level</dt><dd>error</dd>",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "<dt>SARIF kind</dt><dd>review</dd>",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "<dt>Input baseline state</dt><dd>updated</dd>",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "<dt>Message normalisation</dt><dd>collapsed-whitespace, invariant-case-fold</dd>",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "<dt>Lossiness</dt><dd>collapsed-whitespace, message-markdown-fallback</dd>",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "<script>alert",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "http-equiv=\"refresh\"",
            html,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Render_SourceCarriageReturns_UsesLfOnly()
    {
        var json = StableJsonReportSerializer.Serialize(
            ReportTestData.CreateRepresentativeReport(
                "first line\r\nsecond line\rlast line"));

        var html = StaticHtmlReportRenderer.Render(json);

        Assert.DoesNotContain((byte)'\r', html);
    }
}
