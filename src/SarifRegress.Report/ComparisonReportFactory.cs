using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Reporting;
using SarifRegress.Core.Security;

namespace SarifRegress.Report;

/// <summary>
/// Supplies stable metadata that does not belong to the pure matching result.
/// </summary>
public sealed record ComparisonReportMetadata
{
    /// <summary>
    /// Initializes report metadata.
    /// </summary>
    public ComparisonReportMetadata(
        string toolVersion,
        string baselineInputName,
        string candidateInputName,
        string matcherAlgorithmVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(baselineInputName);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidateInputName);
        ArgumentException.ThrowIfNullOrWhiteSpace(matcherAlgorithmVersion);

        ToolVersion = toolVersion;
        BaselineInputName = baselineInputName;
        CandidateInputName = candidateInputName;
        MatcherAlgorithmVersion = matcherAlgorithmVersion;
    }

    /// <summary>
    /// Gets the semantic SarifRegress tool version.
    /// </summary>
    public string ToolVersion { get; }

    /// <summary>
    /// Gets the logical baseline input name.
    /// </summary>
    public string BaselineInputName { get; }

    /// <summary>
    /// Gets the logical candidate input name.
    /// </summary>
    public string CandidateInputName { get; }

    /// <summary>
    /// Gets the matching algorithm version recorded in the report.
    /// </summary>
    public string MatcherAlgorithmVersion { get; }
}

/// <summary>
/// Converts pure matching output into the stable reporting contract.
/// </summary>
public static class ComparisonReportFactory
{
    private const string ToolName = "sarif-regress";

    /// <summary>
    /// Creates a deterministically ordered comparison report.
    /// </summary>
    /// <param name="matchResult">The pure matching result.</param>
    /// <param name="metadata">Stable report metadata.</param>
    /// <returns>The immutable stable report.</returns>
    // Time: O(n log n), Space: O(n), for n decisions and trace records.
    public static ComparisonReport Create(
        MatchResult matchResult,
        ComparisonReportMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(matchResult);
        ArgumentNullException.ThrowIfNull(metadata);
        ValidateResult(matchResult, metadata);

        var findings = matchResult.Decisions
            .Select(CreateFindingReport)
            .OrderBy(
                item => StableJsonNames.Classification(item.Classification),
                StringComparer.Ordinal)
            .ThenBy(
                item => item.Baseline?.FindingKey ?? string.Empty,
                StringComparer.Ordinal)
            .ThenBy(
                item => item.Candidate?.FindingKey ?? string.Empty,
                StringComparer.Ordinal)
            .ToImmutableArray();

        var report = new ComparisonReport(
            ReportContractVersions.OutputSchema,
            ToolName,
            metadata.ToolVersion,
            metadata.BaselineInputName,
            metadata.CandidateInputName,
            CreateSummary(findings),
            findings,
            Diagnostic.Sort(matchResult.Diagnostics),
            new ComparisonMetrics(
                matchResult.CandidateEdgeCount,
                matchResult.ComponentCount,
                matchResult.AmbiguousComponentCount,
                matchResult.Diagnostics.Length),
            new DeterminismDescriptor(
                ReportContractVersions.JsonCanonicalisation,
                ReportContractVersions.CrossPlatformNormalisation,
                metadata.MatcherAlgorithmVersion));
        return StableComparisonReport.NormalizeAndValidate(
            report,
            ResourceLimits.Default);
    }

    private static FindingReport CreateFindingReport(FindingDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);

        return new FindingReport(
            decision.Classification,
            decision.Baseline?.SourceReference,
            decision.Candidate?.SourceReference,
            decision.Baseline is null
                ? null
                : FindingSnapshotFactory.Create(decision.Baseline),
            decision.Candidate is null
                ? null
                : FindingSnapshotFactory.Create(decision.Candidate),
            SortDecision(decision.Decision));
    }

    private static DecisionTrace SortDecision(DecisionTrace decision)
    {
        ArgumentNullException.ThrowIfNull(decision);

        var evidence = decision.Evidence
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.BaselineValue ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateValue ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.Origin)
            .ThenBy(item => item.PrecedenceTier)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ThenBy(item => item.Lossy)
            .ToImmutableArray();

        var rejectedAlternatives = decision.RejectedAlternatives
            .OrderBy(item => item.FindingKey, StringComparer.Ordinal)
            .ThenBy(item => item.Reason, StringComparer.Ordinal)
            .ThenBy(item => item.PrecedenceTier)
            .ThenBy(item => item.DecisionVector.PrecedenceTier)
            .ThenBy(item => item.DecisionVector.ProducerFingerprintStrength)
            .ThenBy(item => item.DecisionVector.PathMatchKind)
            .ThenBy(item => item.DecisionVector.ContextAgreement)
            .ThenBy(item => item.DecisionVector.CodeFlowAgreement)
            .ThenBy(item => item.DecisionVector.MessageAgreement)
            .ThenBy(item => item.DecisionVector.RegionDriftBand)
            .ToImmutableArray();

        var transformations = decision.Transformations
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.OriginalValue ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.TransformedValue ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(item => item.IsLossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();

        return decision with
        {
            Evidence = evidence,
            RejectedAlternatives = rejectedAlternatives,
            Transformations = transformations,
            Diagnostics = Diagnostic.Sort(decision.Diagnostics),
        };
    }

    private static ComparisonSummary CreateSummary(
        ImmutableArray<FindingReport> findings)
    {
        var baselineCount = findings
            .Where(item => item.Baseline is not null)
            .Select(item => item.Baseline!.FindingKey)
            .Distinct(StringComparer.Ordinal)
            .Count();
        var candidateCount = findings
            .Where(item => item.Candidate is not null)
            .Select(item => item.Candidate!.FindingKey)
            .Distinct(StringComparer.Ordinal)
            .Count();

        return new ComparisonSummary(
            baselineCount,
            candidateCount,
            Count(findings, FindingClassification.New),
            Count(findings, FindingClassification.Unchanged),
            Count(findings, FindingClassification.Moved),
            Count(findings, FindingClassification.Modified),
            Count(findings, FindingClassification.Resolved),
            Count(findings, FindingClassification.Ambiguous));
    }

    private static int Count(
        ImmutableArray<FindingReport> findings,
        FindingClassification classification) =>
        findings.Count(item => item.Classification == classification);

    private static void ValidateResult(
        MatchResult matchResult,
        ComparisonReportMetadata metadata)
    {
        if (matchResult.CandidateEdgeCount < 0
            || matchResult.ComponentCount < 0
            || matchResult.AmbiguousComponentCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(matchResult),
                "Matching operation counts cannot be negative.");
        }

        foreach (var decision in matchResult.Decisions)
        {
            ArgumentNullException.ThrowIfNull(decision);
            ArgumentNullException.ThrowIfNull(decision.Decision);
            if (decision.Baseline is null && decision.Candidate is null)
            {
                throw new ArgumentException(
                    "A finding decision must identify a baseline or candidate finding.",
                    nameof(matchResult));
            }

            if (!string.Equals(
                    decision.Decision.MatcherAlgorithmVersion,
                    metadata.MatcherAlgorithmVersion,
                    StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "Every decision must use the matcher algorithm version recorded in report metadata.",
                    nameof(matchResult));
            }
        }
    }
}
