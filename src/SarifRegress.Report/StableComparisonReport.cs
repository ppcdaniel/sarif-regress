using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Reporting;
using SarifRegress.Core.Security;

namespace SarifRegress.Report;

/// <summary>
/// Validates stable-report invariants and establishes total array ordering.
/// </summary>
internal static class StableComparisonReport
{
    private const string ToolName = "sarif-regress";

    /// <summary>
    /// Returns a validated report whose observable arrays use canonical ordering.
    /// </summary>
    /// <param name="report">The report to validate and normalize.</param>
    /// <param name="limits">Resource bounds for untrusted report content.</param>
    /// <returns>The canonical report.</returns>
    // Time: O(n log n), Space: O(n), for n report and trace records.
    public static ComparisonReport NormalizeAndValidate(
        ComparisonReport report,
        ResourceLimits limits)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();

        ValidateHeader(report, limits);
        ValidateSummaryRanges(report.Summary);
        ValidateMetrics(report.Metrics);
        ValidateCollection(
            report.Findings,
            "findings",
            limits.MaximumRunCollectionItems);
        ValidateCollection(
            report.Diagnostics,
            "diagnostics",
            limits.MaximumRunCollectionItems);

        var baselineKeys = new HashSet<string>(StringComparer.Ordinal);
        var candidateKeys = new HashSet<string>(StringComparer.Ordinal);
        var normalizedFindings = ImmutableArray.CreateBuilder<FindingReport>(
            report.Findings.Length);
        foreach (var finding in report.Findings)
        {
            if (finding is null)
            {
                throw Invalid("The 'findings' array cannot contain null values.");
            }

            normalizedFindings.Add(
                NormalizeFinding(
                    finding,
                    report.Determinism.MatcherAlgorithm,
                    baselineKeys,
                    candidateKeys,
                    limits));
        }

        foreach (var diagnostic in report.Diagnostics)
        {
            ValidateDiagnostic(diagnostic, "diagnostics[]", limits);
        }

        var findings = normalizedFindings
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
        var diagnostics = Diagnostic.Sort(report.Diagnostics);
        var expectedSummary = CreateSummary(findings);
        if (report.Summary != expectedSummary)
        {
            throw Invalid(
                "The report summary does not match its finding records.");
        }

        if (report.Metrics.Diagnostics != diagnostics.Length)
        {
            throw Invalid(
                "The report diagnostic metric does not match the global diagnostic array.");
        }

        return report with
        {
            Findings = findings,
            Diagnostics = diagnostics,
        };
    }

    private static void ValidateHeader(
        ComparisonReport report,
        ResourceLimits limits)
    {
        if (!string.Equals(
                report.OutputSchemaVersion,
                ReportContractVersions.OutputSchema,
                StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"Output schema version '{report.OutputSchemaVersion}' is not supported.");
        }

        if (!string.Equals(report.ToolName, ToolName, StringComparison.Ordinal))
        {
            throw Invalid($"The report tool name must be '{ToolName}'.");
        }

        RequireText(report.ToolVersion, "tool.version", limits);
        RequireText(report.BaselineInputName, "inputs.baseline", limits);
        RequireText(report.CandidateInputName, "inputs.candidate", limits);
        ArgumentNullException.ThrowIfNull(report.Summary);
        ArgumentNullException.ThrowIfNull(report.Metrics);
        ArgumentNullException.ThrowIfNull(report.Determinism);

        if (!string.Equals(
                report.Determinism.JsonCanonicalisation,
                ReportContractVersions.JsonCanonicalisation,
                StringComparison.Ordinal))
        {
            throw Invalid(
                "The report JSON canonicalisation identifier is unsupported.");
        }

        if (!string.Equals(
                report.Determinism.CrossPlatformNormalisation,
                ReportContractVersions.CrossPlatformNormalisation,
                StringComparison.Ordinal))
        {
            throw Invalid(
                "The report cross-platform normalisation identifier is unsupported.");
        }

        RequireText(
            report.Determinism.MatcherAlgorithm,
            "determinism.matcherAlgorithm",
            limits);
    }

    private static FindingReport NormalizeFinding(
        FindingReport finding,
        string matcherAlgorithm,
        ISet<string> baselineKeys,
        ISet<string> candidateKeys,
        ResourceLimits limits)
    {
        _ = StableJsonNames.Classification(finding.Classification);
        ArgumentNullException.ThrowIfNull(finding.Decision);

        var hasBaseline = finding.Baseline is not null;
        var hasCandidate = finding.Candidate is not null;
        ValidateClassificationSides(
            finding.Classification,
            hasBaseline,
            hasCandidate);

        if (finding.BaselineReference is not null && !hasBaseline)
        {
            throw Invalid(
                "A baseline source reference requires a baseline finding snapshot.");
        }

        if (finding.CandidateReference is not null && !hasCandidate)
        {
            throw Invalid(
                "A candidate source reference requires a candidate finding snapshot.");
        }

        if (finding.BaselineReference is not null)
        {
            ValidateSourceReference(
                finding.BaselineReference,
                InputKind.Baseline,
                "findings[].baselineRef",
                limits);
        }

        if (finding.CandidateReference is not null)
        {
            ValidateSourceReference(
                finding.CandidateReference,
                InputKind.Candidate,
                "findings[].candidateRef",
                limits);
        }

        var baseline = finding.Baseline is null
            ? null
            : NormalizeSnapshot(
                finding.Baseline,
                baselineKeys,
                "findings[].baseline",
                limits);
        var candidate = finding.Candidate is null
            ? null
            : NormalizeSnapshot(
                finding.Candidate,
                candidateKeys,
                "findings[].candidate",
                limits);
        var decision = NormalizeDecision(
            finding.Decision,
            finding.Classification,
            matcherAlgorithm,
            limits);

        return finding with
        {
            Baseline = baseline,
            Candidate = candidate,
            Decision = decision,
        };
    }

    private static void ValidateClassificationSides(
        FindingClassification classification,
        bool hasBaseline,
        bool hasCandidate)
    {
        var valid = classification switch
        {
            FindingClassification.New => !hasBaseline && hasCandidate,
            FindingClassification.Unchanged
                or FindingClassification.Moved
                or FindingClassification.Modified => hasBaseline && hasCandidate,
            FindingClassification.Resolved => hasBaseline && !hasCandidate,
            FindingClassification.Ambiguous => hasBaseline ^ hasCandidate,
            _ => false,
        };
        if (!valid)
        {
            throw Invalid(
                $"Classification '{StableJsonNames.Classification(classification)}' "
                + "has an invalid baseline/candidate side combination.");
        }
    }

    private static FindingSnapshot NormalizeSnapshot(
        FindingSnapshot snapshot,
        ISet<string> observedKeys,
        string propertyName,
        ResourceLimits limits)
    {
        RequireText(snapshot.FindingKey, $"{propertyName}.findingKey", limits);
        RequireText(
            snapshot.ProducerFamily,
            $"{propertyName}.producerFamily",
            limits);
        RequireText(
            snapshot.CanonicalRule,
            $"{propertyName}.canonicalRule",
            limits);
        ValidateText(
            snapshot.CanonicalMessage,
            $"{propertyName}.canonicalMessage",
            limits);
        ValidateOptionalText(
            snapshot.CanonicalUri,
            $"{propertyName}.canonicalUri",
            limits,
            allowEmpty: false);
        if (!observedKeys.Add(snapshot.FindingKey))
        {
            throw Invalid(
                $"Finding key '{snapshot.FindingKey}' occurs more than once on the same input side.");
        }

        ValidateCollection(
            snapshot.DerivedFingerprints,
            $"{propertyName}.derivedFingerprints",
            limits.MaximumRunCollectionItems);
        var fingerprintNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var fingerprint in snapshot.DerivedFingerprints)
        {
            if (fingerprint is null)
            {
                throw Invalid(
                    $"The '{propertyName}.derivedFingerprints' array cannot contain null values.");
            }

            RequireText(
                fingerprint.Name,
                $"{propertyName}.derivedFingerprints[].name",
                limits);
            RequireText(
                fingerprint.Value,
                $"{propertyName}.derivedFingerprints[].value",
                limits);
            RequireText(
                fingerprint.AlgorithmVersion,
                $"{propertyName}.derivedFingerprints[].algorithmVersion",
                limits);
            if (string.Equals(
                    fingerprint.Name,
                    ReportContractVersions.SarifFingerprint,
                    StringComparison.Ordinal)
                && !string.Equals(
                    fingerprint.AlgorithmVersion,
                    ReportContractVersions.SarifFingerprintAlgorithm,
                    StringComparison.Ordinal))
            {
                throw Invalid(
                    $"Derived fingerprint '{fingerprint.Name}' has an unsupported algorithm version.");
            }

            if (!fingerprintNames.Add(fingerprint.Name))
            {
                throw Invalid(
                    $"Derived fingerprint name '{fingerprint.Name}' occurs more than once.");
            }
        }

        var fingerprints = snapshot.DerivedFingerprints
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Value, StringComparer.Ordinal)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
        return snapshot with { DerivedFingerprints = fingerprints };
    }

    private static DecisionTrace NormalizeDecision(
        DecisionTrace decision,
        FindingClassification classification,
        string matcherAlgorithm,
        ResourceLimits limits)
    {
        _ = StableJsonNames.Precedence(decision.PrecedenceTier);
        _ = StableJsonNames.Confidence(decision.DisplayConfidence);
        RequireText(
            decision.MatcherAlgorithmVersion,
            "findings[].decision.matcherAlgorithmVersion",
            limits);
        if (!string.Equals(
                decision.MatcherAlgorithmVersion,
                matcherAlgorithm,
                StringComparison.Ordinal))
        {
            throw Invalid(
                "Every decision must use the report's matcher algorithm version.");
        }

        var classificationIsAmbiguous =
            classification == FindingClassification.Ambiguous;
        if (decision.Ambiguous != classificationIsAmbiguous)
        {
            throw Invalid(
                "The decision ambiguity flag must agree with the finding classification.");
        }

        ValidateCollection(
            decision.Evidence,
            "findings[].evidence",
            limits.MaximumRunCollectionItems);
        ValidateCollection(
            decision.RejectedAlternatives,
            "findings[].rejectedAlternatives",
            limits.MaximumRejectedAlternatives);
        ValidateCollection(
            decision.Transformations,
            "findings[].transforms",
            limits.MaximumRunCollectionItems);
        ValidateCollection(
            decision.Diagnostics,
            "findings[].diagnostics",
            limits.MaximumRunCollectionItems);

        foreach (var evidence in decision.Evidence)
        {
            if (evidence is null)
            {
                throw Invalid(
                    "The 'findings[].evidence' array cannot contain null values.");
            }

            RequireText(evidence.Kind, "findings[].evidence[].kind", limits);
            ValidateOptionalText(
                evidence.BaselineValue,
                "findings[].evidence[].baselineValue",
                limits,
                allowEmpty: true);
            ValidateOptionalText(
                evidence.CandidateValue,
                "findings[].evidence[].candidateValue",
                limits,
                allowEmpty: true);
            _ = StableJsonNames.Origin(evidence.Origin);
            _ = StableJsonNames.Precedence(evidence.PrecedenceTier);
            RequireText(
                evidence.AlgorithmVersion,
                "findings[].evidence[].algorithmVersion",
                limits);
        }

        foreach (var alternative in decision.RejectedAlternatives)
        {
            if (alternative is null)
            {
                throw Invalid(
                    "The 'findings[].rejectedAlternatives' array cannot contain null values.");
            }

            RequireText(
                alternative.FindingKey,
                "findings[].rejectedAlternatives[].findingKey",
                limits);
            RequireText(
                alternative.Reason,
                "findings[].rejectedAlternatives[].reason",
                limits);
            _ = StableJsonNames.Precedence(alternative.PrecedenceTier);
            ValidateDecisionVector(alternative.DecisionVector);
        }

        foreach (var transformation in decision.Transformations)
        {
            if (transformation is null)
            {
                throw Invalid(
                    "The 'findings[].transforms' array cannot contain null values.");
            }

            RequireText(
                transformation.Kind,
                "findings[].transforms[].kind",
                limits);
            ValidateOptionalText(
                transformation.OriginalValue,
                "findings[].transforms[].originalValue",
                limits,
                allowEmpty: true);
            ValidateOptionalText(
                transformation.TransformedValue,
                "findings[].transforms[].transformedValue",
                limits,
                allowEmpty: true);
            RequireText(
                transformation.AlgorithmVersion,
                "findings[].transforms[].algorithmVersion",
                limits);
        }

        foreach (var diagnostic in decision.Diagnostics)
        {
            ValidateDiagnostic(
                diagnostic,
                "findings[].diagnostics[]",
                limits);
        }

        return decision with
        {
            Evidence = decision.Evidence
                .OrderBy(item => item.Kind, StringComparer.Ordinal)
                .ThenBy(item => item.BaselineValue is null ? 0 : 1)
                .ThenBy(item => item.BaselineValue, StringComparer.Ordinal)
                .ThenBy(item => item.CandidateValue is null ? 0 : 1)
                .ThenBy(item => item.CandidateValue, StringComparer.Ordinal)
                .ThenBy(item => item.Origin)
                .ThenBy(item => item.PrecedenceTier)
                .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
                .ThenBy(item => item.Lossy)
                .ToImmutableArray(),
            RejectedAlternatives = decision.RejectedAlternatives
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
                .ToImmutableArray(),
            Transformations = decision.Transformations
                .OrderBy(item => item.Kind, StringComparer.Ordinal)
                .ThenBy(item => item.OriginalValue is null ? 0 : 1)
                .ThenBy(item => item.OriginalValue, StringComparer.Ordinal)
                .ThenBy(item => item.TransformedValue is null ? 0 : 1)
                .ThenBy(item => item.TransformedValue, StringComparer.Ordinal)
                .ThenBy(item => item.IsLossy)
                .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
                .ToImmutableArray(),
            Diagnostics = Diagnostic.Sort(decision.Diagnostics),
        };
    }

    private static void ValidateDecisionVector(DecisionVector vector)
    {
        _ = StableJsonNames.Precedence(vector.PrecedenceTier);
        _ = StableJsonNames.PathMatch(vector.PathMatchKind);
        _ = StableJsonNames.Agreement(vector.ContextAgreement);
        _ = StableJsonNames.Agreement(vector.CodeFlowAgreement);
        _ = StableJsonNames.Agreement(vector.MessageAgreement);
        if (vector.ProducerFingerprintStrength < 0)
        {
            throw Invalid(
                "A rejected alternative's producer fingerprint strength cannot be negative.");
        }

        if (vector.RegionDriftBand < 0)
        {
            throw Invalid(
                "A rejected alternative's region drift band cannot be negative.");
        }
    }

    private static void ValidateDiagnostic(
        Diagnostic diagnostic,
        string propertyName,
        ResourceLimits limits)
    {
        if (diagnostic is null)
        {
            throw Invalid($"The '{propertyName}' value cannot be null.");
        }

        RequireText(diagnostic.Code, $"{propertyName}.code", limits);
        _ = StableJsonNames.Severity(diagnostic.Severity);
        _ = StableJsonNames.Stage(diagnostic.Stage);
        RequireText(diagnostic.Message, $"{propertyName}.message", limits);
        ValidateOptionalText(
            diagnostic.StandardBasis,
            $"{propertyName}.standardBasis",
            limits,
            allowEmpty: false);
        ValidateOptionalText(
            diagnostic.Help,
            $"{propertyName}.help",
            limits,
            allowEmpty: false);
        if (diagnostic.SourceReference is not null)
        {
            ValidateSourceReference(
                diagnostic.SourceReference,
                expectedInput: null,
                $"{propertyName}.sourceRef",
                limits);
        }
    }

    private static void ValidateSourceReference(
        SourceReference sourceReference,
        InputKind? expectedInput,
        string propertyName,
        ResourceLimits limits)
    {
        _ = StableJsonNames.Input(sourceReference.Input);
        if (expectedInput.HasValue && sourceReference.Input != expectedInput.Value)
        {
            throw Invalid(
                $"The '{propertyName}.input' value does not identify the expected report side.");
        }

        ValidateText(
            sourceReference.JsonPointer,
            $"{propertyName}.jsonPointer",
            limits);
    }

    private static void ValidateSummaryRanges(ComparisonSummary summary)
    {
        if (summary.BaselineCount < 0
            || summary.CandidateCount < 0
            || summary.New < 0
            || summary.Unchanged < 0
            || summary.Moved < 0
            || summary.Modified < 0
            || summary.Resolved < 0
            || summary.Ambiguous < 0)
        {
            throw Invalid("Report summary counts cannot be negative.");
        }
    }

    private static void ValidateMetrics(ComparisonMetrics metrics)
    {
        if (metrics.CandidateEdges < 0
            || metrics.AssignmentComponents < 0
            || metrics.AmbiguousComponents < 0
            || metrics.Diagnostics < 0)
        {
            throw Invalid("Report metrics cannot be negative.");
        }

        if (metrics.AmbiguousComponents > metrics.AssignmentComponents)
        {
            throw Invalid(
                "Ambiguous assignment components cannot exceed all assignment components.");
        }
    }

    private static ComparisonSummary CreateSummary(
        ImmutableArray<FindingReport> findings) =>
        new(
            findings.Count(item => item.Baseline is not null),
            findings.Count(item => item.Candidate is not null),
            Count(findings, FindingClassification.New),
            Count(findings, FindingClassification.Unchanged),
            Count(findings, FindingClassification.Moved),
            Count(findings, FindingClassification.Modified),
            Count(findings, FindingClassification.Resolved),
            Count(findings, FindingClassification.Ambiguous));

    private static int Count(
        ImmutableArray<FindingReport> findings,
        FindingClassification classification) =>
        findings.Count(item => item.Classification == classification);

    private static void ValidateCollection<T>(
        ImmutableArray<T> values,
        string propertyName,
        int maximumItems)
    {
        if (values.IsDefault)
        {
            throw Invalid($"The required '{propertyName}' array is uninitialized.");
        }

        if (values.Length > maximumItems)
        {
            throw Invalid(
                $"The '{propertyName}' array exceeds the configured {maximumItems}-item limit.");
        }
    }

    private static void RequireText(
        string value,
        string propertyName,
        ResourceLimits limits)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw Invalid($"The required '{propertyName}' value cannot be blank.");
        }

        ValidateText(value, propertyName, limits);
    }

    private static void ValidateText(
        string value,
        string propertyName,
        ResourceLimits limits)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > limits.MaximumStringCharacters)
        {
            throw Invalid(
                $"The '{propertyName}' value exceeds the configured "
                + $"{limits.MaximumStringCharacters}-character limit.");
        }
    }

    private static void ValidateOptionalText(
        string? value,
        string propertyName,
        ResourceLimits limits,
        bool allowEmpty)
    {
        if (value is null)
        {
            return;
        }

        if (!allowEmpty && value.Length == 0)
        {
            throw Invalid($"The optional '{propertyName}' value cannot be empty.");
        }

        ValidateText(value, propertyName, limits);
    }

    private static ArgumentException Invalid(string message) =>
        new(message, "report");
}
