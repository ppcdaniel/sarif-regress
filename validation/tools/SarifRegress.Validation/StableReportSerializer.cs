using System.Text.Json;

namespace SarifRegress.Validation;

/// <summary>Writes every project-owned report with explicit property and ordinal array order.</summary>
public static class StableReportSerializer
{
    /// <summary>Serializes the frozen SarifRegress holdout report.</summary>
    public static byte[] Serialize(SarifRegressHoldoutReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return StableJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "2");
            writer.WriteString("reportKind", "sarif-regress-independent-holdout");
            WriteEvaluation(writer, report.Evaluation);
            writer.WritePropertyName("aggregate");
            WriteHoldoutMetrics(writer, report.Aggregate);
            writer.WriteStartArray("producers");
            foreach (ProducerHoldoutMetrics producer in report.Producers.OrderBy(
                         item => item.ProducerId,
                         StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("producerId", producer.ProducerId);
                writer.WritePropertyName("metrics");
                WriteHoldoutMetrics(writer, producer.Metrics);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("cases");
            foreach (SarifRegressCaseResult item in report.Cases.OrderBy(
                         value => value.CaseId,
                         StringComparer.Ordinal))
            {
                WriteSarifRegressCase(writer, item);
            }

            writer.WriteEndArray();
            writer.WritePropertyName("diagnosticCounts");
            WriteDiagnosticCounts(writer, report.DiagnosticCounts);
            writer.WriteEndObject();
        });
    }

    /// <summary>Serializes the normalized Microsoft SARIF Multitool baseline.</summary>
    public static byte[] Serialize(SarifMultitoolBaselineReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return StableJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "1");
            writer.WriteString("reportKind", "sarif-multitool-normalized-baseline");
            WriteEvaluation(writer, report.Evaluation);
            writer.WritePropertyName("tool");
            WriteMultitoolEvidence(writer, report.Tool);
            writer.WritePropertyName("aggregate");
            WriteMultitoolMetrics(writer, report.Aggregate, includeStateCounts: true);
            writer.WriteStartArray("producers");
            foreach (ProducerMultitoolMetrics producer in report.Producers.OrderBy(
                         item => item.ProducerId,
                         StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("producerId", producer.ProducerId);
                writer.WritePropertyName("metrics");
                WriteMultitoolMetrics(writer, producer.Metrics, includeStateCounts: true);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("cases");
            foreach (MultitoolCaseResult item in report.Cases.OrderBy(
                         value => value.CaseId,
                         StringComparer.Ordinal))
            {
                WriteMultitoolCase(writer, item);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });
    }

    /// <summary>Serializes the shared-ground-truth comparison and release recommendation.</summary>
    public static byte[] Serialize(ComparisonSummaryReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return StableJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "2");
            writer.WriteString("reportKind", "holdout-external-baseline-comparison");
            WriteEvaluation(writer, report.Evaluation);
            writer.WritePropertyName("reportHashes");
            WriteReportHashes(writer, report.ReportHashes);
            writer.WritePropertyName("thresholds");
            WriteThresholds(writer, report.Thresholds);
            writer.WritePropertyName("releaseConditions");
            WriteReleaseConditions(writer, report.ReleaseConditions);
            writer.WritePropertyName("sarifRegress");
            writer.WriteStartObject();
            writer.WritePropertyName("metrics");
            WriteSarifComparisonMetrics(writer, report.SarifRegress.Metrics);
            writer.WriteEndObject();
            writer.WritePropertyName("sarifMultitool");
            writer.WriteStartObject();
            writer.WriteString("toolName", report.SarifMultitool.ToolName);
            writer.WriteString("exactVersion", report.SarifMultitool.ExactVersion);
            writer.WritePropertyName("metrics");
            WriteMultitoolComparisonMetrics(writer, report.SarifMultitool.Metrics);
            writer.WriteEndObject();
            writer.WritePropertyName("aggregate");
            WriteToolComparisonMetrics(writer, report.Aggregate);
            writer.WriteStartArray("producers");
            foreach (ProducerComparison producer in report.Producers.OrderBy(
                         item => item.ProducerId,
                         StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("producerId", producer.ProducerId);
                writer.WritePropertyName("sarifRegress");
                WriteSarifComparisonMetrics(writer, producer.SarifRegress);
                writer.WritePropertyName("sarifMultitool");
                WriteMultitoolComparisonMetrics(writer, producer.SarifMultitool);
                writer.WritePropertyName("comparison");
                WriteToolComparisonMetrics(writer, producer.Comparison);
                writer.WritePropertyName("qualityGates");
                WriteProducerQualityGates(writer, producer.QualityGates);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("relationships");
            foreach (RelationshipComparison relationship in report.Relationships
                         .OrderBy(item => item.CaseId, StringComparer.Ordinal)
                         .ThenBy(item => item.RelationshipId, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("relationshipId", relationship.RelationshipId);
                writer.WriteString("caseId", relationship.CaseId);
                writer.WriteString("producerId", relationship.ProducerId);
                writer.WriteBoolean("sarifRegressCorrect", relationship.SarifRegressCorrect);
                WriteNullableBoolean(writer, "multitoolCorrect", relationship.MultitoolCorrect);
                WriteNullableBoolean(writer, "toolsAgree", relationship.ToolsAgree);
                writer.WriteString("correctnessCategory", relationship.CorrectnessCategory);
                WriteNullableString(writer, "nonComparableReason", relationship.NonComparableReason);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("nonComparableRelationships");
            foreach (NonComparableRelationship relationship in
                     report.NonComparableRelationships
                         .OrderBy(item => item.CaseId, StringComparer.Ordinal)
                         .ThenBy(item => item.RelationshipId, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("relationshipId", relationship.RelationshipId);
                writer.WriteString("caseId", relationship.CaseId);
                writer.WriteString("producerId", relationship.ProducerId);
                writer.WriteString("reason", relationship.Reason);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("semanticDifferences");
            foreach (SemanticDifference difference in report.SemanticDifferences.OrderBy(
                         item => item.Code,
                         StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("code", difference.Code);
                writer.WriteStartArray("affectedRelationshipIds");
                foreach (string id in difference.AffectedRelationshipIds.Order(
                             StringComparer.Ordinal))
                {
                    writer.WriteStringValue(id);
                }

                writer.WriteEndArray();
                writer.WriteString("explanation", difference.Explanation);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteString("releaseRecommendation", report.ReleaseRecommendation);
            writer.WriteStartArray("recommendationReasons");
            foreach (string reason in report.RecommendationReasons)
            {
                writer.WriteStringValue(reason);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });
    }

    /// <summary>Serializes the immutable matcher-v2 to matcher-v3 decision delta.</summary>
    public static byte[] Serialize(MatcherV2ToV3DeltaReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return StableJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "1");
            writer.WriteString("reportKind", "matcher-v2-to-v3-delta");
            writer.WritePropertyName("inputHashes");
            writer.WriteStartObject();
            writer.WriteString(
                "matcherV2HistoryChecksumManifestSha256",
                report.InputHashes.MatcherV2HistoryChecksumManifestSha256);
            writer.WriteString(
                "matcherV2ReportSha256",
                report.InputHashes.MatcherV2ReportSha256);
            writer.WriteString(
                "matcherV3ReportSha256",
                report.InputHashes.MatcherV3ReportSha256);
            writer.WriteString(
                "holdoutManifestSha256",
                report.InputHashes.HoldoutManifestSha256);
            writer.WriteEndObject();
            writer.WritePropertyName("matcherV2");
            WriteMatcherMetricsSnapshot(writer, report.MatcherV2);
            writer.WritePropertyName("matcherV3");
            WriteMatcherMetricsSnapshot(writer, report.MatcherV3);
            writer.WriteStartArray("algorithmVersionChanges");
            foreach (AlgorithmVersionChange change in report.AlgorithmVersionChanges
                         .OrderBy(item => item.Name, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("name", change.Name);
                WriteNullableString(
                    writer,
                    "matcherV2Version",
                    change.MatcherV2Version);
                WriteNullableString(
                    writer,
                    "matcherV3Version",
                    change.MatcherV3Version);
                writer.WriteBoolean("changed", change.Changed);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WritePropertyName("cases");
            WriteCaseDelta(writer, report.Cases);
            writer.WritePropertyName("relationships");
            WriteRelationshipDelta(writer, report.Relationships);
            writer.WriteStartArray("newlyIntroducedFalseMatches");
            WriteDeltaRelationships(writer, report.NewlyIntroducedFalseMatches);
            writer.WriteEndArray();
            writer.WritePropertyName("ambiguityChanges");
            WriteAmbiguityDelta(writer, report.AmbiguityChanges);
            writer.WritePropertyName("ingestionSuccessChanges");
            WriteIngestionDelta(writer, report.IngestionSuccessChanges);
            writer.WriteStartArray("remainingFailures");
            WriteDeltaRelationships(writer, report.RemainingFailures);
            writer.WriteEndArray();
            writer.WriteNumber("changedDecisionCount", report.ChangedDecisionCount);
            writer.WriteNumber(
                "changedDecisionTraceCount",
                report.ChangedDecisionTraceCount);
            writer.WriteNumber(
                "changedDecisionWithoutTraceCount",
                report.ChangedDecisionWithoutTraceCount);
            writer.WriteStartArray("changedDecisionsWithoutTrace");
            WriteDeltaRelationships(writer, report.ChangedDecisionsWithoutTrace);
            writer.WriteEndArray();
            writer.WriteBoolean(
                "everyChangedDecisionHasTrace",
                report.EveryChangedDecisionHasTrace);
            writer.WriteEndObject();
        });
    }

    private static void WriteEvaluation(Utf8JsonWriter writer, EvaluationIdentity value)
    {
        writer.WritePropertyName("evaluation");
        writer.WriteStartObject();
        writer.WriteString("repositoryCommitSha", value.RepositoryCommitSha);
        writer.WriteString("sourceTreeSha256", value.SourceTreeSha256);
        writer.WriteString("sarifRegressToolVersion", value.SarifRegressToolVersion);
        writer.WriteString("matcherAlgorithmVersion", value.MatcherAlgorithmVersion);
        writer.WriteStartArray("fingerprintAlgorithmVersions");
        foreach (NamedAlgorithmVersion algorithm in value.FingerprintAlgorithmVersions
                     .OrderBy(item => item.Name, StringComparer.Ordinal)
                     .ThenBy(item => item.Version, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("name", algorithm.Name);
            writer.WriteString("version", algorithm.Version);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteString("outputSchemaVersion", value.OutputSchemaVersion);
        writer.WriteString("configurationSchemaVersion", value.ConfigurationSchemaVersion);
        writer.WriteString("holdoutManifestSha256", value.HoldoutManifestSha256);
        writer.WriteEndObject();
    }

    private static void WriteMatcherMetricsSnapshot(
        Utf8JsonWriter writer,
        MatcherMetricsSnapshot value)
    {
        writer.WriteStartObject();
        WriteEvaluation(writer, value.Evaluation);
        writer.WritePropertyName("aggregate");
        WriteHoldoutMetrics(writer, value.Aggregate);
        writer.WriteStartArray("producers");
        foreach (ProducerHoldoutMetrics producer in value.Producers.OrderBy(
                     item => item.ProducerId,
                     StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("producerId", producer.ProducerId);
            writer.WritePropertyName("metrics");
            WriteHoldoutMetrics(writer, producer.Metrics);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteCaseDelta(
        Utf8JsonWriter writer,
        MatcherCaseDelta value)
    {
        writer.WriteStartObject();
        writer.WriteStartArray("fixed");
        WriteDeltaCases(writer, value.Fixed);
        writer.WriteEndArray();
        writer.WriteStartArray("regressed");
        WriteDeltaCases(writer, value.Regressed);
        writer.WriteEndArray();
        writer.WriteStartArray("stillFailing");
        WriteDeltaCases(writer, value.StillFailing);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteRelationshipDelta(
        Utf8JsonWriter writer,
        MatcherRelationshipDelta value)
    {
        writer.WriteStartObject();
        writer.WriteStartArray("fixed");
        WriteDeltaRelationships(writer, value.Fixed);
        writer.WriteEndArray();
        writer.WriteStartArray("regressed");
        WriteDeltaRelationships(writer, value.Regressed);
        writer.WriteEndArray();
        writer.WriteStartArray("stillFailing");
        WriteDeltaRelationships(writer, value.StillFailing);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteAmbiguityDelta(
        Utf8JsonWriter writer,
        MatcherAmbiguityDelta value)
    {
        writer.WriteStartObject();
        writer.WriteNumber(
            "matcherV2CorrectRefusals",
            value.MatcherV2CorrectRefusals);
        writer.WriteNumber(
            "matcherV3CorrectRefusals",
            value.MatcherV3CorrectRefusals);
        writer.WriteNumber(
            "matcherV2UnexpectedRefusals",
            value.MatcherV2UnexpectedRefusals);
        writer.WriteNumber(
            "matcherV3UnexpectedRefusals",
            value.MatcherV3UnexpectedRefusals);
        writer.WriteNumber(
            "matcherV2IncorrectAutoMatches",
            value.MatcherV2IncorrectAutoMatches);
        writer.WriteNumber(
            "matcherV3IncorrectAutoMatches",
            value.MatcherV3IncorrectAutoMatches);
        writer.WriteStartArray("fixed");
        WriteDeltaRelationships(writer, value.Fixed);
        writer.WriteEndArray();
        writer.WriteStartArray("regressed");
        WriteDeltaRelationships(writer, value.Regressed);
        writer.WriteEndArray();
        writer.WriteStartArray("stillFailing");
        WriteDeltaRelationships(writer, value.StillFailing);
        writer.WriteEndArray();
        writer.WriteStartArray("unexpectedRefusalsResolved");
        WriteDeltaRelationships(writer, value.UnexpectedRefusalsResolved);
        writer.WriteEndArray();
        writer.WriteStartArray("unexpectedRefusalsIntroduced");
        WriteDeltaRelationships(writer, value.UnexpectedRefusalsIntroduced);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteIngestionDelta(
        Utf8JsonWriter writer,
        MatcherIngestionSuccessDelta value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("matcherV2Failures", value.MatcherV2Failures);
        writer.WriteNumber("matcherV3Failures", value.MatcherV3Failures);
        writer.WriteStartArray("newlySuccessful");
        WriteDeltaCases(writer, value.NewlySuccessful);
        writer.WriteEndArray();
        writer.WriteStartArray("newlyFailed");
        WriteDeltaCases(writer, value.NewlyFailed);
        writer.WriteEndArray();
        writer.WriteStartArray("stillFailing");
        WriteDeltaCases(writer, value.StillFailing);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteDeltaCases(
        Utf8JsonWriter writer,
        IEnumerable<MatcherDeltaCaseReference> values)
    {
        foreach (MatcherDeltaCaseReference value in values
                     .OrderBy(item => item.CaseId, StringComparer.Ordinal)
                     .ThenBy(item => item.ProducerId, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("caseId", value.CaseId);
            writer.WriteString("producerId", value.ProducerId);
            writer.WriteEndObject();
        }
    }

    private static void WriteDeltaRelationships(
        Utf8JsonWriter writer,
        IEnumerable<MatcherDeltaRelationshipReference> values)
    {
        foreach (MatcherDeltaRelationshipReference value in values
                     .OrderBy(item => item.CaseId, StringComparer.Ordinal)
                     .ThenBy(item => item.RelationshipId, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("caseId", value.CaseId);
            writer.WriteString("producerId", value.ProducerId);
            writer.WriteString("relationshipId", value.RelationshipId);
            writer.WriteString("matcherV2Outcome", value.MatcherV2Outcome);
            writer.WriteString("matcherV3Outcome", value.MatcherV3Outcome);
            writer.WriteEndObject();
        }
    }

    private static void WriteHoldoutMetrics(Utf8JsonWriter writer, HoldoutMetrics value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("groundTruthUnits", value.GroundTruthUnits);
        writer.WriteNumber("labelledRelationships", value.LabelledRelationships);
        writer.WriteNumber("labelledMatches", value.LabelledMatches);
        writer.WriteNumber("truePositives", value.TruePositives);
        writer.WriteNumber("falsePositives", value.FalsePositives);
        writer.WriteNumber("falseNegatives", value.FalseNegatives);
        writer.WriteNumber("classificationMismatches", value.ClassificationMismatches);
        writer.WriteNumber(
            "expectedNewClassifications",
            value.ExpectedNewClassifications);
        writer.WriteNumber("newClassifications", value.NewClassifications);
        writer.WriteNumber(
            "correctNewClassifications",
            value.CorrectNewClassifications);
        writer.WriteNumber(
            "incorrectNewClassifications",
            value.IncorrectNewClassifications);
        writer.WriteNumber(
            "newClassificationAccuracy",
            value.NewClassificationAccuracy);
        writer.WriteNumber(
            "expectedResolvedClassifications",
            value.ExpectedResolvedClassifications);
        writer.WriteNumber("resolvedClassifications", value.ResolvedClassifications);
        writer.WriteNumber(
            "correctResolvedClassifications",
            value.CorrectResolvedClassifications);
        writer.WriteNumber(
            "incorrectResolvedClassifications",
            value.IncorrectResolvedClassifications);
        writer.WriteNumber(
            "resolvedClassificationAccuracy",
            value.ResolvedClassificationAccuracy);
        writer.WriteNumber("ambiguousClassifications", value.AmbiguousClassifications);
        writer.WriteNumber("correctAmbiguityRefusals", value.CorrectAmbiguityRefusals);
        writer.WriteNumber("unexpectedAmbiguityRefusals", value.UnexpectedAmbiguityRefusals);
        writer.WriteNumber(
            "incorrectlyAutoMatchedAmbiguousCases",
            value.IncorrectlyAutoMatchedAmbiguousCases);
        writer.WriteNumber("ingestionFailures", value.IngestionFailures);
        writer.WriteNumber("structuralFailures", value.StructuralFailures);
        writer.WriteNumber("precision", value.Precision);
        writer.WriteNumber("recall", value.Recall);
        writer.WriteNumber("f1", value.F1);
        writer.WriteEndObject();
    }

    private static void WriteSarifRegressCase(
        Utf8JsonWriter writer,
        SarifRegressCaseResult value)
    {
        writer.WriteStartObject();
        writer.WriteString("caseId", value.CaseId);
        writer.WriteString("producerId", value.ProducerId);
        writer.WriteString("status", value.Status);
        writer.WritePropertyName("inputHashes");
        WriteInputHashes(writer, value.InputHashes);
        WriteNullableString(writer, "engineReportSha256", value.EngineReportSha256);
        writer.WritePropertyName("metrics");
        WriteHoldoutMetrics(writer, value.Metrics);
        writer.WriteStartArray("relationshipResults");
        foreach (RelationshipResult relationship in value.RelationshipResults.OrderBy(
                     item => item.RelationshipId,
                     StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("relationshipId", relationship.RelationshipId);
            writer.WritePropertyName("groundTruth");
            WriteGroundTruth(writer, relationship.GroundTruth);
            writer.WritePropertyName("actual");
            writer.WriteStartObject();
            writer.WriteString("state", relationship.Actual.State);
            WriteNullableString(writer, "baselineKey", relationship.Actual.BaselineKey);
            WriteNullableString(writer, "candidateKey", relationship.Actual.CandidateKey);
            writer.WriteStartArray("decisionTraces");
            foreach (DecisionTraceProjection trace in
                     relationship.Actual.DecisionTraces
                         .OrderBy(item => item.Side, StringComparer.Ordinal)
                         .ThenBy(item => item.Classification, StringComparer.Ordinal)
                         .ThenBy(item => item.PrecedenceTier, StringComparer.Ordinal)
                         .ThenBy(
                             item => item.MatcherAlgorithmVersion,
                             StringComparer.Ordinal))
            {
                WriteDecisionTrace(writer, trace);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteString("outcome", relationship.Outcome);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WritePropertyName("outcomes");
        WriteOutcomeDetails(writer, value.Outcomes);
        writer.WritePropertyName("diagnosticCounts");
        WriteDiagnosticCounts(writer, value.DiagnosticCounts);
        writer.WriteEndObject();
    }

    private static void WriteOutcomeDetails(Utf8JsonWriter writer, OutcomeDetails value)
    {
        writer.WriteStartObject();
        WriteRelationshipReferences(writer, "falseMatches", value.FalseMatches);
        WriteRelationshipReferences(writer, "missedMatches", value.MissedMatches);
        WriteRelationshipReferences(
            writer,
            "classificationMismatches",
            value.ClassificationMismatches);
        writer.WriteStartArray("ambiguityRefusals");
        foreach (AmbiguityRefusal refusal in value.AmbiguityRefusals.OrderBy(
                     item => item.RelationshipId,
                     StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("relationshipId", refusal.RelationshipId);
            writer.WriteBoolean("expected", refusal.Expected);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        WriteRelationshipReferences(
            writer,
            "incorrectAmbiguityMatches",
            value.IncorrectAmbiguityMatches);
        writer.WriteStartArray("ingestionFailures");
        foreach (IngestionFailure failure in value.IngestionFailures
                     .OrderBy(item => item.Input, StringComparer.Ordinal)
                     .ThenBy(item => item.DiagnosticCode, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("input", failure.Input);
            writer.WriteString("diagnosticCode", failure.DiagnosticCode);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("structuralFailures");
        foreach (StructuralFailure failure in value.StructuralFailures
                     .OrderBy(item => item.Code, StringComparer.Ordinal)
                     .ThenBy(item => item.RelativePath, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("code", failure.Code);
            writer.WriteString("relativePath", failure.RelativePath);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteRelationshipReferences(
        Utf8JsonWriter writer,
        string propertyName,
        IEnumerable<RelationshipReference> values)
    {
        writer.WriteStartArray(propertyName);
        foreach (RelationshipReference value in values.OrderBy(
                     item => item.RelationshipId,
                     StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("relationshipId", value.RelationshipId);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteDiagnosticCounts(
        Utf8JsonWriter writer,
        IEnumerable<DiagnosticCount> values)
    {
        writer.WriteStartArray();
        foreach (DiagnosticCount value in values.OrderBy(
                     item => item.Code,
                     StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("code", value.Code);
            writer.WriteNumber("count", value.Count);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteMultitoolEvidence(
        Utf8JsonWriter writer,
        MultitoolToolEvidence value)
    {
        writer.WriteStartObject();
        writer.WriteString("name", value.Name);
        writer.WriteString("packageId", value.PackageId);
        writer.WriteString("exactVersion", value.ExactVersion);
        writer.WriteString("projectUrl", value.ProjectUrl);
        writer.WriteString("sourceCommitSha", value.SourceCommitSha);
        writer.WriteString("packageUrl", value.PackageUrl);
        writer.WriteString("packageSha256", value.PackageSha256);
        writer.WriteNumber("packageSizeBytes", value.PackageSizeBytes);
        writer.WriteString("license", value.License);
        writer.WriteString("helpOutputSha256", value.HelpOutputSha256);
        writer.WriteString("versionOutputSha256", value.VersionOutputSha256);
        writer.WriteEndObject();
    }

    private static void WriteMultitoolMetrics(
        Utf8JsonWriter writer,
        MultitoolMetrics value,
        bool includeStateCounts)
    {
        writer.WriteStartObject();
        writer.WriteNumber("groundTruthUnits", value.GroundTruthUnits);
        writer.WriteNumber("labelledRelationships", value.LabelledRelationships);
        writer.WriteNumber("comparableRelationships", value.ComparableRelationships);
        writer.WriteNumber("nonComparableRelationships", value.NonComparableRelationships);
        writer.WriteNumber("truePositives", value.TruePositives);
        writer.WriteNumber("falsePositives", value.FalsePositives);
        writer.WriteNumber("falseNegatives", value.FalseNegatives);
        writer.WriteNumber("errors", value.Errors);
        writer.WriteNumber("unsupported", value.Unsupported);
        writer.WriteNumber("precision", value.Precision);
        writer.WriteNumber("recall", value.Recall);
        writer.WriteNumber("f1", value.F1);
        if (includeStateCounts)
        {
            writer.WritePropertyName("states");
            writer.WriteStartObject();
            writer.WriteNumber("new", value.States.New);
            writer.WriteNumber("absent", value.States.Absent);
            writer.WriteNumber("unchanged", value.States.Unchanged);
            writer.WriteNumber("updated", value.States.Updated);
            writer.WriteNumber("error", value.States.Error);
            writer.WriteNumber("unsupported", value.States.Unsupported);
            writer.WriteEndObject();
        }

        writer.WriteEndObject();
    }

    private static void WriteMultitoolCase(
        Utf8JsonWriter writer,
        MultitoolCaseResult value)
    {
        writer.WriteStartObject();
        writer.WriteString("caseId", value.CaseId);
        writer.WriteString("producerId", value.ProducerId);
        writer.WritePropertyName("inputHashes");
        WriteInputHashes(writer, value.InputHashes);
        writer.WritePropertyName("invocation");
        writer.WriteStartObject();
        writer.WriteString("workingDirectory", value.Invocation.WorkingDirectory);
        writer.WriteString("executable", value.Invocation.Executable);
        writer.WriteStartArray("arguments");
        foreach (string argument in value.Invocation.Arguments)
        {
            writer.WriteStringValue(argument);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteString("rawArtifactRelativePath", value.RawArtifactRelativePath);
        writer.WriteBoolean(
            "instrumentationStateMultisetPreserved",
            value.InstrumentationStateMultisetPreserved);
        writer.WritePropertyName("metrics");
        WriteMultitoolMetrics(writer, value.Metrics, includeStateCounts: true);
        writer.WriteStartArray("relationshipResults");
        foreach (MultitoolRelationshipResult relationship in value.RelationshipResults
                     .OrderBy(item => item.RelationshipId, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("relationshipId", relationship.RelationshipId);
            writer.WritePropertyName("groundTruth");
            WriteGroundTruth(writer, relationship.GroundTruth);
            writer.WriteString("multitoolState", relationship.MultitoolState);
            writer.WriteBoolean("taxonomyMapped", relationship.TaxonomyMapped);
            WriteNullableString(
                writer,
                "mappedClassification",
                relationship.MappedClassification);
            writer.WriteBoolean("comparable", relationship.Comparable);
            writer.WriteString("comparabilityReason", relationship.ComparabilityReason);
            WriteNullableBoolean(writer, "correct", relationship.Correct);
            WriteNullableString(
                writer,
                "errorOrUnsupportedCode",
                relationship.ErrorOrUnsupportedCode);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteInputHashes(Utf8JsonWriter writer, CaseInputHashes value)
    {
        writer.WriteStartObject();
        writer.WriteString("baselineSarifSha256", value.BaselineSarifSha256);
        writer.WriteString("candidateSarifSha256", value.CandidateSarifSha256);
        writer.WriteString("labelsSha256", value.LabelsSha256);
        writer.WriteString("notesSha256", value.NotesSha256);
        writer.WriteString("producerInputTreeSha256", value.ProducerInputTreeSha256);
        WriteNullableString(writer, "configSha256", value.ConfigSha256);
        writer.WriteEndObject();
    }

    private static void WriteGroundTruth(
        Utf8JsonWriter writer,
        GroundTruthRelationship value)
    {
        writer.WriteStartObject();
        writer.WriteString("kind", value.Kind);
        WriteNullableString(writer, "baselineKey", value.BaselineKey);
        WriteNullableString(writer, "candidateKey", value.CandidateKey);
        writer.WriteString("expectedClassification", value.ExpectedClassification);
        writer.WriteEndObject();
    }

    private static void WriteReportHashes(
        Utf8JsonWriter writer,
        ComparisonReportHashes value)
    {
        writer.WriteStartObject();
        writer.WriteString("holdoutManifestSha256", value.HoldoutManifestSha256);
        writer.WriteString("evaluationMetadataSha256", value.EvaluationMetadataSha256);
        writer.WriteString("sarifRegressReportSha256", value.SarifRegressReportSha256);
        writer.WriteString(
            "sarifMultitoolBaselineReportSha256",
            value.SarifMultitoolBaselineReportSha256);
        writer.WriteString(
            "matcherV2ReportSha256",
            value.MatcherV2ReportSha256);
        writer.WriteString(
            "v2ToV3DeltaReportSha256",
            value.V2ToV3DeltaReportSha256);
        writer.WriteEndObject();
    }

    private static void WriteThresholds(Utf8JsonWriter writer, ReleaseThresholds value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("minimumPrecision", value.MinimumPrecision);
        writer.WriteNumber("minimumRecall", value.MinimumRecall);
        writer.WriteNumber(
            "minimumPerProducerPrecision",
            value.MinimumPerProducerPrecision);
        writer.WriteNumber(
            "minimumPerProducerRecall",
            value.MinimumPerProducerRecall);
        writer.WriteNumber(
            "maximumIncorrectlyAutoMatchedAmbiguousCases",
            value.MaximumIncorrectlyAutoMatchedAmbiguousCases);
        writer.WriteNumber(
            "maximumUnexplainedIngestionFailures",
            value.MaximumUnexplainedIngestionFailures);
        writer.WriteNumber("maximumStructuralFailures", value.MaximumStructuralFailures);
        writer.WriteBoolean("requireCompleteLabelGraph", value.RequireCompleteLabelGraph);
        writer.WriteBoolean(
            "requireCrossPlatformByteIdentity",
            value.RequireCrossPlatformByteIdentity);
        writer.WriteBoolean("requireCompletedEvaluation", value.RequireCompletedEvaluation);
        writer.WriteBoolean(
            "requireChangedDecisionExplanations",
            value.RequireChangedDecisionExplanations);
        writer.WriteEndObject();
    }

    private static void WriteReleaseConditions(
        Utf8JsonWriter writer,
        ReleaseConditions value)
    {
        writer.WriteStartObject();
        writer.WriteBoolean("precisionMet", value.PrecisionMet);
        writer.WriteBoolean("recallMet", value.RecallMet);
        writer.WriteBoolean(
            "allProducerPrecisionMet",
            value.AllProducerPrecisionMet);
        writer.WriteBoolean(
            "allProducerRecallMet",
            value.AllProducerRecallMet);
        writer.WriteBoolean(
            "zeroIncorrectAmbiguityMatches",
            value.ZeroIncorrectAmbiguityMatches);
        writer.WriteBoolean(
            "noUnexplainedIngestionFailures",
            value.NoUnexplainedIngestionFailures);
        writer.WriteBoolean("noStructuralFailures", value.NoStructuralFailures);
        writer.WriteBoolean(
            "completeLabelGraphSatisfied",
            value.CompleteLabelGraphSatisfied);
        writer.WriteBoolean(
            "crossPlatformByteIdentity",
            value.CrossPlatformByteIdentity);
        writer.WriteBoolean("evaluationCompleted", value.EvaluationCompleted);
        writer.WriteBoolean(
            "everyChangedDecisionExplained",
            value.EveryChangedDecisionExplained);
        writer.WriteEndObject();
    }

    private static void WriteSarifComparisonMetrics(
        Utf8JsonWriter writer,
        SarifRegressComparisonMetrics value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("groundTruthUnits", value.GroundTruthUnits);
        writer.WriteNumber("labelledRelationships", value.LabelledRelationships);
        writer.WriteNumber("labelledMatches", value.LabelledMatches);
        writer.WriteNumber("truePositives", value.TruePositives);
        writer.WriteNumber("falsePositives", value.FalsePositives);
        writer.WriteNumber("falseNegatives", value.FalseNegatives);
        writer.WriteNumber("classificationMismatches", value.ClassificationMismatches);
        writer.WriteNumber(
            "expectedNewClassifications",
            value.ExpectedNewClassifications);
        writer.WriteNumber(
            "correctNewClassifications",
            value.CorrectNewClassifications);
        writer.WriteNumber(
            "incorrectNewClassifications",
            value.IncorrectNewClassifications);
        writer.WriteNumber(
            "newClassificationAccuracy",
            value.NewClassificationAccuracy);
        writer.WriteNumber(
            "expectedResolvedClassifications",
            value.ExpectedResolvedClassifications);
        writer.WriteNumber(
            "correctResolvedClassifications",
            value.CorrectResolvedClassifications);
        writer.WriteNumber(
            "incorrectResolvedClassifications",
            value.IncorrectResolvedClassifications);
        writer.WriteNumber(
            "resolvedClassificationAccuracy",
            value.ResolvedClassificationAccuracy);
        writer.WriteNumber("correctAmbiguityRefusals", value.CorrectAmbiguityRefusals);
        writer.WriteNumber(
            "incorrectlyAutoMatchedAmbiguousCases",
            value.IncorrectlyAutoMatchedAmbiguousCases);
        writer.WriteNumber("ingestionFailures", value.IngestionFailures);
        writer.WriteNumber(
            "unexplainedIngestionFailures",
            value.UnexplainedIngestionFailures);
        writer.WriteNumber("structuralFailures", value.StructuralFailures);
        writer.WriteNumber("precision", value.Precision);
        writer.WriteNumber("recall", value.Recall);
        writer.WriteNumber("f1", value.F1);
        writer.WriteEndObject();
    }

    private static void WriteProducerQualityGates(
        Utf8JsonWriter writer,
        ProducerQualityGates value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("minimumPrecision", value.MinimumPrecision);
        writer.WriteNumber("minimumRecall", value.MinimumRecall);
        writer.WriteBoolean("precisionMet", value.PrecisionMet);
        writer.WriteBoolean("recallMet", value.RecallMet);
        writer.WriteEndObject();
    }

    private static void WriteDecisionTrace(
        Utf8JsonWriter writer,
        DecisionTraceProjection value)
    {
        writer.WriteStartObject();
        writer.WriteString("side", value.Side);
        writer.WriteString("classification", value.Classification);
        writer.WriteString("precedenceTier", value.PrecedenceTier);
        writer.WriteString("displayConfidence", value.DisplayConfidence);
        writer.WriteBoolean("ambiguous", value.Ambiguous);
        writer.WriteString(
            "matcherAlgorithmVersion",
            value.MatcherAlgorithmVersion);
        writer.WriteStartArray("evidence");
        foreach (DecisionEvidenceProjection evidence in value.Evidence)
        {
            writer.WriteStartObject();
            writer.WriteString("kind", evidence.Kind);
            writer.WriteString("origin", evidence.Origin);
            writer.WriteString("precedenceTier", evidence.PrecedenceTier);
            writer.WriteBoolean("lossy", evidence.Lossy);
            writer.WriteString("algorithmVersion", evidence.AlgorithmVersion);
            writer.WriteNumber("count", evidence.Count);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("rejectedAlternatives");
        foreach (RejectedAlternativeProjection alternative in
                 value.RejectedAlternatives)
        {
            writer.WriteStartObject();
            writer.WriteString("precedenceTier", alternative.PrecedenceTier);
            writer.WritePropertyName("decisionVector");
            WriteDecisionVector(writer, alternative.DecisionVector);
            writer.WriteNumber("count", alternative.Count);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("transformations");
        foreach (DecisionTransformationProjection transformation in
                 value.Transformations)
        {
            writer.WriteStartObject();
            writer.WriteString("kind", transformation.Kind);
            writer.WriteBoolean("lossy", transformation.Lossy);
            writer.WriteString(
                "algorithmVersion",
                transformation.AlgorithmVersion);
            writer.WriteNumber("count", transformation.Count);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("diagnostics");
        foreach (DecisionDiagnosticProjection diagnostic in value.Diagnostics)
        {
            writer.WriteStartObject();
            writer.WriteString("code", diagnostic.Code);
            writer.WriteString("severity", diagnostic.Severity);
            writer.WriteString("stage", diagnostic.Stage);
            writer.WriteNumber("count", diagnostic.Count);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteDecisionVector(
        Utf8JsonWriter writer,
        DecisionVectorProjection value)
    {
        writer.WriteStartObject();
        writer.WriteString("precedenceTier", value.PrecedenceTier);
        writer.WriteNumber(
            "producerFingerprintStrength",
            value.ProducerFingerprintStrength);
        writer.WriteString("pathMatchKind", value.PathMatchKind);
        writer.WriteString("contextAgreement", value.ContextAgreement);
        writer.WriteString("codeFlowAgreement", value.CodeFlowAgreement);
        writer.WriteString("messageAgreement", value.MessageAgreement);
        writer.WriteNumber("regionDriftBand", value.RegionDriftBand);
        writer.WriteEndObject();
    }

    private static void WriteMultitoolComparisonMetrics(
        Utf8JsonWriter writer,
        MultitoolComparisonMetrics value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("groundTruthUnits", value.GroundTruthUnits);
        writer.WriteNumber("labelledRelationships", value.LabelledRelationships);
        writer.WriteNumber("comparableRelationships", value.ComparableRelationships);
        writer.WriteNumber("nonComparableRelationships", value.NonComparableRelationships);
        writer.WriteNumber("truePositives", value.TruePositives);
        writer.WriteNumber("falsePositives", value.FalsePositives);
        writer.WriteNumber("falseNegatives", value.FalseNegatives);
        writer.WriteNumber("precision", value.Precision);
        writer.WriteNumber("recall", value.Recall);
        writer.WriteNumber("f1", value.F1);
        writer.WriteEndObject();
    }

    private static void WriteToolComparisonMetrics(
        Utf8JsonWriter writer,
        ToolComparisonMetrics value)
    {
        writer.WriteStartObject();
        writer.WriteNumber("groundTruthUnits", value.GroundTruthUnits);
        writer.WriteNumber(
            "positiveMatchRelationships",
            value.PositiveMatchRelationships);
        writer.WriteNumber("comparableUnits", value.ComparableUnits);
        writer.WriteNumber("bothToolsAgree", value.BothToolsAgree);
        writer.WriteNumber("bothToolsCorrect", value.BothToolsCorrect);
        writer.WriteNumber("sarifRegressOnlyCorrect", value.SarifRegressOnlyCorrect);
        writer.WriteNumber("multitoolOnlyCorrect", value.MultitoolOnlyCorrect);
        writer.WriteNumber("bothIncorrect", value.BothIncorrect);
        writer.WriteNumber("nonComparable", value.NonComparable);
        writer.WriteEndObject();
    }

    private static void WriteNullableString(
        Utf8JsonWriter writer,
        string propertyName,
        string? value)
    {
        if (value is null)
        {
            writer.WriteNull(propertyName);
        }
        else
        {
            writer.WriteString(propertyName, value);
        }
    }

    private static void WriteNullableBoolean(
        Utf8JsonWriter writer,
        string propertyName,
        bool? value)
    {
        if (value.HasValue)
        {
            writer.WriteBoolean(propertyName, value.Value);
        }
        else
        {
            writer.WriteNull(propertyName);
        }
    }
}
