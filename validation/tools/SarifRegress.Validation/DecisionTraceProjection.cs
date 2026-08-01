using System.Collections.Immutable;
using System.Text.Json;

namespace SarifRegress.Validation;

/// <summary>Retains one grouped evidence category without source-controlled values.</summary>
public sealed record DecisionEvidenceProjection(
    string Kind,
    string Origin,
    string PrecedenceTier,
    bool Lossy,
    string AlgorithmVersion,
    int Count);

/// <summary>Retains the semantic, value-free part of an assignment decision vector.</summary>
public sealed record DecisionVectorProjection(
    string PrecedenceTier,
    int ProducerFingerprintStrength,
    string PathMatchKind,
    string ContextAgreement,
    string CodeFlowAgreement,
    string MessageAgreement,
    int RegionDriftBand);

/// <summary>Counts rejected alternatives with the same value-free decision vector.</summary>
public sealed record RejectedAlternativeProjection(
    string PrecedenceTier,
    DecisionVectorProjection DecisionVector,
    int Count);

/// <summary>Retains one grouped canonicalisation transform without path values.</summary>
public sealed record DecisionTransformationProjection(
    string Kind,
    bool Lossy,
    string AlgorithmVersion,
    int Count);

/// <summary>Retains one grouped diagnostic identity without source text or locations.</summary>
public sealed record DecisionDiagnosticProjection(
    string Code,
    string Severity,
    string Stage,
    int Count);

/// <summary>
/// Projects one product decision explanation without producer values, paths, messages,
/// finding keys, rejected-alternative reasons, or diagnostic prose.
/// </summary>
public sealed record DecisionTraceProjection(
    string Side,
    string Classification,
    string PrecedenceTier,
    string DisplayConfidence,
    bool Ambiguous,
    string MatcherAlgorithmVersion,
    ImmutableArray<DecisionEvidenceProjection> Evidence,
    ImmutableArray<RejectedAlternativeProjection> RejectedAlternatives,
    ImmutableArray<DecisionTransformationProjection> Transformations,
    ImmutableArray<DecisionDiagnosticProjection> Diagnostics);

/// <summary>Creates bounded, value-free decision projections from stable product JSON.</summary>
internal static class DecisionTraceProjectionFactory
{
    /// <summary>Projects one finding record and rejects malformed or oversized traces.</summary>
    public static DecisionTraceProjection Create(
        JsonElement finding,
        ValidationLimits? limits = null)
    {
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        effectiveLimits.Validate();
        RequireObject(finding, "finding");
        string classification = RequireWireValue(
            finding,
            "classification",
            effectiveLimits,
            IsClassification);
        string side = DetermineSide(finding);
        JsonElement decision = RequireObjectProperty(finding, "decision");
        string precedenceTier = RequireWireValue(
            decision,
            "precedenceTier",
            effectiveLimits,
            IsPrecedenceTier);
        string displayConfidence = RequireWireValue(
            decision,
            "displayConfidence",
            effectiveLimits,
            IsDisplayConfidence);
        bool ambiguous = RequireBoolean(decision, "ambiguous");
        if (ambiguous != string.Equals(
                classification,
                "ambiguous",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "A projected decision's ambiguity flag must match its classification.");
        }

        return new DecisionTraceProjection(
            side,
            classification,
            precedenceTier,
            displayConfidence,
            ambiguous,
            RequireText(
                decision,
                "matcherAlgorithmVersion",
                effectiveLimits),
            ProjectEvidence(
                RequireBoundedArray(finding, "evidence", effectiveLimits),
                effectiveLimits),
            ProjectRejectedAlternatives(
                RequireBoundedArray(
                    finding,
                    "rejectedAlternatives",
                    effectiveLimits),
                effectiveLimits),
            ProjectTransformations(
                RequireBoundedArray(finding, "transforms", effectiveLimits),
                effectiveLimits),
            ProjectDiagnostics(
                RequireBoundedArray(finding, "diagnostics", effectiveLimits),
                effectiveLimits));
    }

    /// <summary>Orders at most one baseline, candidate, or paired trace per relationship.</summary>
    public static ImmutableArray<DecisionTraceProjection> OrderAndValidate(
        IEnumerable<DecisionTraceProjection> traces,
        ValidationLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(traces);
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        effectiveLimits.Validate();
        DecisionTraceProjection[] values = traces.ToArray();
        if (values.Length > effectiveLimits.MaximumDecisionTracesPerRelationship)
        {
            throw new InvalidDataException(
                "A relationship exceeds the configured decision-trace projection limit.");
        }

        if (values.Any(item => item is null))
        {
            throw new InvalidDataException(
                "A relationship decision-trace projection cannot contain null.");
        }

        if (values.GroupBy(item => item.Side, StringComparer.Ordinal)
            .Any(group => group.Count() > 1))
        {
            throw new InvalidDataException(
                "A relationship decision-trace projection repeats an input side.");
        }

        return values
            .OrderBy(item => SideOrder(item.Side))
            .ThenBy(item => item.Classification, StringComparer.Ordinal)
            .ThenBy(item => item.PrecedenceTier, StringComparer.Ordinal)
            .ThenBy(item => item.MatcherAlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static ImmutableArray<DecisionEvidenceProjection> ProjectEvidence(
        JsonElement.ArrayEnumerator source,
        ValidationLimits limits)
    {
        var values = new List<EvidenceKey>();
        foreach (JsonElement item in source)
        {
            RequireObject(item, "evidence item");
            values.Add(new EvidenceKey(
                RequireText(item, "kind", limits),
                RequireWireValue(item, "origin", limits, IsEvidenceOrigin),
                RequireWireValue(
                    item,
                    "precedenceTier",
                    limits,
                    IsPrecedenceTier),
                RequireBoolean(item, "lossy"),
                RequireText(item, "algorithmVersion", limits)));
        }

        return values
            .GroupBy(item => item)
            .OrderBy(group => group.Key.Kind, StringComparer.Ordinal)
            .ThenBy(group => group.Key.Origin, StringComparer.Ordinal)
            .ThenBy(group => group.Key.PrecedenceTier, StringComparer.Ordinal)
            .ThenBy(group => group.Key.Lossy)
            .ThenBy(group => group.Key.AlgorithmVersion, StringComparer.Ordinal)
            .Select(group => new DecisionEvidenceProjection(
                group.Key.Kind,
                group.Key.Origin,
                group.Key.PrecedenceTier,
                group.Key.Lossy,
                group.Key.AlgorithmVersion,
                group.Count()))
            .ToImmutableArray();
    }

    private static ImmutableArray<RejectedAlternativeProjection>
        ProjectRejectedAlternatives(
            JsonElement.ArrayEnumerator source,
            ValidationLimits limits)
    {
        var values = new List<RejectedAlternativeKey>();
        foreach (JsonElement item in source)
        {
            RequireObject(item, "rejected alternative");
            values.Add(new RejectedAlternativeKey(
                RequireWireValue(
                    item,
                    "precedenceTier",
                    limits,
                    IsPrecedenceTier),
                ProjectDecisionVector(
                    RequireObjectProperty(item, "decisionVector"),
                    limits)));
        }

        return values
            .GroupBy(item => item)
            .OrderBy(group => group.Key.PrecedenceTier, StringComparer.Ordinal)
            .ThenBy(group => group.Key.DecisionVector.PrecedenceTier,
                StringComparer.Ordinal)
            .ThenBy(group =>
                group.Key.DecisionVector.ProducerFingerprintStrength)
            .ThenBy(group => group.Key.DecisionVector.PathMatchKind,
                StringComparer.Ordinal)
            .ThenBy(group => group.Key.DecisionVector.ContextAgreement,
                StringComparer.Ordinal)
            .ThenBy(group => group.Key.DecisionVector.CodeFlowAgreement,
                StringComparer.Ordinal)
            .ThenBy(group => group.Key.DecisionVector.MessageAgreement,
                StringComparer.Ordinal)
            .ThenBy(group => group.Key.DecisionVector.RegionDriftBand)
            .Select(group => new RejectedAlternativeProjection(
                group.Key.PrecedenceTier,
                group.Key.DecisionVector,
                group.Count()))
            .ToImmutableArray();
    }

    private static DecisionVectorProjection ProjectDecisionVector(
        JsonElement vector,
        ValidationLimits limits)
    {
        RequireObject(vector, "decision vector");
        return new DecisionVectorProjection(
            RequireWireValue(
                vector,
                "precedenceTier",
                limits,
                IsPrecedenceTier),
            RequireNonNegativeInteger(vector, "producerFingerprintStrength"),
            RequireWireValue(vector, "pathMatchKind", limits, IsPathMatchKind),
            RequireWireValue(
                vector,
                "contextAgreement",
                limits,
                IsAgreementBand),
            RequireWireValue(
                vector,
                "codeFlowAgreement",
                limits,
                IsAgreementBand),
            RequireWireValue(
                vector,
                "messageAgreement",
                limits,
                IsAgreementBand),
            RequireNonNegativeInteger(vector, "regionDriftBand"));
    }

    private static ImmutableArray<DecisionTransformationProjection>
        ProjectTransformations(
            JsonElement.ArrayEnumerator source,
            ValidationLimits limits)
    {
        var values = new List<TransformationKey>();
        foreach (JsonElement item in source)
        {
            RequireObject(item, "transformation");
            values.Add(new TransformationKey(
                RequireText(item, "kind", limits),
                RequireBoolean(item, "lossy"),
                RequireText(item, "algorithmVersion", limits)));
        }

        return values
            .GroupBy(item => item)
            .OrderBy(group => group.Key.Kind, StringComparer.Ordinal)
            .ThenBy(group => group.Key.Lossy)
            .ThenBy(group => group.Key.AlgorithmVersion, StringComparer.Ordinal)
            .Select(group => new DecisionTransformationProjection(
                group.Key.Kind,
                group.Key.Lossy,
                group.Key.AlgorithmVersion,
                group.Count()))
            .ToImmutableArray();
    }

    private static ImmutableArray<DecisionDiagnosticProjection>
        ProjectDiagnostics(
            JsonElement.ArrayEnumerator source,
            ValidationLimits limits)
    {
        var values = new List<DiagnosticKey>();
        foreach (JsonElement item in source)
        {
            RequireObject(item, "diagnostic");
            values.Add(new DiagnosticKey(
                RequireText(item, "code", limits),
                RequireWireValue(
                    item,
                    "severity",
                    limits,
                    IsDiagnosticSeverity),
                RequireWireValue(
                    item,
                    "stage",
                    limits,
                    IsDiagnosticStage)));
        }

        return values
            .GroupBy(item => item)
            .OrderBy(group => group.Key.Code, StringComparer.Ordinal)
            .ThenBy(group => group.Key.Severity, StringComparer.Ordinal)
            .ThenBy(group => group.Key.Stage, StringComparer.Ordinal)
            .Select(group => new DecisionDiagnosticProjection(
                group.Key.Code,
                group.Key.Severity,
                group.Key.Stage,
                group.Count()))
            .ToImmutableArray();
    }

    private static JsonElement.ArrayEnumerator RequireBoundedArray(
        JsonElement parent,
        string propertyName,
        ValidationLimits limits)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                $"A decision trace lacks array property '{propertyName}'.");
        }

        if (value.GetArrayLength() > limits.MaximumDecisionTraceItems)
        {
            throw new InvalidDataException(
                $"Decision trace array '{propertyName}' exceeds the configured projection limit.");
        }

        return value.EnumerateArray();
    }

    private static JsonElement RequireObjectProperty(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement value))
        {
            throw new InvalidDataException(
                $"A decision trace lacks object property '{propertyName}'.");
        }

        RequireObject(value, propertyName);
        return value;
    }

    private static void RequireObject(JsonElement value, string description)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                $"The projected {description} must be an object.");
        }
    }

    private static string RequireWireValue(
        JsonElement parent,
        string propertyName,
        ValidationLimits limits,
        Func<string, bool> isSupported)
    {
        string value = RequireText(parent, propertyName, limits);
        if (!isSupported(value))
        {
            throw new InvalidDataException(
                $"Decision trace property '{propertyName}' has unsupported value '{value}'.");
        }

        return value;
    }

    private static string RequireText(
        JsonElement parent,
        string propertyName,
        ValidationLimits limits)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element)
            || element.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException(
                $"A decision trace lacks string property '{propertyName}'.");
        }

        string value = element.GetString()
            ?? throw new InvalidDataException(
                $"Decision trace property '{propertyName}' is null.");
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > limits.MaximumStringCharacters)
        {
            throw new InvalidDataException(
                $"Decision trace property '{propertyName}' violates string bounds.");
        }

        return value;
    }

    private static bool RequireBoolean(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element)
            || element.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException(
                $"A decision trace lacks Boolean property '{propertyName}'.");
        }

        return element.GetBoolean();
    }

    private static int RequireNonNegativeInteger(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out JsonElement element)
            || !element.TryGetInt32(out int value)
            || value < 0)
        {
            throw new InvalidDataException(
                $"Decision vector property '{propertyName}' must be a non-negative integer.");
        }

        return value;
    }

    private static string DetermineSide(JsonElement finding)
    {
        bool baseline = HasSnapshot(finding, "baseline");
        bool candidate = HasSnapshot(finding, "candidate");
        return (baseline, candidate) switch
        {
            (true, true) => "pair",
            (true, false) => "baseline",
            (false, true) => "candidate",
            _ => throw new InvalidDataException(
                "A projected finding decision has neither input side."),
        };
    }

    private static bool HasSnapshot(JsonElement finding, string propertyName)
    {
        if (!finding.TryGetProperty(propertyName, out JsonElement snapshot))
        {
            throw new InvalidDataException(
                $"A projected finding lacks property '{propertyName}'.");
        }

        return snapshot.ValueKind switch
        {
            JsonValueKind.Null => false,
            JsonValueKind.Object => true,
            _ => throw new InvalidDataException(
                $"Projected finding property '{propertyName}' must be an object or null."),
        };
    }

    private static int SideOrder(string side) => side switch
    {
        "baseline" => 0,
        "candidate" => 1,
        "pair" => 2,
        _ => throw new InvalidDataException(
            $"Unsupported decision-trace side '{side}'."),
    };

    private static bool IsClassification(string value) => value is
        "new" or "unchanged" or "moved" or "modified" or "resolved" or
        "ambiguous";

    private static bool IsPrecedenceTier(string value) => value is
        "refuse" or "weak-contextual" or "path-problem" or "strong-moved" or
        "exact-canonical" or "exact-producer" or "override";

    private static bool IsDisplayConfidence(string value) => value is
        "low" or "medium" or "high";

    private static bool IsEvidenceOrigin(string value) => value is
        "producer" or "configuration" or "repository" or "system";

    private static bool IsPathMatchKind(string value) => value is
        "none" or "aliased" or "exact";

    private static bool IsAgreementBand(string value) => value is
        "none" or "compatible" or "exact";

    private static bool IsDiagnosticSeverity(string value) => value is
        "note" or "warning" or "error";

    private static bool IsDiagnosticStage(string value) => value is
        "io" or "parse" or "schema" or "unsupported" or "canonicalisation" or
        "repository" or "fingerprint" or "match" or "github-compat" or
        "security" or "report" or "internal";

    private readonly record struct EvidenceKey(
        string Kind,
        string Origin,
        string PrecedenceTier,
        bool Lossy,
        string AlgorithmVersion);

    private readonly record struct RejectedAlternativeKey(
        string PrecedenceTier,
        DecisionVectorProjection DecisionVector);

    private readonly record struct TransformationKey(
        string Kind,
        bool Lossy,
        string AlgorithmVersion);

    private readonly record struct DiagnosticKey(
        string Code,
        string Severity,
        string Stage);
}
