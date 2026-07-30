using System.Text.Json;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Matching;

namespace SarifRegress.Report;

internal static class StableJsonNames
{
    public static string Classification(FindingClassification value) =>
        value switch
        {
            FindingClassification.New => "new",
            FindingClassification.Unchanged => "unchanged",
            FindingClassification.Moved => "moved",
            FindingClassification.Modified => "modified",
            FindingClassification.Resolved => "resolved",
            FindingClassification.Ambiguous => "ambiguous",
            _ => throw UnknownEnum(value),
        };

    public static FindingClassification ParseClassification(string value) =>
        value switch
        {
            "new" => FindingClassification.New,
            "unchanged" => FindingClassification.Unchanged,
            "moved" => FindingClassification.Moved,
            "modified" => FindingClassification.Modified,
            "resolved" => FindingClassification.Resolved,
            "ambiguous" => FindingClassification.Ambiguous,
            _ => throw UnknownName(nameof(FindingClassification), value),
        };

    public static string Input(InputKind value) =>
        value switch
        {
            InputKind.Baseline => "baseline",
            InputKind.Candidate => "candidate",
            InputKind.Configuration => "configuration",
            InputKind.Corpus => "corpus",
            _ => throw UnknownEnum(value),
        };

    public static InputKind ParseInput(string value) =>
        value switch
        {
            "baseline" => InputKind.Baseline,
            "candidate" => InputKind.Candidate,
            "configuration" => InputKind.Configuration,
            "corpus" => InputKind.Corpus,
            _ => throw UnknownName(nameof(InputKind), value),
        };

    public static string Precedence(PrecedenceTier value) =>
        value switch
        {
            PrecedenceTier.Refuse => "refuse",
            PrecedenceTier.WeakContextual => "weak-contextual",
            PrecedenceTier.PathProblem => "path-problem",
            PrecedenceTier.StrongMoved => "strong-moved",
            PrecedenceTier.ExactCanonical => "exact-canonical",
            PrecedenceTier.ExactProducer => "exact-producer",
            PrecedenceTier.Override => "override",
            _ => throw UnknownEnum(value),
        };

    public static PrecedenceTier ParsePrecedence(string value) =>
        value switch
        {
            "refuse" => PrecedenceTier.Refuse,
            "weak-contextual" => PrecedenceTier.WeakContextual,
            "path-problem" => PrecedenceTier.PathProblem,
            "strong-moved" => PrecedenceTier.StrongMoved,
            "exact-canonical" => PrecedenceTier.ExactCanonical,
            "exact-producer" => PrecedenceTier.ExactProducer,
            "override" => PrecedenceTier.Override,
            _ => throw UnknownName(nameof(PrecedenceTier), value),
        };

    public static string Confidence(DisplayConfidence value) =>
        value switch
        {
            DisplayConfidence.Low => "low",
            DisplayConfidence.Medium => "medium",
            DisplayConfidence.High => "high",
            _ => throw UnknownEnum(value),
        };

    public static DisplayConfidence ParseConfidence(string value) =>
        value switch
        {
            "low" => DisplayConfidence.Low,
            "medium" => DisplayConfidence.Medium,
            "high" => DisplayConfidence.High,
            _ => throw UnknownName(nameof(DisplayConfidence), value),
        };

    public static string Origin(EvidenceOrigin value) =>
        value switch
        {
            EvidenceOrigin.Producer => "producer",
            EvidenceOrigin.Configuration => "configuration",
            EvidenceOrigin.Repository => "repository",
            EvidenceOrigin.System => "system",
            _ => throw UnknownEnum(value),
        };

    public static EvidenceOrigin ParseOrigin(string value) =>
        value switch
        {
            "producer" => EvidenceOrigin.Producer,
            "configuration" => EvidenceOrigin.Configuration,
            "repository" => EvidenceOrigin.Repository,
            "system" => EvidenceOrigin.System,
            _ => throw UnknownName(nameof(EvidenceOrigin), value),
        };

    public static string PathMatch(PathMatchKind value) =>
        value switch
        {
            PathMatchKind.None => "none",
            PathMatchKind.Aliased => "aliased",
            PathMatchKind.Exact => "exact",
            _ => throw UnknownEnum(value),
        };

    public static PathMatchKind ParsePathMatch(string value) =>
        value switch
        {
            "none" => PathMatchKind.None,
            "aliased" => PathMatchKind.Aliased,
            "exact" => PathMatchKind.Exact,
            _ => throw UnknownName(nameof(PathMatchKind), value),
        };

    public static string Agreement(AgreementBand value) =>
        value switch
        {
            AgreementBand.None => "none",
            AgreementBand.Compatible => "compatible",
            AgreementBand.Exact => "exact",
            _ => throw UnknownEnum(value),
        };

    public static AgreementBand ParseAgreement(string value) =>
        value switch
        {
            "none" => AgreementBand.None,
            "compatible" => AgreementBand.Compatible,
            "exact" => AgreementBand.Exact,
            _ => throw UnknownName(nameof(AgreementBand), value),
        };

    public static string Severity(DiagnosticSeverity value) =>
        value switch
        {
            DiagnosticSeverity.Note => "note",
            DiagnosticSeverity.Warning => "warning",
            DiagnosticSeverity.Error => "error",
            _ => throw UnknownEnum(value),
        };

    public static DiagnosticSeverity ParseSeverity(string value) =>
        value switch
        {
            "note" => DiagnosticSeverity.Note,
            "warning" => DiagnosticSeverity.Warning,
            "error" => DiagnosticSeverity.Error,
            _ => throw UnknownName(nameof(DiagnosticSeverity), value),
        };

    public static string Stage(DiagnosticStage value) =>
        value switch
        {
            DiagnosticStage.Io => "io",
            DiagnosticStage.Parse => "parse",
            DiagnosticStage.Schema => "schema",
            DiagnosticStage.Unsupported => "unsupported",
            DiagnosticStage.Canonicalisation => "canonicalisation",
            DiagnosticStage.Repository => "repository",
            DiagnosticStage.Fingerprint => "fingerprint",
            DiagnosticStage.Match => "match",
            DiagnosticStage.GithubCompatibility => "github-compat",
            DiagnosticStage.Security => "security",
            DiagnosticStage.Report => "report",
            DiagnosticStage.Internal => "internal",
            _ => throw UnknownEnum(value),
        };

    public static DiagnosticStage ParseStage(string value) =>
        value switch
        {
            "io" => DiagnosticStage.Io,
            "parse" => DiagnosticStage.Parse,
            "schema" => DiagnosticStage.Schema,
            "unsupported" => DiagnosticStage.Unsupported,
            "canonicalisation" => DiagnosticStage.Canonicalisation,
            "repository" => DiagnosticStage.Repository,
            "fingerprint" => DiagnosticStage.Fingerprint,
            "match" => DiagnosticStage.Match,
            "github-compat" => DiagnosticStage.GithubCompatibility,
            "security" => DiagnosticStage.Security,
            "report" => DiagnosticStage.Report,
            "internal" => DiagnosticStage.Internal,
            _ => throw UnknownName(nameof(DiagnosticStage), value),
        };

    private static ArgumentOutOfRangeException UnknownEnum<T>(T value)
        where T : struct, Enum =>
        new(nameof(value), value, $"Unknown {typeof(T).Name} value.");

    private static JsonException UnknownName(string enumName, string value) =>
        new($"'{value}' is not a supported {enumName} wire value.");
}
