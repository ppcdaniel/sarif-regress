using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SarifRegress.Validation;

/// <summary>
/// Retains the matcher-v3.2 report-binding state established by the interpretation erratum.
/// </summary>
public sealed record HoldoutInterpretationErratumSnapshot(
    string CurrentMatcherAlgorithmVersion,
    string CurrentReportBindingStatus,
    string? CurrentReportSha256)
{
    /// <summary>The original bootstrap state whose tracked outputs still use v3.1 contracts.</summary>
    public const string LegacyCandidateUnboundStatus = "candidate-unbound";

    /// <summary>The reusable bootstrap state for re-attesting matcher-v3.2 output.</summary>
    public const string RefreshUnboundStatus = "refresh-unbound";

    /// <summary>The state whose report bytes are bound by the erratum.</summary>
    public const string BoundStatus = "bound";

    /// <summary>Gets whether the current report intentionally has no artifact binding.</summary>
    public bool IsCurrentReportUnbound =>
        IsUnboundStatus(CurrentReportBindingStatus);

    /// <summary>
    /// Gets whether tracked output predates matcher-v3.2 and therefore needs archived schemas.
    /// </summary>
    public bool UsesArchivedMatcherV31Outputs => string.Equals(
        CurrentReportBindingStatus,
        LegacyCandidateUnboundStatus,
        StringComparison.Ordinal);

    /// <summary>
    /// Validates a bound report, or returns false for a fail-closed bootstrap state.
    /// </summary>
    public bool ValidateCurrentReport(
        string matcherAlgorithmVersion,
        ReadOnlySpan<byte> reportBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(matcherAlgorithmVersion);
        if (!string.Equals(
                CurrentMatcherAlgorithmVersion,
                matcherAlgorithmVersion,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The holdout interpretation erratum does not cover the current matcher version.");
        }

        if (IsCurrentReportUnbound)
        {
            if (CurrentReportSha256 is not null)
            {
                throw new InvalidDataException(
                    "An unbound holdout report cannot carry a report digest.");
            }

            return false;
        }

        if (!string.Equals(
                CurrentReportBindingStatus,
                BoundStatus,
                StringComparison.Ordinal)
            || CurrentReportSha256 is null)
        {
            throw new InvalidDataException(
                "The current holdout report binding has an unknown state.");
        }

        string actualSha256 = Convert.ToHexString(SHA256.HashData(reportBytes))
            .ToLowerInvariant();
        if (!string.Equals(
                CurrentReportSha256,
                actualSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The generated holdout report is not hash-bound by the interpretation erratum.");
        }

        return true;
    }

    private static bool IsUnboundStatus(string status) =>
        string.Equals(status, LegacyCandidateUnboundStatus, StringComparison.Ordinal)
        || string.Equals(status, RefreshUnboundStatus, StringComparison.Ordinal);
}

/// <summary>
/// Validates the non-destructive correction that distinguishes the independent matcher-v2
/// evaluation from exposed-holdout matcher-v3 and matcher-v3.1 regression evidence.
/// </summary>
public sealed class HoldoutInterpretationErratumReader
{
    public const string RelativePath =
        "validation/holdout/interpretation-erratum.json";
    public const string ChecksumManifestRelativePath =
        "validation/holdout/interpretation-erratum.checksums.sha256";
    public const string SchemaRelativePath =
        "validation/schemas/interpretation-erratum.schema.json";

    private const string MatcherV2ReportRelativePath =
        "validation/history/matcher-v2/sarif-regress-holdout.json";
    private const string MatcherV3MetadataRelativePath =
        "validation/history/matcher-v3/metadata.json";
    private const string MatcherV3ReportRelativePath =
        "validation/history/matcher-v3/sarif-regress-holdout.json";
    private const string MatcherV31ReportRelativePath =
        "validation/history/matcher-v3.1/sarif-regress-holdout.json";
    private const string MatcherV32ReportRelativePath =
        "validation/expected/sarif-regress-holdout.json";
    private const string MatcherV2AlgorithmVersion =
        MatcherV2HistoryReader.MatcherV2AlgorithmVersion;
    private const string MatcherV3AlgorithmVersion =
        MatcherV3HistoryReader.MatcherV3AlgorithmVersion;
    private const string MatcherV31AlgorithmVersion =
        MatcherV3HistoryReader.MatcherV31AlgorithmVersion;
    private const string MatcherV32AlgorithmVersion =
        MatcherV31HistoryReader.MatcherV32AlgorithmVersion;
    private const string IndependentInterpretation = "independent-first-evaluation";
    private const string CorrectedInterpretation =
        "exposed-holdout-regression-evidence";
    private const string CorrectionReason =
        "implementation-informed-by-frozen-holdout";

    private static readonly ImmutableArray<string> ChecksummedFiles =
    [
        RelativePath,
        SchemaRelativePath,
        MatcherV2ReportRelativePath,
        MatcherV3MetadataRelativePath,
        MatcherV3ReportRelativePath,
        MatcherV31ReportRelativePath,
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly JsonSchemaValidator schemaValidator;
    private readonly ValidationLimits limits;

    /// <summary>Creates a bounded reader for the fixed repository erratum.</summary>
    public HoldoutInterpretationErratumReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
        schemaValidator = new JsonSchemaValidator(this.limits);
    }

    /// <summary>
    /// Verifies the dedicated checksum graph, strict schema, artifact bindings, and claim policy.
    /// </summary>
    public HoldoutInterpretationErratumSnapshot Read(string repositoryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        string root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(repositoryRoot));
        byte[] checksumBytes = Read(
            root,
            ChecksumManifestRelativePath,
            limits.MaximumManifestBytes);
        ImmutableSortedDictionary<string, string> checksums =
            ChecksumManifest.Parse(checksumBytes);
        byte[] erratumBytes = Read(root, RelativePath, limits.MaximumManifestBytes);
        JsonNode node = BoundedJsonFile.ParseNode(
            erratumBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            Path.GetFileName(RelativePath));
        _ = schemaValidator.ValidateNode(
            StablePath.Resolve(root, SchemaRelativePath),
            node,
            Path.GetFileName(RelativePath),
            root);
        ErratumDocument document = node.Deserialize<ErratumDocument>(
                SerializerOptions)
            ?? throw new InvalidDataException(
                "The holdout interpretation erratum is empty.");
        VerifyChecksumGraph(root, checksums, document.CurrentReportBinding);
        ValidateDocument(document, checksums);
        AmbientDataGuard.Validate(erratumBytes, root);

        return new HoldoutInterpretationErratumSnapshot(
            document.CurrentReportBinding.MatcherAlgorithmVersion,
            document.CurrentReportBinding.Status,
            document.CurrentReportBinding.Artifact?.Sha256);
    }

    private void VerifyChecksumGraph(
        string repositoryRoot,
        ImmutableSortedDictionary<string, string> checksums,
        CurrentReportBindingDocument currentReportBinding)
    {
        IEnumerable<string> paths = ChecksummedFiles;
        if (string.Equals(
                currentReportBinding.Status,
                HoldoutInterpretationErratumSnapshot.BoundStatus,
                StringComparison.Ordinal))
        {
            paths = paths.Append(MatcherV32ReportRelativePath);
        }

        string[] expectedPaths = paths
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!checksums.Keys.SequenceEqual(expectedPaths, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The interpretation-erratum checksum manifest has an unexpected file set.");
        }

        foreach (string relativePath in expectedPaths)
        {
            long maximumBytes = GetMaximumBytes(relativePath);
            string actualSha256 = BoundedJsonFile.ComputeSha256(
                StablePath.Resolve(repositoryRoot, relativePath),
                maximumBytes,
                repositoryRoot);
            if (!string.Equals(
                    checksums[relativePath],
                    actualSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Interpretation-erratum checksum verification failed for '{relativePath}'.");
            }
        }
    }

    private static void ValidateDocument(
        ErratumDocument document,
        IReadOnlyDictionary<string, string> checksums)
    {
        RequireEqual("schema version", "2", document.SchemaVersion);
        RequireEqual("kind", "holdout-interpretation-erratum/v2", document.Kind);
        RequireEqual(
            "independent claim scope",
            "matcher-v2-first-evaluation-only",
            document.InterpretationPolicy.IndependentClaimScope);
        RequireEqual(
            "future independent claim requirement",
            "new-untouched-or-blinded-corpus",
            document.InterpretationPolicy.FutureIndependentClaimRequirement);
        RequireEqual(
            "independent baseline matcher",
            MatcherV2AlgorithmVersion,
            document.IndependentBaseline.MatcherAlgorithmVersion);
        RequireEqual(
            "independent baseline interpretation",
            IndependentInterpretation,
            document.IndependentBaseline.Interpretation);
        ValidateBindings(
            document.IndependentBaseline.Artifacts,
            [MatcherV2ReportRelativePath],
            checksums,
            "matcher-v2 baseline");

        if (document.Corrections.Length != 2)
        {
            throw new InvalidDataException(
                "The interpretation erratum must contain exactly two corrections.");
        }

        ValidateCorrection(
            document.Corrections[0],
            MatcherV3AlgorithmVersion,
            [
                "frozen-independent-holdout-evaluation",
                "sarif-regress-independent-holdout",
            ],
            [MatcherV3MetadataRelativePath, MatcherV3ReportRelativePath],
            checksums);
        ValidateCorrection(
            document.Corrections[1],
            MatcherV31AlgorithmVersion,
            ["sarif-regress-independent-holdout"],
            [MatcherV31ReportRelativePath],
            checksums);

        RequireEqual(
            "current matcher version",
            MatcherV32AlgorithmVersion,
            document.CurrentReportBinding.MatcherAlgorithmVersion);
        var currentReportSnapshot = new HoldoutInterpretationErratumSnapshot(
            document.CurrentReportBinding.MatcherAlgorithmVersion,
            document.CurrentReportBinding.Status,
            document.CurrentReportBinding.Artifact?.Sha256);
        if (currentReportSnapshot.IsCurrentReportUnbound)
        {
            if (document.CurrentReportBinding.Artifact is not null)
            {
                throw new InvalidDataException(
                    "An unbound matcher-v3.2 report must not identify report bytes.");
            }
        }
        else if (string.Equals(
                     document.CurrentReportBinding.Status,
                     HoldoutInterpretationErratumSnapshot.BoundStatus,
                     StringComparison.Ordinal)
                 && document.CurrentReportBinding.Artifact is not null)
        {
            ValidateBindings(
                [document.CurrentReportBinding.Artifact],
                [MatcherV32ReportRelativePath],
                checksums,
                MatcherV32AlgorithmVersion);
        }
        else
        {
            throw new InvalidDataException(
                "The matcher-v3.2 report binding is neither pending nor complete.");
        }

        if (document.Integrity.HistoricalArtifactsRewritten
            || document.Integrity.HoldoutLabelsChanged
            || document.Integrity.QualityThresholdsChanged)
        {
            throw new InvalidDataException(
                "An interpretation erratum may not claim a historical evidence mutation.");
        }
    }

    private static void ValidateCorrection(
        CorrectionDocument correction,
        string matcherAlgorithmVersion,
        IReadOnlyList<string> expectedLegacyClaims,
        IReadOnlyList<string> expectedArtifactPaths,
        IReadOnlyDictionary<string, string> checksums)
    {
        RequireEqual(
            "corrected matcher version",
            matcherAlgorithmVersion,
            correction.MatcherAlgorithmVersion);
        if (!correction.LegacyClaims.SequenceEqual(
                expectedLegacyClaims,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                $"The {matcherAlgorithmVersion} correction does not name the exact legacy claims.");
        }

        RequireEqual(
            "corrected interpretation",
            CorrectedInterpretation,
            correction.CorrectedInterpretation);
        RequireEqual("correction reason", CorrectionReason, correction.ReasonCode);
        if (correction.MetricsChanged)
        {
            throw new InvalidDataException(
                "The interpretation correction must not rewrite historical metrics.");
        }

        ValidateBindings(
            correction.Artifacts,
            expectedArtifactPaths,
            checksums,
            matcherAlgorithmVersion);
    }

    private static void ValidateBindings(
        IReadOnlyList<ArtifactBindingDocument> bindings,
        IReadOnlyList<string> expectedPaths,
        IReadOnlyDictionary<string, string> checksums,
        string scope)
    {
        if (bindings.Count != expectedPaths.Count)
        {
            throw new InvalidDataException(
                $"The {scope} interpretation has an unexpected artifact count.");
        }

        for (int index = 0; index < expectedPaths.Count; index++)
        {
            ArtifactBindingDocument binding = bindings[index];
            string expectedPath = expectedPaths[index];
            RequireEqual($"{scope} artifact path", expectedPath, binding.Path);
            if (!checksums.TryGetValue(expectedPath, out string? checksummedSha256)
                || !string.Equals(
                    binding.Sha256,
                    checksummedSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The {scope} artifact '{expectedPath}' is not bound to its checksum manifest entry.");
            }
        }
    }

    private long GetMaximumBytes(string relativePath)
    {
        if (string.Equals(relativePath, SchemaRelativePath, StringComparison.Ordinal))
        {
            return limits.MaximumSchemaBytes;
        }

        return relativePath.EndsWith("sarif-regress-holdout.json", StringComparison.Ordinal)
            ? limits.MaximumSarifBytes
            : limits.MaximumManifestBytes;
    }

    private static byte[] Read(
        string repositoryRoot,
        string relativePath,
        long maximumBytes) =>
        BoundedJsonFile.ReadBytes(
            StablePath.Resolve(repositoryRoot, relativePath),
            maximumBytes,
            repositoryRoot);

    private static void RequireEqual(
        string name,
        string expected,
        string observed)
    {
        if (!string.Equals(expected, observed, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Interpretation erratum {name} '{observed}' does not equal '{expected}'.");
        }
    }

    private sealed class ErratumDocument
    {
        public required string SchemaVersion { get; init; }
        public required string Kind { get; init; }
        public required InterpretationPolicyDocument InterpretationPolicy { get; init; }
        public required IndependentBaselineDocument IndependentBaseline { get; init; }
        public required CorrectionDocument[] Corrections { get; init; }
        public required CurrentReportBindingDocument CurrentReportBinding { get; init; }
        public required IntegrityDocument Integrity { get; init; }
    }

    private sealed class InterpretationPolicyDocument
    {
        public required string IndependentClaimScope { get; init; }
        public required string FutureIndependentClaimRequirement { get; init; }
    }

    private sealed class IndependentBaselineDocument
    {
        public required string MatcherAlgorithmVersion { get; init; }
        public required string Interpretation { get; init; }
        public required ArtifactBindingDocument[] Artifacts { get; init; }
    }

    private sealed class CorrectionDocument
    {
        public required string MatcherAlgorithmVersion { get; init; }
        public required string[] LegacyClaims { get; init; }
        public required string CorrectedInterpretation { get; init; }
        public required string ReasonCode { get; init; }
        public required bool MetricsChanged { get; init; }
        public required ArtifactBindingDocument[] Artifacts { get; init; }
    }

    private sealed class ArtifactBindingDocument
    {
        public required string Path { get; init; }
        public required string Sha256 { get; init; }
    }

    private sealed class CurrentReportBindingDocument
    {
        public required string MatcherAlgorithmVersion { get; init; }
        public required string Status { get; init; }
        public ArtifactBindingDocument? Artifact { get; init; }
    }

    private sealed class IntegrityDocument
    {
        public required bool HistoricalArtifactsRewritten { get; init; }
        public required bool HoldoutLabelsChanged { get; init; }
        public required bool QualityThresholdsChanged { get; init; }
    }
}
