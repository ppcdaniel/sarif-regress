using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SarifRegress.Validation;

/// <summary>Names the immutable inputs whose hosted byte identity was attested.</summary>
public sealed record CrossPlatformAttestationExpectation(
    string RepositoryCommitSha,
    string HoldoutManifestSha256,
    string EvaluationMetadataSha256,
    string SarifRegressReportSha256,
    string SarifMultitoolBaselineReportSha256,
    string V3ToV31DeltaReportSha256);

/// <summary>Retains exact validated attestation bytes for checksum construction.</summary>
public sealed record ValidatedCrossPlatformAttestation(
    byte[] ExactBytes,
    string Sha256);

/// <summary>Reads one fixed, committed GitHub Actions cross-platform attestation.</summary>
public sealed class CrossPlatformAttestationReader
{
    public const string RelativePath =
        "validation/holdout/cross-platform-attestation.json";

    private const string SchemaRelativePath =
        "validation/schemas/cross-platform-attestation.schema.json";
    private const string RepositoryName = "ppcdaniel/sarif-regress";
    private const string WorkflowPath = ".github/workflows/holdout-validation.yml";
    private const string CoordinatorJobName =
        "Compare Linux and Windows normalized bytes";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly ValidationLimits limits;
    private readonly JsonSchemaValidator schemaValidator;

    /// <summary>Creates a bounded attestation reader.</summary>
    public CrossPlatformAttestationReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
        schemaValidator = new JsonSchemaValidator(this.limits);
    }

    /// <summary>
    /// Validates exact bytes, hosted evidence structure, and all frozen input hashes.
    /// </summary>
    public ValidatedCrossPlatformAttestation Read(
        string repositoryRoot,
        string attestationPath,
        CrossPlatformAttestationExpectation expected)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(attestationPath);
        ArgumentNullException.ThrowIfNull(expected);
        string root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(repositoryRoot));
        string fixedPath = StablePath.Resolve(root, RelativePath);
        string suppliedPath = Path.GetFullPath(attestationPath);
        if (!string.Equals(
            fixedPath,
            suppliedPath,
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Cross-platform attestation must be the committed '{RelativePath}' file.");
        }

        byte[] bytes = BoundedJsonFile.ReadBytes(
            fixedPath,
            limits.MaximumManifestBytes,
            root);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            bytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        JsonNode node = JsonNode.Parse(
                bytes,
                nodeOptions: null,
                documentOptions: new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = limits.MaximumJsonDepth,
                })
            ?? throw new InvalidDataException(
                "The cross-platform attestation contains only null.");
        BoundedJsonFile.EnsureStringBounds(node, limits.MaximumStringCharacters);
        _ = schemaValidator.ValidateNode(
            StablePath.Resolve(root, SchemaRelativePath),
            node,
            Path.GetFileName(fixedPath),
            root);
        AttestationDocument document = node.Deserialize<AttestationDocument>(
                SerializerOptions)
            ?? throw new InvalidDataException(
                "The cross-platform attestation is empty.");
        Validate(document, expected);
        AmbientDataGuard.Validate(bytes, root);
        return new ValidatedCrossPlatformAttestation(
            bytes,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
    }

    /// <summary>Gets the fixed committed path for command-line construction.</summary>
    public static string GetPath(string repositoryRoot) =>
        StablePath.Resolve(repositoryRoot, RelativePath);

    private static void Validate(
        AttestationDocument document,
        CrossPlatformAttestationExpectation expected)
    {
        RequireEqual("schema version", "3", document.SchemaVersion);
        RequireEqual("repository", RepositoryName, document.Repository);
        RequireEqual(
            "frozen repository commit",
            expected.RepositoryCommitSha,
            document.RepositoryCommitSha);
        RequireEqual(
            "holdout manifest SHA-256",
            expected.HoldoutManifestSha256,
            document.HoldoutManifestSha256);
        RequireEqual(
            "evaluation metadata SHA-256",
            expected.EvaluationMetadataSha256,
            document.EvaluationMetadataSha256);
        ValidateReportDigests(document.BaseReports, expected, "base report");

        RequireEqual(
            "workflow path",
            WorkflowPath,
            document.GithubActions.WorkflowPath);
        RequireEqual(
            "workflow conclusion",
            "success",
            document.GithubActions.Conclusion);
        RequireEqual(
            "coordinator job name",
            CoordinatorJobName,
            document.GithubActions.CoordinatorJobName);
        string expectedRunUrl =
            $"https://github.com/{RepositoryName}/actions/runs/"
            + document.GithubActions.RunId.ToString(CultureInfo.InvariantCulture);
        RequireEqual(
            "GitHub Actions run URL",
            expectedRunUrl,
            document.GithubActions.RunUrl);
        RejectZeroDigest(
            "workflow head commit",
            document.GithubActions.WorkflowHeadSha);

        ValidateArtifact(
            document.Artifacts.Linux,
            "holdout-linux",
            expected,
            "Linux");
        ValidateArtifact(
            document.Artifacts.Windows,
            "holdout-windows",
            expected,
            "Windows");
        if (document.Artifacts.Linux.ArtifactId
            == document.Artifacts.Windows.ArtifactId)
        {
            throw new InvalidDataException(
                "Cross-platform attestation repeats one artifact ID for both platforms.");
        }

        if (!document.ByteIdentity.SarifRegressHoldout
            || !document.ByteIdentity.SarifMultitoolBaseline
            || !document.ByteIdentity.V3ToV31Delta)
        {
            throw new InvalidDataException(
                "Cross-platform attestation does not assert every independently generated report byte identity.");
        }
    }

    private static void ValidateArtifact(
        ArtifactDocument artifact,
        string expectedName,
        CrossPlatformAttestationExpectation expected,
        string platform)
    {
        RequireEqual($"{platform} artifact name", expectedName, artifact.Name);
        RejectZeroDigest($"{platform} artifact archive SHA-256", artifact.ArchiveSha256);
        ValidateReportDigests(artifact.ReportDigests, expected, platform);
    }

    private static void ValidateReportDigests(
        ReportDigestDocument digests,
        CrossPlatformAttestationExpectation expected,
        string context)
    {
        RequireEqual(
            $"{context} SarifRegress report SHA-256",
            expected.SarifRegressReportSha256,
            digests.SarifRegressHoldoutSha256);
        RequireEqual(
            $"{context} Multitool report SHA-256",
            expected.SarifMultitoolBaselineReportSha256,
            digests.SarifMultitoolBaselineSha256);
        RequireEqual(
            $"{context} matcher v3-to-v3.1 delta SHA-256",
            expected.V3ToV31DeltaReportSha256,
            digests.V3ToV31DeltaSha256);
    }

    private static void RejectZeroDigest(string name, string value)
    {
        if (value.All(character => character == '0'))
        {
            throw new InvalidDataException(
                $"Cross-platform attestation {name} cannot be all zeroes.");
        }
    }

    private static void RequireEqual(
        string name,
        string expected,
        string observed)
    {
        if (!string.Equals(expected, observed, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Cross-platform attestation {name} does not match the evaluated bytes.");
        }
    }

    private sealed class AttestationDocument
    {
        public required string SchemaVersion { get; init; }
        public required string Repository { get; init; }
        public required string RepositoryCommitSha { get; init; }
        public required string HoldoutManifestSha256 { get; init; }
        public required string EvaluationMetadataSha256 { get; init; }
        public required ReportDigestDocument BaseReports { get; init; }
        public required GithubActionsDocument GithubActions { get; init; }
        public required ArtifactsDocument Artifacts { get; init; }
        public required ByteIdentityDocument ByteIdentity { get; init; }
    }

    private sealed class ReportDigestDocument
    {
        public required string SarifRegressHoldoutSha256 { get; init; }
        public required string SarifMultitoolBaselineSha256 { get; init; }
        public required string V3ToV31DeltaSha256 { get; init; }
    }

    private sealed class GithubActionsDocument
    {
        public required string WorkflowPath { get; init; }
        public required long RunId { get; init; }
        public required int RunAttempt { get; init; }
        public required string RunUrl { get; init; }
        public required string WorkflowHeadSha { get; init; }
        public required string Conclusion { get; init; }
        public required string CoordinatorJobName { get; init; }
    }

    private sealed class ArtifactsDocument
    {
        public required ArtifactDocument Linux { get; init; }
        public required ArtifactDocument Windows { get; init; }
    }

    private sealed class ArtifactDocument
    {
        public required string Name { get; init; }
        public required long ArtifactId { get; init; }
        public required string ArchiveSha256 { get; init; }
        public required ReportDigestDocument ReportDigests { get; init; }
    }

    private sealed class ByteIdentityDocument
    {
        public required bool SarifRegressHoldout { get; init; }
        public required bool SarifMultitoolBaseline { get; init; }
        public required bool V3ToV31Delta { get; init; }
    }
}
