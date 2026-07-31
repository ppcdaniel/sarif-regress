using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SarifRegress.Core;
using SarifRegress.Core.Configuration;
using SarifRegress.Report;

namespace SarifRegress.Validation;

/// <summary>Names one algorithm frozen into the evaluated product build.</summary>
public sealed record NamedAlgorithmVersion(string Name, string Version);

/// <summary>Defines the stable product identity copied into normalized reports.</summary>
public sealed record EvaluationIdentity(
    string RepositoryCommitSha,
    string SourceTreeSha256,
    string SarifRegressToolVersion,
    string MatcherAlgorithmVersion,
    ImmutableArray<NamedAlgorithmVersion> FingerprintAlgorithmVersions,
    string OutputSchemaVersion,
    string ConfigurationSchemaVersion,
    string HoldoutManifestSha256);

/// <summary>Represents the complete committed pre-evaluation metadata document.</summary>
public sealed record EvaluationMetadata(
    string SchemaVersion,
    EvaluationIdentity Identity,
    string OperatingSystem,
    string Architecture,
    string DotnetSdkVersion);

/// <summary>
/// Validates and reads the committed metadata that freezes the product under evaluation.
/// </summary>
public sealed class EvaluationMetadataReader
{
    private const string MetadataRelativePath =
        "validation/holdout/evaluation-metadata.json";
    private const string SchemaRelativePath =
        "validation/schemas/evaluation-metadata.schema.json";

    private static readonly ImmutableHashSet<NamedAlgorithmVersion>
        ExpectedFingerprintAlgorithms =
        ImmutableHashSet.Create(
            new NamedAlgorithmVersion(
                "derived-fingerprint",
                "rule-path-context/v2"),
            new NamedAlgorithmVersion(
                "embedded-snippet",
                "embedded-snippet/v1"),
            new NamedAlgorithmVersion(
                "producer-fingerprint-common",
                "sarifregress/producer-fingerprint-common-version/v1"),
            new NamedAlgorithmVersion(
                "derived-fingerprint-compare",
                "sarifregress/derived-fingerprint-compare/v1"));

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly ValidationLimits limits;
    private readonly JsonSchemaValidator schemaValidator;

    /// <summary>Creates a bounded metadata reader.</summary>
    public EvaluationMetadataReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
        schemaValidator = new JsonSchemaValidator(this.limits);
    }

    /// <summary>Reads metadata and verifies all public product/version invariants.</summary>
    public EvaluationMetadata Read(
        string repositoryRoot,
        string actualManifestSha256)
    {
        string metadataPath = StablePath.Resolve(
            repositoryRoot,
            MetadataRelativePath);
        string schemaPath = StablePath.Resolve(repositoryRoot, SchemaRelativePath);
        JsonNode node = schemaValidator.ValidateFile(
            schemaPath,
            metadataPath,
            limits.MaximumManifestBytes,
            repositoryRoot,
            repositoryRoot);
        MetadataDocument document = node.Deserialize<MetadataDocument>(
                SerializerOptions)
            ?? throw new InvalidDataException("The evaluation metadata is empty.");
        ValidateDocument(document, actualManifestSha256);
        return new EvaluationMetadata(
            document.SchemaVersion,
            new EvaluationIdentity(
                document.RepositoryCommitSha,
                document.SourceTreeSha256,
                document.SarifRegressToolVersion,
                document.MatcherAlgorithmVersion,
                document.FingerprintAlgorithmVersions
                    .Select(item => new NamedAlgorithmVersion(
                        item.Name,
                        item.Version))
                    .OrderBy(item => item.Name, StringComparer.Ordinal)
                    .ThenBy(item => item.Version, StringComparer.Ordinal)
                    .ToImmutableArray(),
                document.OutputSchemaVersion,
                document.ConfigurationSchemaVersion,
                document.HoldoutManifestSha256),
            document.Environment.OperatingSystem,
            document.Environment.Architecture,
            document.Environment.DotnetSdkVersion);
    }

    /// <summary>Gets the exact committed metadata path for checksum construction.</summary>
    public static string GetMetadataPath(string repositoryRoot) =>
        StablePath.Resolve(repositoryRoot, MetadataRelativePath);

    private static void ValidateDocument(
        MetadataDocument document,
        string actualManifestSha256)
    {
        if (!string.Equals(
            document.HoldoutManifestSha256,
            actualManifestSha256,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Evaluation metadata does not identify the exact holdout manifest bytes.");
        }

        RequireEqual(
            "SarifRegress tool version",
            ProductInformation.Version,
            document.SarifRegressToolVersion);
        RequireEqual(
            "matcher algorithm version",
            ProductInformation.MatcherAlgorithmVersion,
            document.MatcherAlgorithmVersion);
        RequireEqual(
            "output schema version",
            ReportContractVersions.OutputSchema,
            document.OutputSchemaVersion);
        RequireEqual(
            "configuration schema version",
            SarifRegressConfiguration.SupportedSchemaVersion,
            document.ConfigurationSchemaVersion);
        NamedAlgorithmVersion[] observedAlgorithms =
            document.FingerprintAlgorithmVersions
            .Select(item => new NamedAlgorithmVersion(item.Name, item.Version))
            .ToArray();
        if (observedAlgorithms.Length != ExpectedFingerprintAlgorithms.Count
            || !observedAlgorithms.ToHashSet()
                .SetEquals(ExpectedFingerprintAlgorithms))
        {
            throw new InvalidDataException(
                "Evaluation metadata does not contain the exact frozen fingerprint algorithm set.");
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
                $"Evaluation metadata {name} '{observed}' does not equal product value '{expected}'.");
        }
    }

    private sealed class MetadataDocument
    {
        public required string SchemaVersion { get; init; }
        public required string RepositoryCommitSha { get; init; }
        public required string SourceTreeSha256 { get; init; }
        public required string SarifRegressToolVersion { get; init; }
        public required string MatcherAlgorithmVersion { get; init; }
        public required NamedAlgorithmDocument[] FingerprintAlgorithmVersions { get; init; }
        public required string OutputSchemaVersion { get; init; }
        public required string ConfigurationSchemaVersion { get; init; }
        public required string HoldoutManifestSha256 { get; init; }
        public required EnvironmentDocument Environment { get; init; }
    }

    private sealed class NamedAlgorithmDocument
    {
        public required string Name { get; init; }
        public required string Version { get; init; }
    }

    private sealed class EnvironmentDocument
    {
        public required string OperatingSystem { get; init; }
        public required string Architecture { get; init; }
        public required string DotnetSdkVersion { get; init; }
    }
}

/// <summary>Fails validation when product source differs from the frozen commit.</summary>
public sealed class FrozenSourceVerifier
{
    private readonly BoundedProcessRunner processRunner;
    private readonly ValidationLimits limits;
    private readonly GitSourceTreeHasher sourceTreeHasher;

    /// <summary>Creates a verifier with injectable process execution for tests.</summary>
    public FrozenSourceVerifier(
        BoundedProcessRunner? processRunner = null,
        ValidationLimits? limits = null)
    {
        this.processRunner = processRunner ?? new BoundedProcessRunner();
        this.limits = limits ?? ValidationLimits.Default;
        sourceTreeHasher = new GitSourceTreeHasher(this.processRunner, this.limits);
    }

    /// <summary>Runs an exact quiet Git diff over <c>src/</c> only.</summary>
    public async ValueTask VerifyAsync(
        string repositoryRoot,
        string frozenCommitSha,
        string expectedSourceTreeSha256,
        CancellationToken cancellationToken = default)
    {
        var invocation = new ProcessInvocation(
            "git",
            [
                "-C",
                repositoryRoot,
                "diff",
                "--quiet",
                frozenCommitSha,
                "--",
                "src",
            ],
            repositoryRoot,
            limits.ProcessTimeout,
            limits.MaximumProcessOutputCharacters);
        ProcessExecutionResult result = await processRunner.RunAsync(
                invocation,
                cancellationToken)
            .ConfigureAwait(false);
        if (result.ExitCode == 0)
        {
            await VerifyCleanStatusAsync(repositoryRoot, cancellationToken)
                .ConfigureAwait(false);
            SourceTreeHashResult hashes = await sourceTreeHasher.ComputeAsync(
                    repositoryRoot,
                    frozenCommitSha,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    hashes.FrozenCommitSha256,
                    expectedSourceTreeSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    hashes.CurrentIndexSha256,
                    expectedSourceTreeSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Tracked product-source blobs do not match the frozen source-tree hash.");
            }

            return;
        }

        if (result.ExitCode == 1)
        {
            throw new InvalidDataException(
                "Product source under src/ differs from the frozen evaluation commit.");
        }

        throw new InvalidDataException(
            "Git could not verify product source against the frozen evaluation commit.");
    }

    private async ValueTask VerifyCleanStatusAsync(
        string repositoryRoot,
        CancellationToken cancellationToken)
    {
        var invocation = new ProcessInvocation(
            "git",
            [
                "-C",
                repositoryRoot,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                "src",
            ],
            repositoryRoot,
            limits.ProcessTimeout,
            limits.MaximumProcessOutputCharacters);
        ProcessExecutionResult result = await processRunner.RunAsync(
                invocation,
                cancellationToken)
            .ConfigureAwait(false);
        if (result.ExitCode != 0 || result.StandardOutput.Length != 0)
        {
            throw new InvalidDataException(
                "Product source contains tracked or untracked working-tree changes.");
        }
    }
}
