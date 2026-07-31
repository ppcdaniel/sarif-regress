using System.Collections.Immutable;
using System.Security.Cryptography;

namespace SarifRegress.Validation;

/// <summary>Coordinates structure checks, both evaluators, stable reports, and exact snapshots.</summary>
public sealed class ValidationApplication
{
    public const string SarifRegressReportFileName = "sarif-regress-holdout.json";
    public const string MultitoolReportFileName = "sarif-multitool-baseline.json";
    public const string ComparisonSummaryFileName = "comparison-summary.json";
    public const string ChecksumManifestFileName = "checksums.sha256";

    private const string ManifestRelativePath = "validation/holdout/manifest.json";
    private const string MetadataRelativePath =
        "validation/holdout/evaluation-metadata.json";
    private const string ExpectedRelativeRoot = "validation/expected";

    private readonly HoldoutManifestReader manifestReader;
    private readonly EvaluationMetadataReader metadataReader;
    private readonly FrozenSourceVerifier sourceVerifier;
    private readonly SarifRegressHoldoutEvaluator sarifRegressEvaluator;
    private readonly SarifMultitoolEvaluator multitoolEvaluator;
    private readonly JsonSchemaValidator schemaValidator;
    private readonly ValidationLimits limits;

    /// <summary>Creates an application with production adapters or focused test doubles.</summary>
    public ValidationApplication(
        HoldoutManifestReader? manifestReader = null,
        EvaluationMetadataReader? metadataReader = null,
        FrozenSourceVerifier? sourceVerifier = null,
        SarifRegressHoldoutEvaluator? sarifRegressEvaluator = null,
        SarifMultitoolEvaluator? multitoolEvaluator = null,
        ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
        this.manifestReader = manifestReader ?? new HoldoutManifestReader(this.limits);
        this.metadataReader = metadataReader ?? new EvaluationMetadataReader(this.limits);
        this.sourceVerifier = sourceVerifier ?? new FrozenSourceVerifier(limits: this.limits);
        this.sarifRegressEvaluator = sarifRegressEvaluator
            ?? new SarifRegressHoldoutEvaluator();
        this.multitoolEvaluator = multitoolEvaluator
            ?? new SarifMultitoolEvaluator();
        schemaValidator = new JsonSchemaValidator(this.limits);
    }

    /// <summary>Runs one strict command and returns a stable process exit code.</summary>
    public async ValueTask<int> RunAsync(
        ValidationOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        string repositoryRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(options.RepositoryRoot));
        string outputRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(options.OutputRoot));
        if (!Directory.Exists(repositoryRoot))
        {
            throw new DirectoryNotFoundException(
                "The repository root does not exist.");
        }

        EnsureOutputRoot(outputRoot);
        ValidatedHoldout holdout = manifestReader.Read(repositoryRoot);
        EvaluationMetadata metadata = metadataReader.Read(
            repositoryRoot,
            holdout.ManifestSha256);
        await sourceVerifier.VerifyAsync(
                repositoryRoot,
                metadata.Identity.RepositoryCommitSha,
                metadata.Identity.SourceTreeSha256,
                cancellationToken)
            .ConfigureAwait(false);
        if (options.Command == ValidationCommand.ValidateStructure)
        {
            return ValidationExitCodes.Success;
        }

        SarifRegressHoldoutReport sarifRegress =
            await sarifRegressEvaluator.EvaluateAsync(
                    repositoryRoot,
                    holdout,
                    metadata.Identity,
                    cancellationToken)
                .ConfigureAwait(false);
        SarifMultitoolBaselineReport multitool =
            await multitoolEvaluator.EvaluateAsync(
                    repositoryRoot,
                    outputRoot,
                    options.MultitoolPath!,
                    options.MultitoolVersion!,
                    holdout,
                    metadata.Identity,
                    cancellationToken)
                .ConfigureAwait(false);
        byte[] sarifRegressBytes = StableReportSerializer.Serialize(sarifRegress);
        byte[] multitoolBytes = StableReportSerializer.Serialize(multitool);
        bool externalReproducibilityFailed = multitool.Cases.Any(item =>
            !item.InstrumentationStateMultisetPreserved
            || item.RelationshipResults.Any(relationship =>
                relationship.ComparabilityReason == "tool-error"));
        var hashes = new ComparisonReportHashes(
            holdout.ManifestSha256,
            BoundedJsonFile.ComputeSha256(
                EvaluationMetadataReader.GetMetadataPath(repositoryRoot),
                limits.MaximumManifestBytes,
                repositoryRoot),
            Sha256(sarifRegressBytes),
            Sha256(multitoolBytes));
        ComparisonSummaryReport comparison = ComparisonSummaryBuilder.Create(
            sarifRegress,
            multitool,
            hashes,
            options.CrossPlatformByteIdentity,
            evaluationCompleted: !externalReproducibilityFailed);
        byte[] comparisonBytes = StableReportSerializer.Serialize(comparison);

        var normalizedBuilder = ImmutableSortedDictionary.CreateBuilder<string, byte[]>(
            StringComparer.Ordinal);
        normalizedBuilder.Add(SarifRegressReportFileName, sarifRegressBytes);
        normalizedBuilder.Add(MultitoolReportFileName, multitoolBytes);
        normalizedBuilder.Add(ComparisonSummaryFileName, comparisonBytes);
        ImmutableSortedDictionary<string, byte[]> normalized =
            normalizedBuilder.ToImmutable();
        foreach ((string _, byte[] bytes) in normalized)
        {
            AmbientDataGuard.Validate(bytes, repositoryRoot);
        }

        WriteAndValidateReports(repositoryRoot, outputRoot, normalized);
        byte[] checksums = CreateChecksumManifest(
            repositoryRoot,
            normalized);
        VerifyChecksumEntries(repositoryRoot, normalized, checksums);
        AmbientDataGuard.Validate(checksums, repositoryRoot);
        string checksumPath = Path.Combine(
            outputRoot,
            ChecksumManifestFileName);
        StableJson.WriteFile(checksumPath, checksums);
        ImmutableSortedDictionary<string, byte[]> allOutputs = normalized
            .Add(ChecksumManifestFileName, checksums);

        if (options.CompareExpected)
        {
            ExpectedOutputVerifier.Verify(options.ExpectedRoot!, allOutputs);
        }

        bool ingestionOrStructureFailed = sarifRegress.Aggregate.IngestionFailures > 0
            || sarifRegress.Aggregate.StructuralFailures > 0;
        return ingestionOrStructureFailed
            || externalReproducibilityFailed
            || !options.CrossPlatformByteIdentity
                ? ValidationExitCodes.ValidationFailure
                : ValidationExitCodes.Success;
    }

    private void WriteAndValidateReports(
        string repositoryRoot,
        string outputRoot,
        IEnumerable<KeyValuePair<string, byte[]>> reports)
    {
        Dictionary<string, string> schemas = new(StringComparer.Ordinal)
        {
            [SarifRegressReportFileName] =
                "validation/schemas/sarif-regress-holdout-report.schema.json",
            [MultitoolReportFileName] =
                "validation/schemas/sarif-multitool-baseline-report.schema.json",
            [ComparisonSummaryFileName] =
                "validation/schemas/comparison-summary.schema.json",
        };
        foreach ((string name, byte[] bytes) in reports.OrderBy(
                     item => item.Key,
                     StringComparer.Ordinal))
        {
            string outputPath = Path.Combine(outputRoot, name);
            StableJson.WriteFile(outputPath, bytes);
            schemaValidator.ValidateFile(
                StablePath.Resolve(repositoryRoot, schemas[name]),
                outputPath,
                limits.MaximumSarifBytes,
                repositoryRoot,
                outputRoot);
        }
    }

    private byte[] CreateChecksumManifest(
        string repositoryRoot,
        IReadOnlyDictionary<string, byte[]> reports)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ManifestRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(repositoryRoot, ManifestRelativePath),
                limits.MaximumManifestBytes,
                repositoryRoot),
            [MetadataRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(repositoryRoot, MetadataRelativePath),
                limits.MaximumManifestBytes,
                repositoryRoot),
        };
        foreach ((string name, byte[] bytes) in reports)
        {
            files.Add($"{ExpectedRelativeRoot}/{name}", bytes);
        }

        return ChecksumManifest.Create(files);
    }

    private void VerifyChecksumEntries(
        string repositoryRoot,
        IReadOnlyDictionary<string, byte[]> reports,
        ReadOnlySpan<byte> checksumBytes)
    {
        ImmutableSortedDictionary<string, string> entries =
            ChecksumManifest.Parse(checksumBytes);
        var expected = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ManifestRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(repositoryRoot, ManifestRelativePath),
                limits.MaximumManifestBytes,
                repositoryRoot),
            [MetadataRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(repositoryRoot, MetadataRelativePath),
                limits.MaximumManifestBytes,
                repositoryRoot),
        };
        foreach ((string name, byte[] bytes) in reports)
        {
            expected.Add($"{ExpectedRelativeRoot}/{name}", bytes);
        }

        if (!entries.Keys.SequenceEqual(
            expected.Keys.Order(StringComparer.Ordinal),
            StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The generated checksum manifest does not cover the exact deterministic input/output set.");
        }

        foreach ((string name, byte[] bytes) in expected)
        {
            if (!string.Equals(entries[name], Sha256(bytes), StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The generated checksum for '{name}' is incorrect.");
            }
        }
    }

    internal static void EnsureOutputRoot(string outputRoot)
    {
        if (!Directory.Exists(outputRoot))
        {
            throw new DirectoryNotFoundException(
                "The validation output root must be a pre-created empty directory.");
        }

        FileAttributes attributes = File.GetAttributes(outputRoot);
        if ((attributes & FileAttributes.Directory) == 0
            || (attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "The validation output root must be a regular non-reparse directory.");
        }

        // Callers provide a fresh private mktemp/GUID directory. Validation is its only
        // writer after this boundary; concurrent mutation by another same-user process
        // is outside the local-runner threat model.
        if (Directory.EnumerateFileSystemEntries(outputRoot).Any())
        {
            throw new InvalidDataException(
                "The validation output root must be empty at startup.");
        }
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
