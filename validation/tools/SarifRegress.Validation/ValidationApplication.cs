using System.Collections.Immutable;
using System.Security.Cryptography;

namespace SarifRegress.Validation;

/// <summary>Coordinates structure checks, both evaluators, stable reports, and exact snapshots.</summary>
public sealed class ValidationApplication
{
    public const string SarifRegressReportFileName = "sarif-regress-holdout.json";
    public const string MultitoolReportFileName = "sarif-multitool-baseline.json";
    public const string ComparisonSummaryFileName = "comparison-summary.json";
    public const string V2ToV3DeltaReportFileName = "v2-to-v3-delta.json";
    public const string ChecksumManifestFileName = "checksums.sha256";

    private const string ManifestRelativePath = "validation/holdout/manifest.json";
    private const string MetadataRelativePath =
        "validation/holdout/evaluation-metadata.json";
    private const string ExpectedRelativeRoot = "validation/expected";
    private const string MatcherV2HistoryChecksumRelativePath =
        "validation/history/matcher-v2/checksums.sha256";
    private const string MatcherV2HistoryReportRelativePath =
        "validation/history/matcher-v2/sarif-regress-holdout.json";

    private readonly HoldoutManifestReader manifestReader;
    private readonly EvaluationMetadataReader metadataReader;
    private readonly CrossPlatformAttestationReader attestationReader;
    private readonly MatcherV2HistoryReader matcherV2HistoryReader;
    private readonly FrozenSourceVerifier sourceVerifier;
    private readonly SarifRegressHoldoutEvaluator sarifRegressEvaluator;
    private readonly SarifMultitoolEvaluator multitoolEvaluator;
    private readonly JsonSchemaValidator schemaValidator;
    private readonly ValidationLimits limits;

    /// <summary>Creates an application with production adapters or focused test doubles.</summary>
    public ValidationApplication(
        HoldoutManifestReader? manifestReader = null,
        EvaluationMetadataReader? metadataReader = null,
        CrossPlatformAttestationReader? attestationReader = null,
        MatcherV2HistoryReader? matcherV2HistoryReader = null,
        FrozenSourceVerifier? sourceVerifier = null,
        SarifRegressHoldoutEvaluator? sarifRegressEvaluator = null,
        SarifMultitoolEvaluator? multitoolEvaluator = null,
        ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
        this.manifestReader = manifestReader ?? new HoldoutManifestReader(this.limits);
        this.metadataReader = metadataReader ?? new EvaluationMetadataReader(this.limits);
        this.attestationReader = attestationReader
            ?? new CrossPlatformAttestationReader(this.limits);
        this.matcherV2HistoryReader = matcherV2HistoryReader
            ?? new MatcherV2HistoryReader(this.limits);
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
        MatcherV2HistorySnapshot matcherV2 = matcherV2HistoryReader.Read(
            repositoryRoot);
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
        string sarifRegressSha256 = Sha256(sarifRegressBytes);
        var deltaInputHashes = new MatcherDeltaInputHashes(
            matcherV2.HistoryChecksumManifestSha256,
            matcherV2.ReportSha256,
            sarifRegressSha256,
            holdout.ManifestSha256);
        MatcherV2ToV3DeltaReport delta = MatcherV2ToV3DeltaBuilder.Create(
            matcherV2,
            sarifRegress,
            deltaInputHashes,
            limits);
        byte[] deltaBytes = StableReportSerializer.Serialize(delta);
        bool externalReproducibilityFailed = multitool.Cases.Any(item =>
            !item.InstrumentationStateMultisetPreserved
            || item.RelationshipResults.Any(relationship =>
                relationship.ComparabilityReason == "tool-error"));
        string metadataSha256 = BoundedJsonFile.ComputeSha256(
            EvaluationMetadataReader.GetMetadataPath(repositoryRoot),
            limits.MaximumManifestBytes,
            repositoryRoot);
        var hashes = new ComparisonReportHashes(
            holdout.ManifestSha256,
            metadataSha256,
            sarifRegressSha256,
            Sha256(multitoolBytes),
            matcherV2.ReportSha256,
            Sha256(deltaBytes));
        ValidatedCrossPlatformAttestation? attestation =
            options.CrossPlatformAttestationPath is null
                ? null
                : attestationReader.Read(
                    repositoryRoot,
                    options.CrossPlatformAttestationPath,
                    new CrossPlatformAttestationExpectation(
                        metadata.Identity.RepositoryCommitSha,
                        holdout.ManifestSha256,
                        metadataSha256,
                        hashes.SarifRegressReportSha256,
                        hashes.SarifMultitoolBaselineReportSha256,
                        hashes.V2ToV3DeltaReportSha256));
        ComparisonSummaryReport comparison = ComparisonSummaryBuilder.Create(
            sarifRegress,
            multitool,
            hashes,
            attestation is not null,
            evaluationCompleted: !externalReproducibilityFailed,
            changedDecisionExplanations: new ChangedDecisionExplanationCoverage(
                delta.ChangedDecisionCount,
                delta.ChangedDecisionTraceCount));
        byte[] comparisonBytes = StableReportSerializer.Serialize(comparison);

        var normalizedBuilder = ImmutableSortedDictionary.CreateBuilder<string, byte[]>(
            StringComparer.Ordinal);
        normalizedBuilder.Add(SarifRegressReportFileName, sarifRegressBytes);
        normalizedBuilder.Add(MultitoolReportFileName, multitoolBytes);
        normalizedBuilder.Add(V2ToV3DeltaReportFileName, deltaBytes);
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
            normalized,
            attestation);
        VerifyChecksumEntries(
            repositoryRoot,
            normalized,
            attestation,
            checksums);
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

        return DetermineEvaluationExitCode(
            sarifRegress,
            externalReproducibilityFailed,
            attestation is not null,
            delta.EveryChangedDecisionHasTrace);
    }

    /// <summary>
    /// Treats reproduced engine defects as evidence while retaining infrastructure gates.
    /// </summary>
    internal static int DetermineEvaluationExitCode(
        SarifRegressHoldoutReport sarifRegress,
        bool externalReproducibilityFailed,
        bool crossPlatformByteIdentity,
        bool everyChangedDecisionHasTrace = true)
    {
        ArgumentNullException.ThrowIfNull(sarifRegress);
        return sarifRegress.Aggregate.StructuralFailures > 0
            || externalReproducibilityFailed
            || !crossPlatformByteIdentity
            || !everyChangedDecisionHasTrace
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
            [V2ToV3DeltaReportFileName] =
                "validation/schemas/v2-to-v3-delta.schema.json",
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
        IReadOnlyDictionary<string, byte[]> reports,
        ValidatedCrossPlatformAttestation? attestation)
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
            [MatcherV2HistoryChecksumRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(
                    repositoryRoot,
                    MatcherV2HistoryChecksumRelativePath),
                limits.MaximumManifestBytes,
                repositoryRoot),
            [MatcherV2HistoryReportRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(repositoryRoot, MatcherV2HistoryReportRelativePath),
                limits.MaximumSarifBytes,
                repositoryRoot),
        };
        foreach ((string name, byte[] bytes) in reports)
        {
            files.Add($"{ExpectedRelativeRoot}/{name}", bytes);
        }
        if (attestation is not null)
        {
            files.Add(
                CrossPlatformAttestationReader.RelativePath,
                attestation.ExactBytes);
        }

        return ChecksumManifest.Create(files);
    }

    private void VerifyChecksumEntries(
        string repositoryRoot,
        IReadOnlyDictionary<string, byte[]> reports,
        ValidatedCrossPlatformAttestation? attestation,
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
            [MatcherV2HistoryChecksumRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(
                    repositoryRoot,
                    MatcherV2HistoryChecksumRelativePath),
                limits.MaximumManifestBytes,
                repositoryRoot),
            [MatcherV2HistoryReportRelativePath] = BoundedJsonFile.ReadBytes(
                StablePath.Resolve(repositoryRoot, MatcherV2HistoryReportRelativePath),
                limits.MaximumSarifBytes,
                repositoryRoot),
        };
        foreach ((string name, byte[] bytes) in reports)
        {
            expected.Add($"{ExpectedRelativeRoot}/{name}", bytes);
        }
        if (attestation is not null)
        {
            expected.Add(
                CrossPlatformAttestationReader.RelativePath,
                attestation.ExactBytes);
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
