using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Security;

namespace SarifRegress.Validation;

/// <summary>Describes one exactly pinned real SARIF producer.</summary>
public sealed record HoldoutProducer(
    string Id,
    string Family,
    string DisplayName,
    string ExactVersion);

/// <summary>Defines repository paths for one producer-family case.</summary>
public sealed record HoldoutCasePaths(
    string Directory,
    string BaselineSarif,
    string CandidateSarif,
    string Labels,
    string Notes,
    string ProducerInputDirectory,
    string? Config);

/// <summary>Defines declared case counts that are checked against label contents.</summary>
public sealed record HoldoutCaseCounts(
    int BaselineFindings,
    int CandidateFindings,
    int GroundTruthUnits,
    int LabelledRelationships,
    int SameFindingRelationships,
    int NewFindings,
    int ResolvedFindings,
    int NewOrResolvedFindings,
    int AmbiguousOrNearCollisionRelationships);

/// <summary>Describes one case plan and its controlled mutation strata.</summary>
public sealed record HoldoutCasePlan(
    string Id,
    string ProducerId,
    HoldoutCasePaths Paths,
    ImmutableArray<string> Scenarios,
    HoldoutCaseCounts Counts);

/// <summary>Defines the separate, versioned holdout plan.</summary>
public sealed record HoldoutManifest(
    string SchemaVersion,
    string HoldoutId,
    ImmutableArray<HoldoutProducer> Producers,
    ImmutableArray<HoldoutCasePlan> Cases,
    HoldoutCaseCounts Counts);

/// <summary>Provides hashes and labels already checked for one case.</summary>
public sealed record ValidatedHoldoutCase(
    HoldoutCasePlan Plan,
    CorpusLabels Labels,
    CaseInputHashes InputHashes);

/// <summary>Provides all structure required by evaluation in ordinal case order.</summary>
public sealed record ValidatedHoldout(
    HoldoutManifest Manifest,
    string ManifestSha256,
    ImmutableArray<ValidatedHoldoutCase> Cases);

/// <summary>Identifies every committed input that can influence one case result.</summary>
public sealed record CaseInputHashes(
    string BaselineSarifSha256,
    string CandidateSarifSha256,
    string LabelsSha256,
    string NotesSha256,
    string ProducerInputTreeSha256,
    string? ConfigSha256);

/// <summary>
/// Validates manifest schema, provenance topology, counts, case coverage, and development-corpus separation.
/// </summary>
public sealed class HoldoutManifestReader
{
    private const string ManifestRelativePath = "validation/holdout/manifest.json";
    private const string ManifestSchemaRelativePath =
        "validation/schemas/holdout-manifest.schema.json";
    private const string LabelsSchemaRelativePath = "corpus/schema/labels.schema.json";
    private const string CasesRelativeRoot = "validation/holdout/cases";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly ValidationLimits limits;
    private readonly JsonSchemaValidator schemaValidator;

    /// <summary>Creates a reader with fixed untrusted-input bounds.</summary>
    public HoldoutManifestReader(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
        schemaValidator = new JsonSchemaValidator(this.limits);
    }

    /// <summary>
    /// Reads and semantically validates every declared manifest input.
    /// </summary>
    public ValidatedHoldout Read(string repositoryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        string root = Path.GetFullPath(repositoryRoot);
        string manifestPath = StablePath.Resolve(root, ManifestRelativePath);
        string schemaPath = StablePath.Resolve(root, ManifestSchemaRelativePath);
        JsonNode node = schemaValidator.ValidateFile(
            schemaPath,
            manifestPath,
            limits.MaximumManifestBytes,
            root,
            root);
        ManifestDocument document = node.Deserialize<ManifestDocument>(
                SerializerOptions)
            ?? throw new InvalidDataException("The holdout manifest is empty.");

        HoldoutManifest manifest = MapManifest(document);
        ValidateManifestSemantics(root, document, manifest);
        ImmutableArray<ValidatedHoldoutCase> cases = ReadCases(
            root,
            document,
            manifest);
        return new ValidatedHoldout(
            manifest,
            BoundedJsonFile.ComputeSha256(
                manifestPath,
                limits.MaximumManifestBytes,
                root),
            cases);
    }

    private ImmutableArray<ValidatedHoldoutCase> ReadCases(
        string repositoryRoot,
        ManifestDocument document,
        HoldoutManifest manifest)
    {
        string labelSchemaPath = StablePath.Resolve(
            repositoryRoot,
            LabelsSchemaRelativePath);
        Dictionary<string, CaseDocument> documents = document.Cases.ToDictionary(
            item => item.Id,
            StringComparer.Ordinal);
        var cases = ImmutableArray.CreateBuilder<ValidatedHoldoutCase>(
            manifest.Cases.Length);
        foreach (HoldoutCasePlan plan in manifest.Cases.OrderBy(
                     item => item.Id,
                     StringComparer.Ordinal))
        {
            CaseDocument caseDocument = documents[plan.Id];
            string labelsPath = StablePath.Resolve(
                repositoryRoot,
                plan.Paths.Labels);
            schemaValidator.ValidateFile(
                labelSchemaPath,
                labelsPath,
                limits.MaximumLabelBytes,
                repositoryRoot,
                repositoryRoot);
            CorpusLabels labels = CorpusLabelReader.Read(
                labelsPath,
                ResourceLimits.Default);
            ValidateDeclaredCounts(plan, labels);
            ValidateSarifLabelCoverage(repositoryRoot, plan, labels);
            ValidateProvenanceFiles(repositoryRoot, caseDocument);
            cases.Add(new ValidatedHoldoutCase(
                plan,
                labels,
                ComputeInputHashes(repositoryRoot, plan.Paths)));
        }

        return cases.ToImmutable();
    }

    private void ValidateManifestSemantics(
        string repositoryRoot,
        ManifestDocument document,
        HoldoutManifest manifest)
    {
        EnsureUnique(
            manifest.Producers.Select(item => item.Id),
            "producer id");
        EnsureUnique(
            manifest.Producers.Select(item => item.Family),
            "producer family");
        EnsureUnique(manifest.Cases.Select(item => item.Id), "case id");

        HashSet<string> producerIds = manifest.Producers
            .Select(item => item.Id)
            .ToHashSet(StringComparer.Ordinal);
        foreach (HoldoutCasePlan plan in manifest.Cases)
        {
            if (!producerIds.Contains(plan.ProducerId))
            {
                throw new InvalidDataException(
                    $"Holdout case '{plan.Id}' references unknown producer '{plan.ProducerId}'.");
            }

            ValidateCasePaths(repositoryRoot, plan);
        }

        if (!manifest.Cases.Select(item => item.ProducerId)
            .ToHashSet(StringComparer.Ordinal)
            .SetEquals(producerIds))
        {
            throw new InvalidDataException(
                "Every declared producer must have at least one holdout case plan.");
        }

        ValidateDirectoryCoverage(repositoryRoot, manifest.Cases);
        ValidateDevelopmentCorpusSeparation(repositoryRoot, manifest.Cases);
        ValidateAggregateCounts(manifest);
        ValidateCommandSecurity(document.Producers);
    }

    private static HoldoutManifest MapManifest(ManifestDocument document)
    {
        HoldoutProducer[] producers = document.Producers
            .Select(item => new HoldoutProducer(
                item.Id,
                item.Family,
                item.DisplayName,
                item.ExactVersion))
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ToArray();
        HoldoutCasePlan[] cases = document.Cases
            .Select(item => new HoldoutCasePlan(
                item.Id,
                item.ProducerId,
                new HoldoutCasePaths(
                    item.Paths.Directory,
                    item.Paths.BaselineSarif,
                    item.Paths.CandidateSarif,
                    item.Paths.Labels,
                    item.Paths.Notes,
                    item.Paths.ProducerInputDirectory,
                    item.Paths.Config),
                item.Scenarios.Order(StringComparer.Ordinal).ToImmutableArray(),
                MapCounts(item.Counts)))
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ToArray();
        return new HoldoutManifest(
            document.SchemaVersion,
            document.HoldoutId,
            producers.ToImmutableArray(),
            cases.ToImmutableArray(),
            MapCounts(document.Counts));
    }

    private static HoldoutCaseCounts MapCounts(CaseCountsDocument counts) => new(
        counts.BaselineFindings,
        counts.CandidateFindings,
        counts.GroundTruthUnits,
        counts.LabelledRelationships,
        counts.SameFindingRelationships,
        counts.NewFindings,
        counts.ResolvedFindings,
        counts.NewOrResolvedFindings,
        counts.AmbiguousOrNearCollisionRelationships);

    private static HoldoutCaseCounts MapCounts(HoldoutCountsDocument counts) => new(
        BaselineFindings: 0,
        CandidateFindings: 0,
        counts.GroundTruthUnits,
        counts.LabelledRelationships,
        counts.SameFindingRelationships,
        counts.NewFindings,
        counts.ResolvedFindings,
        counts.NewOrResolvedFindings,
        counts.AmbiguousOrNearCollisionRelationships);

    private static void ValidateCasePaths(
        string repositoryRoot,
        HoldoutCasePlan plan)
    {
        string expectedDirectory = $"{CasesRelativeRoot}/{plan.Id}";
        if (!string.Equals(
            plan.Paths.Directory,
            expectedDirectory,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Holdout case '{plan.Id}' directory must be '{expectedDirectory}'.");
        }

        string prefix = expectedDirectory + "/";
        foreach ((string field, string path) in EnumerateCasePaths(plan.Paths))
        {
            StablePath.RequireRepositoryRelative(path, field);
            if (!path.StartsWith(prefix, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Holdout case '{plan.Id}' path '{path}' is outside its case directory.");
            }
        }

        string directory = StablePath.Resolve(repositoryRoot, expectedDirectory);
        EnsureRegularDirectory(directory, expectedDirectory);
        BoundedJsonFile.EnsureRegularFile(
            StablePath.Resolve(repositoryRoot, plan.Paths.BaselineSarif));
        BoundedJsonFile.EnsureRegularFile(
            StablePath.Resolve(repositoryRoot, plan.Paths.CandidateSarif));
        BoundedJsonFile.EnsureRegularFile(
            StablePath.Resolve(repositoryRoot, plan.Paths.Labels));
        BoundedJsonFile.EnsureRegularFile(
            StablePath.Resolve(repositoryRoot, plan.Paths.Notes));
        EnsureRegularDirectory(
            StablePath.Resolve(repositoryRoot, plan.Paths.ProducerInputDirectory),
            plan.Paths.ProducerInputDirectory);
        if (plan.Paths.Config is not null)
        {
            BoundedJsonFile.EnsureRegularFile(
                StablePath.Resolve(repositoryRoot, plan.Paths.Config));
        }
    }

    private static IEnumerable<(string Field, string Path)> EnumerateCasePaths(
        HoldoutCasePaths paths)
    {
        yield return ("paths.directory", paths.Directory);
        yield return ("paths.baselineSarif", paths.BaselineSarif);
        yield return ("paths.candidateSarif", paths.CandidateSarif);
        yield return ("paths.labels", paths.Labels);
        yield return ("paths.notes", paths.Notes);
        yield return ("paths.producerInputDirectory", paths.ProducerInputDirectory);
        if (paths.Config is not null)
        {
            yield return ("paths.config", paths.Config);
        }
    }

    private static void ValidateDeclaredCounts(
        HoldoutCasePlan plan,
        CorpusLabels labels)
    {
        int ambiguousBaseline = labels.ExpectedAmbiguous.Count(key =>
            key.StartsWith("baseline:", StringComparison.Ordinal));
        int ambiguousCandidate = labels.ExpectedAmbiguous.Count(key =>
            key.StartsWith("candidate:", StringComparison.Ordinal));
        HoldoutCaseCounts counts = plan.Counts;
        RequireCount(
            plan.Id,
            "groundTruthUnits",
            counts.GroundTruthUnits,
            labels.Pairs.Length
                + labels.ExpectedNew.Count
                + labels.ExpectedResolved.Count
                + ambiguousBaseline);
        RequireCount(
            plan.Id,
            "labelledRelationships",
            counts.LabelledRelationships,
            labels.Pairs.Length);
        RequireCount(
            plan.Id,
            "sameFindingRelationships",
            counts.SameFindingRelationships,
            labels.Pairs.Length);
        RequireCount(
            plan.Id,
            "newFindings",
            counts.NewFindings,
            labels.ExpectedNew.Count);
        RequireCount(
            plan.Id,
            "resolvedFindings",
            counts.ResolvedFindings,
            labels.ExpectedResolved.Count);
        RequireCount(
            plan.Id,
            "newOrResolvedFindings",
            counts.NewOrResolvedFindings,
            labels.ExpectedNew.Count + labels.ExpectedResolved.Count);
        RequireCount(
            plan.Id,
            "baselineFindings",
            counts.BaselineFindings,
            labels.Pairs.Length + labels.ExpectedResolved.Count + ambiguousBaseline);
        RequireCount(
            plan.Id,
            "candidateFindings",
            counts.CandidateFindings,
            labels.Pairs.Length + labels.ExpectedNew.Count + ambiguousCandidate);
        if (counts.AmbiguousOrNearCollisionRelationships <= 0
            || labels.ExpectedAmbiguous.Count == 0)
        {
            throw new InvalidDataException(
                $"Holdout case '{plan.Id}' must label an ambiguity or near collision.");
        }

        if (ambiguousBaseline != ambiguousCandidate
            || labels.ExpectedAmbiguous.Count % 2 != 0
            || counts.AmbiguousOrNearCollisionRelationships != ambiguousBaseline)
        {
            throw new InvalidDataException(
                $"Holdout case '{plan.Id}' ambiguity count must equal the labelled count on each side.");
        }
    }

    private static void RequireCount(
        string caseId,
        string name,
        int declared,
        int observed)
    {
        if (declared != observed)
        {
            throw new InvalidDataException(
                $"Holdout case '{caseId}' declares {name}={declared}, but labels contain {observed}.");
        }
    }

    private void ValidateSarifLabelCoverage(
        string repositoryRoot,
        HoldoutCasePlan plan,
        CorpusLabels labels)
    {
        ImmutableHashSet<string> baselineFindings = ReadFindingKeys(
            repositoryRoot,
            StablePath.Resolve(repositoryRoot, plan.Paths.BaselineSarif),
            "baseline");
        ImmutableHashSet<string> candidateFindings = ReadFindingKeys(
            repositoryRoot,
            StablePath.Resolve(repositoryRoot, plan.Paths.CandidateSarif),
            "candidate");
        RequireCount(
            plan.Id,
            "baselineFindings",
            plan.Counts.BaselineFindings,
            baselineFindings.Count);
        RequireCount(
            plan.Id,
            "candidateFindings",
            plan.Counts.CandidateFindings,
            candidateFindings.Count);
        string[] labelledBaseline = labels.Pairs.Select(item => item.BaselineKey)
            .Concat(labels.ExpectedResolved)
            .Concat(labels.ExpectedAmbiguous.Where(item =>
                item.StartsWith("baseline:", StringComparison.Ordinal)))
            .ToArray();
        string[] labelledCandidate = labels.Pairs.Select(item => item.CandidateKey)
            .Concat(labels.ExpectedNew)
            .Concat(labels.ExpectedAmbiguous.Where(item =>
                item.StartsWith("candidate:", StringComparison.Ordinal)))
            .ToArray();
        EnsureExactFindingCoverage(
            plan.Id,
            "baseline",
            labelledBaseline,
            baselineFindings);
        EnsureExactFindingCoverage(
            plan.Id,
            "candidate",
            labelledCandidate,
            candidateFindings);
    }

    private ImmutableHashSet<string> ReadFindingKeys(
        string repositoryRoot,
        string path,
        string side)
    {
        JsonNode root = BoundedJsonFile.ReadNode(
            path,
            limits.MaximumSarifBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            repositoryRoot);
        if (root is not JsonObject rootObject
            || rootObject["runs"] is not JsonArray runs)
        {
            throw new InvalidDataException(
                "A holdout SARIF input does not contain a root runs array.");
        }

        var keys = ImmutableHashSet.CreateBuilder<string>(StringComparer.Ordinal);
        for (var runIndex = 0; runIndex < runs.Count; runIndex++)
        {
            if (runs[runIndex] is not JsonObject run)
            {
                throw new InvalidDataException(
                    "A holdout SARIF run is not an object.");
            }

            if (run["results"] is not JsonArray results)
            {
                continue;
            }

            for (var resultIndex = 0; resultIndex < results.Count; resultIndex++)
            {
                if (results[resultIndex] is not JsonObject)
                {
                    throw new InvalidDataException(
                        "A holdout SARIF result is not an object.");
                }

                if (keys.Count >= limits.MaximumResultsPerCase)
                {
                    throw new InvalidDataException(
                        "A holdout SARIF input exceeds the validation result limit.");
                }

                keys.Add($"{side}:{runIndex}:{resultIndex}");
            }
        }

        return keys.ToImmutable();
    }

    private static void EnsureExactFindingCoverage(
        string caseId,
        string side,
        IReadOnlyCollection<string> labelled,
        ImmutableHashSet<string> actual)
    {
        HashSet<string> labelledSet = labelled.ToHashSet(StringComparer.Ordinal);
        if (labelledSet.Count != labelled.Count
            || !labelledSet.SetEquals(actual))
        {
            throw new InvalidDataException(
                $"Holdout case '{caseId}' labels do not cover every {side} SARIF result exactly once.");
        }
    }

    private static void ValidateAggregateCounts(HoldoutManifest manifest)
    {
        RequireAggregate(
            manifest,
            "groundTruthUnits",
            item => item.GroundTruthUnits,
            manifest.Counts.GroundTruthUnits);
        RequireAggregate(
            manifest,
            "labelledRelationships",
            item => item.LabelledRelationships,
            manifest.Counts.LabelledRelationships);
        RequireAggregate(
            manifest,
            "sameFindingRelationships",
            item => item.SameFindingRelationships,
            manifest.Counts.SameFindingRelationships);
        RequireAggregate(
            manifest,
            "newFindings",
            item => item.NewFindings,
            manifest.Counts.NewFindings);
        RequireAggregate(
            manifest,
            "resolvedFindings",
            item => item.ResolvedFindings,
            manifest.Counts.ResolvedFindings);
        RequireAggregate(
            manifest,
            "newOrResolvedFindings",
            item => item.NewOrResolvedFindings,
            manifest.Counts.NewOrResolvedFindings);
        RequireAggregate(
            manifest,
            "ambiguousOrNearCollisionRelationships",
            item => item.AmbiguousOrNearCollisionRelationships,
            manifest.Counts.AmbiguousOrNearCollisionRelationships);
    }

    private static void RequireAggregate(
        HoldoutManifest manifest,
        string name,
        Func<HoldoutCaseCounts, int> selector,
        int declared)
    {
        int observed = manifest.Cases.Sum(item => selector(item.Counts));
        if (declared != observed)
        {
            throw new InvalidDataException(
                $"Holdout aggregate declares {name}={declared}, but case plans total {observed}.");
        }
    }

    private static void ValidateDirectoryCoverage(
        string repositoryRoot,
        ImmutableArray<HoldoutCasePlan> cases)
    {
        string casesRoot = StablePath.Resolve(repositoryRoot, CasesRelativeRoot);
        EnsureRegularDirectory(casesRoot, CasesRelativeRoot);
        string[] actual = Directory.EnumerateDirectories(casesRoot)
            .Select(Path.GetFileName)
            .Where(item => item is not null)
            .Select(item => item!)
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] declared = cases.Select(item => item.Id)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(declared, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The holdout cases directory does not exactly match the manifest case plan.");
        }
    }

    private static void ValidateDevelopmentCorpusSeparation(
        string repositoryRoot,
        ImmutableArray<HoldoutCasePlan> cases)
    {
        string developmentCases = Path.Combine(repositoryRoot, "corpus", "cases");
        HashSet<string> developmentIds = Directory.EnumerateDirectories(
                developmentCases)
            .Select(Path.GetFileName)
            .Where(item => item is not null)
            .Select(item => item!)
            .ToHashSet(StringComparer.Ordinal);
        string? overlap = cases.Select(item => item.Id)
            .Order(StringComparer.Ordinal)
            .FirstOrDefault(developmentIds.Contains);
        if (overlap is not null)
        {
            throw new InvalidDataException(
                $"Holdout case id '{overlap}' overlaps the development corpus.");
        }
    }

    private static void ValidateCommandSecurity(
        IEnumerable<ProducerDocument> producers)
    {
        foreach (ProducerDocument producer in producers)
        {
            if (producer.ExactVersion.Contains("latest", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"Producer '{producer.Id}' is not pinned to an exact version.");
            }

            foreach (CommandDocument command in producer.Commands.Install.Concat(
                         producer.Commands.Capture).Append(
                         producer.Commands.Reproduction))
            {
                string flattened = string.Join(' ', command.Arguments);
                if (flattened.Contains("curl |", StringComparison.OrdinalIgnoreCase)
                    || flattened.Contains("wget |", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        $"Producer '{producer.Id}' uses an unauditable pipe-to-shell command.");
                }
            }
        }
    }

    private static void ValidateProvenanceFiles(
        string repositoryRoot,
        CaseDocument document)
    {
        foreach (SourceTransformationDocument transformation in
                 document.SourceTransformations)
        {
            RequireProvenanceFile(repositoryRoot, transformation.Script);
            foreach (string path in transformation.InputPaths.Concat(
                         transformation.OutputPaths))
            {
                RequireProvenancePath(repositoryRoot, path);
            }
        }

        foreach (RawSarifMutationDocument mutation in document.RawSarifMutations)
        {
            RequireProvenanceFile(repositoryRoot, mutation.OriginalCapture);
            RequireProvenanceFile(repositoryRoot, mutation.Script);
        }
    }

    private static void RequireProvenanceFile(
        string repositoryRoot,
        string relativePath) => BoundedJsonFile.EnsureRegularFile(
        StablePath.Resolve(repositoryRoot, relativePath));

    private static void RequireProvenancePath(
        string repositoryRoot,
        string relativePath)
    {
        string path = StablePath.Resolve(repositoryRoot, relativePath);
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            throw new FileNotFoundException(
                $"Provenance path '{relativePath}' does not exist.",
                path);
        }
    }

    private CaseInputHashes ComputeInputHashes(
        string repositoryRoot,
        HoldoutCasePaths paths) => new(
        HashFile(repositoryRoot, paths.BaselineSarif, limits.MaximumSarifBytes),
        HashFile(repositoryRoot, paths.CandidateSarif, limits.MaximumSarifBytes),
        HashFile(repositoryRoot, paths.Labels, limits.MaximumLabelBytes),
        HashFile(repositoryRoot, paths.Notes, limits.MaximumLabelBytes),
        TreeHasher.Compute(
            StablePath.Resolve(repositoryRoot, paths.ProducerInputDirectory),
            limits.MaximumSarifBytes,
            limits.MaximumResultsPerCase),
        paths.Config is null
            ? null
            : HashFile(repositoryRoot, paths.Config, limits.MaximumLabelBytes));

    private static string HashFile(
        string repositoryRoot,
        string relativePath,
        long maximumBytes) => BoundedJsonFile.ComputeSha256(
        StablePath.Resolve(repositoryRoot, relativePath),
        maximumBytes,
        repositoryRoot);

    private static void EnsureUnique(IEnumerable<string> values, string kind)
    {
        var observed = new HashSet<string>(StringComparer.Ordinal);
        string? duplicate = values.Order(StringComparer.Ordinal)
            .FirstOrDefault(value => !observed.Add(value));
        if (duplicate is not null)
        {
            throw new InvalidDataException(
                $"Holdout manifest repeats {kind} '{duplicate}'.");
        }
    }

    private static void EnsureRegularDirectory(string path, string logicalName)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException(
                $"Required directory '{logicalName}' does not exist.");
        }

        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Required directory '{logicalName}' cannot be a symbolic link or reparse point.");
        }
    }

    private sealed class ManifestDocument
    {
        public required string SchemaVersion { get; init; }
        public required string HoldoutId { get; init; }
        public required ProducerDocument[] Producers { get; init; }
        public required CaseDocument[] Cases { get; init; }
        public required HoldoutCountsDocument Counts { get; init; }
    }

    private sealed class ProducerDocument
    {
        public required string Id { get; init; }
        public required string Family { get; init; }
        public required string DisplayName { get; init; }
        public required string ExactVersion { get; init; }
        public required string SourceCommit { get; init; }
        public required string ProjectUrl { get; init; }
        public required string ReleaseUrl { get; init; }
        public required LicenseDocument License { get; init; }
        public required string CaptureDate { get; init; }
        public required CommandsDocument Commands { get; init; }
        public required DownloadDocument[] Downloads { get; init; }
        public required CapturePolicyDocument CapturePolicy { get; init; }
    }

    private sealed class LicenseDocument
    {
        public required string SpdxIdentifier { get; init; }
        public required string Name { get; init; }
        public required string Url { get; init; }
    }

    private sealed class CommandsDocument
    {
        public required CommandDocument Reproduction { get; init; }
        public required CommandDocument[] Install { get; init; }
        public required CommandDocument[] Capture { get; init; }
    }

    private sealed class CommandDocument
    {
        public required string WorkingDirectory { get; init; }
        public required string Executable { get; init; }
        public required string[] Arguments { get; init; }
        public required EnvironmentVariableDocument[] Environment { get; init; }
    }

    private sealed class EnvironmentVariableDocument
    {
        public required string Name { get; init; }
        public required string Value { get; init; }
    }

    private sealed class DownloadDocument
    {
        public required string FileName { get; init; }
        public required string Url { get; init; }
        public required string Sha256 { get; init; }
        public required long SizeBytes { get; init; }
        public required bool Immutable { get; init; }
    }

    private sealed class CapturePolicyDocument
    {
        public required string RulesSource { get; init; }
        public required bool DownloadsRemoteRules { get; init; }
        public required bool ExecutesFixtureCode { get; init; }
        public required bool FollowsSarifNetworkUris { get; init; }
    }

    private sealed class CaseDocument
    {
        public required string Id { get; init; }
        public required string ProducerId { get; init; }
        public required CasePathsDocument Paths { get; init; }
        public required string[] Scenarios { get; init; }
        public required CaseCountsDocument Counts { get; init; }
        public required InputProvenanceDocument InputProvenance { get; init; }
        public required SourceTransformationDocument[] SourceTransformations { get; init; }
        public required RawSarifMutationDocument[] RawSarifMutations { get; init; }
    }

    private sealed class CasePathsDocument
    {
        public required string Directory { get; init; }
        public required string BaselineSarif { get; init; }
        public required string CandidateSarif { get; init; }
        public required string Labels { get; init; }
        public required string Notes { get; init; }
        public required string ProducerInputDirectory { get; init; }
        public string? Config { get; init; }
    }

    private sealed class CaseCountsDocument
    {
        public required int BaselineFindings { get; init; }
        public required int CandidateFindings { get; init; }
        public required int GroundTruthUnits { get; init; }
        public required int LabelledRelationships { get; init; }
        public required int SameFindingRelationships { get; init; }
        public required int NewFindings { get; init; }
        public required int ResolvedFindings { get; init; }
        public required int NewOrResolvedFindings { get; init; }
        public required int AmbiguousOrNearCollisionRelationships { get; init; }
    }

    private sealed class HoldoutCountsDocument
    {
        public required int ProducerFamilies { get; init; }
        public required int Cases { get; init; }
        public required int GroundTruthUnits { get; init; }
        public required int LabelledRelationships { get; init; }
        public required int SameFindingRelationships { get; init; }
        public required int NewFindings { get; init; }
        public required int ResolvedFindings { get; init; }
        public required int NewOrResolvedFindings { get; init; }
        public required int AmbiguousOrNearCollisionRelationships { get; init; }
    }

    private sealed class InputProvenanceDocument
    {
        public required string Origin { get; init; }
        public required LicenseDocument License { get; init; }
        public string? SourceUrl { get; init; }
        public required bool ContainsRealSecrets { get; init; }
        public required bool ContainsProprietaryCode { get; init; }
    }

    private sealed class SourceTransformationDocument
    {
        public required string Id { get; init; }
        public required string Kind { get; init; }
        public required string Script { get; init; }
        public required string[] InputPaths { get; init; }
        public required string[] OutputPaths { get; init; }
        public required string Description { get; init; }
    }

    private sealed class RawSarifMutationDocument
    {
        public required string Id { get; init; }
        public required string OriginalCapture { get; init; }
        public required string Script { get; init; }
        public required string[] ChangedFields { get; init; }
        public required string SemanticIdentity { get; init; }
        public required string Rationale { get; init; }
    }
}

/// <summary>Computes a cross-platform hash over an ordinal relative-path/file-hash projection.</summary>
public static class TreeHasher
{
    /// <summary>
    /// Time: O(total file bytes + n log n); Space: O(n) paths plus one bounded file.
    /// </summary>
    public static string Compute(
        string directory,
        long maximumFileBytes,
        int maximumFiles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumFileBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumFiles);
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException(
                $"Tree-hash directory '{Path.GetFileName(directory)}' does not exist.");
        }

        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("A tree-hash root cannot be a symbolic link.");
        }

        string? linkedDirectory = Directory.EnumerateDirectories(
                directory,
                "*",
                SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal)
            .FirstOrDefault(path =>
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0);
        if (linkedDirectory is not null)
        {
            throw new InvalidDataException(
                "A producer input tree cannot contain a symbolic-link directory.");
        }

        string[] files = Directory.EnumerateFiles(
                directory,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetFullPath(path))
            .OrderBy(
                path => Path.GetRelativePath(directory, path)
                    .Replace(Path.DirectorySeparatorChar, '/'),
                StringComparer.Ordinal)
            .ToArray();
        if (files.Length > maximumFiles)
        {
            throw new InvalidDataException(
                $"Producer input tree exceeds the {maximumFiles}-file limit.");
        }

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (string path in files)
        {
            BoundedJsonFile.EnsureRegularFile(path);
            string relative = Path.GetRelativePath(directory, path)
                .Replace(Path.DirectorySeparatorChar, '/');
            StablePath.RequireRepositoryRelative(relative, "producer input tree path");
            string fileHash = BoundedJsonFile.ComputeSha256(
                path,
                maximumFileBytes,
                directory);
            hash.AppendData(Encoding.UTF8.GetBytes($"{relative}\0{fileHash}\n"));
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}
