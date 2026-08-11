using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SarifRegress.Validation;

internal sealed record SparseSideManifest(
    string SourceRoot,
    string SarifPath,
    string SourceTreeSha256,
    string ProjectedSarifSha256,
    int ResultCount);

internal sealed record SparseFamilyManifest(
    string Id,
    string LabelsPath,
    SparseSideManifest Baseline,
    SparseSideManifest Candidate);

internal sealed record SparseResearchManifest(
    string Sha256,
    ImmutableArray<SparseFamilyManifest> Families,
    ImmutableDictionary<string, string> IntegritySha256);

internal static class SparseResearchManifestReader
{
    internal const string SparseRootRelativePath = "validation/research/sparse-sarif";
    internal const string ManifestRelativePath = SparseRootRelativePath + "/manifest.json";
    internal const string ImplementationManifestRelativePath =
        SparseRootRelativePath + "/experiment-implementation-manifest.json";
    private static readonly ImmutableArray<string> ImplementationRoots =
    [
        "src/SarifRegress.Cli",
        "src/SarifRegress.Core",
        "src/SarifRegress.Match",
        "src/SarifRegress.Report",
        "src/SarifRegress.Sarif",
        "validation/tools/SarifRegress.Validation",
    ];

    internal static SparseResearchManifest Read(
        string repositoryRoot,
        ValidationLimits limits)
    {
        string path = StablePath.Resolve(repositoryRoot, ManifestRelativePath);
        byte[] manifestBytes = BoundedJsonFile.ReadBytes(
            path,
            limits.MaximumManifestBytes,
            repositoryRoot);
        JsonNode manifestNode = BoundedJsonFile.ParseNode(
            manifestBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            Path.GetFileName(path));
        string schemaPath = StablePath.Resolve(
            repositoryRoot,
            SparseRootRelativePath + "/schemas/manifest.schema.json");
        JsonObject root = RequireObject(new JsonSchemaValidator(limits).ValidateNode(
            schemaPath,
            manifestNode,
            Path.GetFileName(path),
            schemaApprovedRoot: repositoryRoot));
        if (!string.Equals(String(root, "schemaVersion"), "1", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The sparse corpus manifest schema version is not supported.");
        }

        JsonArray familiesNode = RequireArray(root["families"], "families");
        if (familiesNode.Count is < 1 or > 16)
        {
            throw new InvalidDataException("The sparse corpus family count is outside its bound.");
        }

        var families = familiesNode
            .Select((node, index) => ReadFamily(
                RequireObject(node, $"families[{index}]"),
                index))
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ToImmutableArray();
        if (families.Select(item => item.Id).Distinct(StringComparer.Ordinal).Count()
            != families.Length)
        {
            throw new InvalidDataException("The sparse corpus repeats a family identifier.");
        }

        JsonObject integrity = RequireObject(root["integrity"], "integrity");
        if (!string.Equals(String(integrity, "algorithm"), "sha256", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The sparse corpus integrity algorithm is not supported.");
        }

        JsonArray integrityFiles = RequireArray(integrity["files"], "integrity.files");
        var integrityHashes = ImmutableDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        foreach ((JsonNode? node, int index) in integrityFiles.Select(
                     (node, index) => (node, index)))
        {
            JsonObject file = RequireObject(node, $"integrity.files[{index}]");
            string relative = StablePath.RequireRepositoryRelative(
                String(file, "path"),
                $"integrity.files[{index}].path");
            if (!integrityHashes.TryAdd(
                    relative,
                    Sha256(file, "sha256", $"integrity.files[{index}]")))
            {
                throw new InvalidDataException(
                    "The sparse corpus integrity map repeats a path.");
            }
        }

        return new SparseResearchManifest(
            SparseSarifExperimentSerializer.Sha256(manifestBytes),
            families,
            integrityHashes.ToImmutable());
    }

    internal static string ResolveSparsePath(string repositoryRoot, string relativePath) =>
        StablePath.Resolve(
            repositoryRoot,
            SparseRootRelativePath + "/"
            + StablePath.RequireRepositoryRelative(relativePath, "sparse path"));

    internal static string ValidateImplementationManifest(
        string repositoryRoot,
        ValidationLimits limits)
    {
        string path = StablePath.Resolve(
            repositoryRoot,
            ImplementationManifestRelativePath);
        string schemaPath = StablePath.Resolve(
            repositoryRoot,
            SparseRootRelativePath
            + "/schemas/experiment-implementation-manifest.schema.json");
        byte[] manifestBytes = BoundedJsonFile.ReadBytes(
            path,
            limits.MaximumManifestBytes,
            repositoryRoot);
        JsonNode manifestNode = BoundedJsonFile.ParseNode(
            manifestBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            Path.GetFileName(path));
        JsonObject root = RequireObject(new JsonSchemaValidator(limits).ValidateNode(
            schemaPath,
            manifestNode,
            Path.GetFileName(path),
            schemaApprovedRoot: repositoryRoot));
        if (!string.Equals(String(root, "schemaVersion"), "1", StringComparison.Ordinal)
            || !string.Equals(
                String(root, "kind"),
                "sparse-experiment-implementation-manifest/v1",
                StringComparison.Ordinal)
            || !string.Equals(String(root, "algorithm"), "sha256", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The sparse implementation manifest contract is not supported.");
        }

        JsonArray files = RequireArray(root["files"], "files");
        string[] paths = files.Select((node, index) => String(
                RequireObject(node, $"files[{index}]"),
                "path"))
            .ToArray();
        ImmutableArray<string> expectedPaths = GetImplementationPaths(repositoryRoot);
        if (!paths.SequenceEqual(expectedPaths, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The sparse implementation manifest does not list the exact admitted harness files in ordinal order.");
        }

        for (var index = 0; index < files.Count; index++)
        {
            JsonObject file = RequireObject(files[index], $"files[{index}]");
            string expected = Sha256(file, "sha256", $"files[{index}]");
            string actual = BoundedJsonFile.ComputeSha256(
                StablePath.Resolve(repositoryRoot, paths[index]),
                limits.MaximumSarifBytes,
                repositoryRoot);
            if (!string.Equals(expected, actual, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Sparse implementation file '{paths[index]}' does not match its manifest hash.");
            }
        }

        return SparseSarifExperimentSerializer.Sha256(manifestBytes);
    }

    private static ImmutableArray<string> GetImplementationPaths(string repositoryRoot)
    {
        var paths = new List<string>
        {
            "Directory.Build.props",
            "Directory.Packages.props",
            "global.json",
        };
        foreach (string relativeRoot in ImplementationRoots)
        {
            string root = StablePath.Resolve(repositoryRoot, relativeRoot);
            if (!Directory.Exists(root)
                || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Sparse implementation root '{relativeRoot}' must be a non-link directory.");
            }

            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                foreach (FileSystemInfo entry in new DirectoryInfo(pending.Pop())
                             .EnumerateFileSystemInfos()
                             .OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidDataException(
                            "Sparse implementation roots cannot contain links or junctions.");
                    }

                    if ((entry.Attributes & FileAttributes.Directory) != 0)
                    {
                        if (entry.Name is "bin" or "obj")
                        {
                            continue;
                        }

                        pending.Push(entry.FullName);
                        continue;
                    }

                    if (!entry.Name.EndsWith(".cs", StringComparison.Ordinal)
                        && !entry.Name.EndsWith(".csproj", StringComparison.Ordinal)
                        && !string.Equals(
                            entry.Name,
                            "packages.lock.json",
                            StringComparison.Ordinal))
                    {
                        continue;
                    }

                    string relative = Path.GetRelativePath(repositoryRoot, entry.FullName)
                        .Replace(Path.DirectorySeparatorChar, '/');
                    paths.Add(StablePath.RequireRepositoryRelative(
                        relative,
                        "implementation source path"));
                    if (paths.Count > 256)
                    {
                        throw new InvalidDataException(
                            "The sparse implementation source set exceeds its 256-file bound.");
                    }
                }
            }
        }

        return paths
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static SparseFamilyManifest ReadFamily(JsonObject value, int index)
    {
        string prefix = $"families[{index}]";
        return new SparseFamilyManifest(
            FamilyId(value, prefix),
            RelativePath(value, "labelsPath", prefix),
            ReadSide(RequireObject(value["baseline"], prefix + ".baseline"), prefix + ".baseline"),
            ReadSide(RequireObject(value["candidate"], prefix + ".candidate"), prefix + ".candidate"));
    }

    private static SparseSideManifest ReadSide(JsonObject value, string prefix)
    {
        int resultCount = Integer(value, "resultCount");
        if (resultCount is < 0 or > 100_000)
        {
            throw new InvalidDataException($"Manifest field '{prefix}.resultCount' is outside its bound.");
        }

        return new SparseSideManifest(
            RelativePath(value, "sourceRoot", prefix),
            RelativePath(value, "sarifPath", prefix),
            Sha256(value, "sourceTreeSha256", prefix),
            Sha256(value, "projectedSarifSha256", prefix),
            resultCount);
    }

    private static string RelativePath(
        JsonObject value,
        string property,
        string prefix) =>
        StablePath.RequireRepositoryRelative(String(value, property), prefix + "." + property);

    private static string FamilyId(JsonObject value, string prefix)
    {
        string id = String(value, "id");
        if (id.Length is < 3 or > 64
            || !IsLowerAsciiLetter(id[0])
            || id.Split('-').Any(segment => segment.Length == 0
                || segment.Any(character => !IsLowerAsciiLetterOrDigit(character))))
        {
            throw new InvalidDataException(
                $"Manifest field '{prefix}.id' must be a 3-64 character lowercase ASCII identifier.");
        }

        return id;

        static bool IsLowerAsciiLetterOrDigit(char character) =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9';

        static bool IsLowerAsciiLetter(char character) =>
            character is >= 'a' and <= 'z';
    }

    private static string Sha256(JsonObject value, string property, string prefix)
    {
        string result = String(value, property);
        if (result.Length != 64 || !result.All(character =>
                character is (>= '0' and <= '9') or (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException($"Manifest field '{prefix}.{property}' is not a lowercase SHA-256.");
        }

        return result;
    }

    private static string String(JsonObject value, string property) =>
        value[property]?.GetValue<string>()
        ?? throw new InvalidDataException($"Manifest field '{property}' is missing.");

    private static int Integer(JsonObject value, string property) =>
        value[property]?.GetValue<int>()
        ?? throw new InvalidDataException($"Manifest field '{property}' is missing.");

    private static JsonObject RequireObject(JsonNode? node, string name = "root") =>
        node as JsonObject
        ?? throw new InvalidDataException($"Sparse manifest value '{name}' must be an object.");

    private static JsonArray RequireArray(JsonNode? node, string name) =>
        node as JsonArray
        ?? throw new InvalidDataException($"Sparse manifest value '{name}' must be an array.");
}

/// <summary>Serializes and parses the two deterministic sparse experiment artifacts.</summary>
public static class SparseSarifExperimentSerializer
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    /// <summary>Serializes label-neutral experiment observations.</summary>
    public static byte[] Serialize(SparseExperimentObservations value) =>
        SerializeValue(value);

    /// <summary>Serializes independently scored gate evidence.</summary>
    public static byte[] Serialize(SparseExperimentGateEvidence value) =>
        SerializeValue(value);

    /// <summary>Reads a bounded observation artifact without consulting labels.</summary>
    public static SparseExperimentObservations ReadObservations(
        string path,
        string approvedRoot,
        ValidationLimits? limits = null)
    {
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        byte[] bytes = BoundedJsonFile.ReadBytes(
            path,
            effectiveLimits.MaximumSarifBytes,
            approvedRoot);
        return ReadObservations(bytes, effectiveLimits);
    }

    /// <summary>Reads an observation artifact from already bounded exact bytes.</summary>
    public static SparseExperimentObservations ReadObservations(
        ReadOnlySpan<byte> bytes,
        ValidationLimits? limits = null)
    {
        ValidationLimits effectiveLimits = limits ?? ValidationLimits.Default;
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            bytes,
            effectiveLimits.MaximumJsonDepth,
            effectiveLimits.MaximumStringCharacters);
        return JsonSerializer.Deserialize<SparseExperimentObservations>(bytes, Options)
            ?? throw new InvalidDataException("The sparse observation artifact contains only null.");
    }

    /// <summary>Returns the lowercase SHA-256 of exact artifact bytes.</summary>
    public static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] SerializeValue<T>(T value)
        where T : notnull => StableJson.Serialize(
            writer => JsonSerializer.Serialize(writer, value, Options));

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            AllowTrailingCommas = false,
            MaxDepth = 128,
            PropertyNameCaseInsensitive = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
        options.Converters.Add(
            new JsonStringEnumConverter(
                JsonNamingPolicy.KebabCaseLower,
                allowIntegerValues: false));
        return options;
    }
}
