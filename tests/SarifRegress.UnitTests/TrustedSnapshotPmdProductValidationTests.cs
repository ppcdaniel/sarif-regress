using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SarifRegress.Cli;

namespace SarifRegress.UnitTests;

public sealed class TrustedSnapshotPmdProductValidationTests
{
    private const int MaximumJsonBytes = 8 * 1024 * 1024;
    private const int MaximumSourceBytes = 1024 * 1024;
    private const int MaximumFilesPerSnapshot = 64;
    private const int MaximumResultsPerSide = 64;
    private const int MaximumJsonDepth = 64;
    private const string MissedRelationshipId = "relationship-b-08";
    private const string LifecycleAmbiguityId = "pmd-clean-a-ambiguity-001";
    private static readonly string[] CleanFamilyIds =
    [
        "pmd-clean-a",
        "pmd-clean-b",
    ];

    [Fact]
    public void Trusted_snapshot_clean_pmd_profile_is_exact_product_evidence()
    {
        string repositoryRoot = FindRepositoryRoot();
        using var workspace = new TestWorkspace();
        string configurationPath = workspace.WriteConfiguration();
        var expectedRelationships = new HashSet<Relationship>();
        var actualRelationships = new HashSet<Relationship>();
        var labelledAmbiguityEndpoints = new HashSet<Endpoint>();
        var pairedEndpoints = new HashSet<Endpoint>();

        foreach (string familyId in CleanFamilyIds)
        {
            string caseRoot = Path.Combine(
                repositoryRoot,
                "validation",
                "research",
                "sparse-sarif",
                "cases",
                familyId);
            FamilyLabels labels = ReadLabels(caseRoot, familyId);
            string baselineManifest = workspace.WriteManifest(
                familyId,
                Side.Baseline,
                Path.Combine(caseRoot, "baseline", "source"));
            string candidateManifest = workspace.WriteManifest(
                familyId,
                Side.Candidate,
                Path.Combine(caseRoot, "candidate", "source"));

            InvocationResult first = InvokeCompare(
                repositoryRoot,
                configurationPath,
                caseRoot,
                baselineManifest,
                candidateManifest);
            InvocationResult second = InvokeCompare(
                repositoryRoot,
                configurationPath,
                caseRoot,
                baselineManifest,
                candidateManifest);

            Assert.Equal(
                Encoding.UTF8.GetBytes(first.Output),
                Encoding.UTF8.GetBytes(second.Output));
            ActualOutcome actual = ReadActualOutcome(first.Output, labels);
            ExpectedOutcome expected = CreateExpectedOutcome(labels);
            AssertSetEqual(expected.Relationships, actual.Relationships, Format);
            AssertSetEqual(expected.New, actual.New, Format);
            AssertSetEqual(expected.Resolved, actual.Resolved, Format);
            AssertSetEqual(expected.Ambiguous, actual.Ambiguous, Format);

            expectedRelationships.UnionWith(labels.Relationships.Values);
            actualRelationships.UnionWith(actual.Relationships);
            labelledAmbiguityEndpoints.UnionWith(
                labels.Ambiguities.Values.SelectMany(
                    ambiguity => ambiguity.AllEndpoints));
            pairedEndpoints.UnionWith(
                actual.Relationships.SelectMany(
                    relationship => new[]
                    {
                        relationship.Baseline,
                        relationship.Candidate,
                    }));
        }

        Assert.True(
            expectedRelationships.Intersect(actualRelationships).Count() == 18,
            "The exact clean-profile true-positive total must remain 18.");
        Assert.Empty(actualRelationships.Except(expectedRelationships));
        Assert.Single(expectedRelationships.Except(actualRelationships));
        Assert.Empty(labelledAmbiguityEndpoints.Intersect(pairedEndpoints));
    }

    private static FamilyLabels ReadLabels(string caseRoot, string familyId)
    {
        IReadOnlyDictionary<FindingSelector, Endpoint> baselineIndex =
            ReadSarifIndex(
                Path.Combine(caseRoot, "baseline.sarif"),
                familyId,
                Side.Baseline);
        IReadOnlyDictionary<FindingSelector, Endpoint> candidateIndex =
            ReadSarifIndex(
                Path.Combine(caseRoot, "candidate.sarif"),
                familyId,
                Side.Candidate);
        using JsonDocument document = ReadJson(
            Path.Combine(caseRoot, "labels.json"));
        JsonElement root = document.RootElement;
        Assert.Equal(familyId, RequiredString(root, "familyId"));
        var relationships = new Dictionary<string, Relationship>(
            StringComparer.Ordinal);
        var newEndpoints = new HashSet<Endpoint>();
        var resolvedEndpoints = new HashSet<Endpoint>();
        var ambiguities = new Dictionary<string, LabelledAmbiguity>(
            StringComparer.Ordinal);
        var coveredBaseline = new HashSet<Endpoint>();
        var coveredCandidate = new HashSet<Endpoint>();

        foreach (JsonElement label in BoundedArray(
            root,
            "relationships").EnumerateArray())
        {
            string id = RequiredString(label, "id");
            Endpoint baseline = Resolve(
                label.GetProperty("baseline"),
                baselineIndex,
                id);
            Endpoint candidate = Resolve(
                label.GetProperty("candidate"),
                candidateIndex,
                id);
            Assert.True(relationships.TryAdd(
                id,
                new Relationship(
                    baseline,
                    candidate,
                    RequiredString(label, "expectedClassification"))));
            Assert.True(coveredBaseline.Add(baseline));
            Assert.True(coveredCandidate.Add(candidate));
        }

        foreach (JsonElement label in BoundedArray(
            root,
            "new").EnumerateArray())
        {
            string id = RequiredString(label, "id");
            Endpoint endpoint = Resolve(
                label.GetProperty("candidate"),
                candidateIndex,
                id);
            Assert.True(newEndpoints.Add(endpoint));
            Assert.True(coveredCandidate.Add(endpoint));
        }

        foreach (JsonElement label in BoundedArray(
            root,
            "resolved").EnumerateArray())
        {
            string id = RequiredString(label, "id");
            Endpoint endpoint = Resolve(
                label.GetProperty("baseline"),
                baselineIndex,
                id);
            Assert.True(resolvedEndpoints.Add(endpoint));
            Assert.True(coveredBaseline.Add(endpoint));
        }

        foreach (JsonElement label in BoundedArray(
            root,
            "ambiguities").EnumerateArray())
        {
            string id = RequiredString(label, "id");
            Endpoint[] baseline = ResolveMany(
                label,
                "baseline",
                baselineIndex,
                id);
            Endpoint[] candidate = ResolveMany(
                label,
                "candidate",
                candidateIndex,
                id);
            Assert.True(ambiguities.TryAdd(
                id,
                new LabelledAmbiguity(baseline, candidate)));
            Assert.All(
                baseline,
                endpoint => Assert.True(coveredBaseline.Add(endpoint)));
            Assert.All(
                candidate,
                endpoint => Assert.True(coveredCandidate.Add(endpoint)));
        }

        AssertSetEqual(baselineIndex.Values, coveredBaseline, Format);
        AssertSetEqual(candidateIndex.Values, coveredCandidate, Format);
        return new FamilyLabels(
            familyId,
            baselineIndex.Values.ToHashSet(),
            candidateIndex.Values.ToHashSet(),
            relationships,
            newEndpoints,
            resolvedEndpoints,
            ambiguities);
    }

    private static IReadOnlyDictionary<FindingSelector, Endpoint> ReadSarifIndex(
        string path,
        string familyId,
        Side side)
    {
        using JsonDocument document = ReadJson(path);
        JsonElement runs = BoundedArray(
            document.RootElement,
            "runs",
            maximumItems: 4);
        var index = new Dictionary<FindingSelector, Endpoint>();
        int runIndex = 0;
        foreach (JsonElement run in runs.EnumerateArray())
        {
            JsonElement results = BoundedArray(run, "results");
            int resultIndex = 0;
            foreach (JsonElement result in results.EnumerateArray())
            {
                JsonElement locations = BoundedArray(
                    result,
                    "locations",
                    maximumItems: 1);
                JsonElement location = Assert.Single(
                    locations.EnumerateArray());
                FindingSelector selector = ReadSarifSelector(
                    result,
                    location.GetProperty("physicalLocation"));
                Assert.True(index.TryAdd(
                    selector,
                    new Endpoint(familyId, side, runIndex, resultIndex)));
                resultIndex++;
            }

            runIndex++;
        }

        Assert.InRange(index.Count, 1, MaximumResultsPerSide);
        return index;
    }

    private static FindingSelector ReadSarifSelector(
        JsonElement result,
        JsonElement physicalLocation)
    {
        JsonElement region = physicalLocation.GetProperty("region");
        return new FindingSelector(
            RequiredString(result, "ruleId"),
            RequiredString(
                physicalLocation.GetProperty("artifactLocation"),
                "uri"),
            RequiredInt(region, "startLine"),
            RequiredInt(region, "startColumn"),
            RequiredInt(region, "endLine"),
            RequiredInt(region, "endColumn"),
            RequiredString(result.GetProperty("message"), "text"));
    }

    private static Endpoint Resolve(
        JsonElement label,
        IReadOnlyDictionary<FindingSelector, Endpoint> index,
        string labelId)
    {
        JsonElement region = label.GetProperty("region");
        var selector = new FindingSelector(
            RequiredString(label, "ruleId"),
            RequiredString(label, "artifactUri"),
            RequiredInt(region, "startLine"),
            RequiredInt(region, "startColumn"),
            RequiredInt(region, "endLine"),
            RequiredInt(region, "endColumn"),
            RequiredString(label, "message"));
        Assert.True(
            index.ContainsKey(selector),
            $"Label '{labelId}' does not identify exactly one SARIF result.");
        return index[selector];
    }

    private static Endpoint[] ResolveMany(
        JsonElement parent,
        string propertyName,
        IReadOnlyDictionary<FindingSelector, Endpoint> index,
        string labelId) => BoundedArray(parent, propertyName)
        .EnumerateArray()
        .Select(label => Resolve(label, index, labelId))
        .ToArray();

    private static ExpectedOutcome CreateExpectedOutcome(FamilyLabels labels)
    {
        var relationships = labels.Relationships.Values.ToHashSet();
        var newEndpoints = new HashSet<Endpoint>(labels.New);
        var resolvedEndpoints = new HashSet<Endpoint>(labels.Resolved);
        var ambiguousEndpoints = labels.Ambiguities.Values
            .SelectMany(ambiguity => ambiguity.AllEndpoints)
            .ToHashSet();

        if (labels.Relationships.TryGetValue(
                MissedRelationshipId,
                out Relationship missed))
        {
            Assert.True(relationships.Remove(missed));
            Assert.True(newEndpoints.Add(missed.Candidate));
            Assert.True(resolvedEndpoints.Add(missed.Baseline));
        }

        if (labels.Ambiguities.TryGetValue(
                LifecycleAmbiguityId,
                out LabelledAmbiguity? lifecycleAmbiguity))
        {
            ambiguousEndpoints.ExceptWith(lifecycleAmbiguity.AllEndpoints);
            newEndpoints.UnionWith(lifecycleAmbiguity.Candidate);
            resolvedEndpoints.UnionWith(lifecycleAmbiguity.Baseline);
        }

        return new ExpectedOutcome(
            relationships,
            newEndpoints,
            resolvedEndpoints,
            ambiguousEndpoints);
    }

    private static ActualOutcome ReadActualOutcome(
        string reportJson,
        FamilyLabels labels)
    {
        Assert.InRange(
            Encoding.UTF8.GetByteCount(reportJson),
            1,
            MaximumJsonBytes);
        using JsonDocument document = JsonDocument.Parse(
            reportJson,
            new JsonDocumentOptions { MaxDepth = MaximumJsonDepth });
        JsonElement findings = BoundedArray(
            document.RootElement,
            "findings",
            labels.Baseline.Count + labels.Candidate.Count);
        var relationships = new HashSet<Relationship>();
        var newEndpoints = new HashSet<Endpoint>();
        var resolvedEndpoints = new HashSet<Endpoint>();
        var ambiguousEndpoints = new HashSet<Endpoint>();
        var observedEndpoints = new HashSet<Endpoint>();

        foreach (JsonElement finding in findings.EnumerateArray())
        {
            string classification = RequiredString(finding, "classification");
            Endpoint? baseline = ReadReference(
                finding.GetProperty("baselineRef"),
                labels,
                Side.Baseline);
            Endpoint? candidate = ReadReference(
                finding.GetProperty("candidateRef"),
                labels,
                Side.Candidate);
            switch (classification)
            {
                case "unchanged":
                case "moved":
                case "modified":
                    Assert.NotNull(baseline);
                    Assert.NotNull(candidate);
                    Assert.True(relationships.Add(new Relationship(
                        baseline.Value,
                        candidate.Value,
                        classification)));
                    AddOnce(observedEndpoints, baseline.Value);
                    AddOnce(observedEndpoints, candidate.Value);
                    break;
                case "new":
                    Assert.Null(baseline);
                    Assert.NotNull(candidate);
                    Assert.True(newEndpoints.Add(candidate.Value));
                    AddOnce(observedEndpoints, candidate.Value);
                    break;
                case "resolved":
                    Assert.NotNull(baseline);
                    Assert.Null(candidate);
                    Assert.True(resolvedEndpoints.Add(baseline.Value));
                    AddOnce(observedEndpoints, baseline.Value);
                    break;
                case "ambiguous":
                    Assert.NotEqual(baseline.HasValue, candidate.HasValue);
                    Endpoint ambiguous = baseline ?? candidate!.Value;
                    Assert.True(ambiguousEndpoints.Add(ambiguous));
                    AddOnce(observedEndpoints, ambiguous);
                    break;
                default:
                    Assert.Fail($"Unexpected classification '{classification}'.");
                    break;
            }
        }

        AssertSetEqual(
            labels.Baseline.Concat(labels.Candidate),
            observedEndpoints,
            Format);
        return new ActualOutcome(
            relationships,
            newEndpoints,
            resolvedEndpoints,
            ambiguousEndpoints);
    }

    private static Endpoint? ReadReference(
        JsonElement reference,
        FamilyLabels labels,
        Side side)
    {
        if (reference.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        Assert.Equal(
            side == Side.Baseline ? "baseline" : "candidate",
            RequiredString(reference, "input"));
        int runIndex = RequiredInt(reference, "runIndex");
        int resultIndex = RequiredInt(reference, "resultIndex");
        Assert.Equal(
            $"/runs/{runIndex}/results/{resultIndex}",
            RequiredString(reference, "jsonPointer"));
        var endpoint = new Endpoint(
            labels.FamilyId,
            side,
            runIndex,
            resultIndex);
        Assert.Contains(
            endpoint,
            side == Side.Baseline ? labels.Baseline : labels.Candidate);
        return endpoint;
    }

    private static InvocationResult InvokeCompare(
        string repositoryRoot,
        string configurationPath,
        string caseRoot,
        string baselineManifest,
        string candidateManifest)
    {
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        int exitCode = CliApplication.Run(
            [
                "compare",
                "--baseline", Path.Combine(caseRoot, "baseline.sarif"),
                "--candidate", Path.Combine(caseRoot, "candidate.sarif"),
                "--config", configurationPath,
                "--baseline-repo", Path.Combine(caseRoot, "baseline", "source"),
                "--baseline-snapshot-manifest", baselineManifest,
                "--candidate-repo", Path.Combine(caseRoot, "candidate", "source"),
                "--candidate-snapshot-manifest", candidateManifest,
            ],
            output,
            error,
            repositoryRoot);
        Assert.True(
            exitCode == 0,
            error + Environment.NewLine + output);
        return new InvocationResult(output.ToString());
    }

    private static JsonDocument ReadJson(string path)
    {
        byte[] bytes = ReadBytes(path, MaximumJsonBytes);
        return JsonDocument.Parse(
            bytes,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaximumJsonDepth,
            });
    }

    private static byte[] ReadBytes(string path, int maximumBytes)
    {
        var file = new FileInfo(path);
        Assert.InRange(file.Length, 1, maximumBytes);
        byte[] bytes = new byte[checked((int)file.Length)];
        using FileStream stream = File.OpenRead(path);
        stream.ReadExactly(bytes);
        Assert.Equal(-1, stream.ReadByte());
        return bytes;
    }

    private static JsonElement BoundedArray(
        JsonElement parent,
        string propertyName,
        int maximumItems = MaximumResultsPerSide)
    {
        JsonElement value = parent.GetProperty(propertyName);
        Assert.Equal(JsonValueKind.Array, value.ValueKind);
        Assert.InRange(value.GetArrayLength(), 0, maximumItems);
        return value;
    }

    private static string RequiredString(
        JsonElement parent,
        string propertyName) => Assert.IsType<string>(
        parent.GetProperty(propertyName).GetString());

    private static int RequiredInt(
        JsonElement parent,
        string propertyName) => parent.GetProperty(propertyName).GetInt32();

    private static void AddOnce(ISet<Endpoint> endpoints, Endpoint endpoint) =>
        Assert.True(
            endpoints.Add(endpoint),
            $"Endpoint '{Format(endpoint)}' was reported more than once.");

    private static void AssertSetEqual<T>(
        IEnumerable<T> expected,
        IEnumerable<T> actual,
        Func<T, string> format) => Assert.Equal(
        expected.Select(format).Order(StringComparer.Ordinal),
        actual.Select(format).Order(StringComparer.Ordinal));

    private static string Format(Endpoint endpoint) =>
        $"{endpoint.FamilyId}:{endpoint.Side.ToString().ToLowerInvariant()}:" +
        $"{endpoint.RunIndex}:{endpoint.ResultIndex}";

    private static string Format(Relationship relationship) =>
        $"{Format(relationship.Baseline)}->{Format(relationship.Candidate)}:" +
        relationship.Classification;

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        for (int depth = 0; directory is not null && depth < 12; depth++)
        {
            string labelsPath = Path.Combine(
                directory.FullName,
                "validation",
                "research",
                "sparse-sarif",
                "cases",
                "pmd-clean-a",
                "labels.json");
            if (File.Exists(labelsPath))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate the bounded PMD clean fixtures.");
    }

    private enum Side
    {
        Baseline,
        Candidate,
    }

    private readonly record struct FindingSelector(
        string RuleId,
        string ArtifactUri,
        int StartLine,
        int StartColumn,
        int EndLine,
        int EndColumn,
        string Message);

    private readonly record struct Endpoint(
        string FamilyId,
        Side Side,
        int RunIndex,
        int ResultIndex);

    private readonly record struct Relationship(
        Endpoint Baseline,
        Endpoint Candidate,
        string Classification);

    private sealed record LabelledAmbiguity(
        IReadOnlyList<Endpoint> Baseline,
        IReadOnlyList<Endpoint> Candidate)
    {
        public IEnumerable<Endpoint> AllEndpoints =>
            Baseline.Concat(Candidate);
    }

    private sealed record FamilyLabels(
        string FamilyId,
        IReadOnlySet<Endpoint> Baseline,
        IReadOnlySet<Endpoint> Candidate,
        IReadOnlyDictionary<string, Relationship> Relationships,
        IReadOnlySet<Endpoint> New,
        IReadOnlySet<Endpoint> Resolved,
        IReadOnlyDictionary<string, LabelledAmbiguity> Ambiguities);

    private sealed record ExpectedOutcome(
        IReadOnlySet<Relationship> Relationships,
        IReadOnlySet<Endpoint> New,
        IReadOnlySet<Endpoint> Resolved,
        IReadOnlySet<Endpoint> Ambiguous);

    private sealed record ActualOutcome(
        IReadOnlySet<Relationship> Relationships,
        IReadOnlySet<Endpoint> New,
        IReadOnlySet<Endpoint> Resolved,
        IReadOnlySet<Endpoint> Ambiguous);

    private sealed record InvocationResult(string Output);

    private sealed class TestWorkspace : IDisposable
    {
        public TestWorkspace()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "sarif-regress-pmd-product-validation",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string WriteConfiguration()
        {
            string path = Path.Combine(Root, "regress.json");
            File.WriteAllText(
                path,
                "{\n  \"schemaVersion\": \"1\",\n" +
                "  \"policy\": { \"failOn\": [] }\n}\n");
            return path;
        }

        public string WriteManifest(
            string familyId,
            Side side,
            string sourceRoot)
        {
            string[] sourcePaths = Directory
                .EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories)
                .OrderBy(
                    path => Path.GetRelativePath(sourceRoot, path),
                    StringComparer.Ordinal)
                .Take(MaximumFilesPerSnapshot + 1)
                .ToArray();
            Assert.InRange(sourcePaths.Length, 1, MaximumFilesPerSnapshot);
            var files = new SortedDictionary<string, string>(
                StringComparer.Ordinal);
            foreach (string sourcePath in sourcePaths)
            {
                string relativePath = Path
                    .GetRelativePath(sourceRoot, sourcePath)
                    .Replace(Path.DirectorySeparatorChar, '/');
                byte[] sourceBytes = ReadBytes(sourcePath, MaximumSourceBytes);
                Assert.True(files.TryAdd(
                    relativePath,
                    Convert.ToHexString(SHA256.HashData(sourceBytes))
                        .ToLowerInvariant()));
            }

            byte[] manifest = JsonSerializer.SerializeToUtf8Bytes(
                new { schemaVersion = "1", files });
            string path = Path.Combine(
                Root,
                $"{familyId}-{side.ToString().ToLowerInvariant()}-manifest.json");
            File.WriteAllBytes(path, manifest);
            return path;
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
