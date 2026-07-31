using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SarifRegress.Cli.Corpus;

namespace SarifRegress.Validation;

/// <summary>Defines the four SARIF baseline states plus normalized failures.</summary>
public enum MultitoolState
{
    New,
    Absent,
    Unchanged,
    Updated,
    Error,
    Unsupported,
}

/// <summary>Captures verified Microsoft SARIF Multitool package provenance.</summary>
public sealed record MultitoolToolEvidence(
    string Name,
    string PackageId,
    string ExactVersion,
    string ProjectUrl,
    string SourceCommitSha,
    string PackageUrl,
    string PackageSha256,
    long PackageSizeBytes,
    string License,
    string HelpOutputSha256,
    string VersionOutputSha256);

/// <summary>Defines the stable, repository-relative projection of one invocation.</summary>
public sealed record NormalizedInvocation(
    string WorkingDirectory,
    string Executable,
    ImmutableArray<string> Arguments);

/// <summary>Reports parsed states keyed by original finding identity.</summary>
public sealed record ParsedMultitoolOutput(
    ImmutableSortedDictionary<string, MultitoolState> StatesByFindingKey,
    ImmutableHashSet<string> MissingCorrespondenceKeys,
    ImmutableSortedDictionary<string, string?> LocationsByFindingKey,
    ImmutableSortedDictionary<string, string> PreviousKeysByCandidateKey,
    bool InstrumentationStateStable)
{
    /// <summary>Creates a legacy signature-only projection for focused parser tests.</summary>
    public ParsedMultitoolOutput(
        ImmutableSortedDictionary<string, MultitoolState> statesByFindingKey,
        ImmutableHashSet<string> missingCorrespondenceKeys,
        ImmutableSortedDictionary<string, string?> locationsByFindingKey)
        : this(
            statesByFindingKey,
            missingCorrespondenceKeys,
            locationsByFindingKey,
            ImmutableSortedDictionary<string, string>.Empty
                .WithComparers(StringComparer.Ordinal),
            InstrumentationStateStable: true)
    {
    }
}

/// <summary>Identifies the primary normalized invocation and both raw comparison outputs.</summary>
public sealed record MultitoolCaseExecution(
    NormalizedInvocation Invocation,
    string RawPath,
    string UninstrumentedRawPath);

/// <summary>Reports one Multitool classification against one ground-truth unit.</summary>
public sealed record MultitoolRelationshipResult(
    string RelationshipId,
    GroundTruthRelationship GroundTruth,
    string MultitoolState,
    bool TaxonomyMapped,
    string? MappedClassification,
    bool Comparable,
    string ComparabilityReason,
    bool? Correct,
    string? ErrorOrUnsupportedCode);

/// <summary>Counts raw Multitool states.</summary>
public sealed record MultitoolStateCounts(
    int New,
    int Absent,
    int Unchanged,
    int Updated,
    int Error,
    int Unsupported);

/// <summary>Defines Multitool metrics only where equivalent measurement is possible.</summary>
public sealed record MultitoolMetrics(
    int GroundTruthUnits,
    int LabelledRelationships,
    int ComparableRelationships,
    int NonComparableRelationships,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    int Errors,
    int Unsupported,
    decimal Precision,
    decimal Recall,
    decimal F1,
    MultitoolStateCounts States);

/// <summary>Associates one producer family with normalized Multitool metrics.</summary>
public sealed record ProducerMultitoolMetrics(
    string ProducerId,
    MultitoolMetrics Metrics);

/// <summary>Reports one full Multitool case projection.</summary>
public sealed record MultitoolCaseResult(
    string CaseId,
    string ProducerId,
    CaseInputHashes InputHashes,
    NormalizedInvocation Invocation,
    string RawArtifactRelativePath,
    bool InstrumentationStateMultisetPreserved,
    MultitoolMetrics Metrics,
    ImmutableArray<MultitoolRelationshipResult> RelationshipResults);

/// <summary>Reports the complete normalized external baseline.</summary>
public sealed record SarifMultitoolBaselineReport(
    EvaluationIdentity Evaluation,
    MultitoolToolEvidence Tool,
    MultitoolMetrics Aggregate,
    ImmutableArray<ProducerMultitoolMetrics> Producers,
    ImmutableArray<MultitoolCaseResult> Cases);

/// <summary>Builds the shared, stable relationship identifiers used by both reports.</summary>
public static class GroundTruthRelationshipFactory
{
    /// <summary>Creates positive pairs, lifecycle labels, and paired ambiguity groups.</summary>
    public static ImmutableArray<(string RelationshipId, GroundTruthRelationship GroundTruth)>
        Create(CorpusLabels labels)
    {
        ArgumentNullException.ThrowIfNull(labels);
        var values = ImmutableArray.CreateBuilder<(
            string RelationshipId,
            GroundTruthRelationship GroundTruth)>();
        LabelledPair[] pairs = labels.Pairs
            .OrderBy(item => item.BaselineKey, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateKey, StringComparer.Ordinal)
            .ToArray();
        for (var index = 0; index < pairs.Length; index++)
        {
            values.Add((
                Id("match", index),
                new GroundTruthRelationship(
                    "match",
                    pairs[index].BaselineKey,
                    pairs[index].CandidateKey,
                    Classification(pairs[index].Classification))));
        }

        AddLifecycle(values, "new", labels.ExpectedNew, isBaseline: false);
        AddLifecycle(values, "resolved", labels.ExpectedResolved, isBaseline: true);
        string[] baselineAmbiguous = labels.ExpectedAmbiguous
            .Where(item => item.StartsWith("baseline:", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] candidateAmbiguous = labels.ExpectedAmbiguous
            .Where(item => item.StartsWith("candidate:", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (baselineAmbiguous.Length != candidateAmbiguous.Length)
        {
            throw new InvalidDataException(
                "Ambiguity labels are not balanced across both inputs.");
        }

        for (var index = 0; index < baselineAmbiguous.Length; index++)
        {
            values.Add((
                Id("ambiguous", index),
                new GroundTruthRelationship(
                    "ambiguous",
                    baselineAmbiguous[index],
                    candidateAmbiguous[index],
                    "ambiguous")));
        }

        return values.OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    /// <summary>Creates globally unique report identifiers by prefixing the stable case id.</summary>
    public static ImmutableArray<(string RelationshipId, GroundTruthRelationship GroundTruth)>
        Create(string caseId, CorpusLabels labels)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caseId);
        return Create(labels)
            .Select(item => (
                $"{caseId}-{item.RelationshipId}",
                item.GroundTruth))
            .ToImmutableArray();
    }

    private static void AddLifecycle(
        ImmutableArray<(string RelationshipId, GroundTruthRelationship GroundTruth)>.Builder values,
        string kind,
        IEnumerable<string> keys,
        bool isBaseline)
    {
        string[] ordered = keys.Order(StringComparer.Ordinal).ToArray();
        for (var index = 0; index < ordered.Length; index++)
        {
            values.Add((
                Id(kind, index),
                new GroundTruthRelationship(
                    kind,
                    isBaseline ? ordered[index] : null,
                    isBaseline ? null : ordered[index],
                    kind)));
        }
    }

    private static string Id(string kind, int zeroBasedIndex) =>
        $"{kind}-{zeroBasedIndex + 1:D3}";

    private static string Classification(SarifRegress.Core.Matching.FindingClassification value) =>
        value switch
        {
            SarifRegress.Core.Matching.FindingClassification.Unchanged => "unchanged",
            SarifRegress.Core.Matching.FindingClassification.Moved => "moved",
            SarifRegress.Core.Matching.FindingClassification.Modified => "modified",
            _ => throw new InvalidDataException(
                $"A labelled pair cannot use classification '{value}'."),
        };
}

/// <summary>
/// Parses Multitool SARIF without trusting its generated GUIDs, timestamps, or result order.
/// </summary>
public sealed class MultitoolOutputParser
{
    private readonly ValidationLimits limits;

    /// <summary>Creates a bounded external-output parser.</summary>
    public MultitoolOutputParser(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>
    /// Time: O(r log r); Space: O(r), where r is the total number of SARIF results.
    /// </summary>
    public ParsedMultitoolOutput Parse(
        string baselinePath,
        string candidatePath,
        string rawOutputPath,
        string? approvedRoot = null)
    {
        ImmutableArray<InputResult> baseline = ReadInputResults(
            baselinePath,
            "baseline",
            approvedRoot: approvedRoot);
        ImmutableArray<InputResult> candidate = ReadInputResults(
            candidatePath,
            "candidate",
            approvedRoot: approvedRoot);
        ImmutableArray<OutputResult> output = ReadOutputResults(
            rawOutputPath,
            approvedRoot);
        if (output.Count(item => item.State != MultitoolState.Absent)
            != candidate.Length)
        {
            throw new InvalidDataException(
                "Multitool output does not contain exactly one current state per candidate result.");
        }

        var states = ImmutableSortedDictionary.CreateBuilder<string, MultitoolState>(
            StringComparer.Ordinal);
        var missing = ImmutableHashSet.CreateBuilder<string>(StringComparer.Ordinal);
        MapStates(
            candidate,
            output.Where(item => item.State != MultitoolState.Absent),
            states,
            missing);
        MapStates(
            baseline,
            output.Where(item => item.State == MultitoolState.Absent),
            states,
            missing,
            onlyMappedInputs: true);
        var locations = baseline.Concat(candidate)
            .ToImmutableSortedDictionary(
                item => item.FindingKey,
                item => item.Location,
                StringComparer.Ordinal);
        return new ParsedMultitoolOutput(
            states.ToImmutable(),
            missing.ToImmutable(),
            locations,
            BuildSignatureCorrespondences(baseline, candidate),
            InstrumentationStateStable: true);
    }

    /// <summary>
    /// Parses deterministic GUID-instrumented inputs and proves instrumentation did not alter
    /// the external tool's run-to-run state multiset.
    /// </summary>
    public ParsedMultitoolOutput ParseInstrumented(
        string instrumentedBaselinePath,
        string instrumentedCandidatePath,
        string instrumentedOutputPath,
        string uninstrumentedOutputPath,
        string? approvedRoot = null)
    {
        ImmutableArray<InputResult> baseline = ReadInputResults(
            instrumentedBaselinePath,
            "baseline",
            requireGuid: true,
            approvedRoot: approvedRoot);
        ImmutableArray<InputResult> candidate = ReadInputResults(
            instrumentedCandidatePath,
            "candidate",
            requireGuid: true,
            approvedRoot: approvedRoot);
        ImmutableArray<OutputResult> output = ReadOutputResults(
            instrumentedOutputPath,
            approvedRoot);
        ImmutableArray<OutputResult> originalOutput = ReadOutputResults(
            uninstrumentedOutputPath,
            approvedRoot);
        bool instrumentationStable = StateMultiset(output)
            .SequenceEqual(StateMultiset(originalOutput));
        if (output.Count(item => item.State != MultitoolState.Absent)
            != candidate.Length)
        {
            throw new InvalidDataException(
                "Instrumented Multitool output does not contain exactly one current state per candidate result.");
        }

        Dictionary<string, InputResult> baselineByGuid = ToGuidDictionary(
            baseline,
            "baseline");
        Dictionary<string, InputResult> candidateByGuid = ToGuidDictionary(
            candidate,
            "candidate");
        if (baselineByGuid.Keys.Intersect(
            candidateByGuid.Keys,
            StringComparer.Ordinal).Any())
        {
            throw new InvalidDataException(
                "Instrumented baseline and candidate result GUIDs are not side-disjoint.");
        }

        var states = ImmutableSortedDictionary.CreateBuilder<string, MultitoolState>(
            StringComparer.Ordinal);
        var previous = ImmutableSortedDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        var missing = ImmutableHashSet.CreateBuilder<string>(StringComparer.Ordinal);
        var observedOutputGuids = new HashSet<string>(StringComparer.Ordinal);
        foreach (OutputResult result in output)
        {
            if (result.Guid is null || !observedOutputGuids.Add(result.Guid))
            {
                throw new InvalidDataException(
                    "Instrumented Multitool output is missing a unique result guid.");
            }

            if (result.State == MultitoolState.Absent)
            {
                if (!baselineByGuid.TryGetValue(result.Guid, out InputResult? absent))
                {
                    throw new InvalidDataException(
                        "An absent Multitool result does not reference an instrumented baseline guid.");
                }

                states.Add(absent.FindingKey, result.State);
                continue;
            }

            if (!candidateByGuid.TryGetValue(result.Guid, out InputResult? current))
            {
                throw new InvalidDataException(
                    "A current Multitool result does not reference an instrumented candidate guid.");
            }

            states.Add(current.FindingKey, result.State);
            if (result.PreviousGuid is not null)
            {
                if (baselineByGuid.TryGetValue(
                    result.PreviousGuid,
                    out InputResult? prior))
                {
                    previous.Add(current.FindingKey, prior.FindingKey);
                    if (states.ContainsKey(prior.FindingKey))
                    {
                        throw new InvalidDataException(
                            "Multitool output maps one baseline result more than once.");
                    }

                    states.Add(prior.FindingKey, result.State);
                }
                else
                {
                    missing.Add(current.FindingKey);
                }
            }
            else if (result.State is MultitoolState.Unchanged or MultitoolState.Updated)
            {
                missing.Add(current.FindingKey);
            }
        }

        missing.UnionWith(candidate
            .Where(item => !states.ContainsKey(item.FindingKey))
            .Select(item => item.FindingKey));
        ImmutableSortedDictionary<string, string?> locations = baseline
            .Concat(candidate)
            .ToImmutableSortedDictionary(
                item => item.FindingKey,
                item => item.Location,
                StringComparer.Ordinal);
        return new ParsedMultitoolOutput(
            states.ToImmutable(),
            missing.ToImmutable(),
            locations,
            previous.ToImmutable(),
            instrumentationStable);
    }

    private ImmutableArray<InputResult> ReadInputResults(
        string path,
        string side,
        bool requireGuid = false,
        string? approvedRoot = null)
    {
        byte[] bytes = approvedRoot is null
            ? BoundedJsonFile.ReadBytes(path, limits.MaximumSarifBytes)
            : BoundedJsonFile.ReadBytes(
                path,
                limits.MaximumSarifBytes,
                approvedRoot);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            bytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        using JsonDocument document = JsonDocument.Parse(
            bytes,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = limits.MaximumJsonDepth,
            });
        BoundedJsonFile.EnsureStringBounds(
            document.RootElement,
            limits.MaximumStringCharacters);
        var results = ImmutableArray.CreateBuilder<InputResult>();
        JsonElement runs = document.RootElement.GetProperty("runs");
        var runIndex = 0;
        foreach (JsonElement run in runs.EnumerateArray())
        {
            RunProjection projection = RunProjection.Create(run);
            if (run.TryGetProperty("results", out JsonElement runResults))
            {
                var resultIndex = 0;
                foreach (JsonElement result in runResults.EnumerateArray())
                {
                    EnsureResultLimit(results.Count);
                    ResultSignature signature = ResultSignature.Create(result, projection);
                    string? guid = ReadGuid(result, "guid");
                    if (requireGuid && guid is null)
                    {
                        throw new InvalidDataException(
                            "An instrumented SARIF input result is missing its guid.");
                    }

                    results.Add(new InputResult(
                        $"{side}:{runIndex}:{resultIndex}",
                        signature.Hash,
                        signature.Location,
                        guid));
                    resultIndex++;
                }
            }

            runIndex++;
        }

        return results.ToImmutable();
    }

    private ImmutableArray<OutputResult> ReadOutputResults(
        string path,
        string? approvedRoot = null)
    {
        byte[] bytes = approvedRoot is null
            ? BoundedJsonFile.ReadBytes(path, limits.MaximumSarifBytes)
            : BoundedJsonFile.ReadBytes(
                path,
                limits.MaximumSarifBytes,
                approvedRoot);
        BoundedJsonFile.EnsureTokenBoundsAndUniqueProperties(
            bytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters);
        using JsonDocument document = JsonDocument.Parse(
            bytes,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = limits.MaximumJsonDepth,
            });
        BoundedJsonFile.EnsureStringBounds(
            document.RootElement,
            limits.MaximumStringCharacters);
        var results = ImmutableArray.CreateBuilder<OutputResult>();
        foreach (JsonElement run in document.RootElement
                     .GetProperty("runs")
                     .EnumerateArray())
        {
            RunProjection projection = RunProjection.Create(run);
            if (!run.TryGetProperty("results", out JsonElement runResults))
            {
                continue;
            }

            foreach (JsonElement result in runResults.EnumerateArray())
            {
                EnsureResultLimit(results.Count);
                MultitoolState state = ParseState(
                    result.TryGetProperty("baselineState", out JsonElement value)
                        ? value.GetString()
                        : null);
                results.Add(new OutputResult(
                    ResultSignature.Create(result, projection).Hash,
                    state,
                    ReadGuid(result, "guid"),
                    ReadPreviousGuid(result)));
            }
        }

        return results.ToImmutable();
    }

    private void EnsureResultLimit(int currentCount)
    {
        if (currentCount >= limits.MaximumResultsPerCase)
        {
            throw new InvalidDataException(
                $"SARIF result count exceeds the {limits.MaximumResultsPerCase}-result limit.");
        }
    }

    private static void MapStates(
        IEnumerable<InputResult> inputs,
        IEnumerable<OutputResult> outputs,
        ImmutableSortedDictionary<string, MultitoolState>.Builder states,
        ImmutableHashSet<string>.Builder missing,
        bool onlyMappedInputs = false)
    {
        Dictionary<string, OutputResult[]> outputGroups = outputs
            .GroupBy(item => item.Signature, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.OrderBy(item => item.State).ToArray(),
                StringComparer.Ordinal);
        foreach (IGrouping<string, InputResult> inputGroup in inputs.GroupBy(
                     item => item.Signature,
                     StringComparer.Ordinal))
        {
            InputResult[] inputValues = inputGroup
                .OrderBy(item => item.FindingKey, StringComparer.Ordinal)
                .ToArray();
            if (!outputGroups.TryGetValue(inputGroup.Key, out OutputResult[]? outputValues))
            {
                if (!onlyMappedInputs)
                {
                    missing.UnionWith(inputValues.Select(item => item.FindingKey));
                }

                continue;
            }

            MultitoolState[] distinctStates = outputValues
                .Select(item => item.State)
                .Distinct()
                .ToArray();
            if (outputValues.Length != inputValues.Length
                || distinctStates.Length != 1)
            {
                missing.UnionWith(inputValues.Select(item => item.FindingKey));
                continue;
            }

            foreach (InputResult input in inputValues)
            {
                states[input.FindingKey] = distinctStates[0];
            }
        }
    }

    private static ImmutableSortedDictionary<string, string>
        BuildSignatureCorrespondences(
            ImmutableArray<InputResult> baseline,
            ImmutableArray<InputResult> candidate)
    {
        Dictionary<string, InputResult[]> baselineGroups = baseline
            .GroupBy(item => item.Signature, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.ToArray(),
                StringComparer.Ordinal);
        var values = ImmutableSortedDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        foreach (IGrouping<string, InputResult> group in candidate.GroupBy(
                     item => item.Signature,
                     StringComparer.Ordinal))
        {
            InputResult[] current = group.ToArray();
            if (current.Length == 1
                && baselineGroups.TryGetValue(group.Key, out InputResult[]? prior)
                && prior.Length == 1)
            {
                values.Add(current[0].FindingKey, prior[0].FindingKey);
            }
        }

        return values.ToImmutable();
    }

    private static Dictionary<string, InputResult> ToGuidDictionary(
        IEnumerable<InputResult> results,
        string side)
    {
        var values = new Dictionary<string, InputResult>(StringComparer.Ordinal);
        foreach (InputResult result in results)
        {
            if (result.Guid is null || !values.TryAdd(result.Guid, result))
            {
                throw new InvalidDataException(
                    $"Instrumented {side} SARIF contains a missing or duplicate result guid.");
            }
        }

        return values;
    }

    private static IEnumerable<(MultitoolState State, int Count)> StateMultiset(
        IEnumerable<OutputResult> results) => results
        .GroupBy(item => item.State)
        .OrderBy(group => group.Key)
        .Select(group => (group.Key, group.Count()));

    private static string? ReadGuid(JsonElement result, string propertyName)
    {
        if (!result.TryGetProperty(propertyName, out JsonElement element)
            || element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? value = element.GetString();
        return Guid.TryParse(value, out Guid guid)
            ? guid.ToString("D")
            : throw new InvalidDataException(
                $"Multitool SARIF contains an invalid {propertyName} value.");
    }

    private static string? ReadPreviousGuid(JsonElement result)
    {
        if (!result.TryGetProperty("properties", out JsonElement properties)
            || !properties.TryGetProperty(
                "ResultMatching",
                out JsonElement matching)
            || !matching.TryGetProperty(
                "PreviousGuid",
                out JsonElement previous)
            || previous.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? value = previous.GetString();
        return Guid.TryParse(value, out Guid guid)
            ? guid.ToString("D")
            : throw new InvalidDataException(
                "Multitool SARIF contains an invalid ResultMatching.PreviousGuid value.");
    }

    private static MultitoolState ParseState(string? value) => value switch
    {
        "new" => MultitoolState.New,
        "absent" => MultitoolState.Absent,
        "unchanged" => MultitoolState.Unchanged,
        "updated" => MultitoolState.Updated,
        _ => MultitoolState.Unsupported,
    };

    private sealed record InputResult(
        string FindingKey,
        string Signature,
        string? Location,
        string? Guid);

    private sealed record OutputResult(
        string Signature,
        MultitoolState State,
        string? Guid,
        string? PreviousGuid);

    private sealed record RunProjection(
        ImmutableArray<string?> ArtifactUris,
        ImmutableArray<string?> RuleIds)
    {
        public static RunProjection Create(JsonElement run)
        {
            ImmutableArray<string?> artifacts = run.TryGetProperty(
                "artifacts",
                out JsonElement artifactArray)
                ? artifactArray.EnumerateArray()
                    .Select(item => item.TryGetProperty("location", out JsonElement location)
                        && location.TryGetProperty("uri", out JsonElement uri)
                            ? uri.GetString()
                            : null)
                    .ToImmutableArray()
                : [];
            ImmutableArray<string?> rules = [];
            if (run.TryGetProperty("tool", out JsonElement tool)
                && tool.TryGetProperty("driver", out JsonElement driver)
                && driver.TryGetProperty("rules", out JsonElement ruleArray))
            {
                rules = ruleArray.EnumerateArray()
                    .Select(item => item.TryGetProperty("id", out JsonElement id)
                        ? id.GetString()
                        : null)
                    .ToImmutableArray();
            }

            return new RunProjection(artifacts, rules);
        }
    }

    private sealed record ResultSignature(string Hash, string? Location)
    {
        public static ResultSignature Create(
            JsonElement result,
            RunProjection run)
        {
            string? rule = GetRule(result, run);
            string? message = GetMessage(result);
            string? location = GetLocation(result, run);
            string? region = GetRegion(result);
            byte[] projection = StableJson.Serialize(writer =>
            {
                writer.WriteStartObject();
                WriteOptional(writer, "rule", rule);
                WriteOptional(writer, "message", message);
                WriteOptional(writer, "location", location);
                WriteOptional(writer, "region", region);
                WriteFingerprintObject(writer, result, "fingerprints");
                WriteFingerprintObject(writer, result, "partialFingerprints");
                writer.WriteEndObject();
            });
            return new ResultSignature(
                Convert.ToHexString(SHA256.HashData(projection)).ToLowerInvariant(),
                location);
        }

        private static string? GetRule(JsonElement result, RunProjection run)
        {
            if (result.TryGetProperty("ruleId", out JsonElement ruleId))
            {
                return ruleId.GetString();
            }

            if (result.TryGetProperty("ruleIndex", out JsonElement ruleIndex)
                && ruleIndex.TryGetInt32(out int index)
                && index >= 0
                && index < run.RuleIds.Length)
            {
                return run.RuleIds[index];
            }

            return null;
        }

        private static string? GetMessage(JsonElement result)
        {
            if (!result.TryGetProperty("message", out JsonElement message))
            {
                return null;
            }

            foreach (string name in new[] { "text", "markdown", "id" })
            {
                if (message.TryGetProperty(name, out JsonElement value))
                {
                    return $"{name}:{value.GetString()}";
                }
            }

            return null;
        }

        private static string? GetLocation(JsonElement result, RunProjection run)
        {
            if (!TryGetPhysicalLocation(result, out JsonElement physical)
                || !physical.TryGetProperty("artifactLocation", out JsonElement artifact))
            {
                return null;
            }

            if (artifact.TryGetProperty("uri", out JsonElement uri))
            {
                return uri.GetString();
            }

            if (artifact.TryGetProperty("index", out JsonElement indexElement)
                && indexElement.TryGetInt32(out int index)
                && index >= 0
                && index < run.ArtifactUris.Length)
            {
                return run.ArtifactUris[index];
            }

            return null;
        }

        private static string? GetRegion(JsonElement result)
        {
            if (!TryGetPhysicalLocation(result, out JsonElement physical)
                || !physical.TryGetProperty("region", out JsonElement region))
            {
                return null;
            }

            return string.Join(
                ':',
                GetInteger(region, "startLine"),
                GetInteger(region, "startColumn"),
                GetInteger(region, "endLine"),
                GetInteger(region, "endColumn"));
        }

        private static bool TryGetPhysicalLocation(
            JsonElement result,
            out JsonElement physical)
        {
            physical = default;
            if (!result.TryGetProperty("locations", out JsonElement locations))
            {
                return false;
            }

            JsonElement.ArrayEnumerator enumerator = locations.EnumerateArray();
            return enumerator.MoveNext()
                && enumerator.Current.TryGetProperty(
                    "physicalLocation",
                    out physical);
        }

        private static string GetInteger(JsonElement value, string propertyName) =>
            value.TryGetProperty(propertyName, out JsonElement property)
                && property.TryGetInt32(out int integer)
                    ? integer.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : string.Empty;

        private static void WriteFingerprintObject(
            Utf8JsonWriter writer,
            JsonElement result,
            string propertyName)
        {
            writer.WriteStartObject(propertyName);
            if (result.TryGetProperty(propertyName, out JsonElement values)
                && values.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty property in values.EnumerateObject()
                             .OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    property.Value.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        private static void WriteOptional(
            Utf8JsonWriter writer,
            string name,
            string? value)
        {
            if (value is null)
            {
                writer.WriteNull(name);
            }
            else
            {
                writer.WriteString(name, value);
            }
        }
    }
}

/// <summary>Normalizes ground truth and parsed Multitool states without forcing unlike taxonomies.</summary>
public static class MultitoolRelationshipNormalizer
{
    /// <summary>Creates one explicit record for every ground-truth relationship.</summary>
    public static ImmutableArray<MultitoolRelationshipResult> Normalize(
        ValidatedHoldoutCase holdoutCase,
        ParsedMultitoolOutput parsed)
    {
        ArgumentNullException.ThrowIfNull(holdoutCase);
        ArgumentNullException.ThrowIfNull(parsed);
        return GroundTruthRelationshipFactory.Create(
                holdoutCase.Plan.Id,
                holdoutCase.Labels)
            .Select(item => NormalizeRelationship(holdoutCase, item, parsed))
            .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    /// <summary>
    /// Preserves every ground-truth unit when external execution or parsing fails.
    /// </summary>
    public static ImmutableArray<MultitoolRelationshipResult> NormalizeToolError(
        ValidatedHoldoutCase holdoutCase,
        string stableCode)
    {
        ArgumentNullException.ThrowIfNull(holdoutCase);
        ArgumentException.ThrowIfNullOrWhiteSpace(stableCode);
        return GroundTruthRelationshipFactory.Create(
                holdoutCase.Plan.Id,
                holdoutCase.Labels)
            .Select(item => NonComparable(
                item,
                MultitoolState.Error,
                "tool-error",
                stableCode))
            .OrderBy(item => item.RelationshipId, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static MultitoolRelationshipResult NormalizeRelationship(
        ValidatedHoldoutCase holdoutCase,
        (string RelationshipId, GroundTruthRelationship GroundTruth) item,
        ParsedMultitoolOutput parsed)
    {
        GroundTruthRelationship truth = item.GroundTruth;
        if (!parsed.InstrumentationStateStable)
        {
            return NonComparable(
                item,
                MultitoolState.Error,
                "tool-error",
                "MULTITOOL_INSTRUMENTATION_CHANGED_STATES");
        }

        string? stateKey = truth.Kind == "resolved"
            ? truth.BaselineKey
            : truth.CandidateKey;
        MultitoolState state = MultitoolState.Unsupported;
        bool hasState = stateKey is not null
            && parsed.StatesByFindingKey.TryGetValue(
                stateKey,
                out state);
        if (truth.Kind == "ambiguous")
        {
            return NonComparable(
                item,
                hasState ? state : MultitoolState.Unsupported,
                "multitool-does-not-express-ambiguity",
                hasState ? null : "MULTITOOL_STATE_UNAVAILABLE");
        }

        if (truth.Kind == "match"
            && IsPathAliasRelationship(holdoutCase, truth, parsed))
        {
            return NonComparable(
                item,
                hasState ? state : MultitoolState.Unsupported,
                "path-rebase-configuration-not-supported",
                hasState ? null : "MULTITOOL_STATE_UNAVAILABLE");
        }

        if (!hasState || stateKey is null)
        {
            return NonComparable(
                item,
                MultitoolState.Unsupported,
                "missing-correspondence-data",
                "MULTITOOL_CORRESPONDENCE_MISSING");
        }

        if (state is MultitoolState.Error or MultitoolState.Unsupported)
        {
            return NonComparable(
                item,
                state,
                state == MultitoolState.Error ? "tool-error" : "unsupported-sarif-shape",
                state == MultitoolState.Error
                    ? "MULTITOOL_EXECUTION_ERROR"
                    : "MULTITOOL_STATE_UNSUPPORTED");
        }

        if (truth.Kind == "match")
        {
            if (state == MultitoolState.New)
            {
                return Comparable(
                    item,
                    state,
                    taxonomyMapped: true,
                    mappedClassification: "new",
                    correct: false);
            }

            if (parsed.MissingCorrespondenceKeys.Contains(stateKey)
                || !parsed.PreviousKeysByCandidateKey.TryGetValue(
                    stateKey,
                    out string? previousKey))
            {
                return NonComparable(
                    item,
                    MultitoolState.Unsupported,
                    "missing-correspondence-data",
                    "MULTITOOL_CORRESPONDENCE_MISSING");
            }

            bool exactIdentity = string.Equals(
                truth.BaselineKey,
                previousKey,
                StringComparison.Ordinal);
            return Comparable(
                item,
                state,
                taxonomyMapped: state == MultitoolState.Unchanged,
                mappedClassification: state == MultitoolState.Unchanged
                    ? "unchanged"
                    : null,
                correct: exactIdentity);
        }

        if (truth.Kind == "new")
        {
            return Comparable(
                item,
                state,
                taxonomyMapped: state == MultitoolState.New,
                mappedClassification: state == MultitoolState.New ? "new" : null,
                correct: state == MultitoolState.New);
        }

        return Comparable(
            item,
            state,
            taxonomyMapped: state == MultitoolState.Absent,
            mappedClassification: state == MultitoolState.Absent ? "resolved" : null,
            correct: state == MultitoolState.Absent);
    }

    private static bool IsPathAliasRelationship(
        ValidatedHoldoutCase holdoutCase,
        GroundTruthRelationship truth,
        ParsedMultitoolOutput parsed)
    {
        if (!holdoutCase.Plan.Scenarios.Contains(
                "windows-posix-path-projection",
                StringComparer.Ordinal)
            || truth.BaselineKey is null
            || truth.CandidateKey is null)
        {
            return false;
        }

        parsed.LocationsByFindingKey.TryGetValue(
            truth.BaselineKey,
            out string? baseline);
        parsed.LocationsByFindingKey.TryGetValue(
            truth.CandidateKey,
            out string? candidate);
        return baseline is not null
            && candidate is not null
            && IsWindowsProjection(baseline) != IsWindowsProjection(candidate)
            && IsPosixProjection(baseline) != IsPosixProjection(candidate);
    }

    private static bool IsWindowsProjection(string value)
    {
        string path = value.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)
            ? value[8..]
            : value;
        return path.Length >= 3
            && char.IsAsciiLetter(path[0])
            && path[1] == ':'
            && path[2] is '/' or '\\';
    }

    private static bool IsPosixProjection(string value) =>
        value.StartsWith("/", StringComparison.Ordinal)
        || (value.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)
            && !IsWindowsProjection(value));

    private static MultitoolRelationshipResult Comparable(
        (string RelationshipId, GroundTruthRelationship GroundTruth) item,
        MultitoolState state,
        bool taxonomyMapped,
        string? mappedClassification,
        bool correct) => new(
        item.RelationshipId,
        item.GroundTruth,
        State(state),
        taxonomyMapped,
        mappedClassification,
        Comparable: true,
        "equivalent-state-semantics",
        correct,
        ErrorOrUnsupportedCode: null);

    private static MultitoolRelationshipResult NonComparable(
        (string RelationshipId, GroundTruthRelationship GroundTruth) item,
        MultitoolState state,
        string reason,
        string? code) => new(
        item.RelationshipId,
        item.GroundTruth,
        State(state),
        TaxonomyMapped: false,
        MappedClassification: null,
        Comparable: false,
        reason,
        Correct: null,
        ErrorOrUnsupportedCode: code);

    public static string State(MultitoolState state) => state switch
    {
        MultitoolState.New => "new",
        MultitoolState.Absent => "absent",
        MultitoolState.Unchanged => "unchanged",
        MultitoolState.Updated => "updated",
        MultitoolState.Error => "error",
        MultitoolState.Unsupported => "unsupported",
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };
}

/// <summary>Computes external baseline counts using only comparable identity semantics.</summary>
public static class MultitoolMetricsCalculator
{
    /// <summary>Computes one case without treating non-comparable records as failures.</summary>
    public static MultitoolMetrics Create(
        int labelledMatchRelationships,
        IEnumerable<MultitoolRelationshipResult> relationships)
    {
        MultitoolRelationshipResult[] values = relationships.ToArray();
        MultitoolRelationshipResult[] matchValues = values
            .Where(item => item.GroundTruth.Kind == "match")
            .ToArray();
        int comparable = matchValues.Count(item => item.Comparable);
        int truePositives = matchValues.Count(item =>
            item.Comparable
            && item.Correct == true);
        int falseNegatives = matchValues.Count(item =>
            item.Comparable
            && item.Correct == false);
        int falsePositives = values.Count(item =>
            item.Comparable
            && item.Correct == false
            && (item.GroundTruth.Kind == "match"
                && (item.MultitoolState is "unchanged" or "updated")
                || item.GroundTruth.Kind == "new"
                && (item.MultitoolState is "unchanged" or "updated")));
        decimal precision = Divide(truePositives, truePositives + falsePositives);
        decimal recall = Divide(truePositives, truePositives + falseNegatives);
        decimal f1 = precision + recall == 0
            ? 0
            : decimal.Round(
                2 * precision * recall / (precision + recall),
                6,
                MidpointRounding.ToEven);
        return new MultitoolMetrics(
            values.Length,
            labelledMatchRelationships,
            comparable,
            matchValues.Length - comparable,
            truePositives,
            falsePositives,
            falseNegatives,
            values.Count(item => item.MultitoolState == "error"),
            values.Count(item => item.MultitoolState == "unsupported"),
            precision,
            recall,
            f1,
            CountStates(values));
    }

    /// <summary>Aggregates counts and recomputes ratios from raw totals.</summary>
    public static MultitoolMetrics Aggregate(IEnumerable<MultitoolMetrics> metrics)
    {
        MultitoolMetrics[] values = metrics.ToArray();
        int tp = values.Sum(item => item.TruePositives);
        int fp = values.Sum(item => item.FalsePositives);
        int fn = values.Sum(item => item.FalseNegatives);
        decimal precision = Divide(tp, tp + fp);
        decimal recall = Divide(tp, tp + fn);
        decimal f1 = precision + recall == 0
            ? 0
            : decimal.Round(2 * precision * recall / (precision + recall), 6);
        return new MultitoolMetrics(
            values.Sum(item => item.GroundTruthUnits),
            values.Sum(item => item.LabelledRelationships),
            values.Sum(item => item.ComparableRelationships),
            values.Sum(item => item.NonComparableRelationships),
            tp,
            fp,
            fn,
            values.Sum(item => item.Errors),
            values.Sum(item => item.Unsupported),
            precision,
            recall,
            f1,
            new MultitoolStateCounts(
                values.Sum(item => item.States.New),
                values.Sum(item => item.States.Absent),
                values.Sum(item => item.States.Unchanged),
                values.Sum(item => item.States.Updated),
                values.Sum(item => item.States.Error),
                values.Sum(item => item.States.Unsupported)));
    }

    private static MultitoolStateCounts CountStates(
        IEnumerable<MultitoolRelationshipResult> values)
    {
        string[] states = values.Select(item => item.MultitoolState).ToArray();
        return new MultitoolStateCounts(
            states.Count(item => item == "new"),
            states.Count(item => item == "absent"),
            states.Count(item => item == "unchanged"),
            states.Count(item => item == "updated"),
            states.Count(item => item == "error"),
            states.Count(item => item == "unsupported"));
    }

    private static decimal Divide(int numerator, int denominator) => denominator == 0
        ? 1
        : decimal.Round((decimal)numerator / denominator, 6);
}

/// <summary>Normalizes generated tool help/version text for cross-platform evidence hashes.</summary>
public static class ToolOutputNormalizer
{
    /// <summary>Hashes LF-normalized stdout and stderr separated by one NUL byte.</summary>
    public static string ComputeSha256(string standardOutput, string standardError)
    {
        string normalizedOutput = NormalizeNewlines(standardOutput);
        string normalizedError = NormalizeNewlines(standardError);
        byte[] bytes = Encoding.UTF8.GetBytes(
            normalizedOutput + "\0" + normalizedError);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    /// <summary>Converts CRLF and bare CR to LF without other rewriting.</summary>
    public static string NormalizeNewlines(string value) => value
        .Replace("\r\n", "\n", StringComparison.Ordinal)
        .Replace('\r', '\n');
}

/// <summary>
/// Creates artifact-only SARIF copies with deterministic, side-disjoint result GUIDs so
/// Multitool can expose exact prior-result correspondence.
/// </summary>
public sealed class MultitoolSarifInstrumenter
{
    private static readonly byte[] GuidDomain = Encoding.ASCII.GetBytes(
        "sarifregress/multitool-instrumentation/v1\0");

    private readonly ValidationLimits limits;

    /// <summary>Creates a bounded instrumenter.</summary>
    public MultitoolSarifInstrumenter(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>Writes deterministic baseline and candidate copies without changing committed inputs.</summary>
    public void Instrument(
        string baselineInputPath,
        string candidateInputPath,
        string baselineOutputPath,
        string candidateOutputPath,
        string? inputApprovedRoot = null)
    {
        InstrumentSide(
            baselineInputPath,
            baselineOutputPath,
            "baseline",
            inputApprovedRoot);
        InstrumentSide(
            candidateInputPath,
            candidateOutputPath,
            "candidate",
            inputApprovedRoot);
    }

    private void InstrumentSide(
        string inputPath,
        string outputPath,
        string side,
        string? inputApprovedRoot)
    {
        JsonNode root = BoundedJsonFile.ReadNode(
            inputPath,
            limits.MaximumSarifBytes,
            limits.MaximumJsonDepth,
            limits.MaximumStringCharacters,
            inputApprovedRoot);
        if (root is not JsonObject rootObject
            || rootObject["runs"] is not JsonArray runs)
        {
            throw new InvalidDataException(
                "SARIF instrumentation requires a root runs array.");
        }

        var resultCount = 0;
        for (var runIndex = 0; runIndex < runs.Count; runIndex++)
        {
            if (runs[runIndex] is not JsonObject run
                || run["results"] is not JsonArray results)
            {
                continue;
            }

            for (var resultIndex = 0; resultIndex < results.Count; resultIndex++)
            {
                if (resultCount >= limits.MaximumResultsPerCase)
                {
                    throw new InvalidDataException(
                        "SARIF instrumentation exceeded the per-case result limit.");
                }

                if (results[resultIndex] is not JsonObject result)
                {
                    throw new InvalidDataException(
                        "SARIF instrumentation encountered a non-object result.");
                }

                result["guid"] = DeterministicGuid(side, runIndex, resultIndex);
                if (result["properties"] is JsonObject properties)
                {
                    properties.Remove("ResultMatching");
                }

                resultCount++;
            }
        }

        byte[] bytes = StableJson.Serialize(writer => root.WriteTo(writer));
        if (bytes.LongLength > limits.MaximumSarifBytes)
        {
            throw new InvalidDataException(
                "Instrumented SARIF exceeds the external-output byte limit.");
        }

        StableJson.WriteFile(outputPath, bytes);
    }

    private static string DeterministicGuid(
        string side,
        int runIndex,
        int resultIndex)
    {
        byte[] value = Encoding.ASCII.GetBytes(
            $"{side}:{runIndex}:{resultIndex}");
        byte[] material = new byte[GuidDomain.Length + value.Length];
        GuidDomain.CopyTo(material, 0);
        value.CopyTo(material, GuidDomain.Length);
        byte[] digest = SHA256.HashData(material);
        digest[6] = (byte)((digest[6] & 0x0f) | 0x50);
        digest[8] = (byte)((digest[8] & 0x3f) | 0x80);
        string hex = Convert.ToHexString(digest.AsSpan(0, 16)).ToLowerInvariant();
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..32]}";
    }
}

/// <summary>Invokes the exact pinned Multitool and preserves raw output below the artifact root.</summary>
public sealed partial class MultitoolRunner
{
    public const string ExactVersion = "5.5.0";
    public const string PackageId = "Sarif.Multitool";
    public const string ProjectUrl = "https://github.com/microsoft/sarif-sdk";
    public const string SourceCommitSha = "e68c02f86ac02bb9acb3b9da6c3de2291d5b0e2a";
    public const string PackageUrl =
        "https://api.nuget.org/v3-flatcontainer/sarif.multitool/"
        + ExactVersion
        + "/sarif.multitool."
        + ExactVersion
        + ".nupkg";
    public const string PackageSha256 =
        "2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149";
    public const long PackageSizeBytes = 33_705_414;

    private readonly BoundedProcessRunner processRunner;
    private readonly ValidationLimits limits;
    private readonly MultitoolSarifInstrumenter instrumenter;

    /// <summary>Creates a bounded external baseline runner.</summary>
    public MultitoolRunner(
        BoundedProcessRunner? processRunner = null,
        ValidationLimits? limits = null)
    {
        this.processRunner = processRunner ?? new BoundedProcessRunner();
        this.limits = limits ?? ValidationLimits.Default;
        instrumenter = new MultitoolSarifInstrumenter(this.limits);
    }

    /// <summary>Verifies generated help and version output from the installed package.</summary>
    public async ValueTask<MultitoolToolEvidence> VerifyToolAsync(
        string multitoolPath,
        string expectedVersion,
        string repositoryRoot,
        string outputRoot,
        CancellationToken cancellationToken = default)
    {
        if (!string.Equals(expectedVersion, ExactVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Multitool version must be the repository-pinned exact version {ExactVersion}.");
        }

        ToolCommand command = ToolCommand.Create(multitoolPath);
        ProcessExecutionResult version = await RunAsync(
                command,
                ["version"],
                repositoryRoot,
                cancellationToken)
            .ConfigureAwait(false);
        ProcessExecutionResult help = await RunAsync(
                command,
                ["match-results-forward", "--help"],
                repositoryRoot,
                cancellationToken)
            .ConfigureAwait(false);
        WriteRawText(outputRoot, "raw/multitool/version.stdout.txt", version.StandardOutput);
        WriteRawText(outputRoot, "raw/multitool/version.stderr.txt", version.StandardError);
        WriteRawText(outputRoot, "raw/multitool/help.stdout.txt", help.StandardOutput);
        WriteRawText(outputRoot, "raw/multitool/help.stderr.txt", help.StandardError);
        if (version.ExitCode != 0 || help.ExitCode != 0)
        {
            throw new InvalidDataException(
                "Pinned Multitool help or version generation failed.");
        }

        string versionText = version.StandardOutput + "\n" + version.StandardError;
        if (!Regex.IsMatch(
            versionText,
            $@"(?<![0-9.]){Regex.Escape(expectedVersion)}(?![0-9.])",
            RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                "Installed Multitool version output does not identify the pinned exact version.");
        }

        string helpText = help.StandardOutput + "\n" + help.StandardError;
        foreach (string required in new[]
                 {
                     "match-results-forward",
                     "--previous",
                     "--output-file-path",
                 })
        {
            if (!helpText.Contains(required, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Generated Multitool help does not contain required syntax '{required}'.");
            }
        }

        return new MultitoolToolEvidence(
            "Microsoft SARIF Multitool",
            PackageId,
            ExactVersion,
            ProjectUrl,
            SourceCommitSha,
            PackageUrl,
            PackageSha256,
            PackageSizeBytes,
            "MIT",
            ToolOutputNormalizer.ComputeSha256(
                help.StandardOutput,
                help.StandardError),
            ToolOutputNormalizer.ComputeSha256(
                version.StandardOutput,
                version.StandardError));
    }

    /// <summary>Runs one complete case and returns its normalized invocation and raw path.</summary>
    public async ValueTask<MultitoolCaseExecution> RunCaseAsync(
            string multitoolPath,
            ValidatedHoldoutCase holdoutCase,
            string repositoryRoot,
            string outputRoot,
            CancellationToken cancellationToken = default)
    {
        ToolCommand command = ToolCommand.Create(multitoolPath);
        MultitoolCaseExecution execution = DescribeCaseExecution(
            command,
            holdoutCase.Plan.Id);
        string baseline = StablePath.Resolve(
            repositoryRoot,
            holdoutCase.Plan.Paths.BaselineSarif);
        string candidate = StablePath.Resolve(
            repositoryRoot,
            holdoutCase.Plan.Paths.CandidateSarif);
        string rawPrefix = $"raw/multitool/{holdoutCase.Plan.Id}";
        string instrumentedBaselineRelative = rawPrefix + ".instrumented-baseline.sarif";
        string instrumentedCandidateRelative = rawPrefix + ".instrumented-candidate.sarif";
        string instrumentedOutputRelative = execution.RawPath;
        string uninstrumentedOutputRelative = execution.UninstrumentedRawPath;
        string instrumentedBaseline = ResolveOutput(
            outputRoot,
            instrumentedBaselineRelative);
        string instrumentedCandidate = ResolveOutput(
            outputRoot,
            instrumentedCandidateRelative);
        string instrumentedOutput = ResolveOutput(
            outputRoot,
            instrumentedOutputRelative);
        string uninstrumentedOutput = ResolveOutput(
            outputRoot,
            uninstrumentedOutputRelative);
        Directory.CreateDirectory(Path.GetDirectoryName(instrumentedOutput)!);
        instrumenter.Instrument(
            baseline,
            candidate,
            instrumentedBaseline,
            instrumentedCandidate,
            repositoryRoot);
        await ExecuteMatchAsync(
                command,
                baseline,
                candidate,
                uninstrumentedOutput,
                rawPrefix + ".uninstrumented",
                repositoryRoot,
                outputRoot,
                holdoutCase.Plan.Id,
                cancellationToken)
            .ConfigureAwait(false);
        await ExecuteMatchAsync(
                command,
                instrumentedBaseline,
                instrumentedCandidate,
                instrumentedOutput,
                rawPrefix + ".instrumented",
                repositoryRoot,
                outputRoot,
                holdoutCase.Plan.Id,
                cancellationToken)
            .ConfigureAwait(false);

        return execution;
    }

    /// <summary>Builds the exact stable invocation before external execution begins.</summary>
    public MultitoolCaseExecution DescribeCaseExecution(
        string multitoolPath,
        string caseId) => DescribeCaseExecution(
        ToolCommand.Create(multitoolPath),
        caseId);

    /// <summary>
    /// Ensures failed and timed-out cases retain bounded raw evidence file slots.
    /// </summary>
    public string PreserveCaseFailureEvidence(
        string outputRoot,
        string caseId,
        string stableCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stableCode);
        string rawPrefix = $"raw/multitool/{caseId}";
        foreach (string suffix in new[]
                 {
                     ".uninstrumented.stdout.txt",
                     ".uninstrumented.stderr.txt",
                     ".instrumented.stdout.txt",
                     ".instrumented.stderr.txt",
                 })
        {
            string path = ResolveOutput(outputRoot, rawPrefix + suffix);
            if (!File.Exists(path))
            {
                WriteRawText(outputRoot, rawPrefix + suffix, string.Empty);
            }
        }

        string failurePath = rawPrefix + ".failure-code.txt";
        WriteRawText(outputRoot, failurePath, stableCode + "\n");
        return failurePath;
    }

    private static MultitoolCaseExecution DescribeCaseExecution(
        ToolCommand command,
        string caseId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caseId);
        string rawPrefix = $"raw/multitool/{caseId}";
        string instrumentedBaselineRelative = rawPrefix + ".instrumented-baseline.sarif";
        string instrumentedCandidateRelative = rawPrefix + ".instrumented-candidate.sarif";
        string instrumentedOutputRelative = rawPrefix + ".instrumented-output.sarif";
        string uninstrumentedOutputRelative = rawPrefix + ".uninstrumented-output.sarif";
        ImmutableArray<string> normalizedArguments = command.PrefixArguments.AddRange(
        [
            "match-results-forward",
            instrumentedCandidateRelative,
            "--previous",
            instrumentedBaselineRelative,
            "--output-file-path",
            instrumentedOutputRelative,
        ]);
        return new MultitoolCaseExecution(
            new NormalizedInvocation(
                ".",
                command.NormalizedExecutable,
                normalizedArguments),
            instrumentedOutputRelative,
            uninstrumentedOutputRelative);
    }

    private async ValueTask ExecuteMatchAsync(
        ToolCommand command,
        string baselinePath,
        string candidatePath,
        string outputPath,
        string rawEvidencePrefix,
        string repositoryRoot,
        string outputRoot,
        string caseId,
        CancellationToken cancellationToken)
    {
        if (File.Exists(outputPath))
        {
            File.Delete(outputPath);
        }

        ProcessExecutionResult result = await RunAsync(
                command,
                [
                    "match-results-forward",
                    candidatePath,
                    "--previous",
                    baselinePath,
                    "--output-file-path",
                    outputPath,
                ],
                repositoryRoot,
                cancellationToken)
            .ConfigureAwait(false);
        WriteRawText(
            outputRoot,
            rawEvidencePrefix + ".stdout.txt",
            result.StandardOutput);
        WriteRawText(
            outputRoot,
            rawEvidencePrefix + ".stderr.txt",
            result.StandardError);
        if (result.ExitCode != 0)
        {
            throw new InvalidDataException(
                $"Multitool execution failed for case '{caseId}'.");
        }

        try
        {
            if (new FileInfo(outputPath).Length > limits.MaximumSarifBytes)
            {
                File.Delete(outputPath);
                WriteRawText(
                    outputRoot,
                    rawEvidencePrefix + ".output-omitted.txt",
                    "MULTITOOL_RAW_OUTPUT_SIZE_LIMIT\n");
                throw new InvalidDataException(
                    $"Multitool output for case '{caseId}' exceeded its byte limit.");
            }

            BoundedJsonFile.ReadBytes(
                outputPath,
                limits.MaximumSarifBytes,
                outputRoot);
        }
        catch
        {
            RemoveUnsafeOutput(outputPath);
            throw;
        }
    }

    private async ValueTask<ProcessExecutionResult> RunAsync(
        ToolCommand command,
        ImmutableArray<string> arguments,
        string repositoryRoot,
        CancellationToken cancellationToken)
    {
        var invocation = new ProcessInvocation(
            command.FileName,
            command.PrefixArguments.AddRange(arguments),
            repositoryRoot,
            limits.ProcessTimeout,
            limits.MaximumProcessOutputCharacters);
        return await processRunner.RunAsync(invocation, cancellationToken)
            .ConfigureAwait(false);
    }

    private static void WriteRawText(
        string outputRoot,
        string relativePath,
        string value)
    {
        string path = ResolveOutput(outputRoot, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, value, new UTF8Encoding(false, true));
    }

    private static void RemoveUnsafeOutput(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Directory.Delete(path);
                }
                else
                {
                    File.Delete(path);
                }
            }
        }
        catch (Exception exception) when (exception is
            FileNotFoundException or
            DirectoryNotFoundException)
        {
            // The rejected path disappeared after the fixed-handle open failed.
        }
    }

    private static string ResolveOutput(string outputRoot, string relativePath)
    {
        StablePath.RequireRepositoryRelative(relativePath, "raw artifact path");
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outputRoot));
        string path = Path.GetFullPath(
            relativePath.Replace('/', Path.DirectorySeparatorChar),
            root);
        if (!path.StartsWith(
            root + Path.DirectorySeparatorChar,
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal))
        {
            throw new InvalidDataException("A raw artifact path escaped output-root.");
        }

        return path;
    }

    private sealed record ToolCommand(
        string FileName,
        string NormalizedExecutable,
        ImmutableArray<string> PrefixArguments)
    {
        public static ToolCommand Create(string path)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            string fileName = Path.GetFileNameWithoutExtension(path);
            if (string.Equals(fileName, "dotnet", StringComparison.OrdinalIgnoreCase))
            {
                return new ToolCommand(
                    path,
                    "dotnet",
                    ["tool", "run", "sarif", "--"]);
            }

            if (!string.Equals(fileName, "sarif", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "--multitool-path must identify direct sarif[.exe] or the dotnet host.");
            }

            return new ToolCommand(path, "sarif", []);
        }
    }
}
