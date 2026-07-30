using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Security;
using SarifRegress.Match;
using SarifRegress.Sarif.Configuration;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.Cli.Corpus;

/// <summary>
/// Defines one bounded deterministic corpus execution.
/// </summary>
public sealed record CorpusRunRequest
{
    /// <summary>
    /// Initializes a corpus request.
    /// </summary>
    /// <param name="corpusRoot">The directory containing <c>cases</c>.</param>
    /// <param name="thresholds">Optional quality gates.</param>
    /// <param name="limits">Optional untrusted-input limits.</param>
    public CorpusRunRequest(
        string corpusRoot,
        CorpusThresholds? thresholds = null,
        ResourceLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(corpusRoot);
        CorpusRoot = Path.GetFullPath(corpusRoot);
        Thresholds = thresholds ?? CorpusThresholds.Mvp;
        Limits = limits ?? ResourceLimits.Default;
        Thresholds.Validate();
        Limits.Validate();
    }

    /// <summary>
    /// Gets the absolute corpus root used only for local I/O.
    /// </summary>
    public string CorpusRoot { get; }

    /// <summary>
    /// Gets corpus quality gates.
    /// </summary>
    public CorpusThresholds Thresholds { get; }

    /// <summary>
    /// Gets untrusted-input bounds.
    /// </summary>
    public ResourceLimits Limits { get; }
}

/// <summary>
/// Enumerates and evaluates tracked corpus cases in ordinal order.
/// </summary>
public sealed class CorpusRunner
{
    /// <summary>
    /// Gets the stable corpus metrics schema version.
    /// </summary>
    public const string ReportSchemaVersion = "1";

    private const int StreamBufferBytes = 64 * 1024;

    /// <summary>
    /// Ingests, matches, and evaluates every case under the corpus root.
    /// </summary>
    /// <param name="request">The bounded corpus request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The complete deterministic evaluation.</returns>
    public async ValueTask<CorpusRunResult> RunAsync(
        CorpusRunRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        string casesRoot = Path.Combine(request.CorpusRoot, "cases");
        if (!Directory.Exists(casesRoot))
        {
            throw new DirectoryNotFoundException(
                "The corpus root does not contain a cases directory.");
        }

        var boundedCaseDirectories = new List<string>();
        foreach (var directory in Directory.EnumerateDirectories(casesRoot))
        {
            if (boundedCaseDirectories.Count >= request.Limits.MaximumRuns)
            {
                throw new InvalidDataException(
                    $"The corpus exceeds the {request.Limits.MaximumRuns}-case limit.");
            }

            boundedCaseDirectories.Add(directory);
        }

        string[] caseDirectories = boundedCaseDirectories
            .OrderBy(
                directory => Path.GetFileName(directory) ?? string.Empty,
                StringComparer.Ordinal)
            .ToArray();
        if (caseDirectories.Length == 0)
        {
            throw new InvalidDataException(
                "The corpus must contain at least one case.");
        }

        var caseRuns = ImmutableArray.CreateBuilder<CorpusCaseRun>(
            caseDirectories.Length);
        var evaluations = ImmutableArray.CreateBuilder<CorpusCaseEvaluation>(
            caseDirectories.Length);
        foreach (var caseDirectory in caseDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await RunCaseAsync(
                    caseDirectory,
                    request.Limits,
                    cancellationToken)
                .ConfigureAwait(false);
            caseRuns.Add(result.CaseRun);
            evaluations.Add(
                new CorpusCaseEvaluation(
                    result.CaseRun.CaseName,
                    result.CaseRun.Metrics));
        }

        var aggregate = CorpusEvaluator.Aggregate(evaluations);
        var failures = CorpusQualityGate.Evaluate(
            caseRuns,
            aggregate.Aggregate,
            request.Thresholds);
        return new CorpusRunResult(
            ReportSchemaVersion,
            request.Thresholds,
            caseRuns.ToImmutable(),
            aggregate.Aggregate,
            failures);
    }

    private static async ValueTask<CaseExecution> RunCaseAsync(
        string caseDirectory,
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
        var caseName = Path.GetFileName(caseDirectory);
        if (string.IsNullOrWhiteSpace(caseName))
        {
            throw new InvalidDataException(
                "A corpus case directory has no stable name.");
        }

        EnsureRegularDirectory(caseDirectory, caseName);
        string labelsPath = RequiredRegularFile(
            caseDirectory,
            "labels.json",
            caseName);
        string baselinePath = RequiredRegularFile(
            caseDirectory,
            "baseline.sarif",
            caseName);
        string candidatePath = RequiredRegularFile(
            caseDirectory,
            "candidate.sarif",
            caseName);
        CorpusLabels labels = CorpusLabelReader.Read(labelsPath, limits);
        var configuration = await ReadConfigurationAsync(
                caseDirectory,
                limits,
                cancellationToken)
            .ConfigureAwait(false);
        var repositoryContext = CreateRepositoryContext(configuration);
        var ingestor = new SarifIngestor(repositoryContext);
        var baseline = await IngestAsync(
                ingestor,
                baselinePath,
                InputKind.Baseline,
                $"{caseName}/baseline.sarif",
                configuration,
                cancellationToken)
            .ConfigureAwait(false);
        var candidate = await IngestAsync(
                ingestor,
                candidatePath,
                InputKind.Candidate,
                $"{caseName}/candidate.sarif",
                configuration,
                cancellationToken)
            .ConfigureAwait(false);

        var observedInvalid = new[]
        {
            (Input: InputKind.Baseline, IsInvalid: !baseline.IsValid),
            (Input: InputKind.Candidate, IsInvalid: !candidate.IsValid),
        }
            .Where(item => item.IsInvalid)
            .Select(item => item.Input)
            .Order()
            .ToImmutableArray();
        var expectedInvalid = labels.ExpectedInvalidInputs
            .Order()
            .ToImmutableArray();
        var inputExpectationsMatch = observedInvalid.SequenceEqual(expectedInvalid);

        CorpusCaseEvaluation evaluation;
        CorpusCaseArtifact artifact;
        if (observedInvalid.Length > 0)
        {
            EnsureInvalidCaseHasNoFindingLabels(caseName, labels);
            evaluation = CorpusEvaluator.Evaluate(
                caseName,
                labels,
                []);
            artifact =
                CorpusCaseArtifactSerializer.CreateInvalidInputDiagnostics(
                    caseName,
                    baseline,
                    candidate);
        }
        else
        {
            ValidateLabelGraph(
                caseName,
                labels,
                baseline.ComparisonInput.Findings.Select(item => item.FindingKey),
                candidate.ComparisonInput.Findings.Select(item => item.FindingKey));
            var matchResult = new FindingMatcher().Match(
                baseline.ComparisonInput,
                candidate.ComparisonInput,
                configuration);
            evaluation = CorpusEvaluator.Evaluate(
                caseName,
                labels,
                matchResult.Decisions);
            artifact = CorpusCaseArtifactSerializer.CreateComparison(
                caseName,
                matchResult);
        }

        var metrics = evaluation.Metrics;
        var passed = inputExpectationsMatch
            && metrics.FalsePositives == 0
            && metrics.FalseNegatives == 0
            && metrics.ExpectationsSatisfied;
        return new CaseExecution(
            new CorpusCaseRun(
                caseName,
                expectedInvalid,
                observedInvalid,
                artifact,
                metrics,
                passed));
    }

    private static async ValueTask<SarifRegressConfiguration>
        ReadConfigurationAsync(
            string caseDirectory,
            ResourceLimits limits,
            CancellationToken cancellationToken)
    {
        string path = Path.Combine(caseDirectory, "config.json");
        SarifRegressConfiguration configuration;
        if (!File.Exists(path))
        {
            configuration = SarifRegressConfiguration.Default;
        }
        else
        {
            EnsureRegularFile(
                path,
                Path.GetFileName(caseDirectory) ?? "<unknown>");
            await using var stream = OpenInput(path);
            var result = await new SarifConfigurationReader(limits)
                .ReadAsync(stream, cancellationToken)
                .ConfigureAwait(false);
            if (!result.IsValid)
            {
                throw new InvalidDataException(
                    $"Corpus case '{Path.GetFileName(caseDirectory)}' has an invalid configuration.");
            }

            configuration = result.Configuration!;
        }

        string? repositoryRoot = configuration.RepositoryRoot;
        if (repositoryRoot is not null)
        {
            repositoryRoot = Path.GetFullPath(repositoryRoot, caseDirectory);
            if (!Directory.Exists(repositoryRoot))
            {
                throw new InvalidDataException(
                    $"Corpus case '{Path.GetFileName(caseDirectory)}' repository root does not exist.");
            }
        }

        return new SarifRegressConfiguration(
            configuration.SchemaVersion,
            repositoryRoot,
            configuration.PathRebases,
            configuration.PathAliases,
            configuration.RuleAliases,
            configuration.Matching,
            configuration.Policy,
            configuration.Reporting,
            configuration.Limits);
    }

    private static IRepositoryContext? CreateRepositoryContext(
        SarifRegressConfiguration configuration)
    {
        return configuration.Matching.EnableRepositoryContext
            && configuration.RepositoryRoot is not null
                ? new FileSystemRepositoryContext(
                    configuration.RepositoryRoot,
                    configuration.Limits)
                : null;
    }

    private static async ValueTask<SarifIngestionResult> IngestAsync(
        SarifIngestor ingestor,
        string path,
        InputKind input,
        string logicalName,
        SarifRegressConfiguration configuration,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenInput(path);
        return await ingestor.IngestAsync(
                stream,
                new SarifIngestionRequest(input, logicalName, configuration),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static FileStream OpenInput(string path) =>
        new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            StreamBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static void ValidateLabelGraph(
        string caseName,
        CorpusLabels labels,
        IEnumerable<string> baselineFindingKeys,
        IEnumerable<string> candidateFindingKeys)
    {
        var baselineKeys = baselineFindingKeys.ToHashSet(StringComparer.Ordinal);
        var candidateKeys = candidateFindingKeys.ToHashSet(StringComparer.Ordinal);
        var coveredBaseline = new HashSet<string>(StringComparer.Ordinal);
        var coveredCandidate = new HashSet<string>(StringComparer.Ordinal);

        foreach (var pair in labels.Pairs)
        {
            RequireKnownKey(caseName, "baseline", pair.BaselineKey, baselineKeys);
            RequireKnownKey(caseName, "candidate", pair.CandidateKey, candidateKeys);
            RequireSingleLabel(caseName, pair.BaselineKey, coveredBaseline);
            RequireSingleLabel(caseName, pair.CandidateKey, coveredCandidate);
        }

        foreach (var key in labels.ExpectedResolved)
        {
            RequireKnownKey(caseName, "baseline", key, baselineKeys);
            RequireSingleLabel(caseName, key, coveredBaseline);
        }

        foreach (var key in labels.ExpectedNew)
        {
            RequireKnownKey(caseName, "candidate", key, candidateKeys);
            RequireSingleLabel(caseName, key, coveredCandidate);
        }

        foreach (var key in labels.ExpectedAmbiguous)
        {
            if (baselineKeys.Contains(key))
            {
                RequireSingleLabel(caseName, key, coveredBaseline);
            }
            else if (candidateKeys.Contains(key))
            {
                RequireSingleLabel(caseName, key, coveredCandidate);
            }
            else
            {
                throw new InvalidDataException(
                    $"Corpus case '{caseName}' labels unknown ambiguous finding '{key}'.");
            }
        }

        EnsureCompleteCoverage(caseName, "baseline", baselineKeys, coveredBaseline);
        EnsureCompleteCoverage(caseName, "candidate", candidateKeys, coveredCandidate);
    }

    private static void RequireKnownKey(
        string caseName,
        string side,
        string key,
        IReadOnlySet<string> knownKeys)
    {
        if (!knownKeys.Contains(key))
        {
            throw new InvalidDataException(
                $"Corpus case '{caseName}' labels unknown {side} finding '{key}'.");
        }
    }

    private static void RequireSingleLabel(
        string caseName,
        string key,
        ISet<string> covered)
    {
        if (!covered.Add(key))
        {
            throw new InvalidDataException(
                $"Corpus case '{caseName}' labels finding '{key}' more than once.");
        }
    }

    private static void EnsureCompleteCoverage(
        string caseName,
        string side,
        IReadOnlySet<string> known,
        IReadOnlySet<string> covered)
    {
        var missing = known
            .Where(key => !covered.Contains(key))
            .Order(StringComparer.Ordinal)
            .FirstOrDefault();
        if (missing is not null)
        {
            throw new InvalidDataException(
                $"Corpus case '{caseName}' omits {side} finding '{missing}'.");
        }
    }

    private static void EnsureInvalidCaseHasNoFindingLabels(
        string caseName,
        CorpusLabels labels)
    {
        if (!labels.Pairs.IsEmpty
            || labels.ExpectedAmbiguous.Count > 0
            || labels.ExpectedResolved.Count > 0
            || labels.ExpectedNew.Count > 0)
        {
            throw new InvalidDataException(
                $"Malformed corpus case '{caseName}' cannot label findings.");
        }
    }

    private static string RequiredRegularFile(
        string caseDirectory,
        string fileName,
        string caseName)
    {
        string path = Path.Combine(caseDirectory, fileName);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"Corpus case '{caseName}' is missing {fileName}.",
                path);
        }

        EnsureRegularFile(path, caseName);
        return path;
    }

    private static void EnsureRegularDirectory(string path, string caseName)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Corpus case '{caseName}' cannot be a symbolic link or reparse point.");
        }
    }

    private static void EnsureRegularFile(string path, string caseName)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Corpus case '{caseName}' cannot use symbolic-link fixtures.");
        }
    }

    private sealed record CaseExecution(CorpusCaseRun CaseRun);
}
