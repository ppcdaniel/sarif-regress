using System.Collections.Immutable;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Security;

namespace SarifRegress.Validation;

/// <summary>Runs the frozen SarifRegress corpus adapter over the separate holdout root.</summary>
public sealed class SarifRegressHoldoutEvaluator
{
    private readonly HoldoutCorpusRunnerAdapter corpusRunner;

    /// <summary>Creates an evaluator with the product's existing corpus runner.</summary>
    public SarifRegressHoldoutEvaluator(CorpusRunner? corpusRunner = null)
    {
        this.corpusRunner = new HoldoutCorpusRunnerAdapter(
            corpusRunner ?? new CorpusRunner());
    }

    /// <summary>
    /// Executes every holdout case. Matcher-quality failures remain report evidence and do not throw.
    /// </summary>
    public async ValueTask<SarifRegressHoldoutReport> EvaluateAsync(
        string repositoryRoot,
        ValidatedHoldout holdout,
        EvaluationIdentity identity,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        ArgumentNullException.ThrowIfNull(holdout);
        ArgumentNullException.ThrowIfNull(identity);
        string holdoutRoot = StablePath.Resolve(
            repositoryRoot,
            "validation/holdout");
        ImmutableArray<CorpusCaseRun> completedRuns = await corpusRunner.RunAsync(
                repositoryRoot,
                holdoutRoot,
                holdout,
                cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, CorpusCaseRun> caseRuns = completedRuns.ToDictionary(
            item => item.CaseName,
            StringComparer.Ordinal);
        string[] expectedCases = holdout.Cases.Select(item => item.Plan.Id)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!caseRuns.Keys.Order(StringComparer.Ordinal)
            .SequenceEqual(expectedCases, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The existing corpus runner did not evaluate the exact holdout manifest case set.");
        }

        ImmutableArray<SarifRegressCaseResult> cases = holdout.Cases
            .OrderBy(item => item.Plan.Id, StringComparer.Ordinal)
            .Select(item => HoldoutOutcomeClassifier.Classify(
                item,
                caseRuns[item.Plan.Id]))
            .ToImmutableArray();
        ImmutableArray<ProducerHoldoutMetrics> producers = cases
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerHoldoutMetrics(
                group.Key,
                HoldoutMetricsCalculator.Aggregate(
                    group.Select(item => item.Metrics))))
            .ToImmutableArray();
        return new SarifRegressHoldoutReport(
            identity,
            HoldoutMetricsCalculator.Aggregate(cases.Select(item => item.Metrics)),
            producers,
            cases,
            AggregateDiagnostics(cases.SelectMany(item => item.DiagnosticCounts)));
    }

    private static ImmutableArray<DiagnosticCount> AggregateDiagnostics(
        IEnumerable<DiagnosticCount> diagnostics) => diagnostics
        .GroupBy(item => item.Code, StringComparer.Ordinal)
        .OrderBy(group => group.Key, StringComparer.Ordinal)
        .Select(group => new DiagnosticCount(
            group.Key,
            group.Sum(item => item.Count)))
        .ToImmutableArray();
}

/// <summary>Runs and normalizes the pinned external matching baseline.</summary>
public sealed class SarifMultitoolEvaluator
{
    private readonly MultitoolRunner runner;
    private readonly MultitoolOutputParser parser;

    /// <summary>Creates an evaluator with injectable tool and parser adapters.</summary>
    public SarifMultitoolEvaluator(
        MultitoolRunner? runner = null,
        MultitoolOutputParser? parser = null)
    {
        this.runner = runner ?? new MultitoolRunner();
        this.parser = parser ?? new MultitoolOutputParser();
    }

    /// <summary>Executes the same committed case files and retains only stable normalized fields.</summary>
    public async ValueTask<SarifMultitoolBaselineReport> EvaluateAsync(
        string repositoryRoot,
        string outputRoot,
        string multitoolPath,
        string multitoolVersion,
        ValidatedHoldout holdout,
        EvaluationIdentity identity,
        CancellationToken cancellationToken = default)
    {
        MultitoolToolEvidence tool = await runner.VerifyToolAsync(
                multitoolPath,
                multitoolVersion,
                repositoryRoot,
                outputRoot,
                cancellationToken)
            .ConfigureAwait(false);
        var cases = ImmutableArray.CreateBuilder<MultitoolCaseResult>(
            holdout.Cases.Length);
        foreach (ValidatedHoldoutCase holdoutCase in holdout.Cases.OrderBy(
                     item => item.Plan.Id,
                     StringComparer.Ordinal))
        {
            MultitoolCaseExecution execution = runner.DescribeCaseExecution(
                multitoolPath,
                holdoutCase.Plan.Id);
            ImmutableArray<MultitoolRelationshipResult> relationships;
            bool instrumentationStateStable;
            string rawArtifactRelativePath;
            try
            {
                execution = await runner.RunCaseAsync(
                            multitoolPath,
                            holdoutCase,
                            repositoryRoot,
                            outputRoot,
                            cancellationToken)
                        .ConfigureAwait(false);
                string rawPrefix = $"raw/multitool/{holdoutCase.Plan.Id}";
                ParsedMultitoolOutput parsed = parser.ParseInstrumented(
                    ResolveOutput(outputRoot, rawPrefix + ".instrumented-baseline.sarif"),
                    ResolveOutput(outputRoot, rawPrefix + ".instrumented-candidate.sarif"),
                    ResolveOutput(outputRoot, execution.RawPath),
                    ResolveOutput(outputRoot, execution.UninstrumentedRawPath),
                    outputRoot);
                relationships = MultitoolRelationshipNormalizer.Normalize(
                    holdoutCase,
                    parsed);
                instrumentationStateStable = parsed.InstrumentationStateStable;
                rawArtifactRelativePath = execution.RawPath;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (IsExternalCaseFailure(exception))
            {
                const string code = "MULTITOOL_CASE_EVALUATION_FAILED";
                rawArtifactRelativePath = runner.PreserveCaseFailureEvidence(
                    outputRoot,
                    holdoutCase.Plan.Id,
                    code);
                relationships = MultitoolRelationshipNormalizer.NormalizeToolError(
                    holdoutCase,
                    code);
                instrumentationStateStable = false;
            }

            cases.Add(new MultitoolCaseResult(
                holdoutCase.Plan.Id,
                holdoutCase.Plan.ProducerId,
                holdoutCase.InputHashes,
                execution.Invocation,
                rawArtifactRelativePath,
                instrumentationStateStable,
                MultitoolMetricsCalculator.Create(
                    holdoutCase.Labels.Pairs.Length,
                    relationships),
                relationships));
        }

        ImmutableArray<MultitoolCaseResult> completedCases = cases.ToImmutable();
        ImmutableArray<ProducerMultitoolMetrics> producers = completedCases
            .GroupBy(item => item.ProducerId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ProducerMultitoolMetrics(
                group.Key,
                MultitoolMetricsCalculator.Aggregate(
                    group.Select(item => item.Metrics))))
            .ToImmutableArray();
        return new SarifMultitoolBaselineReport(
            identity,
            tool,
            MultitoolMetricsCalculator.Aggregate(
                completedCases.Select(item => item.Metrics)),
            producers,
            completedCases);
    }

    private static bool IsExternalCaseFailure(Exception exception) => exception is
        InvalidDataException or
        IOException or
        UnauthorizedAccessException or
        System.ComponentModel.Win32Exception or
        System.Text.Json.JsonException or
        NotSupportedException;

    private static string ResolveOutput(string outputRoot, string relativePath)
    {
        StablePath.RequireRepositoryRelative(relativePath, "raw artifact path");
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outputRoot));
        string path = Path.GetFullPath(
            relativePath.Replace('/', Path.DirectorySeparatorChar),
            root);
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, comparison))
        {
            throw new InvalidDataException("Raw Multitool output escaped output-root.");
        }

        return path;
    }
}
