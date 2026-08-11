using System.Collections.Immutable;
using System.Text;
using SarifRegress.Cli.Corpus;
using SarifRegress.Core.Security;

namespace SarifRegress.Validation;

/// <summary>
/// Adapts labelled holdout ingestion failures without changing the frozen corpus runner.
/// </summary>
internal sealed class HoldoutCorpusRunnerAdapter
{
    private const string CasesDirectoryName = "cases";
    private const string InvalidLabelPrefix = "Malformed corpus case '";
    private const string InvalidLabelSuffix = "' cannot label findings.";
    private static readonly byte[] LabelNeutralDocument = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true).GetBytes(
        """
        {
          "schemaVersion": "1",
          "pairs": [],
          "expectedAmbiguous": [],
          "expectedResolved": [],
          "expectedNew": [],
          "expectedInvalidInputs": []
        }

        """);

    private readonly CorpusRunner runner;
    private readonly ValidationLimits limits;

    /// <summary>Creates an adapter around the product's unmodified corpus runner.</summary>
    public HoldoutCorpusRunnerAdapter(
        CorpusRunner runner,
        ValidationLimits? limits = null)
    {
        this.runner = runner ?? throw new ArgumentNullException(nameof(runner));
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>
    /// Uses the original all-case execution path unless a labelled ingestion failure
    /// requires validation-only normalization.
    /// </summary>
    public async ValueTask<ImmutableArray<CorpusCaseRun>> RunAsync(
        string repositoryRoot,
        string holdoutRoot,
        ValidatedHoldout holdout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(holdoutRoot);
        ArgumentNullException.ThrowIfNull(holdout);
        var request = CreateRequest(holdoutRoot);
        try
        {
            CorpusRunResult result = await runner.RunAsync(request, cancellationToken)
                .ConfigureAwait(false);
            return result.Cases;
        }
        catch (InvalidDataException exception) when (
            IsLabelledIngestionFailure(exception))
        {
            return await RunCasesIndividuallyAsync(
                    repositoryRoot,
                    holdout,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask<ImmutableArray<CorpusCaseRun>>
        RunCasesIndividuallyAsync(
            string repositoryRoot,
            ValidatedHoldout holdout,
            CancellationToken cancellationToken)
    {
        var cases = ImmutableArray.CreateBuilder<CorpusCaseRun>(
            holdout.Cases.Length);
        foreach (ValidatedHoldoutCase holdoutCase in holdout.Cases.OrderBy(
                     item => item.Plan.Id,
                     StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            cases.Add(await RunIsolatedCaseAsync(
                    repositoryRoot,
                    holdoutCase,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return cases.ToImmutable();
    }

    private async ValueTask<CorpusCaseRun> RunIsolatedCaseAsync(
        string repositoryRoot,
        ValidatedHoldoutCase holdoutCase,
        CancellationToken cancellationToken)
    {
        string temporaryRoot = CreateTemporaryCorpus(
            repositoryRoot,
            holdoutCase);
        try
        {
            var request = CreateRequest(temporaryRoot);
            try
            {
                return await RunSingleCaseAsync(request, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidDataException exception) when (
                IsLabelledIngestionFailure(exception))
            {
                string labelsPath = Path.Combine(
                    temporaryRoot,
                    CasesDirectoryName,
                    holdoutCase.Plan.Id,
                    "labels.json");
                File.WriteAllBytes(labelsPath, LabelNeutralDocument);
                CorpusCaseRun neutralRun = await RunSingleCaseAsync(
                        request,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (neutralRun.ObservedInvalidInputs.IsEmpty)
                {
                    throw new InvalidDataException(
                        "A labelled ingestion failure did not reproduce with label-neutral evaluation.",
                        exception);
                }

                CorpusMetrics failedMetrics = CorpusEvaluator.Evaluate(
                    holdoutCase.Plan.Id,
                    holdoutCase.Labels,
                    []).Metrics;
                return neutralRun with
                {
                    ExpectedInvalidInputs = holdoutCase.Labels.ExpectedInvalidInputs
                        .Order()
                        .ToImmutableArray(),
                    Metrics = failedMetrics,
                    Passed = false,
                    DiagnosticExpectationsAsserted =
                        !holdoutCase.Labels.ExpectedDiagnostics.IsDefault,
                    ExpectedDiagnosticCount =
                        holdoutCase.Labels.ExpectedDiagnostics.IsDefault
                            ? 0
                            : holdoutCase.Labels.ExpectedDiagnostics.Length,
                    ExplanationExpectationsAsserted =
                        !holdoutCase.Labels.ExpectedExplanations.IsDefault,
                    ExpectedExplanationCount =
                        holdoutCase.Labels.ExpectedExplanations.IsDefault
                            ? 0
                            : holdoutCase.Labels.ExpectedExplanations.Length,
                };
            }
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    private async ValueTask<CorpusCaseRun> RunSingleCaseAsync(
        CorpusRunRequest request,
        CancellationToken cancellationToken)
    {
        CorpusRunResult result = await runner.RunAsync(request, cancellationToken)
            .ConfigureAwait(false);
        if (result.Cases.Length != 1)
        {
            throw new InvalidDataException(
                "An isolated holdout corpus must produce exactly one case result.");
        }

        return result.Cases[0];
    }

    private string CreateTemporaryCorpus(
        string repositoryRoot,
        ValidatedHoldoutCase holdoutCase)
    {
        string caseId = holdoutCase.Plan.Id;
        if (string.IsNullOrWhiteSpace(caseId)
            || !string.Equals(Path.GetFileName(caseId), caseId, StringComparison.Ordinal)
            || caseId is "." or "..")
        {
            throw new InvalidDataException(
                "A holdout case id must be one portable path segment.");
        }

        DirectoryInfo temporary = Directory.CreateTempSubdirectory(
            "sarif-regress-holdout-ingestion-");
        string temporaryCase = Path.Combine(
            temporary.FullName,
            CasesDirectoryName,
            caseId);
        Directory.CreateDirectory(temporaryCase);
        try
        {
            CopyRequiredFile(
                repositoryRoot,
                holdoutCase.Plan.Paths.BaselineSarif,
                Path.Combine(temporaryCase, "baseline.sarif"),
                limits.MaximumSarifBytes);
            CopyRequiredFile(
                repositoryRoot,
                holdoutCase.Plan.Paths.CandidateSarif,
                Path.Combine(temporaryCase, "candidate.sarif"),
                limits.MaximumSarifBytes);
            CopyRequiredFile(
                repositoryRoot,
                holdoutCase.Plan.Paths.Labels,
                Path.Combine(temporaryCase, "labels.json"),
                limits.MaximumLabelBytes);
            if (holdoutCase.Plan.Paths.Config is not null)
            {
                CopyRequiredFile(
                    repositoryRoot,
                    holdoutCase.Plan.Paths.Config,
                    Path.Combine(temporaryCase, "config.json"),
                    limits.MaximumLabelBytes);
            }

            string producerInput = StablePath.Resolve(
                repositoryRoot,
                holdoutCase.Plan.Paths.ProducerInputDirectory);
            CopyProducerInputTree(
                producerInput,
                Path.Combine(temporaryCase, "producer-input"));
            return temporary.FullName;
        }
        catch
        {
            Directory.Delete(temporary.FullName, recursive: true);
            throw;
        }
    }

    private static CorpusRunRequest CreateRequest(string corpusRoot) => new(
        corpusRoot,
        CorpusThresholds.Mvp,
        ResourceLimits.Default);

    private static bool IsLabelledIngestionFailure(
        InvalidDataException exception) => exception.Message.StartsWith(
            InvalidLabelPrefix,
            StringComparison.Ordinal)
        && exception.Message.EndsWith(InvalidLabelSuffix, StringComparison.Ordinal);

    private static void CopyRequiredFile(
        string repositoryRoot,
        string sourceRelativePath,
        string destinationPath,
        long maximumBytes)
    {
        string sourcePath = StablePath.Resolve(repositoryRoot, sourceRelativePath);
        byte[] bytes = BoundedJsonFile.ReadBytes(
            sourcePath,
            maximumBytes,
            repositoryRoot);
        WriteNewFile(destinationPath, bytes);
    }

    private void CopyProducerInputTree(string sourceRoot, string destinationRoot)
    {
        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException(
                "The holdout producer-input directory does not exist.");
        }

        if ((File.GetAttributes(sourceRoot) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "A producer input tree root cannot be a symbolic link or reparse point.");
        }

        Directory.CreateDirectory(destinationRoot);
        var pending = new Stack<(string Source, string Destination)>();
        pending.Push((sourceRoot, destinationRoot));
        var entryCount = 0;
        while (pending.Count > 0)
        {
            (string source, string destination) = pending.Pop();
            string[] entries = Directory.EnumerateFileSystemEntries(source)
                .Order(StringComparer.Ordinal)
                .ToArray();
            for (var index = entries.Length - 1; index >= 0; index--)
            {
                string entry = entries[index];
                entryCount = checked(entryCount + 1);
                if (entryCount > limits.MaximumResultsPerCase)
                {
                    throw new InvalidDataException(
                        "A producer input tree exceeds the validation entry-count limit.");
                }

                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "A producer input tree cannot contain a symbolic link or reparse point.");
                }

                string name = Path.GetFileName(entry);
                string output = Path.Combine(destination, name);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Directory.CreateDirectory(output);
                    pending.Push((entry, output));
                    continue;
                }

                byte[] bytes = BoundedJsonFile.ReadBytes(
                    entry,
                    limits.MaximumSarifBytes,
                    sourceRoot);
                WriteNewFile(output, bytes);
            }
        }
    }

    private static void WriteNewFile(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None);
        stream.Write(bytes);
    }
}
