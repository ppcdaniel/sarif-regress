using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;
using SarifRegress.Sarif.Canonicalization;
using SarifRegress.Sarif.Fingerprints;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.Sarif.Ingestion;

/// <summary>
/// Stream-deserialises the bounded SARIF 2.1.0 comparison subset into immutable Core findings.
/// </summary>
public sealed class SarifIngestor
{
    /// <summary>
    /// Gets the only SARIF version accepted by the comparison adapter.
    /// </summary>
    public const string SupportedSarifVersion = "2.1.0";

    private const string RuleAliasAlgorithmVersion = "rule-alias/v1";
    private const string RelatedLocationAlgorithmVersion = "related-location/v1";
    private const string CodeFlowContextAlgorithmVersion = "code-flow-context/v1";
    private readonly IRepositoryContext? repositoryContext;

    /// <summary>
    /// Initializes an ingestor with optional, explicitly approved repository access.
    /// </summary>
    /// <param name="repositoryContext">
    /// The bounded read-only source adapter. Null disables all filesystem access.
    /// </param>
    public SarifIngestor(IRepositoryContext? repositoryContext = null)
    {
        this.repositoryContext = repositoryContext;
    }

    /// <summary>
    /// Ingests one untrusted UTF-8 SARIF stream.
    /// </summary>
    /// <param name="input">The readable SARIF stream.</param>
    /// <param name="request">The logical input identity and canonicalisation policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Canonical findings, diagnostics, and bounded aggregate facts.</returns>
    public async ValueTask<SarifIngestionResult> IngestAsync(
        Stream input,
        SarifIngestionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(request);
        var limits = request.Configuration.Limits;
        limits.Validate();
        var diagnostics = new List<Diagnostic>();
        await using var boundedInput =
            new BoundedReadStream(input, limits.MaximumInputBytes);

        SarifLogWire? log;
        try
        {
            log = await JsonSerializer.DeserializeAsync<SarifLogWire>(
                    boundedInput,
                    CreateJsonOptions(limits),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InputLimitExceededException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0100",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"The SARIF input exceeds the configured {limits.MaximumInputBytes}-byte limit.",
                    request.Input));
            return CreateEmptyResult(
                request,
                version: null,
                boundedInput.BytesRead,
                diagnostics);
        }
        catch (JsonStringLimitExceededException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0103",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"A SARIF string exceeds the configured {limits.MaximumStringCharacters}-character limit.",
                    request.Input));
            return CreateEmptyResult(
                request,
                version: null,
                boundedInput.BytesRead,
                diagnostics);
        }
        catch (JsonCollectionLimitExceededException exception)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0102",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"A SARIF {exception.CollectionKind} exceeds the configured {exception.MaximumItems}-item limit.",
                    request.Input));
            return CreateEmptyResult(
                request,
                version: null,
                boundedInput.BytesRead,
                diagnostics);
        }
        catch (JsonException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "PARSE0100",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Parse,
                    "The SARIF input is not valid JSON.",
                    request.Input));
            return CreateEmptyResult(
                request,
                version: null,
                boundedInput.BytesRead,
                diagnostics);
        }
        catch (IOException)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "IO0100",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Io,
                    "The SARIF input could not be read.",
                    request.Input));
            return CreateEmptyResult(
                request,
                version: null,
                boundedInput.BytesRead,
                diagnostics);
        }

        if (log is null)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0100",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "The SARIF root must be a JSON object.",
                    request.Input));
            return CreateEmptyResult(
                request,
                version: null,
                boundedInput.BytesRead,
                diagnostics);
        }

        var summaries = CreateDocumentSummaries(log);
        if (!ValidateDocument(log, request.Input, limits, diagnostics))
        {
            return CreateResult(
                request,
                log.Version,
                boundedInput.BytesRead,
                findings: [],
                summaries,
                diagnostics);
        }

        var pathCanonicalizer = new PathCanonicalizer(request.Configuration);
        var findings = new List<Finding>();
        for (var runIndex = 0; runIndex < log.Runs!.Count; runIndex++)
        {
            var run = log.Runs[runIndex];
            if (run is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0103",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A SARIF run cannot be null.",
                        request.Input,
                        runIndex,
                        resultIndex: null,
                        $"/runs/{runIndex}"));
                continue;
            }

            if (!ValidateRunCollections(
                    run,
                    request.Input,
                    runIndex,
                    limits,
                    diagnostics))
            {
                continue;
            }

            ReportUnsupported(
                run.UnsupportedInvocations,
                "The optional run.invocations structure is not used for comparison.",
                request.Input,
                runIndex,
                resultIndex: null,
                $"/runs/{runIndex}/invocations",
                diagnostics);
            ReportUnsupported(
                run.UnsupportedGraphs,
                "The optional run.graphs structure is not used for comparison.",
                request.Input,
                runIndex,
                resultIndex: null,
                $"/runs/{runIndex}/graphs",
                diagnostics);

            var runFindings = await IngestRunAsync(
                    run,
                    runIndex,
                    request,
                    pathCanonicalizer,
                    diagnostics,
                    cancellationToken)
                .ConfigureAwait(false);
            findings.AddRange(runFindings);
        }

        var assessedFindings =
            FingerprintProcessor.AssessReliability(findings);
        return CreateResult(
            request,
            log.Version,
            boundedInput.BytesRead,
            assessedFindings,
            summaries,
            diagnostics);
    }

    private async ValueTask<ImmutableArray<Finding>> IngestRunAsync(
        SarifRunWire run,
        int runIndex,
        SarifIngestionRequest request,
        PathCanonicalizer pathCanonicalizer,
        ICollection<Diagnostic> documentDiagnostics,
        CancellationToken cancellationToken)
    {
        var driver = run.Tool?.Driver;
        var driverNamePointer = $"/runs/{runIndex}/tool/driver/name";
        if (!TryGetRequiredString(
                driver?.Name,
                request.Input,
                runIndex,
                resultIndex: null,
                driverNamePointer,
                request.Configuration.Limits,
                documentDiagnostics,
                out var toolName))
        {
            return [];
        }

        var toolVersion = SelectOptionalString(
            driver?.SemanticVersion,
            driver?.Version,
            request.Input,
            runIndex,
            request.Configuration.Limits,
            documentDiagnostics);
        var automationCategory = ValidateOptionalString(
            run.AutomationDetails?.Id,
            request.Input,
            runIndex,
            resultIndex: null,
            $"/runs/{runIndex}/automationDetails/id",
            request.Configuration.Limits,
            documentDiagnostics);
        var producerFamily = NormalizeProducerFamily(toolName);
        var producer = new ProducerIdentity(
            toolName,
            toolVersion,
            producerFamily,
            automationCategory);
        var runIdentity = new RunIdentity(
            runIndex,
            automationCategory,
            $"{request.Input.ToString().ToLowerInvariant()}:{runIndex}");
        var locationResolver = new LocationResolver(
            run,
            runIndex,
            request,
            pathCanonicalizer);
        var findings = ImmutableArray.CreateBuilder<Finding>(
            run.Results?.Count ?? 0);

        for (var resultIndex = 0;
             resultIndex < (run.Results?.Count ?? 0);
             resultIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = run.Results![resultIndex];
            var resultPointer = $"/runs/{runIndex}/results/{resultIndex}";
            if (result is null)
            {
                documentDiagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0104",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "A SARIF result cannot be null.",
                        request.Input,
                        runIndex,
                        resultIndex,
                        resultPointer));
                continue;
            }

            if (!ValidateResultCollections(
                    result,
                    request.Input,
                    runIndex,
                    resultIndex,
                    request.Configuration.Limits,
                    documentDiagnostics))
            {
                continue;
            }

            ReportUnsupportedResultFields(
                result,
                request.Input,
                runIndex,
                resultIndex,
                resultPointer,
                documentDiagnostics);

            var sourceReference = new SourceReference(
                request.Input,
                runIndex,
                resultIndex,
                resultPointer);
            var finding = await IngestResultAsync(
                    result,
                    driver?.Rules,
                    runIdentity,
                    producer,
                    sourceReference,
                    request,
                    locationResolver,
                    documentDiagnostics,
                    cancellationToken)
                .ConfigureAwait(false);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        return findings.MoveToImmutable();
    }

    private async ValueTask<Finding?> IngestResultAsync(
        SarifResultWire result,
        IReadOnlyList<SarifRuleWire?>? rules,
        RunIdentity runIdentity,
        ProducerIdentity producer,
        SourceReference sourceReference,
        SarifIngestionRequest request,
        LocationResolver locationResolver,
        ICollection<Diagnostic> documentDiagnostics,
        CancellationToken cancellationToken)
    {
        var findingDiagnostics = new List<Diagnostic>();
        var rule = ResolveRule(
            result,
            rules,
            producer,
            request,
            sourceReference,
            findingDiagnostics);
        if (rule is null)
        {
            AddRange(documentDiagnostics, findingDiagnostics);
            return null;
        }

        var messageText = ResolveMessage(
            result.Message,
            sourceReference,
            request.Configuration.Limits,
            findingDiagnostics);
        if (messageText is null)
        {
            AddRange(documentDiagnostics, findingDiagnostics);
            return null;
        }

        var message = MessageCanonicalizer.Canonicalize(messageText);
        var primaryLocationWire = result.Locations?.FirstOrDefault();
        var primaryLocation = locationResolver.ResolvePrimary(
            primaryLocationWire,
            sourceReference.JsonPointer + "/locations/0",
            findingDiagnostics);
        ContextEvidence? context = null;
        if (primaryLocation?.Path.RepositoryRelativePath is string repositoryPath &&
            request.Configuration.Matching.EnableRepositoryContext &&
            repositoryContext is not null)
        {
            var repositoryResult = await repositoryContext
                .ReadAsync(
                    repositoryPath,
                    primaryLocation.Region,
                    request.Configuration.Matching.SnippetLinesRadius,
                    sourceReference,
                    cancellationToken)
                .ConfigureAwait(false);
            context = repositoryResult.Evidence;
            AddRange(findingDiagnostics, repositoryResult.Diagnostics);
        }

        context ??= CreateEmbeddedContext(primaryLocation);
        var relatedLocations = ResolveRelatedLocations(
            result,
            locationResolver,
            sourceReference,
            findingDiagnostics);
        var codeFlow = ResolveCodeFlow(
            result,
            locationResolver,
            sourceReference,
            findingDiagnostics);
        var validatedFingerprints = ValidateFingerprintMap(
            result.Fingerprints,
            sourceReference,
            sourceReference.JsonPointer + "/fingerprints",
            request.Configuration.Limits,
            findingDiagnostics);
        var validatedPartialFingerprints = ValidateFingerprintMap(
            result.PartialFingerprints,
            sourceReference,
            sourceReference.JsonPointer + "/partialFingerprints",
            request.Configuration.Limits,
            findingDiagnostics);
        var importedFingerprints = FingerprintProcessor.Import(
            validatedFingerprints,
            validatedPartialFingerprints,
            sourceReference);
        AddRange(findingDiagnostics, importedFingerprints.Diagnostics);

        var lossiness = new List<string>();
        if (result.Message?.Text is null && result.Message?.Markdown is not null)
        {
            lossiness.Add("message-markdown-fallback");
        }

        if (primaryLocation is not null)
        {
            lossiness.AddRange(
                primaryLocation.Path.Transformations
                    .Where(item => item.IsLossy)
                    .Select(item => item.Kind));
        }

        var finding = new Finding(
            $"{request.Input.ToString().ToLowerInvariant()}:{runIdentity.RunIndex}:{sourceReference.ResultIndex}",
            sourceReference,
            runIdentity,
            producer,
            rule,
            primaryLocation,
            message,
            importedFingerprints.Fingerprints,
            derivedFingerprints: [],
            context,
            relatedLocations,
            codeFlow,
            lossiness,
            findingDiagnostics);
        var derivedFingerprint =
            FingerprintProcessor.DeriveRulePathContext(finding);
        if (derivedFingerprint is not null)
        {
            finding = CloneWithDerivedFingerprint(finding, derivedFingerprint);
        }

        AddRange(documentDiagnostics, findingDiagnostics);
        return finding;
    }

    private static RuleIdentity? ResolveRule(
        SarifResultWire result,
        IReadOnlyList<SarifRuleWire?>? rules,
        ProducerIdentity producer,
        SarifIngestionRequest request,
        SourceReference sourceReference,
        ICollection<Diagnostic> diagnostics)
    {
        string? indexedRuleId = null;
        if (result.RuleIndex is int ruleIndex)
        {
            if (ruleIndex < 0 ||
                ruleIndex >= (rules?.Count ?? 0) ||
                string.IsNullOrWhiteSpace(rules![ruleIndex]?.Id))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0110",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "The result ruleIndex does not resolve to a driver rule.",
                        sourceReference,
                        sourceReference.JsonPointer + "/ruleIndex"));
            }
            else
            {
                indexedRuleId = ValidateOptionalString(
                    rules[ruleIndex]!.Id,
                    sourceReference,
                    sourceReference.JsonPointer + "/ruleIndex",
                    request.Configuration.Limits,
                    diagnostics);
            }
        }

        var explicitRuleId = ValidateOptionalString(
            result.RuleId,
            sourceReference,
            sourceReference.JsonPointer + "/ruleId",
            request.Configuration.Limits,
            diagnostics);
        if (explicitRuleId is not null &&
            indexedRuleId is not null &&
            !string.Equals(
                explicitRuleId,
                indexedRuleId,
                StringComparison.Ordinal))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0111",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Schema,
                    "The result ruleId disagrees with the rule referenced by ruleIndex; ruleId was used.",
                    sourceReference,
                    sourceReference.JsonPointer + "/ruleId"));
        }

        var originalRuleId = explicitRuleId ?? indexedRuleId;
        if (string.IsNullOrWhiteSpace(originalRuleId))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0112",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "The result has no resolvable rule identity.",
                    sourceReference,
                    sourceReference.JsonPointer));
            return null;
        }

        var aliasedId = ResolveConfiguredRuleAlias(
            request.Input,
            producer.Family,
            originalRuleId,
            request.Configuration.RuleAliases);
        if (aliasedId is not null)
        {
            return new RuleIdentity(originalRuleId, aliasedId, AliasApplied: true);
        }

        var canonicalRuleId = originalRuleId.StartsWith(
            producer.Family + "/",
            StringComparison.Ordinal)
            ? originalRuleId
            : $"{producer.Family}/{originalRuleId}";
        return new RuleIdentity(
            originalRuleId,
            canonicalRuleId,
            AliasApplied: false);
    }

    private static string? ResolveConfiguredRuleAlias(
        InputKind input,
        string producerFamily,
        string ruleId,
        IEnumerable<RuleAlias> aliases)
    {
        foreach (var alias in aliases)
        {
            var baselineProducer = NormalizeProducerFamily(
                alias.BaselineProducer);
            var candidateProducer = NormalizeProducerFamily(
                alias.CandidateProducer);
            var matches = input switch
            {
                InputKind.Baseline =>
                    string.Equals(
                        producerFamily,
                        baselineProducer,
                        StringComparison.Ordinal) &&
                    string.Equals(
                        ruleId,
                        alias.BaselineRule,
                        StringComparison.Ordinal),
                InputKind.Candidate =>
                    string.Equals(
                        producerFamily,
                        candidateProducer,
                        StringComparison.Ordinal) &&
                    string.Equals(
                        ruleId,
                        alias.CandidateRule,
                        StringComparison.Ordinal),
                _ => false,
            };
            if (!matches)
            {
                continue;
            }

            var aliasHash = VersionedHash.Compute(
                RuleAliasAlgorithmVersion,
                baselineProducer,
                alias.BaselineRule,
                candidateProducer,
                alias.CandidateRule);
            return $"alias/{aliasHash}";
        }

        return null;
    }

    private static string? ResolveMessage(
        SarifMessageWire? message,
        SourceReference sourceReference,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        var text = message?.Text ?? message?.Markdown;
        if (text is null)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0113",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "The result message must contain text or markdown.",
                    sourceReference,
                    sourceReference.JsonPointer + "/message"));
            return null;
        }

        return ValidateOptionalString(
            text,
            sourceReference,
            message?.Text is not null
                ? sourceReference.JsonPointer + "/message/text"
                : sourceReference.JsonPointer + "/message/markdown",
            limits,
            diagnostics);
    }

    private static ImmutableArray<RelatedLocation> ResolveRelatedLocations(
        SarifResultWire result,
        LocationResolver resolver,
        SourceReference sourceReference,
        ICollection<Diagnostic> diagnostics)
    {
        var related = new List<RelatedLocation>();
        for (var index = 1; index < (result.Locations?.Count ?? 0); index++)
        {
            var pointer = sourceReference.JsonPointer + $"/locations/{index}";
            related.Add(
                resolver.ResolveRelated(
                    result.Locations![index],
                    pointer,
                    diagnostics));
        }

        for (var index = 0;
             index < (result.RelatedLocations?.Count ?? 0);
             index++)
        {
            var pointer =
                sourceReference.JsonPointer + $"/relatedLocations/{index}";
            related.Add(
                resolver.ResolveRelated(
                    result.RelatedLocations![index],
                    pointer,
                    diagnostics));
        }

        return related
            .OrderBy(item => item.StableKey, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static CodeFlowEvidence? ResolveCodeFlow(
        SarifResultWire result,
        LocationResolver resolver,
        SourceReference sourceReference,
        ICollection<Diagnostic> diagnostics)
    {
        if (result.CodeFlows is null || result.CodeFlows.Count == 0)
        {
            return null;
        }

        var anchors = new List<(string Path, string? ContextHash)>();
        for (var flowIndex = 0;
             flowIndex < result.CodeFlows.Count;
             flowIndex++)
        {
            var flow = result.CodeFlows[flowIndex];
            for (var threadIndex = 0;
                 threadIndex < (flow?.ThreadFlows?.Count ?? 0);
                 threadIndex++)
            {
                var threadFlow = flow!.ThreadFlows![threadIndex];
                for (var locationIndex = 0;
                     locationIndex < (threadFlow?.Locations?.Count ?? 0);
                     locationIndex++)
                {
                    var pointer = sourceReference.JsonPointer +
                        $"/codeFlows/{flowIndex}/threadFlows/{threadIndex}/locations/{locationIndex}/location";
                    var resolved = resolver.ResolvePrimary(
                        threadFlow!.Locations![locationIndex]?.Location,
                        pointer,
                        diagnostics);
                    if (resolved is null)
                    {
                        continue;
                    }

                    var contextHash = resolved.EmbeddedSnippet is null
                        ? null
                        : VersionedHash.Compute(
                            CodeFlowContextAlgorithmVersion,
                            NormalizeLineEndings(resolved.EmbeddedSnippet));
                    anchors.Add((resolved.Path.CanonicalUri, contextHash));
                }
            }
        }

        if (anchors.Count == 0)
        {
            return null;
        }

        var sortedAnchors = anchors
            .Distinct()
            .OrderBy(item => item.Path, StringComparer.Ordinal)
            .ThenBy(item => item.ContextHash, StringComparer.Ordinal)
            .Select(
                (item, ordinal) =>
                    new CodeFlowAnchor(item.Path, item.ContextHash, ordinal))
            .ToImmutableArray();
        return new CodeFlowEvidence(sortedAnchors);
    }

    private static ContextEvidence? CreateEmbeddedContext(
        PrimaryLocation? location)
    {
        if (location?.EmbeddedSnippet is not string embeddedSnippet)
        {
            return null;
        }

        return new ContextEvidence(
            VersionedHash.Compute(
                FileSystemRepositoryContext.ContextAlgorithmVersion,
                NormalizeLineEndings(embeddedSnippet)),
            TokenWindowHash: null,
            EnclosingSymbol: null,
            location.Region?.StartLine,
            location.Region?.EndLine ?? location.Region?.StartLine);
    }

    private static Finding CloneWithDerivedFingerprint(
        Finding finding,
        DerivedFingerprint derivedFingerprint) =>
        new(
            finding.FindingKey,
            finding.SourceReference,
            finding.Run,
            finding.Producer,
            finding.Rule,
            finding.PrimaryLocation,
            finding.Message,
            finding.ProducerFingerprints,
            [derivedFingerprint],
            finding.Context,
            finding.RelatedLocations,
            finding.CodeFlow,
            finding.Lossiness,
            finding.Diagnostics);

    private static bool ValidateDocument(
        SarifLogWire log,
        InputKind input,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        var isValid = true;
        if (!string.Equals(
                log.Version,
                SupportedSarifVersion,
                StringComparison.Ordinal))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0101",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    $"SARIF version must be \"{SupportedSarifVersion}\".",
                    input,
                    runIndex: null,
                    resultIndex: null,
                    "/version"));
            isValid = false;
        }

        if (log.Runs is null)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0102",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "The SARIF log must contain a runs array.",
                    input,
                    runIndex: null,
                    resultIndex: null,
                    "/runs"));
            return false;
        }

        if (log.Runs.Count > limits.MaximumRuns)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0101",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"The SARIF log exceeds the configured {limits.MaximumRuns}-run limit.",
                    input,
                    runIndex: null,
                    resultIndex: null,
                    "/runs"));
            isValid = false;
        }

        return isValid;
    }

    private static void ReportUnsupportedResultFields(
        SarifResultWire result,
        InputKind input,
        int runIndex,
        int resultIndex,
        string resultPointer,
        ICollection<Diagnostic> diagnostics)
    {
        ReportUnsupported(
            result.UnsupportedLogicalLocations,
            "The optional result.logicalLocations structure is not used for comparison.",
            input,
            runIndex,
            resultIndex,
            resultPointer + "/logicalLocations",
            diagnostics);
        ReportUnsupported(
            result.UnsupportedStacks,
            "The optional result.stacks structure is not used for comparison.",
            input,
            runIndex,
            resultIndex,
            resultPointer + "/stacks",
            diagnostics);
        ReportUnsupported(
            result.UnsupportedSuppressions,
            "The optional result.suppressions structure is retained only by the source SARIF.",
            input,
            runIndex,
            resultIndex,
            resultPointer + "/suppressions",
            diagnostics);
        ReportUnsupported(
            result.UnsupportedAttachments,
            "The optional result.attachments structure is not used for comparison.",
            input,
            runIndex,
            resultIndex,
            resultPointer + "/attachments",
            diagnostics);
    }

    private static void ReportUnsupported(
        UnsupportedJsonValue? value,
        string message,
        InputKind input,
        int runIndex,
        int? resultIndex,
        string pointer,
        ICollection<Diagnostic> diagnostics)
    {
        if (value is null)
        {
            return;
        }

        diagnostics.Add(
            CreateDiagnostic(
                "UNSUPPORTED0100",
                DiagnosticSeverity.Warning,
                DiagnosticStage.Unsupported,
                message,
                input,
                runIndex,
                resultIndex,
                pointer));
    }

    private static bool ValidateRunCollections(
        SarifRunWire run,
        InputKind input,
        int runIndex,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        var isValid = true;
        isValid &= ValidateCollectionCount(
            run.Tool?.Driver?.Rules?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "rules",
            input,
            runIndex,
            resultIndex: null,
            $"/runs/{runIndex}/tool/driver/rules",
            diagnostics);
        isValid &= ValidateCollectionCount(
            run.Artifacts?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "artifacts",
            input,
            runIndex,
            resultIndex: null,
            $"/runs/{runIndex}/artifacts",
            diagnostics);
        isValid &= ValidateCollectionCount(
            run.Results?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "results",
            input,
            runIndex,
            resultIndex: null,
            $"/runs/{runIndex}/results",
            diagnostics);
        isValid &= ValidateCollectionCount(
            run.OriginalUriBaseIds?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "originalUriBaseIds",
            input,
            runIndex,
            resultIndex: null,
            $"/runs/{runIndex}/originalUriBaseIds",
            diagnostics);
        return isValid;
    }

    private static bool ValidateResultCollections(
        SarifResultWire result,
        InputKind input,
        int runIndex,
        int resultIndex,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        var isValid = true;
        isValid &= ValidateCollectionCount(
            result.Locations?.Count ?? 0,
            limits.MaximumLocationsPerResult,
            "locations",
            input,
            runIndex,
            resultIndex,
            $"/runs/{runIndex}/results/{resultIndex}/locations",
            diagnostics);
        isValid &= ValidateCollectionCount(
            result.RelatedLocations?.Count ?? 0,
            limits.MaximumLocationsPerResult,
            "relatedLocations",
            input,
            runIndex,
            resultIndex,
            $"/runs/{runIndex}/results/{resultIndex}/relatedLocations",
            diagnostics);
        isValid &= ValidateCollectionCount(
            result.CodeFlows?.Count ?? 0,
            limits.MaximumCodeFlowsPerResult,
            "codeFlows",
            input,
            runIndex,
            resultIndex,
            $"/runs/{runIndex}/results/{resultIndex}/codeFlows",
            diagnostics);
        isValid &= ValidateCollectionCount(
            result.Fingerprints?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "fingerprints",
            input,
            runIndex,
            resultIndex,
            $"/runs/{runIndex}/results/{resultIndex}/fingerprints",
            diagnostics);
        isValid &= ValidateCollectionCount(
            result.PartialFingerprints?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "partialFingerprints",
            input,
            runIndex,
            resultIndex,
            $"/runs/{runIndex}/results/{resultIndex}/partialFingerprints",
            diagnostics);

        var threadFlowLocations = CountThreadFlowLocations(result);
        isValid &= ValidateCollectionCount(
            threadFlowLocations,
            limits.MaximumThreadFlowLocationsPerResult,
            "thread-flow locations",
            input,
            runIndex,
            resultIndex,
            $"/runs/{runIndex}/results/{resultIndex}/codeFlows",
            diagnostics);
        return isValid;
    }

    private static bool ValidateCollectionCount(
        int actual,
        int maximum,
        string collectionName,
        InputKind input,
        int runIndex,
        int? resultIndex,
        string pointer,
        ICollection<Diagnostic> diagnostics)
    {
        if (actual <= maximum)
        {
            return true;
        }

        diagnostics.Add(
            CreateDiagnostic(
                "SECURITY0102",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                $"The SARIF {collectionName} collection exceeds the configured {maximum}-item limit.",
                input,
                runIndex,
                resultIndex,
                pointer));
        return false;
    }

    private static ImmutableArray<SarifRunSummary> CreateDocumentSummaries(
        SarifLogWire log)
    {
        if (log.Runs is null)
        {
            return [];
        }

        var summaries = ImmutableArray.CreateBuilder<SarifRunSummary>(
            log.Runs.Count);
        for (var runIndex = 0; runIndex < log.Runs.Count; runIndex++)
        {
            var run = log.Runs[runIndex];
            if (run is null)
            {
                summaries.Add(
                    new SarifRunSummary(
                        runIndex,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0));
                continue;
            }

            var results = run.Results ?? [];
            summaries.Add(
                new SarifRunSummary(
                    runIndex,
                    results.Count,
                    run.Tool?.Driver?.Rules?.Count ?? 0,
                    run.Tool?.Extensions?.Count ?? 0,
                    results.MaxOrDefault(
                        result => result?.Locations?.Count ?? 0),
                    results.MaxOrDefault(CountThreadFlowLocations),
                    (run.Tool?.Driver?.Rules ?? []).MaxOrDefault(
                        rule => rule?.Properties?.Tags?.Count ?? 0),
                    results.Count(
                        result => (result?.Locations?.Count ?? 0) > 1),
                    results.Count(
                        result => !HasPrimaryLocationLineHash(result)),
                    results.Count(
                        result => HasNonRepositoryPrimaryLocation(result, run))));
        }

        return summaries.MoveToImmutable();
    }

    private static bool HasPrimaryLocationLineHash(SarifResultWire? result)
    {
        if (result?.PartialFingerprints is null)
        {
            return false;
        }

        return result.PartialFingerprints.Keys.Any(
            name =>
                string.Equals(
                    name,
                    "primaryLocationLineHash",
                    StringComparison.Ordinal) ||
                name.StartsWith(
                    "primaryLocationLineHash/v",
                    StringComparison.Ordinal));
    }

    private static bool HasNonRepositoryPrimaryLocation(
        SarifResultWire? result,
        SarifRunWire run)
    {
        var location = result?.Locations?.FirstOrDefault()?.PhysicalLocation
            ?.ArtifactLocation;
        if (location is null)
        {
            return false;
        }

        SarifArtifactLocationWire? artifact = null;
        if (location.Index is int artifactIndex &&
            artifactIndex >= 0 &&
            artifactIndex < (run.Artifacts?.Count ?? 0))
        {
            artifact = run.Artifacts![artifactIndex]?.Location;
        }

        var uri = location.Uri ?? artifact?.Uri;
        if (uri is null)
        {
            return false;
        }

        return PathCanonicalizer.Classify(uri) !=
            PathKind.RepositoryRelative;
    }

    private static int CountThreadFlowLocations(SarifResultWire? result)
    {
        var count = 0;
        foreach (var codeFlow in result?.CodeFlows ?? [])
        {
            foreach (var threadFlow in codeFlow?.ThreadFlows ?? [])
            {
                count = checked(count + (threadFlow?.Locations?.Count ?? 0));
            }
        }

        return count;
    }

    private static bool TryGetRequiredString(
        string? value,
        InputKind input,
        int runIndex,
        int? resultIndex,
        string pointer,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics,
        out string validated)
    {
        validated = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SCHEMA0114",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Schema,
                    "A required SARIF string is empty.",
                    input,
                    runIndex,
                    resultIndex,
                    pointer));
            return false;
        }

        var checkedValue = ValidateOptionalString(
            value,
            input,
            runIndex,
            resultIndex,
            pointer,
            limits,
            diagnostics);
        if (checkedValue is null)
        {
            return false;
        }

        validated = checkedValue;
        return true;
    }

    private static string? SelectOptionalString(
        string? preferred,
        string? fallback,
        InputKind input,
        int runIndex,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics) =>
        ValidateOptionalString(
            preferred ?? fallback,
            input,
            runIndex,
            resultIndex: null,
            preferred is not null
                ? $"/runs/{runIndex}/tool/driver/semanticVersion"
                : $"/runs/{runIndex}/tool/driver/version",
            limits,
            diagnostics);

    private static string? ValidateOptionalString(
        string? value,
        SourceReference sourceReference,
        string pointer,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics) =>
        ValidateOptionalString(
            value,
            sourceReference.Input,
            sourceReference.RunIndex,
            sourceReference.ResultIndex,
            pointer,
            limits,
            diagnostics);

    private static string? ValidateOptionalString(
        string? value,
        InputKind input,
        int? runIndex,
        int? resultIndex,
        string pointer,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length <= limits.MaximumStringCharacters)
        {
            return value;
        }

        diagnostics.Add(
            CreateDiagnostic(
                "SECURITY0103",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                $"A SARIF string exceeds the configured {limits.MaximumStringCharacters}-character limit.",
                input,
                runIndex,
                resultIndex,
                pointer));
        return null;
    }

    private static IReadOnlyDictionary<string, string?>? ValidateFingerprintMap(
        IReadOnlyDictionary<string, string?>? values,
        SourceReference sourceReference,
        string pointer,
        ResourceLimits limits,
        ICollection<Diagnostic> diagnostics)
    {
        if (values is null)
        {
            return null;
        }

        var validated = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var entry in values.OrderBy(
                     item => item.Key,
                     StringComparer.Ordinal))
        {
            var entryPointer = pointer + "/" +
                SourceReference.EscapePointerSegment(entry.Key);
            var name = ValidateOptionalString(
                entry.Key,
                sourceReference,
                entryPointer,
                limits,
                diagnostics);
            var value = ValidateOptionalString(
                entry.Value,
                sourceReference,
                entryPointer,
                limits,
                diagnostics);
            if (name is not null && value is not null)
            {
                validated.Add(name, value);
            }
        }

        return validated;
    }

    private static string NormalizeProducerFamily(string toolName)
    {
        if (toolName.StartsWith("CodeQL", StringComparison.OrdinalIgnoreCase))
        {
            return "codeql";
        }

        if (toolName.StartsWith("Semgrep", StringComparison.OrdinalIgnoreCase))
        {
            return "semgrep";
        }

        var builder = new StringBuilder(toolName.Length);
        var previousWasSeparator = false;
        foreach (var character in toolName)
        {
            var normalized = character switch
            {
                >= 'A' and <= 'Z' => (char)(character + ('a' - 'A')),
                >= 'a' and <= 'z' or >= '0' and <= '9' => character,
                _ => '-',
            };
            if (normalized == '-')
            {
                if (builder.Length > 0 && !previousWasSeparator)
                {
                    builder.Append(normalized);
                }

                previousWasSeparator = true;
                continue;
            }

            builder.Append(normalized);
            previousWasSeparator = false;
        }

        var family = builder.ToString().TrimEnd('-');
        return family.Length == 0 ? "unknown-producer" : family;
    }

    private static JsonSerializerOptions CreateJsonOptions(ResourceLimits limits)
    {
        var options = new JsonSerializerOptions
        {
            MaxDepth = limits.MaximumJsonDepth,
            PropertyNameCaseInsensitive = false,
        };
        var budget = new JsonReadBudget(
            limits.MaximumThreadFlowLocationsPerResult);
        options.Converters.Add(
            new BoundedStringConverter(limits.MaximumStringCharacters));
        options.Converters.Add(new UnsupportedJsonValueConverter());
        options.Converters.Add(
            new BoundedListConverterFactory(
                elementType => GetCollectionLimit(elementType, limits),
                budget));
        options.Converters.Add(
            new BoundedStringDictionaryConverterFactory(
                limits.MaximumRunCollectionItems));
        return options;
    }

    private static int GetCollectionLimit(
        Type elementType,
        ResourceLimits limits)
    {
        if (elementType == typeof(SarifRunWire))
        {
            return limits.MaximumRuns;
        }

        if (elementType == typeof(SarifLocationWire))
        {
            return limits.MaximumLocationsPerResult;
        }

        if (elementType == typeof(SarifCodeFlowWire))
        {
            return limits.MaximumCodeFlowsPerResult;
        }

        if (elementType == typeof(SarifThreadFlowLocationWire))
        {
            return limits.MaximumThreadFlowLocationsPerResult;
        }

        return limits.MaximumRunCollectionItems;
    }

    private static SarifIngestionResult CreateEmptyResult(
        SarifIngestionRequest request,
        string? version,
        long inputBytes,
        IEnumerable<Diagnostic> diagnostics) =>
        CreateResult(
            request,
            version,
            inputBytes,
            findings: [],
            summaries: [],
            diagnostics);

    private static SarifIngestionResult CreateResult(
        SarifIngestionRequest request,
        string? version,
        long inputBytes,
        IEnumerable<Finding> findings,
        IEnumerable<SarifRunSummary> summaries,
        IEnumerable<Diagnostic> diagnostics)
    {
        var sortedDiagnostics = Diagnostic.Sort(diagnostics);
        var comparisonInput = new ComparisonInput(
            request.Input,
            request.LogicalName,
            findings.ToImmutableArray(),
            sortedDiagnostics);
        var summary = new SarifDocumentSummary(
            request.Input,
            version,
            inputBytes,
            request.CompressedUploadBytes,
            summaries
                .OrderBy(item => item.RunIndex)
                .ToImmutableArray());
        return new SarifIngestionResult(comparisonInput, summary);
    }

    private static Diagnostic CreateDiagnostic(
        string code,
        DiagnosticSeverity severity,
        DiagnosticStage stage,
        string message,
        InputKind input,
        int? runIndex = null,
        int? resultIndex = null,
        string pointer = "") =>
        new(
            code,
            severity,
            stage,
            message,
            new SourceReference(input, runIndex, resultIndex, pointer));

    private static Diagnostic CreateDiagnostic(
        string code,
        DiagnosticSeverity severity,
        DiagnosticStage stage,
        string message,
        SourceReference sourceReference,
        string pointer) =>
        new(
            code,
            severity,
            stage,
            message,
            new SourceReference(
                sourceReference.Input,
                sourceReference.RunIndex,
                sourceReference.ResultIndex,
                pointer));

    private static void AddRange<T>(
        ICollection<T> destination,
        IEnumerable<T> source)
    {
        foreach (var item in source)
        {
            destination.Add(item);
        }
    }

    private static string NormalizeLineEndings(string value) =>
        value
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

    /// <summary>
    /// Resolves artifact indexes and bounded URI-base chains before lexical canonicalisation.
    /// </summary>
    private sealed class LocationResolver
    {
        private readonly SarifRunWire run;
        private readonly int runIndex;
        private readonly SarifIngestionRequest request;
        private readonly PathCanonicalizer pathCanonicalizer;

        public LocationResolver(
            SarifRunWire run,
            int runIndex,
            SarifIngestionRequest request,
            PathCanonicalizer pathCanonicalizer)
        {
            this.run = run;
            this.runIndex = runIndex;
            this.request = request;
            this.pathCanonicalizer = pathCanonicalizer;
        }

        public PrimaryLocation? ResolvePrimary(
            SarifLocationWire? location,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (location?.PhysicalLocation is null)
            {
                if (location?.UnsupportedLogicalLocations is not null)
                {
                    diagnostics.Add(
                        CreateDiagnostic(
                            "UNSUPPORTED0100",
                            DiagnosticSeverity.Warning,
                            DiagnosticStage.Unsupported,
                            "Logical locations without a physical location are not comparison anchors.",
                            request.Input,
                            runIndex,
                            TryExtractResultIndex(pointer),
                            pointer + "/logicalLocations"));
                }

                return null;
            }

            if (location.UnsupportedLogicalLocations is not null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "UNSUPPORTED0100",
                        DiagnosticSeverity.Note,
                        DiagnosticStage.Unsupported,
                        "Location logicalLocations are retained only by the source SARIF.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/logicalLocations"));
            }

            var path = ResolveArtifactLocation(
                location.PhysicalLocation.ArtifactLocation,
                pointer + "/physicalLocation/artifactLocation",
                diagnostics);
            if (path is null)
            {
                return null;
            }

            var region = ResolveRegion(
                location.PhysicalLocation.Region,
                pointer + "/physicalLocation/region",
                diagnostics);
            var snippet = location.PhysicalLocation.Region?.Snippet?.Text ??
                location.PhysicalLocation.Region?.Snippet?.Markdown;
            if (snippet is not null &&
                snippet.Length >
                    request.Configuration.Limits.MaximumStringCharacters)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SECURITY0103",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Security,
                        "An embedded snippet exceeds the configured string limit.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/physicalLocation/region/snippet"));
                snippet = null;
            }

            AddRange(diagnostics, path.Diagnostics);
            return new PrimaryLocation(path, region, snippet);
        }

        public RelatedLocation ResolveRelated(
            SarifLocationWire? location,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            var primary = ResolvePrimary(location, pointer, diagnostics);
            var path = primary?.Path;
            var region = primary?.Region;
            var stableKey = VersionedHash.Compute(
                RelatedLocationAlgorithmVersion,
                path?.CanonicalUri,
                region?.StartLine?.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                region?.StartColumn?.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                region?.EndLine?.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                region?.EndColumn?.ToString(
                    System.Globalization.CultureInfo.InvariantCulture));
            return new RelatedLocation(path, region, stableKey);
        }

        private CanonicalPath? ResolveArtifactLocation(
            SarifArtifactLocationWire? location,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (location is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0120",
                        DiagnosticSeverity.Warning,
                        DiagnosticStage.Schema,
                        "A physical location has no artifactLocation.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer));
                return null;
            }

            var artifact = ResolveArtifactIndex(location, pointer, diagnostics);
            if (location.Index is not null && artifact is null)
            {
                return null;
            }

            if (location.Uri is null && artifact is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0121",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "The artifact location has no resolvable URI.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer));
                return null;
            }

            if (location.Uri is null && location.UriBaseId is not null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0125",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "An artifact location cannot specify uriBaseId without its own URI.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            var sourceReference = new SourceReference(
                request.Input,
                runIndex,
                TryExtractResultIndex(pointer),
                pointer);
            CanonicalPath? explicitPath = null;
            if (location.Uri is not null)
            {
                explicitPath = ResolveAndCanonicalize(
                    location.Uri,
                    location.UriBaseId,
                    sourceReference,
                    pointer,
                    diagnostics);
                if (explicitPath is null)
                {
                    return null;
                }
            }

            CanonicalPath? indexedPath = null;
            if (artifact is not null)
            {
                indexedPath = ResolveAndCanonicalize(
                    artifact.Uri,
                    artifact.UriBaseId,
                    sourceReference,
                    pointer + "/index",
                    diagnostics);
                if (indexedPath is null)
                {
                    return null;
                }
            }

            if (explicitPath is not null &&
                indexedPath is not null &&
                !string.Equals(
                    explicitPath.CanonicalUri,
                    indexedPath.CanonicalUri,
                    StringComparison.Ordinal))
            {
                AddRange(diagnostics, explicitPath.Diagnostics);
                AddRange(diagnostics, indexedPath.Diagnostics);
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0124",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "The artifact location URI and index resolve to different artifacts.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer));
                return null;
            }

            return explicitPath ?? indexedPath;
        }

        private CanonicalPath? ResolveAndCanonicalize(
            string? originalUri,
            string? uriBaseId,
            SourceReference sourceReference,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (string.IsNullOrWhiteSpace(originalUri))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0121",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "The artifact location has no resolvable URI.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer));
                return null;
            }

            if (originalUri.Length >
                request.Configuration.Limits.MaximumStringCharacters)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SECURITY0103",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Security,
                        "An artifact URI exceeds the configured string limit.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uri"));
                return null;
            }

            if (uriBaseId?.Length >
                request.Configuration.Limits.MaximumStringCharacters)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SECURITY0103",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Security,
                        "A URI-base identifier exceeds the configured string limit.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            var originalKind = PathCanonicalizer.Classify(originalUri);
            if (uriBaseId is not null &&
                originalKind is not PathKind.RepositoryRelative and
                not PathKind.DriveRelative)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0126",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "An absolute artifact URI cannot specify uriBaseId.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            string? resolvedUri = null;
            if (uriBaseId is not null)
            {
                resolvedUri = ResolveUriBase(
                    uriBaseId,
                    originalUri,
                    pointer,
                    diagnostics);
                if (resolvedUri is null)
                {
                    return null;
                }
            }

            return pathCanonicalizer.Canonicalize(
                originalUri,
                resolvedUri,
                sourceReference);
        }

        private SarifArtifactLocationWire? ResolveArtifactIndex(
            SarifArtifactLocationWire location,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (location.Index is not int artifactIndex)
            {
                return null;
            }

            if (artifactIndex < 0 ||
                artifactIndex >= (run.Artifacts?.Count ?? 0) ||
                run.Artifacts![artifactIndex]?.Location is null)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0122",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "The artifact index does not resolve to a run artifact.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/index"));
                return null;
            }

            return run.Artifacts[artifactIndex]!.Location;
        }

        private string? ResolveUriBase(
            string uriBaseId,
            string childUri,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            var visited = new HashSet<string>(StringComparer.Ordinal);
            var baseUri = ResolveUriBaseCore(
                uriBaseId,
                visited,
                depth: 0,
                pointer,
                diagnostics);
            return baseUri is null
                ? null
                : CombineLogicalUri(
                    baseUri,
                    childUri,
                    pointer,
                    diagnostics);
        }

        // Time: O(d), where d is the configured URI-base depth. Space: O(d).
        private string? ResolveUriBaseCore(
            string uriBaseId,
            ISet<string> visited,
            int depth,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (depth >= request.Configuration.Limits.MaximumUriBaseDepth)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "CANON0030",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Canonicalisation,
                        $"The URI-base chain exceeds the configured {request.Configuration.Limits.MaximumUriBaseDepth}-level limit.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            if (!visited.Add(uriBaseId))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "CANON0031",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Canonicalisation,
                        "The URI-base chain contains a cycle.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            if (run.OriginalUriBaseIds is null ||
                !run.OriginalUriBaseIds.TryGetValue(
                    uriBaseId,
                    out var baseLocation) ||
                baseLocation is null ||
                string.IsNullOrWhiteSpace(baseLocation.Uri))
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "CANON0032",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Canonicalisation,
                        "The URI-base identifier cannot be resolved.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            var resolved = baseLocation.Uri;
            if (resolved.Length >
                request.Configuration.Limits.MaximumStringCharacters)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SECURITY0103",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Security,
                        "A URI-base value exceeds the configured string limit.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
                return null;
            }

            if (baseLocation.UriBaseId is not null)
            {
                if (baseLocation.UriBaseId.Length >
                    request.Configuration.Limits.MaximumStringCharacters)
                {
                    diagnostics.Add(
                        CreateDiagnostic(
                            "SECURITY0103",
                            DiagnosticSeverity.Error,
                            DiagnosticStage.Security,
                            "A URI-base identifier exceeds the configured string limit.",
                            request.Input,
                            runIndex,
                            TryExtractResultIndex(pointer),
                            pointer + "/uriBaseId"));
                    return null;
                }

                var parent = ResolveUriBaseCore(
                    baseLocation.UriBaseId,
                    visited,
                    depth + 1,
                    pointer,
                    diagnostics);
                if (parent is null)
                {
                    return null;
                }

                resolved = CombineLogicalUri(
                    parent,
                    resolved,
                    pointer,
                    diagnostics);
                if (resolved is null)
                {
                    return null;
                }
            }

            visited.Remove(uriBaseId);
            return resolved;
        }

        private Region? ResolveRegion(
            SarifRegionWire? region,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (region is null)
            {
                return null;
            }

            var hasOffsetProperties =
                region.CharOffset.HasValue ||
                region.CharLength.HasValue ||
                region.ByteOffset.HasValue ||
                region.ByteLength.HasValue;
            if (hasOffsetProperties)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "UNSUPPORTED0101",
                        DiagnosticSeverity.Warning,
                        DiagnosticStage.Unsupported,
                        region.StartLine.HasValue
                            ? "SARIF offset-based region properties are not used; the line-and-column region was used."
                            : "Offset-only SARIF regions are not supported as comparison anchors.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer));
                if (!region.StartLine.HasValue)
                {
                    return null;
                }
            }

            try
            {
                return new Region(
                    region.StartLine,
                    region.StartColumn,
                    region.EndLine,
                    region.EndColumn);
            }
            catch (ArgumentException)
            {
                diagnostics.Add(
                    CreateDiagnostic(
                        "SCHEMA0123",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Schema,
                        "The SARIF region coordinates are invalid.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer));
                return null;
            }
        }

        private string? CombineLogicalUri(
            string baseUri,
            string childUri,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            var childKind = PathCanonicalizer.Classify(childUri);
            if (childKind is not PathKind.RepositoryRelative and
                not PathKind.DriveRelative)
            {
                return IsWithinStringLimit(childUri, pointer, diagnostics)
                    ? childUri
                    : null;
            }

            if ((long)baseUri.Length + childUri.Length + 1 >
                request.Configuration.Limits.MaximumStringCharacters)
            {
                AddCombinedUriLimitDiagnostic(pointer, diagnostics);
                return null;
            }

            if (Uri.TryCreate(baseUri, UriKind.Absolute, out var absoluteBase) &&
                Uri.TryCreate(absoluteBase, childUri, out var combined))
            {
                var absoluteUri = combined.AbsoluteUri;
                return IsWithinStringLimit(
                    absoluteUri,
                    pointer,
                    diagnostics)
                    ? absoluteUri
                    : null;
            }

            var normalizedBase = baseUri.TrimEnd('/', '\\');
            var normalizedChild = childUri.TrimStart('/', '\\');
            if ((long)normalizedBase.Length + 1 + normalizedChild.Length >
                request.Configuration.Limits.MaximumStringCharacters)
            {
                AddCombinedUriLimitDiagnostic(pointer, diagnostics);
                return null;
            }

            return normalizedBase + "/" + normalizedChild;
        }

        private bool IsWithinStringLimit(
            string value,
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            if (value.Length <=
                request.Configuration.Limits.MaximumStringCharacters)
            {
                return true;
            }

            AddCombinedUriLimitDiagnostic(pointer, diagnostics);
            return false;
        }

        private void AddCombinedUriLimitDiagnostic(
            string pointer,
            ICollection<Diagnostic> diagnostics)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "SECURITY0103",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    "A resolved URI exceeds the configured string limit.",
                    request.Input,
                    runIndex,
                    TryExtractResultIndex(pointer),
                    pointer + "/uriBaseId"));
        }

        private static int? TryExtractResultIndex(string pointer)
        {
            const string resultsMarker = "/results/";
            var markerIndex = pointer.IndexOf(
                resultsMarker,
                StringComparison.Ordinal);
            if (markerIndex < 0)
            {
                return null;
            }

            var valueStart = markerIndex + resultsMarker.Length;
            var valueEnd = pointer.IndexOf('/', valueStart);
            var value = valueEnd < 0
                ? pointer.AsSpan(valueStart)
                : pointer.AsSpan(valueStart, valueEnd - valueStart);
            return int.TryParse(
                value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var parsed)
                ? parsed
                : null;
        }
    }
}

internal static class EnumerableExtensions
{
    public static int MaxOrDefault<T>(
        this IEnumerable<T> source,
        Func<T, int> selector)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(selector);
        var maximum = 0;
        foreach (var item in source)
        {
            maximum = Math.Max(maximum, selector(item));
        }

        return maximum;
    }
}
