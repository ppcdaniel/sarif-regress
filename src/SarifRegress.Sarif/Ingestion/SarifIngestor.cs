using System.Collections.Immutable;
using System.Text.Json;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;
using SarifRegress.Sarif.Canonicalization;
using SarifRegress.Sarif.Configuration;
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

    /// <summary>
    /// Gets the configured URI-base provenance algorithm identifier.
    /// </summary>
    public const string ConfiguredUriBaseAlgorithmVersion =
        "sarifregress/configured-uri-base/v1";

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
                    CreateJsonOptions(limits, cancellationToken),
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

        var ruleAliasIndex = RuleAliasResolutionIndex.Create(
            request.Input,
            request.Configuration.RuleAliases);
        var pathCanonicalizer = new PathCanonicalizer(request.Configuration);
        var findings = new List<Finding>();
        for (var runIndex = 0; runIndex < log.Runs!.Count; runIndex++)
        {
            var run = log.Runs[runIndex];
            log.Runs[runIndex] = null;
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
                    ruleAliasIndex,
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
        RuleAliasResolutionIndex ruleAliasIndex,
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
        var producerResolution = ProducerIdentityResolver.Resolve(toolName);
        var producer = new ProducerIdentity(
            toolName,
            toolVersion,
            producerResolution.Family,
            automationCategory,
            producerResolution.AutomaticIdentity);
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
            // Document-wide facts have already been captured. Release each
            // wire result before expanding it into the canonical model.
            run.Results[resultIndex] = null;
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
                    producerResolution.LossinessIdentifier,
                    sourceReference,
                    request,
                    ruleAliasIndex,
                    locationResolver,
                    documentDiagnostics,
                    cancellationToken)
                .ConfigureAwait(false);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        return findings.ToImmutable();
    }

    private async ValueTask<Finding?> IngestResultAsync(
        SarifResultWire result,
        IReadOnlyList<SarifRuleWire?>? rules,
        RunIdentity runIdentity,
        ProducerIdentity producer,
        string? producerLossinessIdentifier,
        SourceReference sourceReference,
        SarifIngestionRequest request,
        RuleAliasResolutionIndex ruleAliasIndex,
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
            ruleAliasIndex,
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
        var metadata = new FindingMetadata(
            ValidateOptionalString(
                result.Level,
                sourceReference,
                sourceReference.JsonPointer + "/level",
                request.Configuration.Limits,
                findingDiagnostics),
            ValidateOptionalString(
                result.Kind,
                sourceReference,
                sourceReference.JsonPointer + "/kind",
                request.Configuration.Limits,
                findingDiagnostics),
            ValidateOptionalString(
                result.BaselineState,
                sourceReference,
                sourceReference.JsonPointer + "/baselineState",
                request.Configuration.Limits,
                findingDiagnostics));
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
                    includeTokenWindow:
                        request.Configuration.Matching.EnableTokenWindows,
                    sourceReference: sourceReference,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            context = repositoryResult.Evidence;
            if (!request.Configuration.Matching.EnableTokenWindows &&
                context is not null)
            {
                context = context with { TokenWindowHash = null };
            }

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
        var importedFingerprints = FingerprintProcessor.ImportForIngestion(
            validatedFingerprints,
            validatedPartialFingerprints,
            sourceReference);
        AddRange(findingDiagnostics, importedFingerprints.Diagnostics);

        var lossiness = new List<string>();
        if (producerLossinessIdentifier is not null)
        {
            lossiness.Add(producerLossinessIdentifier);
        }

        if (result.Message?.Text is null && result.Message?.Markdown is not null)
        {
            lossiness.Add("message-markdown-fallback");
        }

        lossiness.AddRange(message.NormalisationFlags);
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
            findingDiagnostics,
            metadata);
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
        RuleAliasResolutionIndex ruleAliasIndex,
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

        var aliasedId = ruleAliasIndex.Resolve(
            producer.AutomaticIdentity,
            originalRuleId);
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
            finding.Diagnostics,
            finding.Metadata);

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
        isValid &= ValidateCollectionCount(
            run.Invocations?.Count ?? 0,
            limits.MaximumRunCollectionItems,
            "invocations",
            input,
            runIndex,
            resultIndex: null,
            $"/runs/{runIndex}/invocations",
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
            var driverRules = run.Tool?.Driver?.Rules ?? [];
            var extensionRuleCount = 0;
            var maximumTagsPerRule = driverRules.MaxOrDefault(
                rule => rule?.Properties?.Tags?.Count ?? 0);
            foreach (var extension in run.Tool?.Extensions ?? [])
            {
                var extensionRules = extension?.Rules ?? [];
                extensionRuleCount = checked(
                    extensionRuleCount + extensionRules.Count);
                maximumTagsPerRule = Math.Max(
                    maximumTagsPerRule,
                    extensionRules.MaxOrDefault(
                        rule => rule?.Properties?.Tags?.Count ?? 0));
            }

            summaries.Add(
                new SarifRunSummary(
                    runIndex,
                    results.Count,
                    checked(driverRules.Count + extensionRuleCount),
                    run.Tool?.Extensions?.Count ?? 0,
                    results.MaxOrDefault(
                        result => result?.Locations?.Count ?? 0),
                    results.MaxOrDefault(CountThreadFlowLocations),
                    maximumTagsPerRule,
                    results.Count(
                        result => (result?.Locations?.Count ?? 0) > 1),
                    results.Count(
                        result => !HasPrimaryLocationLineHash(result)),
                    results.Count(
                        HasNonRepositoryPrimaryLocation),
                    DriverRuleCount: driverRules.Count,
                    ExtensionRuleCount: extensionRuleCount,
                    MaximumPartialFingerprintsPerResult:
                        results.MaxOrDefault(
                            result =>
                                result?.PartialFingerprints?.Count ?? 0),
                    ResultsWithoutDisplayLocation:
                        results.Count(
                            result => !HasPrimaryDisplayLocation(result)),
                    SourceRootFacts: CreateSourceRootFacts(run, results),
                    IgnoredProperties:
                        CreateGithubIgnoredPropertyFacts(run, results)));
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
        SarifResultWire? result)
    {
        var uri = ResolvePrimaryLocationUri(result);
        if (uri is null)
        {
            return false;
        }

        return PathCanonicalizer.Classify(uri) !=
            PathKind.RepositoryRelative;
    }

    private static bool HasPrimaryDisplayLocation(
        SarifResultWire? result) =>
        !string.IsNullOrWhiteSpace(
            ResolvePrimaryLocationUri(result));

    private static string? ResolvePrimaryLocationUri(
        SarifResultWire? result) =>
        result?.Locations?.FirstOrDefault()?.PhysicalLocation
            ?.ArtifactLocation?.Uri;

    private static GithubSourceRootFacts CreateSourceRootFacts(
        SarifRunWire run,
        IReadOnlyList<SarifResultWire?> results)
    {
        var invocations = run.Invocations ?? [];
        var workingDirectoryUri =
            invocations.FirstOrDefault()?.WorkingDirectory?.Uri;
        var workingDirectoryKind =
            ClassifyWorkingDirectoryUri(workingDirectoryUri);
        Uri? sourceRoot = null;
        if (workingDirectoryKind ==
                GithubWorkingDirectoryUriKind.AbsoluteUri &&
            Uri.TryCreate(
                workingDirectoryUri,
                UriKind.Absolute,
                out var parsedSourceRoot))
        {
            sourceRoot = EnsureDirectoryUri(parsedSourceRoot);
        }

        var absoluteUriLocations = 0;
        var absolutePathLocations = 0;
        var convertibleLocations = 0;
        var outsideSourceRootLocations = 0;
        var schemeMismatches = 0;
        foreach (var result in results)
        {
            var locationUri = ResolvePrimaryLocationUri(result);
            var pathKind = PathCanonicalizer.Classify(locationUri);
            if (pathKind is PathKind.FileUri or PathKind.ExternalUri)
            {
                absoluteUriLocations++;
                if (sourceRoot is null ||
                    !Uri.TryCreate(
                        locationUri,
                        UriKind.Absolute,
                        out var parsedLocation))
                {
                    continue;
                }

                if (!string.Equals(
                        sourceRoot.Scheme,
                        parsedLocation.Scheme,
                        StringComparison.OrdinalIgnoreCase))
                {
                    schemeMismatches++;
                }
                else if (sourceRoot.IsBaseOf(parsedLocation))
                {
                    convertibleLocations++;
                }
                else
                {
                    outsideSourceRootLocations++;
                }
            }
            else if (pathKind is
                     PathKind.PosixAbsolute or
                     PathKind.DriveAbsolute or
                     PathKind.RootRelative or
                     PathKind.Unc or
                     PathKind.Device or
                     PathKind.DeviceUnc)
            {
                absolutePathLocations++;
            }
        }

        return new GithubSourceRootFacts(
            invocations.Count,
            workingDirectoryKind,
            invocations
                .Skip(1)
                .Count(
                    invocation =>
                        !string.IsNullOrWhiteSpace(
                            invocation?.WorkingDirectory?.Uri)),
            absoluteUriLocations,
            absolutePathLocations,
            convertibleLocations,
            outsideSourceRootLocations,
            schemeMismatches);
    }

    private static GithubWorkingDirectoryUriKind
        ClassifyWorkingDirectoryUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return GithubWorkingDirectoryUriKind.Missing;
        }

        var pathKind = PathCanonicalizer.Classify(value);
        if (pathKind is PathKind.FileUri or PathKind.ExternalUri)
        {
            return Uri.TryCreate(value, UriKind.Absolute, out _)
                ? GithubWorkingDirectoryUriKind.AbsoluteUri
                : GithubWorkingDirectoryUriKind.Invalid;
        }

        if (pathKind == PathKind.RepositoryRelative &&
            Uri.TryCreate(value, UriKind.Relative, out _))
        {
            return GithubWorkingDirectoryUriKind.RelativeReference;
        }

        if (pathKind is
            PathKind.PosixAbsolute or
            PathKind.DriveAbsolute or
            PathKind.RootRelative or
            PathKind.Unc or
            PathKind.Device or
            PathKind.DeviceUnc)
        {
            return GithubWorkingDirectoryUriKind.AbsolutePath;
        }

        return GithubWorkingDirectoryUriKind.Invalid;
    }

    private static Uri EnsureDirectoryUri(Uri uri)
    {
        var absolutePath = uri.GetLeftPart(UriPartial.Path);
        if (absolutePath.EndsWith("/", StringComparison.Ordinal))
        {
            return uri;
        }

        return Uri.TryCreate(
                absolutePath + "/",
                UriKind.Absolute,
                out var directoryUri)
            ? directoryUri
            : uri;
    }

    private static ImmutableArray<GithubIgnoredPropertyFact>
        CreateGithubIgnoredPropertyFacts(
            SarifRunWire run,
            IReadOnlyList<SarifResultWire?> results)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        AddIfPresent("run.graphs", run.UnsupportedGraphs);
        AddIfPresent("run.artifacts", run.Artifacts);
        if (HasAutomationRunId(run.AutomationDetails?.Id))
        {
            Increment("automationDetails.id.runId");
        }

        foreach (var result in results)
        {
            if (result is null)
            {
                continue;
            }

            AddIfPresent("result.fingerprints", result.Fingerprints);
            AddIfPresent("result.message.markdown", result.Message?.Markdown);
            AddIfPresent("result.kind", result.Kind);
            AddIfPresent("result.baselineState", result.BaselineState);
            AddIfPresent(
                "result.logicalLocations",
                result.UnsupportedLogicalLocations);
            AddIfPresent("result.stacks", result.UnsupportedStacks);
            AddIfPresent(
                "result.suppressions",
                result.UnsupportedSuppressions);
            AddIfPresent("result.attachments", result.UnsupportedAttachments);
            AddLocationFacts(result.Locations);
            AddLocationFacts(result.RelatedLocations);
            foreach (var codeFlow in result.CodeFlows ?? [])
            {
                foreach (var threadFlow in codeFlow?.ThreadFlows ?? [])
                {
                    AddLocationFacts(
                        (threadFlow?.Locations ?? [])
                            .Select(item => item?.Location));
                }
            }
        }

        return counts
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(
                item =>
                    new GithubIgnoredPropertyFact(item.Key, item.Value))
            .ToImmutableArray();

        void AddLocationFacts(IEnumerable<SarifLocationWire?>? locations)
        {
            foreach (var location in locations ?? [])
            {
                AddIfPresent(
                    "location.message.markdown",
                    location?.Message?.Markdown);
                AddIfPresent(
                    "location.logicalLocations",
                    location?.UnsupportedLogicalLocations);
                AddIfPresent(
                    "artifactLocation.index",
                    location?.PhysicalLocation?.ArtifactLocation?.Index);
                var region = location?.PhysicalLocation?.Region;
                AddIfPresent("region.snippet", region?.Snippet);
                if (region is not null &&
                    (region.CharOffset is not null ||
                     region.CharLength is not null ||
                     region.ByteOffset is not null ||
                     region.ByteLength is not null))
                {
                    Increment("region.offsets");
                }
            }
        }

        void AddIfPresent(string propertyPath, object? value)
        {
            if (value is not null)
            {
                Increment(propertyPath);
            }
        }

        void Increment(string propertyPath)
        {
            counts.TryGetValue(propertyPath, out var current);
            counts[propertyPath] = checked(current + 1);
        }
    }

    private static bool HasAutomationRunId(string? automationId)
    {
        if (string.IsNullOrEmpty(automationId))
        {
            return false;
        }

        var separator = automationId.LastIndexOf('/');
        return separator >= 0 && separator < automationId.Length - 1;
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

        var allValuesAreValid = true;
        foreach (var entry in values)
        {
            if (entry.Key.Length > limits.MaximumStringCharacters ||
                entry.Value is null ||
                entry.Value.Length > limits.MaximumStringCharacters)
            {
                allValuesAreValid = false;
                break;
            }
        }

        if (allValuesAreValid)
        {
            return values;
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

    private static JsonSerializerOptions CreateJsonOptions(
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
        var constraints = new BoundedJsonReadConstraints(
            limits.MaximumJsonDepth,
            limits.MaximumRunCollectionItems,
            limits.MaximumStringCharacters,
            cancellationToken);
        var options = new JsonSerializerOptions
        {
            MaxDepth = limits.MaximumJsonDepth,
            PropertyNameCaseInsensitive = false,
        };
        var budget = new JsonReadBudget(
            limits.MaximumThreadFlowLocationsPerResult,
            cancellationToken);
        options.Converters.Add(
            new BoundedStringConverter(
                limits.MaximumStringCharacters,
                cancellationToken));
        options.Converters.Add(
            new UnsupportedJsonValueConverter(constraints));
        options.Converters.Add(
            new BoundedJsonObjectConverterFactory(
                type =>
                    type.Namespace == typeof(SarifLogWire).Namespace &&
                    type.Name.EndsWith("Wire", StringComparison.Ordinal),
                constraints));
        options.Converters.Add(
            new BoundedListConverterFactory(
                elementType => GetCollectionLimit(elementType, limits),
                constraints,
                budget));
        options.Converters.Add(
            new BoundedStringDictionaryConverterFactory(
                limits.MaximumRunCollectionItems,
                constraints));
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

        if (elementType == typeof(SarifThreadFlowWire))
        {
            return limits.MaximumThreadFlowLocationsPerResult;
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
        private readonly ImmutableArray<UriBaseMapping>
            configuredUriBases;

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
            configuredUriBases = request.Configuration.UriBaseMappings;
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
            var configuredMappings = new List<UriBaseMapping>();
            if (uriBaseId is not null)
            {
                resolvedUri = ResolveUriBase(
                    uriBaseId,
                    originalUri,
                    pointer,
                    diagnostics,
                    configuredMappings);
                if (resolvedUri is null)
                {
                    return null;
                }
            }

            var canonicalPath = pathCanonicalizer.Canonicalize(
                originalUri,
                resolvedUri,
                sourceReference);
            if (configuredMappings.Count == 0)
            {
                return canonicalPath;
            }

            var configurationTransforms = configuredMappings.Select(
                mapping => new TransformationRecord(
                    "configured-uri-base",
                    mapping.Id,
                    transformedValue: null,
                    isLossy: false,
                    ConfiguredUriBaseAlgorithmVersion));
            return new CanonicalPath(
                canonicalPath.OriginalValue,
                canonicalPath.ResolvedValue,
                canonicalPath.CanonicalUri,
                canonicalPath.RepositoryRelativePath,
                canonicalPath.Kind,
                configurationTransforms.Concat(
                    canonicalPath.Transformations),
                canonicalPath.Diagnostics);
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
            ICollection<Diagnostic> diagnostics,
            ICollection<UriBaseMapping> configuredMappings)
        {
            var visited = new HashSet<string>(StringComparer.Ordinal);
            var resolutionLegs = new List<UriBaseResolutionLeg>();
            var baseUri = ResolveUriBaseCore(
                uriBaseId,
                visited,
                depth: 0,
                pointer,
                diagnostics,
                configuredMappings,
                resolutionLegs);
            if (baseUri is null)
            {
                return null;
            }

            if (configuredMappings.Count > 0 &&
                (!ConfiguredUriBasePolicy.IsSafeResolvedRoot(baseUri) ||
                    !HasSafeConfiguredChain(resolutionLegs)))
            {
                AddUnresolvedUriBaseDiagnostic(
                    pointer,
                    diagnostics,
                    "The configured URI-base chain resolved outside approved local roots.");
                return null;
            }

            if (configuredMappings.Count > 0 &&
                !ConfiguredUriBasePolicy.IsSafeArtifactReference(childUri))
            {
                AddUnresolvedUriBaseDiagnostic(
                    pointer,
                    diagnostics,
                    "A configured URI-base mapping cannot resolve a parent-traversing artifact reference.");
                return null;
            }

            return CombineLogicalUri(
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
            ICollection<Diagnostic> diagnostics,
            ICollection<UriBaseMapping> configuredMappings,
            ICollection<UriBaseResolutionLeg> resolutionLegs)
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

            SarifArtifactLocationWire? baseLocation = null;
            var isSarifDefined =
                run.OriginalUriBaseIds is not null &&
                run.OriginalUriBaseIds.TryGetValue(
                    uriBaseId,
                    out baseLocation);
            UriBaseMapping? configuredMapping = null;
            if (!isSarifDefined)
            {
                TryGetConfiguredUriBase(
                    uriBaseId,
                    out configuredMapping);
            }

            if (isSarifDefined &&
                (baseLocation is null ||
                    string.IsNullOrWhiteSpace(baseLocation.Uri)))
            {
                AddUnresolvedUriBaseDiagnostic(
                    pointer,
                    diagnostics,
                    "The SARIF-defined URI-base identifier is invalid.");
                return null;
            }

            if (!isSarifDefined && configuredMapping is null)
            {
                AddUnresolvedUriBaseDiagnostic(
                    pointer,
                    diagnostics,
                    "The URI-base identifier cannot be resolved.");
                return null;
            }

            if (configuredMapping is not null &&
                !ConfiguredUriBasePolicy.IsSafe(configuredMapping))
            {
                AddUnresolvedUriBaseDiagnostic(
                    pointer,
                    diagnostics,
                    "The configured URI-base identifier has an unsafe target.");
                return null;
            }

            var declaredUri = isSarifDefined
                ? baseLocation!.Uri!
                : configuredMapping!.Uri;
            string? resolved = declaredUri;
            var parentUriBaseId = isSarifDefined
                ? baseLocation!.UriBaseId
                : configuredMapping!.UriBaseId;
            if (declaredUri.Length >
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

            if (parentUriBaseId is not null)
            {
                if (parentUriBaseId.Length >
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
                    parentUriBaseId,
                    visited,
                    depth + 1,
                    pointer,
                    diagnostics,
                    configuredMappings,
                    resolutionLegs);
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

            if (configuredMapping is not null)
            {
                configuredMappings.Add(configuredMapping);
                diagnostics.Add(
                    CreateDiagnostic(
                        "CANON0033",
                        DiagnosticSeverity.Note,
                        DiagnosticStage.Canonicalisation,
                        "The missing URI-base identifier was supplied by explicit configuration.",
                        request.Input,
                        runIndex,
                        TryExtractResultIndex(pointer),
                        pointer + "/uriBaseId"));
            }

            resolutionLegs.Add(
                new UriBaseResolutionLeg(declaredUri));

            visited.Remove(uriBaseId);
            return resolved;
        }

        // Time: O(log m), where m is the bounded mapping count. Space: O(1).
        private bool TryGetConfiguredUriBase(
            string uriBaseId,
            out UriBaseMapping? mapping)
        {
            var lower = 0;
            var upper = configuredUriBases.Length - 1;
            while (lower <= upper)
            {
                var middle = lower + ((upper - lower) / 2);
                var candidate = configuredUriBases[middle];
                var comparison = StringComparer.Ordinal.Compare(
                    candidate.Id,
                    uriBaseId);
                if (comparison == 0)
                {
                    mapping = candidate;
                    return true;
                }

                if (comparison < 0)
                {
                    lower = middle + 1;
                }
                else
                {
                    upper = middle - 1;
                }
            }

            mapping = null;
            return false;
        }

        private static bool HasSafeConfiguredChain(
            IReadOnlyList<UriBaseResolutionLeg> resolutionLegs)
        {
            if (resolutionLegs.Count == 0 ||
                !ConfiguredUriBasePolicy.IsSafeResolvedRoot(
                    resolutionLegs[0].Uri))
            {
                return false;
            }

            for (var index = 1; index < resolutionLegs.Count; index++)
            {
                if (!ConfiguredUriBasePolicy.IsSafeRelativeDefinition(
                        resolutionLegs[index].Uri))
                {
                    return false;
                }
            }

            return true;
        }

        private void AddUnresolvedUriBaseDiagnostic(
            string pointer,
            ICollection<Diagnostic> diagnostics,
            string message)
        {
            diagnostics.Add(
                CreateDiagnostic(
                    "CANON0032",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Canonicalisation,
                    message,
                    request.Input,
                    runIndex,
                    TryExtractResultIndex(pointer),
                    pointer + "/uriBaseId"));
        }

        private readonly record struct UriBaseResolutionLeg(string Uri);

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
