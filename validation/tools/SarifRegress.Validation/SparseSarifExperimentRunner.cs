using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;
using SarifRegress.Match;
using SarifRegress.Sarif.Ingestion;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.Validation;

/// <summary>
/// Runs fixed source-context variants without opening the corpus label files.
/// </summary>
public sealed class SparseSarifExperimentRunner
{
    public const string OutputFileName = "sparse-experiment-observations.json";
    public const string ObservationsKind = "sparse-experiment-observations/v1";

    private const int LineRadius = 20;
    private const int MaximumRelativeRegionTerms = 256;
    private const int MaximumRelativeSurroundingTerms = 32;
    private const string ExactAlgorithm = "exact-region-snippet/v1";
    private const string RelativeAlgorithm = "relative-context/v1";
    private const string CombinationAlgorithm = "agreement-only-combination/v1";
    private static readonly ResourceLimits ProductLimits = ResourceLimits.Default;

    private readonly ValidationLimits limits;

    /// <summary>Creates a bounded validation-only experiment runner.</summary>
    public SparseSarifExperimentRunner(ValidationLimits? limits = null)
    {
        this.limits = limits ?? ValidationLimits.Default;
        this.limits.Validate();
    }

    /// <summary>Runs all fixed variants using separate roots for each SARIF side.</summary>
    public async ValueTask<SparseExperimentObservations> RunAsync(
        string repositoryRoot,
        string outputRoot,
        CancellationToken cancellationToken = default)
    {
        string repository = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(repositoryRoot));
        string output = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(outputRoot));
        ValidationApplication.EnsureOutputRoot(output);
        SparseResearchManifest manifest = SparseResearchManifestReader.Read(
            repository,
            limits);
        string implementationManifestSha256 =
            SparseResearchManifestReader.ValidateImplementationManifest(
                repository,
                limits);

        var variants = ImmutableArray.CreateBuilder<SparseVariantObservation>(
            SparseExperimentVariants.Ordered.Length);
        foreach (string variantId in SparseExperimentVariants.Ordered)
        {
            cancellationToken.ThrowIfCancellationRequested();
            variants.Add(await RunVariantAsync(
                    repository,
                    output,
                    manifest,
                    variantId,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return new SparseExperimentObservations(
            SchemaVersion: "1",
            Kind: ObservationsKind,
            manifest.Sha256,
            implementationManifestSha256,
            variants.MoveToImmutable());
    }

    private async ValueTask<SparseVariantObservation> RunVariantAsync(
        string repositoryRoot,
        string outputRoot,
        SparseResearchManifest manifest,
        string variantId,
        CancellationToken cancellationToken)
    {
        var familyRuns = ImmutableArray.CreateBuilder<FamilyRun>(manifest.Families.Length);
        foreach (SparseFamilyManifest family in manifest.Families)
        {
            familyRuns.Add(await RunFamilyAsync(
                    repositoryRoot,
                    family,
                    variantId,
                    ResolveRoot(repositoryRoot, family.Baseline.SourceRoot),
                    ResolveRoot(repositoryRoot, family.Candidate.SourceRoot),
                    enforceTrustedTreeHashes: true,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        if (familyRuns.Any(item => !item.PreflightAccepted))
        {
            throw new InvalidDataException(
                "A clean sparse corpus source tree failed its trusted hash preflight.");
        }

        ImmutableArray<SparseFamilyObservation> families = familyRuns
            .Select(item => item.Observation)
            .ToImmutableArray();
        var productionFamilyRuns = ImmutableArray.CreateBuilder<FamilyRun>(
            manifest.Families.Length);
        foreach (SparseFamilyManifest family in manifest.Families)
        {
            productionFamilyRuns.Add(await RunFamilyAsync(
                    repositoryRoot,
                    family,
                    variantId,
                    ResolveRoot(repositoryRoot, family.Baseline.SourceRoot),
                    ResolveRoot(repositoryRoot, family.Candidate.SourceRoot),
                    enforceTrustedTreeHashes: false,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        ImmutableArray<SparseFamilyObservation> productionFamilies =
            productionFamilyRuns.Select(item => item.Observation).ToImmutableArray();
        ImmutableArray<SparseScenarioObservation> scenarios =
            await RunScenariosAsync(
                    repositoryRoot,
                    outputRoot,
                    manifest,
                    variantId,
                    familyRuns,
                    enforceTrustedTreeHashes: true,
                    cancellationToken)
                .ConfigureAwait(false);
        ImmutableArray<SparseScenarioObservation> productionScenarios =
            await RunScenariosAsync(
                    repositoryRoot,
                    outputRoot,
                    manifest,
                    variantId,
                    productionFamilyRuns,
                    enforceTrustedTreeHashes: false,
                    cancellationToken)
                .ConfigureAwait(false);
        SparseIngestionObservation ingestion = AggregateIngestion(families);
        SparseSecurityObservation security = AggregateSecurity(scenarios);
        var production = new SparseProductionApplicabilityObservation(
            TrustedTreeHashPreflightEnabled: false,
            productionFamilies,
            productionScenarios,
            AggregateIngestion(productionFamilies),
            AggregateSecurity(productionScenarios));
        return new SparseVariantObservation(
            variantId,
            GetAlgorithmVersion(variantId),
            GetParameters(variantId),
            families,
            scenarios,
            ingestion,
            security,
            production);
    }

    private async ValueTask<ImmutableArray<SparseScenarioObservation>> RunScenariosAsync(
        string repositoryRoot,
        string outputRoot,
        SparseResearchManifest manifest,
        string variantId,
        ImmutableArray<FamilyRun>.Builder normalRuns,
        bool enforceTrustedTreeHashes,
        CancellationToken cancellationToken)
    {
        var byId = new Dictionary<string, SparseScenarioObservation>(StringComparer.Ordinal);
        foreach (string id in SparseExperimentScenarios.Ordered)
        {
            bool securityScenario = id is "missing-source-file"
                or "mismatched-source-snapshot"
                or "baseline-root-bound-to-candidate"
                or "candidate-root-bound-to-baseline"
                or "both-roots-swapped";
            if (!securityScenario)
            {
                byId.Add(
                    id,
                    new SparseScenarioObservation(
                        id,
                        normalRuns
                            .Select(run => ScenarioFamilyFromRun(run))
                            .ToImmutableArray()));
                continue;
            }

            var familyOutcomes = ImmutableArray.CreateBuilder<SparseFamilyScenarioObservation>(
                manifest.Families.Length);
            foreach (SparseFamilyManifest family in manifest.Families)
            {
                FamilyRun normalFamilyRun = normalRuns.Single(item =>
                    string.Equals(
                        item.Observation.FamilyId,
                        family.Id,
                        StringComparison.Ordinal));
                SparseNaturalSelector baselineFirst =
                    normalFamilyRun.BaselineSelectors.FirstOrDefault()
                    ?? throw new InvalidDataException(
                        "A sparse baseline family has no finding selector.");
                SparseNaturalSelector candidateFirst =
                    normalFamilyRun.CandidateSelectors.FirstOrDefault()
                    ?? throw new InvalidDataException(
                        "A sparse candidate family has no finding selector.");
                ImmutableArray<SparseNaturalSelector> baselineInSelectedFile =
                    normalFamilyRun.BaselineSelectors.Where(item => string.Equals(
                            item.ArtifactUri,
                            baselineFirst.ArtifactUri,
                            StringComparison.Ordinal))
                        .ToImmutableArray();
                ImmutableArray<SparseNaturalSelector> candidateInSelectedFile =
                    normalFamilyRun.CandidateSelectors.Where(item => string.Equals(
                            item.ArtifactUri,
                            candidateFirst.ArtifactUri,
                            StringComparison.Ordinal))
                        .ToImmutableArray();
                string baselineRoot = ResolveRoot(
                    repositoryRoot,
                    family.Baseline.SourceRoot);
                string candidateRoot = ResolveRoot(
                    repositoryRoot,
                    family.Candidate.SourceRoot);
                var temporaryRoots = new List<string>();
                ImmutableArray<SparseNaturalSelector> affectedBaseline = [];
                ImmutableArray<SparseNaturalSelector> affectedCandidate = [];
                try
                {
                    switch (id)
                    {
                        case "missing-source-file":
                            baselineRoot = CreateAlteredSourceTree(
                                outputRoot,
                                family.Id,
                                "baseline",
                                baselineRoot,
                                baselineFirst.ArtifactUri,
                                removeFirstFile: true);
                            temporaryRoots.Add(baselineRoot);
                            candidateRoot = CreateAlteredSourceTree(
                                outputRoot,
                                family.Id,
                                "candidate",
                                candidateRoot,
                                candidateFirst.ArtifactUri,
                                removeFirstFile: true);
                            temporaryRoots.Add(candidateRoot);
                            affectedBaseline = baselineInSelectedFile;
                            affectedCandidate = candidateInSelectedFile;
                            break;
                        case "mismatched-source-snapshot":
                            baselineRoot = CreateAlteredSourceTree(
                                outputRoot,
                                family.Id,
                                "baseline",
                                baselineRoot,
                                baselineFirst.ArtifactUri,
                                removeFirstFile: false);
                            temporaryRoots.Add(baselineRoot);
                            candidateRoot = CreateAlteredSourceTree(
                                outputRoot,
                                family.Id,
                                "candidate",
                                candidateRoot,
                                candidateFirst.ArtifactUri,
                                removeFirstFile: false);
                            temporaryRoots.Add(candidateRoot);
                            affectedBaseline = baselineInSelectedFile;
                            affectedCandidate = candidateInSelectedFile;
                            break;
                        case "baseline-root-bound-to-candidate":
                            baselineRoot = candidateRoot;
                            break;
                        case "candidate-root-bound-to-baseline":
                            candidateRoot = baselineRoot;
                            break;
                        case "both-roots-swapped":
                            (baselineRoot, candidateRoot) = (candidateRoot, baselineRoot);
                            break;
                    }

                    FamilyRun run = await RunFamilyAsync(
                            repositoryRoot,
                            family,
                            variantId,
                            baselineRoot,
                            candidateRoot,
                            enforceTrustedTreeHashes,
                            cancellationToken)
                        .ConfigureAwait(false);
                    familyOutcomes.Add(ScenarioFamilyFromRun(
                        run,
                        affectedBaseline,
                        affectedCandidate));
                }
                finally
                {
                    foreach (string temporaryRoot in temporaryRoots)
                    {
                        if (Directory.Exists(temporaryRoot))
                        {
                            Directory.Delete(temporaryRoot, recursive: true);
                        }
                    }
                }
            }

            byId.Add(id, new SparseScenarioObservation(id, familyOutcomes.MoveToImmutable()));
        }

        return SparseExperimentScenarios.Ordered
            .Select(id => byId[id])
            .ToImmutableArray();
    }

    private async ValueTask<FamilyRun> RunFamilyAsync(
        string repositoryRoot,
        SparseFamilyManifest family,
        string variantId,
        string baselineRoot,
        string candidateRoot,
        bool enforceTrustedTreeHashes,
        CancellationToken cancellationToken)
    {
        string? baselineTreeHash = TryComputeSourceTreeHash(baselineRoot);
        string? candidateTreeHash = TryComputeSourceTreeHash(candidateRoot);
        bool preflightAccepted = !enforceTrustedTreeHashes
            || string.Equals(
                baselineTreeHash,
                family.Baseline.SourceTreeSha256,
                StringComparison.Ordinal)
            && string.Equals(
                candidateTreeHash,
                family.Candidate.SourceTreeSha256,
                StringComparison.Ordinal);
        if (!preflightAccepted)
        {
            return FamilyRun.Refused(family, baselineTreeHash, candidateTreeHash);
        }

        byte[] baselineSarif = ReadAndVerifySarif(
            repositoryRoot,
            family.Baseline);
        byte[] candidateSarif = ReadAndVerifySarif(
            repositoryRoot,
            family.Candidate);
        SarifRegressConfiguration configuration = ExperimentConfiguration();
        SarifIngestionResult baselineIngestion = await IngestAsync(
                baselineSarif,
                InputKind.Baseline,
                family.Id + "/baseline",
                configuration,
                cancellationToken)
            .ConfigureAwait(false);
        SarifIngestionResult candidateIngestion = await IngestAsync(
                candidateSarif,
                InputKind.Candidate,
                family.Id + "/candidate",
                configuration,
                cancellationToken)
            .ConfigureAwait(false);
        if (baselineIngestion.ComparisonInput.Findings.Length != family.Baseline.ResultCount
            || candidateIngestion.ComparisonInput.Findings.Length != family.Candidate.ResultCount)
        {
            throw new InvalidDataException(
                $"Sparse family '{family.Id}' did not ingest its fixed result counts.");
        }

        SourceReadSet baselineReads = await ReadSourceAtomsAsync(
                baselineIngestion.ComparisonInput,
                baselineRoot,
                ResolveRoot(repositoryRoot, family.Baseline.SourceRoot),
                ResolveRoot(repositoryRoot, family.Candidate.SourceRoot),
                variantId,
                cancellationToken)
            .ConfigureAwait(false);
        SourceReadSet candidateReads = await ReadSourceAtomsAsync(
                candidateIngestion.ComparisonInput,
                candidateRoot,
                ResolveRoot(repositoryRoot, family.Baseline.SourceRoot),
                ResolveRoot(repositoryRoot, family.Candidate.SourceRoot),
                variantId,
                cancellationToken)
            .ConfigureAwait(false);
        ProjectedInputs projected = Project(
            baselineIngestion.ComparisonInput,
            candidateIngestion.ComparisonInput,
            baselineReads.Atoms,
            candidateReads.Atoms,
            variantId);
        ValidateSourceOperationBounds(
            projected,
            baselineIngestion.ComparisonInput.Findings.Length,
            candidateIngestion.ComparisonInput.Findings.Length,
            variantId);
        MatchResult match = new FindingMatcher().Match(
            projected.Baseline,
            projected.Candidate,
            configuration);
        ImmutableArray<SparseAcceptedPair> accepted = match.Decisions
            .Where(item => item.Baseline is not null
                && item.Candidate is not null
                && item.Classification is FindingClassification.Unchanged
                    or FindingClassification.Moved
                    or FindingClassification.Modified)
            .Select(item => new SparseAcceptedPair(
                Selector(item.Baseline!),
                Selector(item.Candidate!),
                item.Classification,
                item.Decision.PrecedenceTier))
            .OrderBy(item => SelectorKey(item.Baseline), StringComparer.Ordinal)
            .ThenBy(item => SelectorKey(item.Candidate), StringComparer.Ordinal)
            .ToImmutableArray();
        ImmutableArray<SparseNaturalSelector> newFindings = SelectDecisions(
            match,
            FindingClassification.New,
            selectCandidate: true);
        ImmutableArray<SparseNaturalSelector> resolvedFindings = SelectDecisions(
            match,
            FindingClassification.Resolved,
            selectCandidate: false);
        ImmutableArray<SparseNaturalSelector> ambiguousBaseline = SelectDecisions(
            match,
            FindingClassification.Ambiguous,
            selectCandidate: false);
        ImmutableArray<SparseNaturalSelector> ambiguousCandidate = SelectDecisions(
            match,
            FindingClassification.Ambiguous,
            selectCandidate: true);
        ImmutableArray<string> diagnosticCodes = baselineIngestion.ComparisonInput.Diagnostics
            .Concat(candidateIngestion.ComparisonInput.Diagnostics)
            .Concat(baselineReads.Diagnostics)
            .Concat(candidateReads.Diagnostics)
            .Concat(match.Diagnostics)
            .Select(item => item.Code)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(item => item, StringComparer.Ordinal)
            .Take(256)
            .ToImmutableArray();
        int ingestionFailures = (baselineIngestion.IsValid ? 0 : 1)
            + (candidateIngestion.IsValid ? 0 : 1);
        int structuralFailures = CountStructuralFailures(
            baselineIngestion.ComparisonInput.Diagnostics)
            + CountStructuralFailures(candidateIngestion.ComparisonInput.Diagnostics);
        var observation = new SparseFamilyObservation(
            family.Id,
            family.Baseline.ProjectedSarifSha256,
            family.Candidate.ProjectedSarifSha256,
            baselineTreeHash ?? EmptyTreeSha256,
            candidateTreeHash ?? EmptyTreeSha256,
            accepted,
            newFindings,
            resolvedFindings,
            ambiguousBaseline,
            ambiguousCandidate,
            diagnosticCodes,
            new SparseOperationCounts(
                projected.SourceFindingsIndexed,
                projected.SourceAtomsIndexed,
                projected.SourceIndexLookups,
                match.CandidateEdgeCount,
                match.ComponentCount,
                match.AmbiguousComponentCount),
            ingestionFailures,
            structuralFailures);
        ImmutableArray<SparseNaturalSelector> baselineSelectors =
            baselineIngestion.ComparisonInput.Findings
            .Select(Selector)
            .OrderBy(SelectorKey, StringComparer.Ordinal)
            .ToImmutableArray();
        ImmutableArray<SparseNaturalSelector> candidateSelectors =
            candidateIngestion.ComparisonInput.Findings
            .Select(Selector)
            .OrderBy(SelectorKey, StringComparer.Ordinal)
            .ToImmutableArray();
        return new FamilyRun(
            preflightAccepted,
            observation,
            baselineSelectors,
            candidateSelectors,
            baselineReads.ReadsFromOppositeRoot,
            candidateReads.ReadsFromOppositeRoot,
            baselineReads.ContainmentViolations + candidateReads.ContainmentViolations);
    }

    private async ValueTask<SourceReadSet> ReadSourceAtomsAsync(
        ComparisonInput input,
        string sourceRoot,
        string declaredBaselineRoot,
        string declaredCandidateRoot,
        string variantId,
        CancellationToken cancellationToken)
    {
        if (string.Equals(
                variantId,
                SparseExperimentVariants.SarifOnlyControl,
                StringComparison.Ordinal))
        {
            return SourceReadSet.Empty;
        }

        var context = new FileSystemRepositoryContext(sourceRoot, ProductLimits);
        var atoms = ImmutableDictionary.CreateBuilder<string, SourceAtoms>(StringComparer.Ordinal);
        var diagnostics = ImmutableArray.CreateBuilder<Diagnostic>();
        int readsFromOppositeRoot = 0;
        int containmentViolations = 0;
        foreach (Finding finding in input.Findings)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (finding.PrimaryLocation?.Path.RepositoryRelativePath is not string path)
            {
                atoms.Add(finding.FindingKey, SourceAtoms.Empty);
                continue;
            }

            bool readsOppositeRoot = input.Input == InputKind.Baseline
                ? PathsEqual(sourceRoot, declaredCandidateRoot)
                : PathsEqual(sourceRoot, declaredBaselineRoot);
            if (readsOppositeRoot)
            {
                readsFromOppositeRoot++;
            }

            RepositoryContextResult result = await context.ReadAsync(
                    path,
                    finding.PrimaryLocation.Region,
                    LineRadius,
                    finding.SourceReference,
                    cancellationToken,
                    includeTokenWindow: true)
                .ConfigureAwait(false);
            diagnostics.AddRange(result.Diagnostics);
            containmentViolations += result.Diagnostics.Count(item =>
                string.Equals(item.Code, "SECURITY0001", StringComparison.Ordinal));
            atoms.Add(
                finding.FindingKey,
                CreateAtoms(finding.PrimaryLocation.Region, result));
        }

        return new SourceReadSet(
            atoms.ToImmutable(),
            diagnostics.ToImmutable(),
            readsFromOppositeRoot,
            containmentViolations);
    }

    private static ProjectedInputs Project(
        ComparisonInput baseline,
        ComparisonInput candidate,
        ImmutableDictionary<string, SourceAtoms> baselineAtoms,
        ImmutableDictionary<string, SourceAtoms> candidateAtoms,
        string variantId)
    {
        SourceContextProjection projection = SourceContextProjection.Empty;
        if (string.Equals(
                variantId,
                SparseExperimentVariants.AgreementOnlyCombination,
                StringComparison.Ordinal))
        {
            projection = CreateCombinationPairs(
                baseline.Findings,
                candidate.Findings,
                baselineAtoms,
                candidateAtoms);
        }
        else if (!string.Equals(
                     variantId,
                     SparseExperimentVariants.SarifOnlyControl,
                     StringComparison.Ordinal))
        {
            projection = CreateUniqueVariantPairs(
                baseline.Findings,
                candidate.Findings,
                baselineAtoms,
                candidateAtoms,
                variantId);
        }

        return new ProjectedInputs(
            ProjectInput(baseline, projection.Baseline, variantId),
            ProjectInput(candidate, projection.Candidate, variantId),
            projection.SourceFindingsIndexed,
            projection.SourceAtomsIndexed,
            projection.SourceIndexLookups);
    }

    private static ComparisonInput ProjectInput(
        ComparisonInput input,
        ImmutableDictionary<string, string> contexts,
        string variantId)
    {
        ImmutableArray<Finding> findings = input.Findings
            .Select(finding =>
            {
                string? contextHash = contexts.TryGetValue(
                    finding.FindingKey,
                    out string? observedContext)
                    ? observedContext
                    : null;
                return CloneWithContext(finding, contextHash, variantId);
            })
            .ToImmutableArray();
        return new ComparisonInput(input.Input, input.LogicalName, findings, input.Diagnostics);
    }

    private static void ValidateSourceOperationBounds(
        ProjectedInputs projected,
        int baselineFindingCount,
        int candidateFindingCount,
        string variantId)
    {
        int totalFindings = checked(baselineFindingCount + candidateFindingCount);
        bool control = string.Equals(
            variantId,
            SparseExperimentVariants.SarifOnlyControl,
            StringComparison.Ordinal);
        int expectedIndexedFindings = control ? 0 : totalFindings;
        if (projected.SourceFindingsIndexed != expectedIndexedFindings
            || projected.SourceAtomsIndexed < 0
            || projected.SourceAtomsIndexed > checked(totalFindings * 3)
            || projected.SourceIndexLookups < 0
            || projected.SourceIndexLookups > checked(projected.SourceAtomsIndexed * 2))
        {
            throw new InvalidDataException(
                $"Sparse variant '{variantId}' exceeded its linear source-index operation bounds.");
        }
    }

    private static SourceContextProjection CreateUniqueVariantPairs(
        ImmutableArray<Finding> baseline,
        ImmutableArray<Finding> candidate,
        ImmutableDictionary<string, SourceAtoms> baselineAtoms,
        ImmutableDictionary<string, SourceAtoms> candidateAtoms,
        string variantId)
    {
        AtomOccurrenceIndex baselineIndex = CreateAtomOccurrenceIndex(
            baseline,
            baselineAtoms,
            variantId);
        AtomOccurrenceIndex candidateIndex = CreateAtomOccurrenceIndex(
            candidate,
            candidateAtoms,
            variantId);
        var baselineResult = ImmutableDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        var candidateResult = ImmutableDictionary.CreateBuilder<string, string>(
            StringComparer.Ordinal);
        int lookups = 0;
        foreach ((AtomIndexKey key, AtomOccurrence occurrence) in baselineIndex.Entries
                     .Where(item => item.Value.Count == 1)
                     .OrderBy(item => item.Key.ProducerFamily, StringComparer.Ordinal)
                     .ThenBy(item => item.Key.RuleId, StringComparer.Ordinal)
                     .ThenBy(item => item.Key.Algorithm, StringComparer.Ordinal)
                     .ThenBy(item => item.Key.Value, StringComparer.Ordinal))
        {
            lookups++;
            if (!candidateIndex.Entries.TryGetValue(
                    key,
                    out AtomOccurrence? candidateOccurrence)
                || candidateOccurrence.Count != 1)
            {
                continue;
            }

            baselineResult.Add(occurrence.UniqueFinding!.FindingKey, key.Value);
            candidateResult.Add(candidateOccurrence.UniqueFinding!.FindingKey, key.Value);
        }

        return new SourceContextProjection(
            baselineResult.ToImmutable(),
            candidateResult.ToImmutable(),
            checked(baselineIndex.FindingsIndexed + candidateIndex.FindingsIndexed),
            checked(baselineIndex.AtomsIndexed + candidateIndex.AtomsIndexed),
            lookups);
    }

    private static AtomOccurrenceIndex CreateAtomOccurrenceIndex(
        ImmutableArray<Finding> findings,
        ImmutableDictionary<string, SourceAtoms> atoms,
        string? individualVariantId)
    {
        var entries = new Dictionary<AtomIndexKey, AtomOccurrence>();
        int atomsIndexed = 0;
        foreach (Finding finding in findings)
        {
            IEnumerable<SourceAtom> selected = individualVariantId is null
                ? atoms[finding.FindingKey].Values()
                : SelectIndividualAtom(
                    individualVariantId,
                    atoms[finding.FindingKey]) is SourceAtom individual
                    ? [individual]
                    : [];
            foreach (SourceAtom atom in selected)
            {
                atomsIndexed++;
                var key = new AtomIndexKey(
                    finding.Producer.AutomaticIdentity,
                    finding.Rule.CanonicalId,
                    atom.Algorithm,
                    atom.Value);
                if (entries.TryGetValue(key, out AtomOccurrence? occurrence))
                {
                    entries[key] = new AtomOccurrence(
                        checked(occurrence.Count + 1),
                        UniqueFinding: null);
                }
                else
                {
                    entries.Add(key, new AtomOccurrence(1, finding));
                }
            }
        }

        return new AtomOccurrenceIndex(entries, findings.Length, atomsIndexed);
    }

    private static SourceAtom? SelectIndividualAtom(
        string variantId,
        SourceAtoms atoms) => variantId switch
        {
            SparseExperimentVariants.ExactRegionSnippet => atoms.ExactRegionHash is string exact
                ? new SourceAtom(ExactAlgorithm, exact)
                : null,
            SparseExperimentVariants.TokenWindow => atoms.TokenWindowHash is string token
                ? new SourceAtom(FileSystemRepositoryContext.TokenWindowAlgorithmVersion, token)
                : null,
            SparseExperimentVariants.RelativeContext => atoms.RelativeContextHash is string relative
                ? new SourceAtom(RelativeAlgorithm, relative)
                : null,
            _ => throw new InvalidDataException(
                $"Variant '{variantId}' is not an individual source-context variant."),
        };

    private static Finding CloneWithContext(
        Finding finding,
        string? contextHash,
        string variantId)
    {
        Region? region = finding.PrimaryLocation?.Region;
        bool tokenWindow = string.Equals(
            variantId,
            SparseExperimentVariants.TokenWindow,
            StringComparison.Ordinal);
        ContextEvidence? context = contextHash is null
            ? null
            : new ContextEvidence(
                SnippetHash: tokenWindow ? null : contextHash,
                TokenWindowHash: tokenWindow ? contextHash : null,
                EnclosingSymbol: null,
                region?.StartLine,
                region?.EndLine ?? region?.StartLine);
        return new Finding(
            finding.FindingKey,
            finding.SourceReference,
            finding.Run,
            finding.Producer,
            finding.Rule,
            finding.PrimaryLocation,
            finding.Message,
            finding.ProducerFingerprints,
            derivedFingerprints: [],
            context,
            finding.RelatedLocations,
            finding.CodeFlow,
            finding.Lossiness,
            finding.Diagnostics,
            finding.Metadata);
    }

    private static SourceContextProjection CreateCombinationPairs(
        ImmutableArray<Finding> baseline,
        ImmutableArray<Finding> candidate,
        ImmutableDictionary<string, SourceAtoms> baselineAtoms,
        ImmutableDictionary<string, SourceAtoms> candidateAtoms)
    {
        AtomOccurrenceIndex baselineIndex = CreateAtomOccurrenceIndex(
            baseline,
            baselineAtoms,
            individualVariantId: null);
        AtomOccurrenceIndex candidateIndex = CreateAtomOccurrenceIndex(
            candidate,
            candidateAtoms,
            individualVariantId: null);
        NominationsResult forward = Nominations(
            baseline,
            baselineAtoms,
            baselineIndex,
            candidateIndex);
        NominationsResult reverse = Nominations(
            candidate,
            candidateAtoms,
            candidateIndex,
            baselineIndex);
        var baselineResult = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        var candidateResult = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        foreach ((string baselineKey, string candidateKey) in forward.Pairs
                     .OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            if (!reverse.Pairs.TryGetValue(candidateKey, out string? reverseKey)
                || !string.Equals(reverseKey, baselineKey, StringComparison.Ordinal))
            {
                continue;
            }

            string pairHash = VersionedHash.Compute(
                CombinationAlgorithm,
                CommonAtoms(baselineAtoms[baselineKey], candidateAtoms[candidateKey]));
            baselineResult.Add(baselineKey, pairHash);
            candidateResult.Add(candidateKey, pairHash);
        }

        return new SourceContextProjection(
            baselineResult.ToImmutable(),
            candidateResult.ToImmutable(),
            checked(baselineIndex.FindingsIndexed + candidateIndex.FindingsIndexed),
            checked(baselineIndex.AtomsIndexed + candidateIndex.AtomsIndexed),
            checked(forward.IndexLookups + reverse.IndexLookups));
    }

    private static NominationsResult Nominations(
        ImmutableArray<Finding> from,
        ImmutableDictionary<string, SourceAtoms> fromAtoms,
        AtomOccurrenceIndex fromIndex,
        AtomOccurrenceIndex toIndex)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        int lookups = 0;
        foreach (Finding finding in from.OrderBy(
                     item => item.FindingKey,
                     StringComparer.Ordinal))
        {
            var nominations = new HashSet<string>(StringComparer.Ordinal);
            bool hasReliableAtom = false;
            bool refused = false;
            foreach (SourceAtom atom in fromAtoms[finding.FindingKey].Values())
            {
                var key = new AtomIndexKey(
                    finding.Producer.AutomaticIdentity,
                    finding.Rule.CanonicalId,
                    atom.Algorithm,
                    atom.Value);
                lookups++;
                if (!fromIndex.Entries.TryGetValue(key, out AtomOccurrence? fromOccurrence)
                    || fromOccurrence.Count != 1)
                {
                    continue;
                }

                hasReliableAtom = true;
                lookups++;
                if (!toIndex.Entries.TryGetValue(key, out AtomOccurrence? toOccurrence)
                    || toOccurrence.Count != 1)
                {
                    refused = true;
                    break;
                }

                nominations.Add(toOccurrence.UniqueFinding!.FindingKey);
            }

            if (hasReliableAtom && !refused && nominations.Count == 1)
            {
                result.Add(finding.FindingKey, nominations.Single());
            }
        }

        return new NominationsResult(result, lookups);
    }

    private static string[] CommonAtoms(SourceAtoms left, SourceAtoms right) =>
        left.Values()
            .Intersect(right.Values())
            .OrderBy(item => item.Algorithm, StringComparer.Ordinal)
            .ThenBy(item => item.Value, StringComparer.Ordinal)
            .Select(item => item.Algorithm + "\u001e" + item.Value)
            .ToArray();

    private static SourceAtoms CreateAtoms(
        Region? region,
        RepositoryContextResult result)
    {
        if (!result.Exists
            || result.Snippet is not string snippet
            || result.Evidence is not ContextEvidence evidence
            || region?.StartLine is not int startLine
            || region.StartColumn is not int startColumn
            || (region.EndLine ?? region.StartLine) is not int endLine
            || region.EndColumn is not int endColumn
            || evidence.StartLine is not int firstLine)
        {
            return SourceAtoms.Empty;
        }

        string[] lines = snippet.Split('\n');
        string? exact = SliceExactRegion(
            lines,
            firstLine,
            startLine,
            startColumn,
            endLine,
            endColumn);
        string? relative = CreateRelativeContext(
            lines,
            firstLine,
            startLine,
            startColumn,
            endLine,
            endColumn);
        return new SourceAtoms(
            exact is null
                ? null
                : VersionedHash.Compute(
                    ExactAlgorithm,
                    exact.Normalize(NormalizationForm.FormC)),
            result.Evidence.TokenWindowHash,
            relative);
    }

    private static string? SliceExactRegion(
        string[] lines,
        int firstLine,
        int startLine,
        int startColumn,
        int endLine,
        int endColumn)
    {
        int firstIndex = startLine - firstLine;
        int lastIndex = endLine - firstLine;
        if (firstIndex < 0 || lastIndex < firstIndex || lastIndex >= lines.Length)
        {
            return null;
        }

        var selected = new string[lastIndex - firstIndex + 1];
        for (int index = firstIndex; index <= lastIndex; index++)
        {
            int from = index == firstIndex ? startColumn - 1 : 0;
            int toExclusive = index == lastIndex ? endColumn - 1 : lines[index].Length;
            if (from < 0 || toExclusive < from || toExclusive > lines[index].Length)
            {
                return null;
            }

            selected[index - firstIndex] = lines[index][from..toExclusive];
        }

        return string.Join('\n', selected);
    }

    private static string? CreateRelativeContext(
        string[] lines,
        int firstLine,
        int startLine,
        int startColumn,
        int endLine,
        int endColumn)
    {
        int firstIndex = startLine - firstLine;
        int lastIndex = endLine - firstLine;
        if (firstIndex < 0
            || lastIndex < firstIndex
            || lastIndex >= lines.Length
            || startColumn - 1 > lines[firstIndex].Length
            || endColumn - 1 > lines[lastIndex].Length)
        {
            return null;
        }

        string beforeText = string.Join('\n', lines[..firstIndex]);
        if (beforeText.Length > 0)
        {
            beforeText += '\n';
        }

        beforeText += lines[firstIndex][..(startColumn - 1)];
        string? insideText = SliceExactRegion(
            lines,
            firstLine,
            startLine,
            startColumn,
            endLine,
            endColumn);
        string afterText = lines[lastIndex][(endColumn - 1)..];
        if (lastIndex + 1 < lines.Length)
        {
            afterText += '\n' + string.Join('\n', lines[(lastIndex + 1)..]);
        }

        string? before = CanonicalTerms(
            beforeText,
            MaximumRelativeSurroundingTerms,
            takeNearestEnd: true,
            refuseOverflow: false);
        string? inside = insideText is null
            ? null
            : CanonicalTerms(
                insideText,
                MaximumRelativeRegionTerms,
                takeNearestEnd: false,
                refuseOverflow: true);
        string? after = CanonicalTerms(
            afterText,
            MaximumRelativeSurroundingTerms,
            takeNearestEnd: false,
            refuseOverflow: false);
        return before is null || inside is null || after is null
            ? null
            : VersionedHash.Compute(
                RelativeAlgorithm,
                VersionedHash.Compute(RelativeAlgorithm + "/before", before),
                VersionedHash.Compute(RelativeAlgorithm + "/region", inside),
                VersionedHash.Compute(RelativeAlgorithm + "/after", after));
    }

    private static string? CanonicalTerms(
        string value,
        int maximumTerms,
        bool takeNearestEnd,
        bool refuseOverflow)
    {
        var terms = new List<string>();
        var current = new StringBuilder();
        foreach (char character in value)
        {
            if (char.IsWhiteSpace(character))
            {
                Flush();
                continue;
            }

            if (char.IsLetterOrDigit(character)
                || character == '_'
                || character >= '\u0080')
            {
                current.Append(character);
                continue;
            }

            Flush();
            terms.Add(character.ToString().Normalize(NormalizationForm.FormC));
        }

        Flush();
        if (terms.Any(term => term.Length > ProductLimits.MaximumStringCharacters)
            || refuseOverflow && terms.Count > maximumTerms)
        {
            return null;
        }

        IEnumerable<string> selected = takeNearestEnd
            ? terms.TakeLast(maximumTerms)
            : terms.Take(maximumTerms);
        return string.Join('\u001f', selected);

        void Flush()
        {
            if (current.Length == 0)
            {
                return;
            }

            terms.Add(current.ToString().Normalize(NormalizationForm.FormC));
            current.Clear();
        }
    }

    private byte[] ReadAndVerifySarif(string repositoryRoot, SparseSideManifest side)
    {
        string path = SparseResearchManifestReader.ResolveSparsePath(
            repositoryRoot,
            side.SarifPath);
        byte[] bytes = BoundedJsonFile.ReadBytes(
            path,
            limits.MaximumSarifBytes,
            repositoryRoot);
        string actual = SparseSarifExperimentSerializer.Sha256(bytes);
        if (!string.Equals(actual, side.ProjectedSarifSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("A sparse projected SARIF hash does not match its manifest.");
        }

        return bytes;
    }

    private static async ValueTask<SarifIngestionResult> IngestAsync(
        byte[] bytes,
        InputKind input,
        string logicalName,
        SarifRegressConfiguration configuration,
        CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        return await new SarifIngestor()
            .IngestAsync(
                stream,
                new SarifIngestionRequest(input, logicalName, configuration),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static SarifRegressConfiguration ExperimentConfiguration()
    {
        SarifRegressConfiguration defaults = SarifRegressConfiguration.Default;
        return new SarifRegressConfiguration(
            defaults.SchemaVersion,
            repositoryRoot: null,
            defaults.PathRebases,
            defaults.PathAliases,
            defaults.RuleAliases,
            defaults.Matching with
            {
                EnableRepositoryContext = false,
                EnableTokenWindows = false,
                AllowWeakMessageSimilarity = false,
            },
            defaults.Policy,
            defaults.Reporting,
            defaults.Limits,
            defaults.UriBaseMappings);
    }

    private static SparseNaturalSelector Selector(Finding finding)
    {
        if (finding.PrimaryLocation?.Path.RepositoryRelativePath is not string path
            || finding.PrimaryLocation.Region is not Region region
            || region.StartLine is not int startLine
            || region.StartColumn is not int startColumn
            || (region.EndLine ?? region.StartLine) is not int endLine
            || region.EndColumn is not int endColumn)
        {
            throw new InvalidDataException(
                "Sparse observations require complete repository-relative locations.");
        }

        return new SparseNaturalSelector(
            finding.Rule.CanonicalId,
            path,
            new SparseRegionSelector(startLine, startColumn, endLine, endColumn),
            finding.Message.CanonicalText);
    }

    private static string SelectorKey(SparseNaturalSelector value) =>
        string.Join(
            "\u001f",
            value.RuleId,
            value.ArtifactUri,
            value.Region.StartLine,
            value.Region.StartColumn,
            value.Region.EndLine,
            value.Region.EndColumn,
            value.Message);

    private static ImmutableArray<SparseNaturalSelector> SelectDecisions(
        MatchResult result,
        FindingClassification classification,
        bool selectCandidate) => result.Decisions
            .Where(item => item.Classification == classification)
            .Select(item => selectCandidate ? item.Candidate : item.Baseline)
            .Where(item => item is not null)
            .Select(item => Selector(item!))
            .Distinct()
            .OrderBy(SelectorKey, StringComparer.Ordinal)
            .ToImmutableArray();

    private static SparseFamilyScenarioObservation ScenarioFamilyFromRun(
        FamilyRun run,
        ImmutableArray<SparseNaturalSelector> affectedBaseline = default,
        ImmutableArray<SparseNaturalSelector> affectedCandidate = default) => new(
            run.Observation.FamilyId,
            run.PreflightAccepted,
            run.Observation.AcceptedPairs,
            affectedBaseline.IsDefault ? [] : affectedBaseline,
            affectedCandidate.IsDefault ? [] : affectedCandidate,
            run.BaselineReadsFromCandidateRoot,
            run.CandidateReadsFromBaselineRoot,
            run.ContainmentViolations,
            run.Observation.IngestionFailures,
            run.Observation.StructuralFailures);

    private static SparseIngestionObservation AggregateIngestion(
        ImmutableArray<SparseFamilyObservation> families) => new(
            CasesEvaluated: checked(families.Length * 2),
            Failures: families.Sum(item => item.IngestionFailures),
            StructuralFailures: families.Sum(item => item.StructuralFailures));

    private static SparseSecurityObservation AggregateSecurity(
        ImmutableArray<SparseScenarioObservation> scenarios) => new(
            scenarios.SelectMany(item => item.Families)
                .Sum(item => item.BaselineReadsFromCandidateRoot),
            scenarios.SelectMany(item => item.Families)
                .Sum(item => item.CandidateReadsFromBaselineRoot),
            scenarios.SelectMany(item => item.Families)
                .Sum(item => item.ContainmentViolations),
            scenarios.SelectMany(item => item.Families)
                .Count(item => item.BaselineReadsFromCandidateRoot > 0
                    || item.CandidateReadsFromBaselineRoot > 0));

    private static int CountStructuralFailures(IEnumerable<Diagnostic> diagnostics) =>
        diagnostics.Count(item => item.Severity == DiagnosticSeverity.Error
            && item.Stage is DiagnosticStage.Parse or DiagnosticStage.Schema);

    internal static SparseVariantParameters GetParameters(string variantId)
    {
        bool isCombination = string.Equals(
            variantId,
            SparseExperimentVariants.AgreementOnlyCombination,
            StringComparison.Ordinal);
        bool hasSource = !string.Equals(
            variantId,
            SparseExperimentVariants.SarifOnlyControl,
            StringComparison.Ordinal);
        return new SparseVariantParameters(
            LineRadius,
            ProductLimits.MaximumTokenWindowTerms,
            MaximumRelativeSurroundingTerms,
            MaximumRelativeRegionTerms,
            EndColumnIsExclusive: true,
            RelativeContextParts:
                "before:nearest-32-within-20-lines,region:256,after:nearest-32-within-20-lines",
            SourceTextNormalization: "utf8-bom-lf-nfc/v1",
            RequireUniqueOnBothSides: hasSource,
            AgreementOnly: isCombination);
    }

    internal static string GetAlgorithmVersion(string variantId) => variantId switch
    {
        SparseExperimentVariants.SarifOnlyControl => "sarifregress/sparse-control/v1",
        SparseExperimentVariants.ExactRegionSnippet => ExactAlgorithm,
        SparseExperimentVariants.TokenWindow => FileSystemRepositoryContext.TokenWindowAlgorithmVersion,
        SparseExperimentVariants.RelativeContext => RelativeAlgorithm,
        SparseExperimentVariants.AgreementOnlyCombination => CombinationAlgorithm,
        _ => throw new InvalidDataException($"Unknown sparse variant '{variantId}'."),
    };

    private static string ResolveRoot(string repositoryRoot, string sparseRelativePath) =>
        SparseResearchManifestReader.ResolveSparsePath(repositoryRoot, sparseRelativePath);

    private static string CreateAlteredSourceTree(
        string outputRoot,
        string familyId,
        string side,
        string sourceRoot,
        string relativePath,
        bool removeFirstFile)
    {
        string destinationRoot = Path.Combine(
            outputRoot,
            $".sparse-{familyId}-{side}-{(removeFirstFile ? "missing" : "mismatched")}");
        if (Directory.Exists(destinationRoot) || File.Exists(destinationRoot))
        {
            throw new InvalidDataException(
                "A sparse scenario temporary root already exists.");
        }

        Directory.CreateDirectory(destinationRoot);
        List<string> sourceFiles = EnumerateSourceFilesForCopy(sourceRoot);
        if (sourceFiles.Count == 0)
        {
            throw new InvalidDataException("A sparse source tree cannot be empty.");
        }

        foreach (string sourcePath in sourceFiles)
        {
            string relative = Path.GetRelativePath(sourceRoot, sourcePath);
            string destinationPath = Path.Combine(destinationRoot, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            byte[] bytes = BoundedJsonFile.ReadBytes(
                sourcePath,
                ProductLimits.MaximumRepositoryFileBytes,
                sourceRoot);
            File.WriteAllBytes(destinationPath, bytes);
        }

        string selectedRelative = StablePath.RequireRepositoryRelative(
            relativePath,
            "scenario source path");
        string firstDestination = Path.Combine(
            destinationRoot,
            selectedRelative.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(firstDestination))
        {
            throw new InvalidDataException(
                "The first ordinal sparse SARIF source file is absent from its source tree.");
        }
        if (removeFirstFile)
        {
            File.Delete(firstDestination);
        }
        else
        {
            using var stream = new FileStream(
                firstDestination,
                FileMode.Append,
                FileAccess.Write,
                FileShare.None);
            stream.WriteByte((byte)'\n');
            stream.Flush(flushToDisk: true);
        }

        return destinationRoot;
    }

    private static List<string> EnumerateSourceFilesForCopy(string sourceRoot)
    {
        var result = new List<string>();
        var pending = new Stack<string>();
        pending.Push(sourceRoot);
        while (pending.Count > 0)
        {
            foreach (FileSystemInfo entry in new DirectoryInfo(pending.Pop())
                         .EnumerateFileSystemInfos()
                         .OrderBy(item => item.Name, StringComparer.Ordinal))
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Sparse source trees cannot contain symbolic links or junctions.");
                }

                if ((entry.Attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(entry.FullName);
                }
                else
                {
                    result.Add(entry.FullName);
                    if (result.Count > 10_000)
                    {
                        throw new InvalidDataException(
                            "A sparse source tree exceeds its 10000-file limit.");
                    }
                }
            }
        }

        return result.OrderBy(
                item => Path.GetRelativePath(sourceRoot, item)
                    .Replace(Path.DirectorySeparatorChar, '/'),
                StringComparer.Ordinal)
            .ToList();
    }

    private static string? TryComputeSourceTreeHash(string sourceRoot)
    {
        if (!Directory.Exists(sourceRoot))
        {
            return null;
        }

        if ((File.GetAttributes(sourceRoot) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("A sparse source root cannot be a reparse point.");
        }

        var pending = new Stack<string>();
        var files = new List<string>();
        pending.Push(sourceRoot);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            foreach (FileSystemInfo entry in new DirectoryInfo(directory)
                         .EnumerateFileSystemInfos()
                         .OrderBy(item => item.Name, StringComparer.Ordinal))
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Sparse source trees cannot contain symbolic links or junctions.");
                }

                if ((entry.Attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(entry.FullName);
                }
                else
                {
                    files.Add(entry.FullName);
                    if (files.Count > 10_000)
                    {
                        throw new InvalidDataException(
                            "A sparse source tree exceeds its 10000-file limit.");
                    }
                }
            }
        }

        var lines = new StringBuilder();
        foreach (string path in files
                     .OrderBy(
                         item => Path.GetRelativePath(sourceRoot, item)
                             .Replace(Path.DirectorySeparatorChar, '/'),
                         StringComparer.Ordinal))
        {
            string relative = Path.GetRelativePath(sourceRoot, path)
                .Replace(Path.DirectorySeparatorChar, '/');
            byte[] bytes = BoundedJsonFile.ReadBytes(
                path,
                ProductLimits.MaximumRepositoryFileBytes,
                sourceRoot);
            lines.Append(SparseSarifExperimentSerializer.Sha256(bytes))
                .Append("  ")
                .Append(relative)
                .Append('\n');
        }

        return Convert.ToHexString(
                SHA256.HashData(Encoding.ASCII.GetBytes(lines.ToString())))
            .ToLowerInvariant();
    }

    private static bool PathsEqual(string left, string right) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal);

    private static string EmptyTreeSha256 { get; } = Convert.ToHexString(
            SHA256.HashData(ReadOnlySpan<byte>.Empty))
        .ToLowerInvariant();

    private sealed record SourceAtoms(
        string? ExactRegionHash,
        string? TokenWindowHash,
        string? RelativeContextHash)
    {
        internal static SourceAtoms Empty { get; } = new(null, null, null);

        internal IEnumerable<SourceAtom> Values()
        {
            if (ExactRegionHash is not null)
            {
                yield return new SourceAtom(ExactAlgorithm, ExactRegionHash);
            }

            if (TokenWindowHash is not null)
            {
                yield return new SourceAtom(
                    FileSystemRepositoryContext.TokenWindowAlgorithmVersion,
                    TokenWindowHash);
            }

            if (RelativeContextHash is not null)
            {
                yield return new SourceAtom(RelativeAlgorithm, RelativeContextHash);
            }
        }
    }

    private sealed record SourceAtom(string Algorithm, string Value);

    private sealed record AtomIndexKey(
        string ProducerFamily,
        string RuleId,
        string Algorithm,
        string Value);

    private sealed record AtomOccurrence(int Count, Finding? UniqueFinding);

    private sealed record AtomOccurrenceIndex(
        Dictionary<AtomIndexKey, AtomOccurrence> Entries,
        int FindingsIndexed,
        int AtomsIndexed);

    private sealed record NominationsResult(
        Dictionary<string, string> Pairs,
        int IndexLookups);

    private sealed record SourceContextProjection(
        ImmutableDictionary<string, string> Baseline,
        ImmutableDictionary<string, string> Candidate,
        int SourceFindingsIndexed,
        int SourceAtomsIndexed,
        int SourceIndexLookups)
    {
        internal static SourceContextProjection Empty { get; } = new(
            ImmutableDictionary<string, string>.Empty,
            ImmutableDictionary<string, string>.Empty,
            0,
            0,
            0);
    }

    private sealed record SourceReadSet(
        ImmutableDictionary<string, SourceAtoms> Atoms,
        ImmutableArray<Diagnostic> Diagnostics,
        int ReadsFromOppositeRoot,
        int ContainmentViolations)
    {
        internal static SourceReadSet Empty { get; } = new(
            ImmutableDictionary<string, SourceAtoms>.Empty,
            [],
            0,
            0);
    }

    private sealed record ProjectedInputs(
        ComparisonInput Baseline,
        ComparisonInput Candidate,
        int SourceFindingsIndexed,
        int SourceAtomsIndexed,
        int SourceIndexLookups);

    private sealed record FamilyRun(
        bool PreflightAccepted,
        SparseFamilyObservation Observation,
        ImmutableArray<SparseNaturalSelector> BaselineSelectors,
        ImmutableArray<SparseNaturalSelector> CandidateSelectors,
        int BaselineReadsFromCandidateRoot,
        int CandidateReadsFromBaselineRoot,
        int ContainmentViolations)
    {
        internal static FamilyRun Refused(
            SparseFamilyManifest family,
            string? baselineTreeHash,
            string? candidateTreeHash) => new(
                PreflightAccepted: false,
                new SparseFamilyObservation(
                    family.Id,
                    family.Baseline.ProjectedSarifSha256,
                    family.Candidate.ProjectedSarifSha256,
                    baselineTreeHash ?? EmptyTreeSha256,
                    candidateTreeHash ?? EmptyTreeSha256,
                    AcceptedPairs: [],
                    NewFindings: [],
                    ResolvedFindings: [],
                    AmbiguousBaselineFindings: [],
                    AmbiguousCandidateFindings: [],
                    DiagnosticCodes: [],
                    new SparseOperationCounts(0, 0, 0, 0, 0, 0),
                    IngestionFailures: 0,
                    StructuralFailures: 0),
                BaselineSelectors: [],
                CandidateSelectors: [],
                0,
                0,
                0);
    }
}
