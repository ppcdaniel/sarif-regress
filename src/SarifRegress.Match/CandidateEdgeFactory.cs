using System.Collections.Immutable;
using SarifRegress.Core.Configuration;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Matching;
using SarifRegress.Core.Paths;
using SarifRegress.Core.Utility;

namespace SarifRegress.Match;

internal sealed class CandidateEdgeFactory
{
    private const int MaximumInlineEvidenceCharacters = 512;
    private const int HighProducerFingerprintStrength = 2;
    private const int DegradedProducerFingerprintStrength = 1;
    private const int ExactRegionBand = 3;
    private const int NearRegionBand = 2;
    private const int AvailableRegionBand = 1;

    private readonly SarifRegressConfiguration configuration;
    private readonly ProducerFingerprintOccurrenceIndex fingerprintOccurrences;
    private readonly ContextFingerprintOccurrenceIndex contextFingerprintOccurrences;
    private readonly CodeFlowAnchorOccurrenceIndex codeFlowAnchorOccurrences;
    private readonly PathAliasIndex pathAliases;
    private readonly RuleAliasIndex ruleAliases;

    public CandidateEdgeFactory(
        SarifRegressConfiguration configuration,
        ProducerFingerprintOccurrenceIndex fingerprintOccurrences,
        ContextFingerprintOccurrenceIndex contextFingerprintOccurrences,
        CodeFlowAnchorOccurrenceIndex codeFlowAnchorOccurrences)
    {
        this.configuration = configuration;
        this.fingerprintOccurrences = fingerprintOccurrences;
        this.contextFingerprintOccurrences = contextFingerprintOccurrences;
        this.codeFlowAnchorOccurrences = codeFlowAnchorOccurrences;
        pathAliases = PathAliasIndex.Create(
            configuration.PathAliases,
            configuration.Matching.PathCaseSensitivity);
        ruleAliases = RuleAliasIndex.Create(configuration.RuleAliases);
    }

    /// <summary>
    /// Evaluates whether a pair is admissible without materializing explanation records.
    /// </summary>
    public bool TryEvaluate(
        Finding baseline,
        Finding candidate,
        out DecisionVector decisionVector) =>
        TryEvaluateCore(
            baseline,
            candidate,
            evidence: null,
            out decisionVector);

    public MatchEdge? Create(Finding baseline, Finding candidate)
    {
        var evidence = new List<EvidenceDraft>(capacity: 8);
        if (!TryEvaluateCore(
                baseline,
                candidate,
                evidence,
                out var decisionVector))
        {
            return null;
        }

        return new MatchEdge(
            baseline,
            candidate,
            decisionVector,
            CreateStableIdentityKey(baseline.FindingKey, candidate.FindingKey),
            CreateEvidence(evidence, decisionVector.PrecedenceTier),
            GetTransformations(baseline, candidate));
    }

    private bool TryEvaluateCore(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft>? evidence,
        out DecisionVector decisionVector)
    {
        var sameDefaultRule = IsSameDefaultRule(baseline, candidate);
        var applicableAliases = sameDefaultRule
            ? ImmutableArray<RuleAlias>.Empty
            : FindApplicableAliases(baseline, candidate);
        if (!sameDefaultRule && applicableAliases.IsEmpty)
        {
            decisionVector = default;
            return false;
        }

        AddRuleEvidence(evidence, baseline, candidate, applicableAliases);

        var producerFingerprint = CompareProducerFingerprints(baseline, candidate, evidence);
        var derivedFingerprint = CompareDerivedFingerprints(baseline, candidate, evidence);
        var pathMatchKind = ComparePaths(baseline, candidate, evidence);
        var context = CompareContext(baseline, candidate, evidence);
        var messageAgreement = CompareMessages(baseline.Message, candidate.Message, evidence);
        var supportingAgreement = CompareSupportingEvidence(baseline, candidate, evidence);
        var regionDriftBand = CompareRegions(
            baseline.PrimaryLocation?.Region,
            candidate.PrimaryLocation?.Region,
            evidence);

        var precedence = DeterminePrecedenceTier(
            aliasApplied: !applicableAliases.IsEmpty,
            producerFingerprint.Strength,
            derivedFingerprint,
            pathMatchKind,
            context,
            messageAgreement);
        if (precedence.Tier == PrecedenceTier.Refuse)
        {
            decisionVector = default;
            return false;
        }

        if (precedence.CollisionOnly)
        {
            // Repeated evidence may retain a bounded same-path candidate edge, but line
            // proximity must not manufacture a preferred pairing inside a collision set.
            regionDriftBand = 0;
        }

        decisionVector = new DecisionVector(
            precedence.Tier,
            producerFingerprint.Strength,
            pathMatchKind,
            context.Agreement,
            supportingAgreement,
            messageAgreement,
            regionDriftBand);
        return true;
    }

    private static ImmutableArray<EvidenceRecord> CreateEvidence(
        IReadOnlyList<EvidenceDraft> evidence,
        PrecedenceTier precedenceTier)
    {
        if (evidence.Count == 0)
        {
            return ImmutableArray<EvidenceRecord>.Empty;
        }

        var records = ImmutableArray.CreateBuilder<EvidenceRecord>(
            evidence.Count);
        for (var index = 0; index < evidence.Count; index++)
        {
            records.Add(
                evidence[index].ToEvidenceRecord(precedenceTier));
        }

        records.Sort(EvidenceRecordComparer.Instance);
        return records.MoveToImmutable();
    }

    private static bool IsSameDefaultRule(Finding baseline, Finding candidate) =>
        string.Equals(
            baseline.Producer.AutomaticIdentity,
            candidate.Producer.AutomaticIdentity,
            StringComparison.Ordinal)
        && string.Equals(
            baseline.Rule.CanonicalId,
            candidate.Rule.CanonicalId,
            StringComparison.Ordinal);

    private ImmutableArray<RuleAlias> FindApplicableAliases(
        Finding baseline,
        Finding candidate) =>
        ruleAliases.FindApplicable(baseline, candidate);

    private static void AddRuleEvidence(
        ICollection<EvidenceDraft>? evidence,
        Finding baseline,
        Finding candidate,
        ImmutableArray<RuleAlias> aliases)
    {
        if (evidence is null)
        {
            return;
        }

        if (aliases.IsEmpty)
        {
            evidence.Add(new EvidenceDraft(
                "rule-identity",
                baseline.Rule.CanonicalId,
                candidate.Rule.CanonicalId,
                EvidenceOrigin.System,
                Lossy: false,
                MatchingAlgorithms.RuleIdentityVersion));
            return;
        }

        foreach (var alias in aliases)
        {
            evidence.Add(new EvidenceDraft(
                "rule-alias",
                $"{alias.BaselineProducer}:{alias.BaselineRule}",
                $"{alias.CandidateProducer}:{alias.CandidateRule}",
                EvidenceOrigin.Configuration,
                Lossy: false,
                MatchingAlgorithms.RuleAliasVersion));
        }
    }

    private ProducerFingerprintComparison CompareProducerFingerprints(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        if (baseline.ProducerFingerprints.IsDefaultOrEmpty
            || candidate.ProducerFingerprints.IsDefaultOrEmpty)
        {
            return ProducerFingerprintComparison.None;
        }

        if (baseline.ProducerFingerprints.Length == 1
            && candidate.ProducerFingerprints.Length == 1)
        {
            var baselineFingerprint = baseline.ProducerFingerprints[0];
            var candidateFingerprint = candidate.ProducerFingerprints[0];
            if (!string.Equals(
                    baselineFingerprint.Family,
                    candidateFingerprint.Family,
                    StringComparison.Ordinal)
                || baselineFingerprint.Version != candidateFingerprint.Version
                || !string.Equals(
                    baselineFingerprint.Value,
                    candidateFingerprint.Value,
                    StringComparison.Ordinal))
            {
                return ProducerFingerprintComparison.None;
            }

            var isReliablyUnique =
                baselineFingerprint.Reliability == FingerprintReliability.High
                && candidateFingerprint.Reliability == FingerprintReliability.High
                && fingerprintOccurrences.IsUnique(
                    InputKind.Baseline,
                    baseline,
                    baselineFingerprint)
                && fingerprintOccurrences.IsUnique(
                    InputKind.Candidate,
                    candidate,
                    candidateFingerprint);
            var comparison = new ProducerFingerprintComparison(
                isReliablyUnique
                    ? HighProducerFingerprintStrength
                    : DegradedProducerFingerprintStrength,
                baselineFingerprint.Family,
                baselineFingerprint.Version,
                baselineFingerprint.Value);
            AddProducerFingerprintEvidence(evidence, comparison);
            return comparison;
        }

        var bestComparison = ProducerFingerprintComparison.None;
        var commonFamilies = baseline.ProducerFingerprints
            .Select(item => item.Family)
            .Intersect(
                candidate.ProducerFingerprints.Select(item => item.Family),
                StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);

        foreach (var family in commonFamilies)
        {
            var baselineFamily = baseline.ProducerFingerprints
                .Where(item => string.Equals(item.Family, family, StringComparison.Ordinal))
                .ToImmutableArray();
            var candidateFamily = candidate.ProducerFingerprints
                .Where(item => string.Equals(item.Family, family, StringComparison.Ordinal))
                .ToImmutableArray();
            var commonVersion = FindGreatestCommonVersion(baselineFamily, candidateFamily);
            if (!commonVersion.HasCommonVersion)
            {
                continue;
            }

            var baselineAtVersion = baselineFamily
                .Where(item => item.Version == commonVersion.Version)
                .OrderBy(item => item.Value, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal);
            var candidateAtVersion = candidateFamily
                .Where(item => item.Version == commonVersion.Version)
                .OrderBy(item => item.Value, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal)
                .ToLookup(item => item.Value, StringComparer.Ordinal);

            foreach (var baselineFingerprint in baselineAtVersion)
            {
                foreach (var candidateFingerprint in candidateAtVersion[
                    baselineFingerprint.Value])
                {
                    var isReliablyUnique =
                        baselineFingerprint.Reliability == FingerprintReliability.High
                        && candidateFingerprint.Reliability == FingerprintReliability.High
                        && fingerprintOccurrences.IsUnique(
                            InputKind.Baseline,
                            baseline,
                            baselineFingerprint)
                        && fingerprintOccurrences.IsUnique(
                            InputKind.Candidate,
                            candidate,
                            candidateFingerprint);
                    var strength = isReliablyUnique
                        ? HighProducerFingerprintStrength
                        : DegradedProducerFingerprintStrength;
                    var comparison = new ProducerFingerprintComparison(
                        strength,
                        family,
                        commonVersion.Version,
                        baselineFingerprint.Value);
                    if (comparison.Strength > bestComparison.Strength)
                    {
                        bestComparison = comparison;
                    }
                }
            }
        }

        AddProducerFingerprintEvidence(evidence, bestComparison);
        return bestComparison;
    }

    private static void AddProducerFingerprintEvidence(
        ICollection<EvidenceDraft>? evidence,
        ProducerFingerprintComparison comparison)
    {
        if (evidence is null || comparison.Strength <= 0)
        {
            return;
        }

        var fingerprintLabel = comparison.Version is null
            ? comparison.Family
            : $"{comparison.Family}/v{comparison.Version.Value}";
        var evidenceValue = $"{fingerprintLabel}:{comparison.Value}";
        evidence.Add(new EvidenceDraft(
            "producer-fingerprint",
            evidenceValue,
            evidenceValue,
            EvidenceOrigin.Producer,
            Lossy: false,
            MatchingAlgorithms.ProducerFingerprintVersion));
    }

    private static CommonVersion FindGreatestCommonVersion(
        ImmutableArray<ProducerFingerprint> baseline,
        ImmutableArray<ProducerFingerprint> candidate)
    {
        var commonNumberedVersions = baseline
            .Where(item => item.Version.HasValue)
            .Select(item => item.Version!.Value)
            .Intersect(
                candidate
                    .Where(item => item.Version.HasValue)
                    .Select(item => item.Version!.Value))
            .ToArray();
        if (commonNumberedVersions.Length > 0)
        {
            return new CommonVersion(HasCommonVersion: true, commonNumberedVersions.Max());
        }

        var hasCommonUnversioned =
            baseline.Any(item => item.Version is null)
            && candidate.Any(item => item.Version is null);
        return new CommonVersion(hasCommonUnversioned, Version: null);
    }

    private DerivedFingerprintComparison CompareDerivedFingerprints(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        if (baseline.DerivedFingerprints.IsDefaultOrEmpty
            || candidate.DerivedFingerprints.IsDefaultOrEmpty)
        {
            return DerivedFingerprintComparison.None;
        }

        var candidateByIdentity = candidate.DerivedFingerprints
            .ToLookup(
                item => new DerivedFingerprintIdentity(item.Name, item.AlgorithmVersion));
        var matches = baseline.DerivedFingerprints
            .SelectMany(
                baselineFingerprint => candidateByIdentity[
                        new DerivedFingerprintIdentity(
                            baselineFingerprint.Name,
                            baselineFingerprint.AlgorithmVersion)]
                    .Where(candidateFingerprint => string.Equals(
                        baselineFingerprint.Value,
                        candidateFingerprint.Value,
                        StringComparison.Ordinal))
                    .Select(candidateFingerprint =>
                    {
                        var baselineCount =
                            contextFingerprintOccurrences.GetDerivedFingerprintCount(
                                InputKind.Baseline,
                                baseline,
                                baselineFingerprint);
                        var candidateCount =
                            contextFingerprintOccurrences.GetDerivedFingerprintCount(
                                InputKind.Candidate,
                                candidate,
                                candidateFingerprint);
                        return new DerivedFingerprintMatch(
                            baselineFingerprint,
                            candidateFingerprint,
                            baselineCount,
                            candidateCount);
                    }))
            .OrderByDescending(item => item.IsUnique)
            .ThenBy(item => item.Baseline.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Baseline.AlgorithmVersion, StringComparer.Ordinal)
            .ThenBy(item => item.Baseline.Value, StringComparer.Ordinal)
            .ToArray();
        if (matches.Length == 0)
        {
            return DerivedFingerprintComparison.None;
        }

        var match = matches[0];
        if (evidence is not null)
        {
            evidence.Add(new EvidenceDraft(
                "derived-fingerprint",
                $"{match.Baseline.Name}:{match.Baseline.Value}",
                $"{match.Candidate.Name}:{match.Candidate.Value}",
                EvidenceOrigin.System,
                Lossy: false,
                MatchingAlgorithms.DerivedFingerprintVersion));
            if (!match.IsUnique)
            {
                evidence.Add(new EvidenceDraft(
                    "derived-fingerprint-collision",
                    ContextFingerprintOccurrenceIndex.FormatDerivedFingerprint(
                        match.Baseline,
                        match.BaselineCount),
                    ContextFingerprintOccurrenceIndex.FormatDerivedFingerprint(
                        match.Candidate,
                        match.CandidateCount),
                    EvidenceOrigin.System,
                    Lossy: false,
                    MatchingAlgorithms.EvidenceOccurrenceVersion));
            }
        }

        return new DerivedFingerprintComparison(
            Unique: match.IsUnique,
            Collided: !match.IsUnique);
    }

    private PathMatchKind ComparePaths(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        var baselinePath = baseline.PrimaryLocation?.Path;
        var candidatePath = candidate.PrimaryLocation?.Path;
        if (baselinePath is null || candidatePath is null)
        {
            return PathMatchKind.None;
        }

        if (PathEquals(baselinePath.CanonicalUri, candidatePath.CanonicalUri))
        {
            evidence?.Add(new EvidenceDraft(
                "canonical-path",
                baselinePath.CanonicalUri,
                candidatePath.CanonicalUri,
                EvidenceOrigin.System,
                Lossy: HasLossyTransform(baselinePath) ||
                    HasLossyTransform(candidatePath),
                MatchingAlgorithms.PathVersion));
            return PathMatchKind.Exact;
        }

        var alias = pathAliases.Find(
            baselinePath,
            candidatePath,
            out _);
        if (alias is not null)
        {
            evidence?.Add(new EvidenceDraft(
                "path-alias",
                alias.Baseline,
                alias.Candidate,
                EvidenceOrigin.Configuration,
                Lossy: false,
                MatchingAlgorithms.PathAliasVersion));
            return PathMatchKind.Aliased;
        }

        evidence?.Add(new EvidenceDraft(
            "canonical-path",
            baselinePath.CanonicalUri,
            candidatePath.CanonicalUri,
            EvidenceOrigin.System,
            Lossy: HasLossyTransform(baselinePath) ||
                HasLossyTransform(candidatePath),
            MatchingAlgorithms.PathVersion));
        return PathMatchKind.None;
    }

    private static bool HasLossyTransform(CanonicalPath path)
    {
        foreach (var transformation in path.Transformations)
        {
            if (transformation.IsLossy)
            {
                return true;
            }
        }

        return false;
    }

    private ContextComparison CompareContext(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        var baselineContext = baseline.Context;
        var candidateContext = candidate.Context;
        if (baselineContext is null || candidateContext is null)
        {
            return ContextComparison.None;
        }

        var uniqueHashCount = 0;
        var collidedHashCount = 0;
        var conflictingHashCount = 0;
        CompareContextHash(
            "context-snippet",
            baseline,
            baselineContext.SnippetHash,
            candidate,
            candidateContext.SnippetHash,
            ref uniqueHashCount,
            ref collidedHashCount,
            ref conflictingHashCount,
            evidence);
        CompareContextHash(
            "context-token-window",
            baseline,
            baselineContext.TokenWindowHash,
            candidate,
            candidateContext.TokenWindowHash,
            ref uniqueHashCount,
            ref collidedHashCount,
            ref conflictingHashCount,
            evidence);

        var agreement = uniqueHashCount > 0 && conflictingHashCount == 0
            ? AgreementBand.Exact
            : uniqueHashCount > 0 || collidedHashCount > 0
                ? AgreementBand.Compatible
                : AgreementBand.None;
        return new ContextComparison(
            agreement,
            ReliableExact: agreement == AgreementBand.Exact,
            Collided: collidedHashCount > 0,
            Conflicting: conflictingHashCount > 0);
    }

    private void CompareContextHash(
        string kind,
        Finding baselineFinding,
        string? baseline,
        Finding candidateFinding,
        string? candidate,
        ref int uniqueHashCount,
        ref int collidedHashCount,
        ref int conflictingHashCount,
        ICollection<EvidenceDraft>? evidence)
    {
        if (baseline is null || candidate is null)
        {
            return;
        }

        if (string.Equals(baseline, candidate, StringComparison.Ordinal))
        {
            var baselineCount = contextFingerprintOccurrences.GetContextCount(
                InputKind.Baseline,
                baselineFinding,
                kind,
                baseline);
            var candidateCount = contextFingerprintOccurrences.GetContextCount(
                InputKind.Candidate,
                candidateFinding,
                kind,
                candidate);
            if (baselineCount == 1 && candidateCount == 1)
            {
                uniqueHashCount++;
            }
            else
            {
                collidedHashCount++;
                if (evidence is not null)
                {
                    evidence.Add(new EvidenceDraft(
                        "context-collision",
                        ContextFingerprintOccurrenceIndex.FormatContextOccurrence(
                            kind,
                            baseline,
                            baselineCount),
                        ContextFingerprintOccurrenceIndex.FormatContextOccurrence(
                            kind,
                            candidate,
                            candidateCount),
                        EvidenceOrigin.System,
                        Lossy: false,
                        MatchingAlgorithms.EvidenceOccurrenceVersion));
                }
            }
        }
        else
        {
            conflictingHashCount++;
        }

        evidence?.Add(new EvidenceDraft(
            kind,
            baseline,
            candidate,
            EvidenceOrigin.Repository,
            Lossy: false,
            MatchingAlgorithms.ContextVersion));
    }

    private static AgreementBand CompareMessages(
        MessageIdentity baseline,
        MessageIdentity candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        AgreementBand agreement;
        if (string.Equals(
            baseline.CanonicalText,
            candidate.CanonicalText,
            StringComparison.Ordinal))
        {
            agreement = AgreementBand.Exact;
        }
        else if (string.Equals(
            baseline.ComparisonText,
            candidate.ComparisonText,
            StringComparison.Ordinal))
        {
            agreement = AgreementBand.Compatible;
        }
        else
        {
            agreement = AgreementBand.None;
        }

        if (evidence is null)
        {
            return agreement;
        }

        var messageEvidence = EvidenceDraft.CreateBounded(
            "message",
            baseline.CanonicalText,
            candidate.CanonicalText,
            EvidenceOrigin.System,
            MatchingAlgorithms.MessageVersion);
        evidence.Add(
            messageEvidence with
            {
                Lossy = messageEvidence.Lossy ||
                    !baseline.NormalisationFlags.IsEmpty ||
                    !candidate.NormalisationFlags.IsEmpty,
            });
        return agreement;
    }

    private AgreementBand CompareSupportingEvidence(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        var codeFlowAgreement = CompareCodeFlow(baseline, candidate, evidence);
        if (evidence is not null)
        {
            _ = CompareRelatedLocations(
                baseline.RelatedLocations,
                candidate.RelatedLocations,
                evidence);
        }

        return codeFlowAgreement;
    }

    private AgreementBand CompareCodeFlow(
        Finding baselineFinding,
        Finding candidateFinding,
        ICollection<EvidenceDraft>? evidence)
    {
        var baseline = baselineFinding.CodeFlow;
        var candidate = candidateFinding.CodeFlow;
        if (baseline is null || candidate is null
            || baseline.Anchors.IsDefaultOrEmpty
            || candidate.Anchors.IsDefaultOrEmpty)
        {
            return AgreementBand.None;
        }

        var baselineAnchors = CreateAnchorSet(baseline);
        var candidateAnchors = CreateAnchorSet(candidate);
        var intersection = baselineAnchors
            .Intersect(candidateAnchors)
            .OrderBy(
                CodeFlowAnchorOccurrenceIndex.GetStableValue,
                StringComparer.Ordinal)
            .ToArray();
        if (intersection.Length == 0)
        {
            return AgreementBand.None;
        }

        var reliableIntersection = intersection
            .Where(anchor =>
                codeFlowAnchorOccurrences.GetCount(
                    InputKind.Baseline,
                    baselineFinding,
                    anchor) == 1
                && codeFlowAnchorOccurrences.GetCount(
                    InputKind.Candidate,
                    candidateFinding,
                    anchor) == 1)
            .ToHashSet();
        if (evidence is not null)
        {
            var collidedIntersection = intersection
                .Where(anchor => !reliableIntersection.Contains(anchor))
                .ToArray();
            if (collidedIntersection.Length > 0)
            {
                AddCodeFlowCollisionEvidence(
                    baselineFinding,
                    candidateFinding,
                    collidedIntersection,
                    evidence);
            }
        }

        var baselineReliableAnchors = baselineAnchors
            .Where(anchor => codeFlowAnchorOccurrences.GetCount(
                InputKind.Baseline,
                baselineFinding,
                anchor) == 1)
            .ToHashSet();
        var candidateReliableAnchors = candidateAnchors
            .Where(anchor => codeFlowAnchorOccurrences.GetCount(
                InputKind.Candidate,
                candidateFinding,
                anchor) == 1)
            .ToHashSet();
        var isExact = reliableIntersection.Count > 0
            && baselineReliableAnchors.SetEquals(candidateReliableAnchors);
        if (evidence is not null)
        {
            var baselineHash = HashOrderedSet(
                MatchingAlgorithms.CodeFlowSetVersion,
                baselineAnchors.Select(CodeFlowAnchorOccurrenceIndex.GetStableValue));
            var candidateHash = HashOrderedSet(
                MatchingAlgorithms.CodeFlowSetVersion,
                candidateAnchors.Select(CodeFlowAnchorOccurrenceIndex.GetStableValue));
            evidence.Add(new EvidenceDraft(
                "code-flow",
                baselineHash,
                candidateHash,
                EvidenceOrigin.System,
                Lossy: false,
                MatchingAlgorithms.CodeFlowSetVersion));
        }

        if (reliableIntersection.Count == 0)
        {
            return AgreementBand.None;
        }

        return isExact ? AgreementBand.Exact : AgreementBand.Compatible;
    }

    private HashSet<CodeFlowAnchorIdentity> CreateAnchorSet(CodeFlowEvidence codeFlow) =>
        codeFlow.Anchors
            .Select(anchor => CodeFlowAnchorOccurrenceIndex.CreateIdentity(
                anchor,
                configuration.Matching.PathCaseSensitivity))
            .ToHashSet();

    private void AddCodeFlowCollisionEvidence(
        Finding baseline,
        Finding candidate,
        IReadOnlyList<CodeFlowAnchorIdentity> collidedAnchors,
        ICollection<EvidenceDraft> evidence)
    {
        evidence.Add(new EvidenceDraft(
            "code-flow-anchor-collision",
            codeFlowAnchorOccurrences.FormatCollisionSummary(
                InputKind.Baseline,
                baseline,
                collidedAnchors),
            codeFlowAnchorOccurrences.FormatCollisionSummary(
                InputKind.Candidate,
                candidate,
                collidedAnchors),
            EvidenceOrigin.System,
            Lossy: true,
            MatchingAlgorithms.CodeFlowOccurrenceVersion));
    }

    private AgreementBand CompareRelatedLocations(
        ImmutableArray<RelatedLocation> baseline,
        ImmutableArray<RelatedLocation> candidate,
        ICollection<EvidenceDraft> evidence)
    {
        if (baseline.IsDefaultOrEmpty || candidate.IsDefaultOrEmpty)
        {
            return AgreementBand.None;
        }

        var baselinePaths = baseline
            .Where(item => item.Path is not null)
            .Select(item => NormalizePathForComparison(item.Path!.CanonicalUri))
            .ToHashSet(StringComparer.Ordinal);
        var candidatePaths = candidate
            .Where(item => item.Path is not null)
            .Select(item => NormalizePathForComparison(item.Path!.CanonicalUri))
            .ToHashSet(StringComparer.Ordinal);
        if (baselinePaths.Count == 0
            || candidatePaths.Count == 0
            || !baselinePaths.Overlaps(candidatePaths))
        {
            return AgreementBand.None;
        }

        var isExact = baselinePaths.SetEquals(candidatePaths);
        evidence.Add(new EvidenceDraft(
            "related-location-paths",
            HashOrderedSet(MatchingAlgorithms.RelatedLocationSetVersion, baselinePaths),
            HashOrderedSet(MatchingAlgorithms.RelatedLocationSetVersion, candidatePaths),
            EvidenceOrigin.System,
            Lossy: false,
            MatchingAlgorithms.RelatedLocationSetVersion));
        return isExact ? AgreementBand.Exact : AgreementBand.Compatible;
    }

    private static string HashOrderedSet(string algorithmVersion, IEnumerable<string> values) =>
        VersionedHash.Compute(
            algorithmVersion,
            values.Order(StringComparer.Ordinal).Cast<string?>().ToArray());

    private static int CompareRegions(
        Region? baseline,
        Region? candidate,
        ICollection<EvidenceDraft>? evidence)
    {
        if (baseline is null || candidate is null)
        {
            return 0;
        }

        if (evidence is not null)
        {
            var baselineValue = FormatRegion(baseline);
            var candidateValue = baseline == candidate
                ? baselineValue
                : FormatRegion(candidate);
            evidence.Add(new EvidenceDraft(
                "region",
                baselineValue,
                candidateValue,
                EvidenceOrigin.System,
                Lossy: false,
                MatchingAlgorithms.RegionVersion));
        }

        if (baseline == candidate)
        {
            return ExactRegionBand;
        }

        if (baseline.StartLine.HasValue
            && candidate.StartLine.HasValue
            && Math.Abs((long)baseline.StartLine.Value - candidate.StartLine.Value) <= 3)
        {
            return NearRegionBand;
        }

        return AvailableRegionBand;
    }

    private static string FormatRegion(Region region) =>
        $"{FormatCoordinate(region.StartLine)}:"
        + $"{FormatCoordinate(region.StartColumn)}-"
        + $"{FormatCoordinate(region.EndLine)}:"
        + FormatCoordinate(region.EndColumn);

    private static string FormatCoordinate(int? coordinate) =>
        coordinate?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "?";

    private PrecedenceSelection DeterminePrecedenceTier(
        bool aliasApplied,
        int producerFingerprintStrength,
        DerivedFingerprintComparison derivedFingerprint,
        PathMatchKind pathMatchKind,
        ContextComparison context,
        AgreementBand messageAgreement)
    {
        var stableContext =
            derivedFingerprint.Unique || context.ReliableExact;
        if (aliasApplied)
        {
            var hasLocationAndRealContext =
                pathMatchKind != PathMatchKind.None
                && context.ReliableExact;
            return hasLocationAndRealContext
                ? new PrecedenceSelection(PrecedenceTier.Override, CollisionOnly: false)
                : PrecedenceSelection.Refuse;
        }

        if (producerFingerprintStrength == HighProducerFingerprintStrength)
        {
            return new PrecedenceSelection(
                PrecedenceTier.ExactProducer,
                CollisionOnly: false);
        }

        if (pathMatchKind == PathMatchKind.Exact && derivedFingerprint.Unique)
        {
            return new PrecedenceSelection(
                PrecedenceTier.ExactCanonical,
                CollisionOnly: false);
        }

        if (stableContext)
        {
            return new PrecedenceSelection(
                PrecedenceTier.StrongMoved,
                CollisionOnly: false);
        }

        var collisionEvidenceConflicts = context.Conflicting
            && (derivedFingerprint.Collided || context.Collided);
        var duplicatedDerivedFingerprintAdmissible =
            derivedFingerprint.Collided
            && pathMatchKind != PathMatchKind.None
            && !collisionEvidenceConflicts;
        var duplicatedRawContextAdmissible =
            context.Collided
            && !collisionEvidenceConflicts
            && (pathMatchKind == PathMatchKind.Aliased
                || pathMatchKind == PathMatchKind.Exact
                    && messageAgreement >= AgreementBand.Compatible);
        if (duplicatedDerivedFingerprintAdmissible
            || duplicatedRawContextAdmissible)
        {
            return new PrecedenceSelection(
                PrecedenceTier.WeakContextual,
                CollisionOnly: true);
        }

        var weakMessageAdmissible = configuration.Matching.AllowWeakMessageSimilarity
            && !collisionEvidenceConflicts
            && messageAgreement >= AgreementBand.Compatible
            && (pathMatchKind == PathMatchKind.Exact
                || context.Agreement >= AgreementBand.Compatible);
        return weakMessageAdmissible
            ? new PrecedenceSelection(
                PrecedenceTier.WeakContextual,
                CollisionOnly: false)
            : PrecedenceSelection.Refuse;
    }

    private ImmutableArray<TransformationRecord> GetTransformations(
        Finding baseline,
        Finding candidate)
    {
        var baselineTransformations = GetPathTransformations(baseline);
        var candidateTransformations = GetPathTransformations(candidate);
        if (baselineTransformations.IsEmpty
            && candidateTransformations.IsEmpty)
        {
            return ImmutableArray<TransformationRecord>.Empty;
        }

        return baselineTransformations
            .Concat(candidateTransformations)
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.OriginalValue, StringComparer.Ordinal)
            .ThenBy(item => item.TransformedValue, StringComparer.Ordinal)
            .ThenBy(item => item.IsLossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static ImmutableArray<TransformationRecord> GetPathTransformations(Finding finding) =>
        finding.PrimaryLocation?.Path.Transformations
        ?? ImmutableArray<TransformationRecord>.Empty;

    private bool PathEquals(string left, string right) =>
        configuration.Matching.PathCaseSensitivity == PathCaseSensitivity.Sensitive
            ? string.Equals(left, right, StringComparison.Ordinal)
            : AsciiEqualsIgnoreCase(left, right);

    private string NormalizePathForComparison(string path)
    {
        if (configuration.Matching.PathCaseSensitivity == PathCaseSensitivity.Sensitive)
        {
            return path;
        }

        return string.Create(
            path.Length,
            path,
            static (destination, source) =>
            {
                for (var index = 0; index < source.Length; index++)
                {
                    destination[index] = FoldAsciiCase(source[index]);
                }
            });
    }

    private static bool AsciiEqualsIgnoreCase(string left, string right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (var index = 0; index < left.Length; index++)
        {
            if (FoldAsciiCase(left[index]) != FoldAsciiCase(right[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static char FoldAsciiCase(char value) =>
        value is >= 'A' and <= 'Z'
            ? (char)(value + ('a' - 'A'))
            : value;

    internal static string CreateStableFindingKey(string findingKey) =>
        string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{findingKey.Length}:{findingKey}");

    private static string CreateStableIdentityKey(string baselineKey, string candidateKey) =>
        string.Concat(
            CreateStableFindingKey(baselineKey),
            CreateStableFindingKey(candidateKey));

    private sealed class EvidenceRecordComparer : IComparer<EvidenceRecord>
    {
        public static EvidenceRecordComparer Instance { get; } = new();

        public int Compare(EvidenceRecord? left, EvidenceRecord? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left is null)
            {
                return -1;
            }

            if (right is null)
            {
                return 1;
            }

            var comparison = StringComparer.Ordinal.Compare(
                left.Kind,
                right.Kind);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = StringComparer.Ordinal.Compare(
                left.BaselineValue,
                right.BaselineValue);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = StringComparer.Ordinal.Compare(
                left.CandidateValue,
                right.CandidateValue);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = left.Origin.CompareTo(right.Origin);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = left.PrecedenceTier.CompareTo(
                right.PrecedenceTier);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = left.Lossy.CompareTo(right.Lossy);
            return comparison != 0
                ? comparison
                : StringComparer.Ordinal.Compare(
                    left.AlgorithmVersion,
                    right.AlgorithmVersion);
        }
    }

    private readonly record struct EvidenceDraft(
        string Kind,
        string? BaselineValue,
        string? CandidateValue,
        EvidenceOrigin Origin,
        bool Lossy,
        string AlgorithmVersion)
    {
        public static EvidenceDraft CreateBounded(
            string kind,
            string? baselineValue,
            string? candidateValue,
            EvidenceOrigin origin,
            string algorithmVersion)
        {
            var boundedBaseline = BoundValue(baselineValue, algorithmVersion);
            var boundedCandidate = BoundValue(candidateValue, algorithmVersion);
            return new EvidenceDraft(
                kind,
                boundedBaseline.Value,
                boundedCandidate.Value,
                origin,
                boundedBaseline.Lossy || boundedCandidate.Lossy,
                algorithmVersion);
        }

        public EvidenceRecord ToEvidenceRecord(PrecedenceTier precedenceTier)
        {
            var boundedBaseline = BoundValue(BaselineValue, AlgorithmVersion);
            var boundedCandidate = BoundValue(CandidateValue, AlgorithmVersion);
            return new EvidenceRecord(
                Kind,
                boundedBaseline.Value,
                boundedCandidate.Value,
                Origin,
                precedenceTier,
                Lossy || boundedBaseline.Lossy || boundedCandidate.Lossy,
                AlgorithmVersion);
        }

        private static BoundedValue BoundValue(string? value, string algorithmVersion)
        {
            if (value is null || value.Length <= MaximumInlineEvidenceCharacters)
            {
                return new BoundedValue(value, Lossy: false);
            }

            return new BoundedValue(
                $"sha256:{VersionedHash.Compute(algorithmVersion, value)}",
                Lossy: true);
        }
    }

    private readonly record struct BoundedValue(string? Value, bool Lossy);

    private readonly record struct ProducerFingerprintComparison(
        int Strength,
        string? Family,
        int? Version,
        string? Value)
    {
        public static ProducerFingerprintComparison None { get; } =
            new(0, null, null, null);
    }

    private readonly record struct CommonVersion(bool HasCommonVersion, int? Version);

    private readonly record struct DerivedFingerprintComparison(
        bool Unique,
        bool Collided)
    {
        public static DerivedFingerprintComparison None { get; } =
            new(Unique: false, Collided: false);
    }

    private readonly record struct DerivedFingerprintMatch(
        DerivedFingerprint Baseline,
        DerivedFingerprint Candidate,
        int BaselineCount,
        int CandidateCount)
    {
        public bool IsUnique => BaselineCount == 1 && CandidateCount == 1;
    }

    private readonly record struct ContextComparison(
        AgreementBand Agreement,
        bool ReliableExact,
        bool Collided,
        bool Conflicting)
    {
        public static ContextComparison None { get; } =
            new(
                AgreementBand.None,
                ReliableExact: false,
                Collided: false,
                Conflicting: false);
    }

    private readonly record struct PrecedenceSelection(
        PrecedenceTier Tier,
        bool CollisionOnly)
    {
        public static PrecedenceSelection Refuse { get; } =
            new(PrecedenceTier.Refuse, CollisionOnly: false);
    }

    private readonly record struct DerivedFingerprintIdentity(
        string Name,
        string AlgorithmVersion);
}

internal sealed class ProducerFingerprintOccurrenceIndex
{
    private readonly Dictionary<OccurrenceKey, int> occurrenceCounts;

    private ProducerFingerprintOccurrenceIndex(
        Dictionary<OccurrenceKey, int> occurrenceCounts,
        ImmutableArray<Diagnostic> diagnostics)
    {
        this.occurrenceCounts = occurrenceCounts;
        Diagnostics = diagnostics;
    }

    public ImmutableArray<Diagnostic> Diagnostics { get; }

    public static ProducerFingerprintOccurrenceIndex Create(
        ImmutableArray<Finding> baseline,
        ImmutableArray<Finding> candidate)
    {
        var occurrenceCounts = new Dictionary<OccurrenceKey, int>();
        AddOccurrences(InputKind.Baseline, baseline, occurrenceCounts);
        AddOccurrences(InputKind.Candidate, candidate, occurrenceCounts);

        var diagnostics = occurrenceCounts
            .Where(item => item.Value > 1)
            .OrderBy(item => item.Key.Input)
            .ThenBy(item => item.Key.RunKey, StringComparer.Ordinal)
            .ThenBy(item => item.Key.ProducerIdentity, StringComparer.Ordinal)
            .ThenBy(item => item.Key.RuleId, StringComparer.Ordinal)
            .ThenBy(item => item.Key.FingerprintFamily, StringComparer.Ordinal)
            .ThenByDescending(item => item.Key.Version)
            .ThenBy(item => item.Key.Value, StringComparer.Ordinal)
            .Select(item => new Diagnostic(
                "MATCH0005",
                DiagnosticSeverity.Warning,
                DiagnosticStage.Match,
                $"Producer fingerprint family '{FormatFamily(item.Key)}' is not unique "
                + $"within the {item.Key.Input.ToString().ToLowerInvariant()} "
                + $"run-and-rule bucket; exact-producer matching is disabled for that value."))
            .ToImmutableArray();

        return new ProducerFingerprintOccurrenceIndex(occurrenceCounts, diagnostics);
    }

    public bool IsUnique(
        InputKind input,
        Finding finding,
        ProducerFingerprint fingerprint)
    {
        var key = CreateKey(input, finding, fingerprint);
        return occurrenceCounts.TryGetValue(key, out var count) && count == 1;
    }

    private static void AddOccurrences(
        InputKind input,
        ImmutableArray<Finding> findings,
        IDictionary<OccurrenceKey, int> occurrenceCounts)
    {
        foreach (var finding in findings)
        {
            if (finding.ProducerFingerprints.IsEmpty)
            {
                continue;
            }

            if (finding.ProducerFingerprints.Length == 1)
            {
                Increment(
                    CreateKey(
                        input,
                        finding,
                        finding.ProducerFingerprints[0]),
                    occurrenceCounts);
                continue;
            }

            var keysForFinding = finding.ProducerFingerprints
                .Select(fingerprint => CreateKey(input, finding, fingerprint))
                .ToHashSet();
            foreach (var key in keysForFinding)
            {
                Increment(key, occurrenceCounts);
            }
        }
    }

    private static void Increment(
        OccurrenceKey key,
        IDictionary<OccurrenceKey, int> occurrenceCounts)
    {
        occurrenceCounts.TryGetValue(key, out var existingCount);
        occurrenceCounts[key] = existingCount + 1;
    }

    private static OccurrenceKey CreateKey(
        InputKind input,
        Finding finding,
        ProducerFingerprint fingerprint) =>
        new(
            input,
            finding.Run.StableRunKey,
            finding.Producer.AutomaticIdentity,
            finding.Rule.CanonicalId,
            fingerprint.Family,
            fingerprint.Version,
            fingerprint.Value);

    private static string FormatFamily(OccurrenceKey key) =>
        key.Version is null
            ? key.FingerprintFamily
            : $"{key.FingerprintFamily}/v{key.Version.Value}";

    private readonly record struct OccurrenceKey(
        InputKind Input,
        string RunKey,
        string ProducerIdentity,
        string RuleId,
        string FingerprintFamily,
        int? Version,
        string Value);
}

internal sealed class RuleAliasIndex
{
    private readonly Dictionary<RuleAliasKey, RuleAlias> aliases;

    private RuleAliasIndex(Dictionary<RuleAliasKey, RuleAlias> aliases)
    {
        this.aliases = aliases;
    }

    public static RuleAliasIndex Create(ImmutableArray<RuleAlias> aliases)
    {
        var indexed = new Dictionary<RuleAliasKey, RuleAlias>();
        foreach (var alias in aliases)
        {
            var baselineProducer = ProducerIdentityResolver.Resolve(
                alias.BaselineProducer);
            var candidateProducer = ProducerIdentityResolver.Resolve(
                alias.CandidateProducer);
            indexed.TryAdd(
                new RuleAliasKey(
                    baselineProducer.AutomaticIdentity,
                    alias.BaselineRule,
                    candidateProducer.AutomaticIdentity,
                    alias.CandidateRule),
                alias);
        }

        return new RuleAliasIndex(indexed);
    }

    public ImmutableArray<RuleAlias> FindApplicable(Finding baseline, Finding candidate)
    {
        var matches = new HashSet<RuleAlias>();
        foreach (var baselineRule in RuleTokens(baseline.Rule))
        {
            foreach (var candidateRule in RuleTokens(candidate.Rule))
            {
                if (aliases.TryGetValue(
                    new RuleAliasKey(
                        baseline.Producer.AutomaticIdentity,
                        baselineRule,
                        candidate.Producer.AutomaticIdentity,
                        candidateRule),
                    out var alias))
                {
                    matches.Add(alias);
                }
            }
        }

        return matches
            .OrderBy(item => item.BaselineProducer, StringComparer.Ordinal)
            .ThenBy(item => item.BaselineRule, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateProducer, StringComparer.Ordinal)
            .ThenBy(item => item.CandidateRule, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static IEnumerable<string> RuleTokens(RuleIdentity rule) =>
        new[]
        {
            rule.CanonicalId,
            rule.OriginalId,
        }.Distinct(StringComparer.Ordinal);

    private readonly record struct RuleAliasKey(
        string BaselineProducer,
        string BaselineRule,
        string CandidateProducer,
        string CandidateRule);
}
