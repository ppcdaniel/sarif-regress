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
    private readonly RuleAliasIndex ruleAliases;

    public CandidateEdgeFactory(
        SarifRegressConfiguration configuration,
        ProducerFingerprintOccurrenceIndex fingerprintOccurrences)
    {
        this.configuration = configuration;
        this.fingerprintOccurrences = fingerprintOccurrences;
        ruleAliases = RuleAliasIndex.Create(configuration.RuleAliases);
    }

    public MatchEdge? Create(Finding baseline, Finding candidate)
    {
        var sameDefaultRule = IsSameDefaultRule(baseline, candidate);
        var applicableAliases = sameDefaultRule
            ? ImmutableArray<RuleAlias>.Empty
            : FindApplicableAliases(baseline, candidate);
        if (!sameDefaultRule && applicableAliases.IsEmpty)
        {
            return null;
        }

        var evidence = new List<EvidenceDraft>();
        AddRuleEvidence(evidence, baseline, candidate, applicableAliases);

        var producerFingerprint = CompareProducerFingerprints(baseline, candidate, evidence);
        var derivedFingerprintExact = CompareDerivedFingerprints(baseline, candidate, evidence);
        var pathMatchKind = ComparePaths(baseline, candidate, evidence);
        var contextAgreement = CompareContext(baseline.Context, candidate.Context, evidence);
        var messageAgreement = CompareMessages(baseline.Message, candidate.Message, evidence);
        var supportingAgreement = CompareSupportingEvidence(baseline, candidate, evidence);
        var regionDriftBand = CompareRegions(
            baseline.PrimaryLocation?.Region,
            candidate.PrimaryLocation?.Region,
            evidence);

        var precedenceTier = DeterminePrecedenceTier(
            aliasApplied: !applicableAliases.IsEmpty,
            producerFingerprint.Strength,
            derivedFingerprintExact,
            pathMatchKind,
            contextAgreement,
            supportingAgreement,
            messageAgreement);
        if (precedenceTier == PrecedenceTier.Refuse)
        {
            return null;
        }

        var decisionVector = new DecisionVector(
            precedenceTier,
            producerFingerprint.Strength,
            pathMatchKind,
            contextAgreement,
            supportingAgreement,
            messageAgreement,
            regionDriftBand);

        return new MatchEdge(
            baseline,
            candidate,
            decisionVector,
            CreateStableIdentityKey(baseline.FindingKey, candidate.FindingKey),
            evidence
                .Select(item => item.ToEvidenceRecord(precedenceTier))
                .OrderBy(item => item.Kind, StringComparer.Ordinal)
                .ThenBy(item => item.BaselineValue, StringComparer.Ordinal)
                .ThenBy(item => item.CandidateValue, StringComparer.Ordinal)
                .ThenBy(item => item.Origin)
                .ThenBy(item => item.PrecedenceTier)
                .ThenBy(item => item.Lossy)
                .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
                .ToImmutableArray(),
            GetTransformations(baseline, candidate));
    }

    private static bool IsSameDefaultRule(Finding baseline, Finding candidate) =>
        string.Equals(
            baseline.Producer.Family,
            candidate.Producer.Family,
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
        ICollection<EvidenceDraft> evidence,
        Finding baseline,
        Finding candidate,
        ImmutableArray<RuleAlias> aliases)
    {
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
        ICollection<EvidenceDraft> evidence)
    {
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

        if (bestComparison.Strength > 0)
        {
            var fingerprintLabel = bestComparison.Version is null
                ? bestComparison.Family
                : $"{bestComparison.Family}/v{bestComparison.Version.Value}";
            evidence.Add(new EvidenceDraft(
                "producer-fingerprint",
                $"{fingerprintLabel}:{bestComparison.Value}",
                $"{fingerprintLabel}:{bestComparison.Value}",
                EvidenceOrigin.Producer,
                Lossy: false,
                MatchingAlgorithms.ProducerFingerprintVersion));
        }

        return bestComparison;
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

    private static bool CompareDerivedFingerprints(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft> evidence)
    {
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
                    .Select(candidateFingerprint => (
                        Baseline: baselineFingerprint,
                        Candidate: candidateFingerprint)))
            .OrderBy(item => item.Baseline.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Baseline.AlgorithmVersion, StringComparer.Ordinal)
            .ThenBy(item => item.Baseline.Value, StringComparer.Ordinal)
            .ToArray();
        if (matches.Length == 0)
        {
            return false;
        }

        var match = matches[0];
        evidence.Add(new EvidenceDraft(
            "derived-fingerprint",
            $"{match.Baseline.Name}:{match.Baseline.Value}",
            $"{match.Candidate.Name}:{match.Candidate.Value}",
            EvidenceOrigin.System,
            Lossy: false,
            MatchingAlgorithms.DerivedFingerprintVersion));
        return true;
    }

    private PathMatchKind ComparePaths(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft> evidence)
    {
        var baselinePath = baseline.PrimaryLocation?.Path;
        var candidatePath = candidate.PrimaryLocation?.Path;
        if (baselinePath is null || candidatePath is null)
        {
            return PathMatchKind.None;
        }

        if (PathEquals(baselinePath.CanonicalUri, candidatePath.CanonicalUri))
        {
            evidence.Add(new EvidenceDraft(
                "canonical-path",
                baselinePath.CanonicalUri,
                candidatePath.CanonicalUri,
                EvidenceOrigin.System,
                Lossy: false,
                MatchingAlgorithms.PathVersion));
            return PathMatchKind.Exact;
        }

        foreach (var alias in configuration.PathAliases)
        {
            if (!AliasMapsPaths(alias, baselinePath, candidatePath))
            {
                continue;
            }

            evidence.Add(new EvidenceDraft(
                "path-alias",
                alias.Baseline,
                alias.Candidate,
                EvidenceOrigin.Configuration,
                Lossy: false,
                MatchingAlgorithms.PathAliasVersion));
            return PathMatchKind.Aliased;
        }

        evidence.Add(new EvidenceDraft(
            "canonical-path",
            baselinePath.CanonicalUri,
            candidatePath.CanonicalUri,
            EvidenceOrigin.System,
            Lossy: false,
            MatchingAlgorithms.PathVersion));
        return PathMatchKind.None;
    }

    private bool AliasMapsPaths(
        PathAlias alias,
        CanonicalPath baselinePath,
        CanonicalPath candidatePath)
    {
        var pathPairs = new[]
        {
            (
                Baseline: baselinePath.RepositoryRelativePath,
                Candidate: candidatePath.RepositoryRelativePath),
            (
                Baseline: baselinePath.CanonicalUri,
                Candidate: candidatePath.CanonicalUri),
        };

        return pathPairs.Any(pair =>
            pair.Baseline is not null
            && pair.Candidate is not null
            && HasMappedSuffix(
                pair.Baseline,
                alias.Baseline,
                pair.Candidate,
                alias.Candidate));
    }

    private bool HasMappedSuffix(
        string baselinePath,
        string baselinePrefix,
        string candidatePath,
        string candidatePrefix)
    {
        if (!PathStartsWith(baselinePath, baselinePrefix)
            || !PathStartsWith(candidatePath, candidatePrefix))
        {
            return false;
        }

        return PathEquals(
            baselinePath[baselinePrefix.Length..],
            candidatePath[candidatePrefix.Length..]);
    }

    private AgreementBand CompareContext(
        ContextEvidence? baseline,
        ContextEvidence? candidate,
        ICollection<EvidenceDraft> evidence)
    {
        if (baseline is null || candidate is null)
        {
            return AgreementBand.None;
        }

        var exactHashCount = 0;
        var conflictingHashCount = 0;
        CompareContextHash(
            "context-snippet",
            baseline.SnippetHash,
            candidate.SnippetHash,
            ref exactHashCount,
            ref conflictingHashCount,
            evidence);
        CompareContextHash(
            "context-token-window",
            baseline.TokenWindowHash,
            candidate.TokenWindowHash,
            ref exactHashCount,
            ref conflictingHashCount,
            evidence);

        if (exactHashCount > 0 && conflictingHashCount == 0)
        {
            return AgreementBand.Exact;
        }

        return exactHashCount > 0
            ? AgreementBand.Compatible
            : AgreementBand.None;
    }

    private static void CompareContextHash(
        string kind,
        string? baseline,
        string? candidate,
        ref int exactHashCount,
        ref int conflictingHashCount,
        ICollection<EvidenceDraft> evidence)
    {
        if (baseline is null || candidate is null)
        {
            return;
        }

        if (string.Equals(baseline, candidate, StringComparison.Ordinal))
        {
            exactHashCount++;
        }
        else
        {
            conflictingHashCount++;
        }

        evidence.Add(new EvidenceDraft(
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
        ICollection<EvidenceDraft> evidence)
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

        evidence.Add(EvidenceDraft.CreateBounded(
            "message",
            baseline.CanonicalText,
            candidate.CanonicalText,
            EvidenceOrigin.System,
            MatchingAlgorithms.MessageVersion));
        return agreement;
    }

    private AgreementBand CompareSupportingEvidence(
        Finding baseline,
        Finding candidate,
        ICollection<EvidenceDraft> evidence)
    {
        var codeFlowAgreement = CompareCodeFlow(baseline.CodeFlow, candidate.CodeFlow, evidence);
        var relatedLocationAgreement = CompareRelatedLocations(
            baseline.RelatedLocations,
            candidate.RelatedLocations,
            evidence);
        return codeFlowAgreement >= relatedLocationAgreement
            ? codeFlowAgreement
            : relatedLocationAgreement;
    }

    private AgreementBand CompareCodeFlow(
        CodeFlowEvidence? baseline,
        CodeFlowEvidence? candidate,
        ICollection<EvidenceDraft> evidence)
    {
        if (baseline is null || candidate is null
            || baseline.Anchors.IsDefaultOrEmpty
            || candidate.Anchors.IsDefaultOrEmpty)
        {
            return AgreementBand.None;
        }

        var baselineAnchors = CreateAnchorSet(baseline);
        var candidateAnchors = CreateAnchorSet(candidate);
        var intersection = baselineAnchors
            .Intersect(candidateAnchors, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (intersection.Length == 0)
        {
            return AgreementBand.None;
        }

        var isExact = baselineAnchors.SetEquals(candidateAnchors);
        var baselineHash = HashOrderedSet(
            MatchingAlgorithms.CodeFlowSetVersion,
            baselineAnchors);
        var candidateHash = HashOrderedSet(
            MatchingAlgorithms.CodeFlowSetVersion,
            candidateAnchors);
        evidence.Add(new EvidenceDraft(
            "code-flow",
            baselineHash,
            candidateHash,
            EvidenceOrigin.System,
            Lossy: false,
            MatchingAlgorithms.CodeFlowSetVersion));
        return isExact ? AgreementBand.Exact : AgreementBand.Compatible;
    }

    private HashSet<string> CreateAnchorSet(CodeFlowEvidence codeFlow) =>
        codeFlow.Anchors
            .Select(anchor => VersionedHash.Compute(
                MatchingAlgorithms.CodeFlowAnchorVersion,
                NormalizePathForComparison(anchor.CanonicalPath),
                anchor.ContextHash))
            .ToHashSet(StringComparer.Ordinal);

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
        ICollection<EvidenceDraft> evidence)
    {
        if (baseline is null || candidate is null)
        {
            return 0;
        }

        evidence.Add(new EvidenceDraft(
            "region",
            FormatRegion(baseline),
            FormatRegion(candidate),
            EvidenceOrigin.System,
            Lossy: false,
            MatchingAlgorithms.RegionVersion));

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

    private PrecedenceTier DeterminePrecedenceTier(
        bool aliasApplied,
        int producerFingerprintStrength,
        bool derivedFingerprintExact,
        PathMatchKind pathMatchKind,
        AgreementBand contextAgreement,
        AgreementBand supportingAgreement,
        AgreementBand messageAgreement)
    {
        var stableContext =
            derivedFingerprintExact || contextAgreement == AgreementBand.Exact;
        if (aliasApplied)
        {
            var hasLocationAndRealContext =
                pathMatchKind != PathMatchKind.None
                && contextAgreement == AgreementBand.Exact;
            return hasLocationAndRealContext
                ? PrecedenceTier.Override
                : PrecedenceTier.Refuse;
        }

        if (producerFingerprintStrength == HighProducerFingerprintStrength)
        {
            return PrecedenceTier.ExactProducer;
        }

        if (pathMatchKind == PathMatchKind.Exact && derivedFingerprintExact)
        {
            return PrecedenceTier.ExactCanonical;
        }

        if (stableContext)
        {
            return PrecedenceTier.StrongMoved;
        }

        if (supportingAgreement >= AgreementBand.Compatible)
        {
            return PrecedenceTier.PathProblem;
        }

        return configuration.Matching.AllowWeakMessageSimilarity
            && messageAgreement >= AgreementBand.Compatible
            && (pathMatchKind == PathMatchKind.Exact
                || contextAgreement >= AgreementBand.Compatible)
            ? PrecedenceTier.WeakContextual
            : PrecedenceTier.Refuse;
    }

    private ImmutableArray<TransformationRecord> GetTransformations(
        Finding baseline,
        Finding candidate) =>
        GetPathTransformations(baseline)
            .Concat(GetPathTransformations(candidate))
            .Distinct()
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.OriginalValue, StringComparer.Ordinal)
            .ThenBy(item => item.TransformedValue, StringComparer.Ordinal)
            .ThenBy(item => item.IsLossy)
            .ThenBy(item => item.AlgorithmVersion, StringComparer.Ordinal)
            .ToImmutableArray();

    private static ImmutableArray<TransformationRecord> GetPathTransformations(Finding finding) =>
        finding.PrimaryLocation?.Path.Transformations
        ?? ImmutableArray<TransformationRecord>.Empty;

    private bool PathEquals(string left, string right) =>
        configuration.Matching.PathCaseSensitivity == PathCaseSensitivity.Sensitive
            ? string.Equals(left, right, StringComparison.Ordinal)
            : AsciiEqualsIgnoreCase(left, right);

    private bool PathStartsWith(string value, string prefix)
    {
        if (prefix.Length == 0 || prefix.Length > value.Length)
        {
            return false;
        }

        if (!PathEquals(value[..prefix.Length], prefix))
        {
            return false;
        }

        return value.Length == prefix.Length
            || IsPathSeparator(prefix[^1])
            || IsPathSeparator(value[prefix.Length]);
    }

    private static bool IsPathSeparator(char value) => value is '/' or '\\';

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

    private static string CreateStableIdentityKey(string baselineKey, string candidateKey) =>
        $"{baselineKey.Length}:{baselineKey}{candidateKey.Length}:{candidateKey}";

    private sealed record EvidenceDraft(
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

    private sealed record BoundedValue(string? Value, bool Lossy);

    private sealed record ProducerFingerprintComparison(
        int Strength,
        string? Family,
        int? Version,
        string? Value)
    {
        public static ProducerFingerprintComparison None { get; } =
            new(0, null, null, null);
    }

    private readonly record struct CommonVersion(bool HasCommonVersion, int? Version);

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
            .ThenBy(item => item.Key.ProducerFamily, StringComparer.Ordinal)
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
            var keysForFinding = finding.ProducerFingerprints
                .Select(fingerprint => CreateKey(input, finding, fingerprint))
                .ToHashSet();
            foreach (var key in keysForFinding)
            {
                occurrenceCounts.TryGetValue(key, out var existingCount);
                occurrenceCounts[key] = existingCount + 1;
            }
        }
    }

    private static OccurrenceKey CreateKey(
        InputKind input,
        Finding finding,
        ProducerFingerprint fingerprint) =>
        new(
            input,
            finding.Run.StableRunKey,
            finding.Producer.Family,
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
        string ProducerFamily,
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
            indexed.TryAdd(
                new RuleAliasKey(
                    alias.BaselineProducer,
                    alias.BaselineRule,
                    alias.CandidateProducer,
                    alias.CandidateRule),
                alias);
        }

        return new RuleAliasIndex(indexed);
    }

    public ImmutableArray<RuleAlias> FindApplicable(Finding baseline, Finding candidate)
    {
        var matches = new HashSet<RuleAlias>();
        foreach (var baselineProducer in ProducerTokens(baseline.Producer))
        {
            foreach (var baselineRule in RuleTokens(baseline.Rule))
            {
                foreach (var candidateProducer in ProducerTokens(candidate.Producer))
                {
                    foreach (var candidateRule in RuleTokens(candidate.Rule))
                    {
                        if (aliases.TryGetValue(
                            new RuleAliasKey(
                                baselineProducer,
                                baselineRule,
                                candidateProducer,
                                candidateRule),
                            out var alias))
                        {
                            matches.Add(alias);
                        }
                    }
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

    private static IEnumerable<string> ProducerTokens(ProducerIdentity producer) =>
        new[]
        {
            producer.Family,
            producer.ToolName,
        }.Distinct(StringComparer.Ordinal);

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
