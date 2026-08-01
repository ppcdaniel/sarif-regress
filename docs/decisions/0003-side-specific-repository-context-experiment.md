# ADR 0003: Side-specific repository-context experiment

- **Status:** Proposed; pre-experiment, research only
- **Date:** 2026-08-02
- **Scope:** Sparse SARIF without fingerprints or snippets; issues #11 and #12

## Context

Matcher v3.1 has no safe correspondence edge for a PMD finding that contains no reliable producer
fingerprint, no embedded snippet, and only repeated rule/path/region/message observations. The
previous exact-location-only proposal was tested against the frozen PMD holdout and rejected. Its
complete hypothetical result was `5 TP / 5 FP / 20 FN`, precision `0.5`, recall `0.2`, and four
silently matched ambiguity endpoints. Exact coordinates are observations, not identity proof.

The old PMD holdout source snapshots also contain adjacent `HOLDOUT:pmd-*` identity markers. They
remain valid label-construction evidence for the historical SARIF-only result, but reading them as
matcher context would expose ground truth. They must not be supplied to this experiment, and the
historical v2/v3/v3.1 holdout reports must not be rewritten.

The clean corpus under `validation/research/sparse-sarif/` was frozen before capture or matcher
output. It provides independently authored baseline and candidate source trees, labels held outside
the matching path, collision cases, and explicit one-to-many and many-to-one ambiguity.

## Decision

Build a research harness with two side-bound repository ingestors. Do not add CLI options,
configuration fields, matcher evidence tiers, algorithm versions, or product output fields before
the experiment passes every fixed gate.

At the pre-capture checkpoint, the contamination policy rejects every `implement-v4` report even
when its projected booleans and hashes appear green. That decision cannot become admissible until
role-specific parsers independently validate and cross-reference the implementation, clean-PMD,
original-holdout, development, resource, security, and cross-platform evidence files. An arbitrary
hash-valid file cannot satisfy more than one evidence role. This fail-closed restriction may be
relaxed only by a separately reviewed experiment-evidence change; it is not a gate waiver.

The harness will construct two independent `FileSystemRepositoryContext` instances using the
existing product security primitive:

| Side | SARIF input | Only permitted source context |
|---|---|---|
| Baseline | baseline SARIF | the declared baseline root |
| Candidate | candidate SARIF | the declared candidate root |

Each ingestor receives only its own context instance. There is no shared context fallback, no
candidate read through the baseline ingestor, no baseline read through the candidate ingestor, and
no cache keyed by relative path alone. Any cache key must include the logical side and the bound
source-tree identity. Context instances and opened handles are disposed independently.

For the research corpus, the harness will preflight each root against the manifest's side-specific
source-tree SHA-256 before ingestion. This detects missing, mismatched, or swapped snapshots without
consulting labels. A production caller normally has no trusted expected tree hash; therefore an
experiment that is safe only because of this corpus-specific preflight is insufficient to ship a
general API.

## Compatibility if the design later ships

The existing shared `--repo <path>` and `repoRoot` behavior must remain unchanged for callers whose
baseline and candidate SARIF refer to one checkout. A future product proposal may add
`--baseline-repo <path>` and `--candidate-repo <path>` with corresponding configuration fields, but
only under this compatibility contract:

- the two side-specific options are supplied together;
- supplying only one is a configuration error;
- shared `--repo` cannot be combined with either side-specific option;
- shared `--repo` continues to bind both ingestors to the same approved root;
- side-specific options bind exactly one root to each ingestor and never fall back to the other;
- stable output records only the logical side, repository-relative path, and versioned evidence,
  never an absolute checkout path.

This ADR does not approve those options or a configuration-schema change. A substantial product
implementation requires a separate stacked draft PR after the experiment.

## Independent security contract for each root

Both roots independently inherit every `FileSystemRepositoryContext` restriction. Applying a check
to one root does not authorize the other.

- Canonicalise each approved root independently, and anchor every read to that root's validated
  directory handle rather than a later pathname recheck.
- Accept only canonical repository-relative paths; reject rooted paths, traversal, URI authorities,
  UNC/network paths, Windows device paths, and encoded traversal.
- Use the existing handle-anchored Linux `openat2`/`statx` or Windows relative `NtCreateFile` walk.
  Reject every symbolic link, junction, and other reparse point; if the safe primitive is
  unavailable, fail closed.
- Read only regular files through the validated handle. Reject directories, devices, sockets,
  named pipes, and entries that change type.
- Enforce `maximumRepositoryFileBytes`, snippet radius, token count, string length, cancellation,
  and strict UTF-8 decoding independently. Do not truncate an arbitrary prefix into evidence.
- Normalise line endings deterministically. Never execute repository code, restore packages,
  invoke a language server, fetch a URI, or make a network request.
- Bound diagnostics and explanations; emit hashes and logical provenance rather than source text or
  absolute paths.

A missing or refused source read makes that evidence unavailable. It never enables weaker path,
location, or message matching.

## Predeclared evidence variants

All hashes are versioned, domain-separated, and computed from bytes returned by the correct side's
bounded repository context. Equality is ordinal and exact.

| Variant | Evidence under test | Edge rule |
|---|---|---|
| `sarif-only-control` | Existing SARIF evidence only | No new source-backed edge |
| `exact-region-snippet` | Hash of the normalised source text covered by the exact SARIF region | Admit only when the value occurs exactly once on each side of the producer/rule bucket |
| `token-window` | Existing bounded `token-window/v1` hash around the region | Admit only for exact, one-per-side occurrence |
| `relative-context` | Separate exact hashes for bounded tokens before, inside, and after the region | Admit only when the complete tuple is unique on both sides |
| `agreement-only-combination` | All reliable atoms available for an endpoint | Admit only when every atom that nominates a candidate agrees; any conflict refuses the edge |

The combination does not add scores for correlated snippet, token-window, and relative-context
observations. Path and region may describe or rank an already qualified edge, but cannot make a
duplicated source value reliable and cannot admit an edge by themselves. The smallest individual
variant that passes every gate is preferred over the combination.

## Predeclared scenario matrix

Every evidence variant is evaluated against the same frozen labels and these scenarios:

1. exact unchanged source and location;
2. region drift with equivalent token context;
3. whole-file and method movement with equivalent token context;
4. repeated context and the frozen one-to-many/many-to-one collisions;
5. missing baseline or candidate source file;
6. a root containing a mismatched source snapshot;
7. the baseline ingestor accidentally bound to the candidate tree;
8. the candidate ingestor accidentally bound to the baseline tree;
9. both roots swapped together;
10. same rule/message observations in different methods and files.

Missing, mismatched, and swapped-root cases must fail closed or leave findings unmatched. They are
security tests, not recall opportunities. If the two declared source trees are byte-identical, the
harness still preserves side identity; equality is recorded as content equivalence, not permission
to cross-read.

## Predetermined matching and scoring

The experiment keeps the current producer-family and canonical-rule buckets, candidate-graph
limits, connected-component construction, bounded one-to-one assignment, stable ordering, and
equal-optimum ambiguity refusal. It does not raise candidate, edge, component, or assignment limits.

Source evidence is an admission atom only under the variant's exact uniqueness rule. There is no
substring, edit-distance, semantic, or fuzzy message similarity. No producer name, PMD rule ID,
fixture path, `%SRCROOT%`, `REDACTED`, or source token is hard-coded into matching behavior. Labels
are loaded only by the post-run evaluator.

The evaluator uses full natural selectors rather than result indices:

- **TP:** one accepted pair equals one labelled relationship;
- **FP:** an accepted pair is not labelled, reuses an endpoint, or pairs any endpoint in a refused
  ambiguity group;
- **FN:** a labelled relationship is not accepted;
- classification accuracy, new/resolved accuracy, ambiguity refusal, ingestion failure, structural
  failure, source-side leakage, root confusion, and containment regression are reported separately.

Precision, recall, and F1 are reported with exact TP/FP/FN. A zero-accepted-pair result may display
precision `1.0` by the existing convention, but must also display the zero denominator and cannot
pass the recall gate.

The clean-PMD precision and recall universe is the 19 frozen relationships in the two research
families. The aggregate holdout universe remains the original frozen 75 real-producer
relationships; it is not replaced or relabelled by the research corpus. The contaminated legacy
PMD source roots are withheld, so the aggregate run may use no source-backed PMD evidence from
them. Existing Semgrep and Gitleaks inputs are rerun unchanged to detect regression. Development
corpus, resource, security, and byte-determinism suites are separate mandatory gates.

## Fixed safety gates

Thresholds are fixed before any result is observed and will not be lowered or reinterpreted:

- PMD precision >= `0.95`;
- PMD recall >= `0.80`;
- aggregate holdout precision >= `0.95`;
- aggregate holdout recall >= `0.90`;
- zero labelled ambiguity silently matched;
- zero source-side leakage;
- zero containment or security regression;
- development corpus remains green;
- existing Semgrep and Gitleaks results do not regress;
- project-owned outputs remain byte-identical across Windows and Linux;
- documented resource budgets remain within their existing limits.

Every gate must pass on the exact proposed product head before matcher v4 can exist. Passing only
the clean corpus, or passing through corpus-specific source-tree hashes that a general caller cannot
supply, is insufficient.

## Stop conditions

Stop the experiment and do not ship when any of the following occurs:

- precision is below `0.95`;
- any labelled ambiguity is automatically paired;
- source contamination is required to obtain the result;
- baseline and candidate roots are confused;
- path or repository security is weakened;
- the feature depends on PMD-specific behavior, constants, or rules;
- the candidate graph becomes unbounded or an existing graph limit is increased;
- recall gains depend on fuzzy message matching.

Also stop on unexplained ingestion/structural failure or non-deterministic output. Do not remove a
difficult case, change a label, tune a radius after seeing results, count one correlated observation
multiple times, or silently choose an equal optimum.

## Consequences

If every gate passes, a separate implementation may introduce side-specific contexts, advance the
matcher to `sarifregress/matcher/v4`, version affected evidence algorithms, and regenerate complete
reports and deltas. That decision requires hosted exact-head Ubuntu and Windows evidence; this ADR
does not claim it.

If any gate fails, matcher v4 is not created. The experiment and failure evidence are preserved,
and documentation will state the supported evidence profile and this unsupported SARIF-only
profile: no reliable fingerprints, no embedded snippets, no trustworthy source snapshots, and
non-unique rule/path/message/location observations. A safe limitation is the required outcome in
that case.
