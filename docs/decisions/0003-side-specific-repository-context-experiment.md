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

Each hosted supporting-evidence role also requires one role-level coordinator projection and its
SHA-256. The projection is a closed, role-specific JSON document containing the admitted corpus
and implementation hashes and the complete ordered five-variant semantic payload. The scanner
reads and hashes those bytes and requires the payload to equal the supporting document; a missing
reference, digest mismatch, different role, partial payload, or unrelated hash-valid file fails the
role. One projection per role avoids a large collection of per-value attestations while binding
every claimed value to coordinator output. Workflow run/head/artifact identities remain in the
wrapper rather than the projection, because artifact IDs and digests do not exist until upload and
would otherwise make a coordinator projection self-referential and unstable across strict reruns.

This local binding is necessary but is not a signature: a repository editor could replace a
projection and its digest together. Final evidence therefore additionally requires an
authenticated exact-head coordinator to verify the listed GitHub artifact IDs, names, and digests,
byte-compare the platform outputs, emit the role projection, and compare its bytes with the
committed projection. Connector-confirmed workflow success and artifact identity close that
external trust step; the repository-only scanner does not claim to authenticate GitHub.

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

The extraction algorithms and their bounds are fixed before the first scored run:

- `exact-region-snippet/v1` removes an optional UTF-8 BOM, rejects invalid UTF-8, normalises CRLF
  and CR to LF, and interprets SARIF columns as one-based UTF-16 code-unit offsets with an exclusive
  `endColumn`. A tab occupies one code unit; it is not expanded. Multiline regions contain the
  suffix of the first line, complete intervening lines, and prefix of the final line joined by LF.
  A missing, inverted, or out-of-range coordinate makes the atom unavailable. The extracted text
  is normalised to Unicode NFC and hashed without trimming whitespace.
- `token-window/v1` is the existing language-agnostic canonicaliser, unchanged: identifier terms
  contain ASCII letters/digits, underscore, or any UTF-16 code unit at or above `U+0080`; other
  non-whitespace ASCII code units are individual terms. This deliberately describes the existing
  code-unit behavior, including non-ASCII punctuation and surrogate halves, rather than claiming
  Unicode-category tokenisation. The complete region must fit within
  `maximumTokenWindowTerms = 256`. The remaining budget
  is divided before/after as the existing algorithm specifies. Overlong terms or regions refuse
  the atom rather than truncating it.
- `relative-context/v1` uses the same tokenizer over a fixed 20-line radius but preserves three
  domain-separated sequences: the nearest 32 terms before the region within that bounded snippet,
  at most 256 complete terms inside it, and the nearest 32 terms after it within the snippet. Each
  sequence and then the ordered tuple are hashed separately. Missing context is represented by an
  empty sequence, not by omitting a tuple member; an overlong term or region makes the whole atom
  unavailable.
- `agreement-only-combination/v1` considers only atoms that are exact and occur once in the
  producer-family/canonical-rule bucket on each side. At least one reliable atom must nominate a
  candidate. Every other reliable atom available for either endpoint must nominate the same
  candidate; a conflict or one-sided nomination refuses the edge. Correlated atoms are not scored
  or counted more than once.

All versioned hashes use ordinal UTF-8 inputs with an explicit algorithm-domain prefix and length
separation. No path, rule, message, producer, or fixture-specific constant is added to a source
atom. Source reads and evidence extraction are completed before labels are opened.

| Variant | Algorithm version | Evidence under test | Edge rule |
|---|---|---|---|
| `sarif-only-control` | `sarifregress/sparse-control/v1` | Existing SARIF evidence only | No new source-backed edge |
| `exact-region-snippet` | `exact-region-snippet/v1` | Hash of the normalised source text covered by the exact SARIF region | Admit only when the value occurs exactly once on each side of the producer/rule bucket |
| `token-window` | `token-window/v1` | Existing bounded token-window hash around the region | Admit only for exact, one-per-side occurrence |
| `relative-context` | `relative-context/v1` | Separate exact hashes for bounded tokens before, inside, and after the region | Admit only when the complete tuple is unique on both sides |
| `agreement-only-combination` | `agreement-only-combination/v1` | All reliable atoms available for an endpoint | Admit only when every atom that nominates a candidate agrees; any conflict refuses the edge |

The combination does not add scores for correlated snippet, token-window, and relative-context
observations. Path and region may describe or rank an already qualified edge, but cannot make a
duplicated source value reliable and cannot admit an edge by themselves. The smallest individual
variant that passes every gate is preferred over the combination.

The observation schema pre-registers these exact versions and parameters. The control has
`requireUniqueOnBothSides = false`; all source variants set it to true. Only the combination sets
`agreementOnly = true`. The token limit is exactly 256, the relative-context radius is exactly 20
lines, and the surrounding/region limits are exactly 32/256 terms. A changed version, radius,
limit, or flag invalidates the experiment before labels are opened.

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

Scenarios 1 through 4 and 10 are evaluated over the complete two-family run; the evaluator selects
their relationship or negative-control subsets only after the label-neutral observation file is
closed. Scenario 1 covers the five `unchanged` relationships. Scenario 2 covers the four
`line-shift`/`region-drift` transformations. Scenario 3 covers the remaining ten labelled moved
relationships. Scenario 4 covers all three ambiguity groups and all nine endpoints. Scenario 10
passes only when the full-run false-positive inventory contains no unlabelled cross-method or
cross-file pair; it never narrows the matcher bucket before matching.

Scenarios 5 through 9 rerun both families from deterministic temporary trees. Scenario 5 removes
the source file selected by the first ordinal SARIF natural selector on the affected side.
Scenario 6 appends one LF byte to that file while retaining the SARIF, producing a different
source-tree hash without adding any token or matcher evidence. Scenarios 7 and 8 bind exactly one
logical ingestor to the opposite admitted tree, and scenario 9 swaps both. Results are recorded per
family and then aggregated; no single boolean may conceal one family's failure. Each family record
also carries the exact naturally selected affected baseline/candidate endpoints. Post-label gate
evidence separately counts accepted pairs that touch those endpoints, so unrelated safe matches do
not make a missing or mismatched source-file scenario fail. The same five
variants are also rerun without trusted source-tree hashes to determine whether safety depends on
the corpus-only preflight.

The two modes have deliberately different assertions. In trusted-tree mode, scenarios 5 through 9
must be rejected by preflight before either side can ingest source. In production-applicability
mode, no trusted hash exists, so preflight acceptance is expected; safety is judged from actual
side-specific read counters, containment outcomes, ingestion/structural facts, and accepted pairs
touching the naturally selected affected endpoints. Unrelated SARIF-only matches do not turn a
missing or mismatched file into a root-confusion failure, and a no-source control does not claim
that an accepted preflight proves repository-context safety.

Missing, mismatched, and swapped-root cases must fail closed or leave findings unmatched. They are
security tests, not recall opportunities. If the two declared source trees are byte-identical, the
harness still preserves side identity; equality is recorded as content equivalence, not permission
to cross-read.

These scenarios establish only bounded research claims. The source-tree preflight and later
per-finding source extraction perform separate handle-anchored reads, so a concurrent mutation can
make the recorded tree digest describe bytes other than those used to derive an atom. The missing
and mismatched scenarios also alter the naturally selected file on both sides in one run; they do
not prove that a one-sided fallback defect would be detected. Finally, opposite-root counters
compare canonical lexical roots and cover the declared swap matrix, but do not establish physical
identity across bind mounts or other filesystem aliases. Immutable snapshot handles, independent
baseline-only and candidate-only mutations, and stable opened-root identities are therefore
production blockers even if the clean-corpus metrics pass.

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

The aggregate gate has a deliberate, non-substitutable universe. Matcher v3.1 has `50 TP / 0 FP /
25 FN` across the original 75 relationships, so recall is `0.666667`. Recall `>= 0.90` requires at
least 68 true positives: 18 safe recoveries from the legacy PMD relationships. Those PMD source
snapshots are withheld because they contain identity markers. Even a perfect `19/19` clean-corpus
result cannot be inserted into or substituted for the original holdout. Unless a separate,
contamination-free validation establishes those legacy-universe recoveries, every Phase 4 variant
fails the aggregate recall gate and matcher v4 must not be created.

The existing 1k/10k/100k matcher benchmark cells do not execute source-context extraction or its
occurrence indexes. They remain relevant to the SARIF-only control but cannot establish a source
variant's resource gate. Each source variant therefore records
`sourceContextProjectionBenchmarked`; it is false/unproven in this experiment unless a separately
bounded source-projection benchmark is executed. Green generic matcher cells cannot promote that
field or authorize matcher v4.

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

A limitation report uses schema version 2, binds the label-neutral observations, independently
scored gate evidence, and the exact implementation manifest, and sets `selectedVariant` to null.
The observation artifact contains natural selectors for accepted pairs, new/resolved findings,
ambiguity endpoints, and each family's scenario outcomes, but contains no label IDs. Only after
those bytes are closed does the evaluator read labels and emit full correspondence metrics,
classification mismatches, correct/missed/incorrect new and resolved counts, ambiguity refusal,
ingestion, security, and affected-endpoint scenario facts. The report must equal that scored
evidence; a digest-only or self-asserted projection is insufficient.
Release, determinism, and resource projections are accepted only inside typed committed
attestations that bind the corpus and implementation-manifest hashes and record one shared source
head. Each attestation contains an ordered `workflow.artifacts` array of exact artifact names,
distinct nonzero IDs, and nonzero archive digests. Release and determinism each bind their two
platform artifacts and coordinator artifact. Resource evidence binds all twelve
`1k/10k/100k x unique/pathological x Linux/Windows` matrix artifacts plus the cross-platform
coordinator; a single per-platform artifact cannot stand in for that matrix. The scanner validates
this structure and the role semantics but cannot authenticate GitHub's artifact service; those
fields may be populated only from connector-confirmed successful runs, and final strict
reproduction remains an external trust-boundary check.

The implementation manifest is not a hand-picked source list. It is the exact ordinal closure of
all `.cs`, `.csproj`, and `packages.lock.json` files below the CLI, Core, Match, Report, SARIF, and
validation-harness projects, plus `Directory.Build.props`, `Directory.Packages.props`, and
`global.json`. The scanner independently enumerates that set, rejects missing or extra entries,
and re-hashes every regular file through a contained handle. POSIX reads use the anchored
directory-descriptor path; the Windows fallback rejects every reparse component and confirms the
opened handle remains below the admitted repository root before and after the bounded read.

The integrity graph is acyclic: observations bind the corpus and implementation manifest; scored
gates bind the exact observations bytes; each supporting attestation binds the corpus and
implementation manifest; and the report references those already-closed artifacts. None of those
artifacts embeds the report hash or the expected-output checksum manifest that later covers it.
It may name a best-observed research variant in prose, but that is not a shipping selection. The
machine-readable reasons must include at least one failure recomputed from bound evidence. Report
precision for zero accepted pairs is exactly `1.0` under the existing convention, while an explicit
`acceptedPairs = TP + FP` denominator prevents that convention from being presented as evidence of
successful matching. No global boolean can authorize matcher v4; each required evidence role must
have its own parser and cross-reference validator, including a future product-implementation role
that this research-only ADR intentionally does not provide.
