# Real-producer generalisation

## Outcome

Matcher v3.2 retains matcher v3's general Semgrep ingestion and repeated-context Gitleaks fixes,
retains v3.1's correction for the five exposed-holdout Gitleaks classification mismatches, and
closes two unsafe weak-evidence admission paths. The first side-specific source-context experiment
reached `9 TP / 0 FP / 10 FN`; that safe stop is preserved below as historical evidence.

The current preview candidate adds a separately versioned, opt-in
`trusted-filename-lexical-context/v1` adapter without creating matcher v4. Independent raw-byte
manifests and retained per-side root capabilities close the original snapshot-safety gaps. On the
predeclared controlled clean PMD corpus, the filename-bound profile produces `18 TP / 0 FP / 1 FN`
(precision `1.0`, recall `0.947368`) and auto-matches no labelled ambiguity. The frozen legacy PMD
oracle remains formally unsatisfiable without an unsafe order/cardinality rule; ADR 0004 records
the proof.

Stable release policy remains:

```json
{
  "releaseRecommendation": "blocked"
}
```

The following table records the historical stacked implementation lineage; PR #32 has since merged
that history to `main`:

| Item | Value |
|---|---|
| Validation base | `0231d6fe779203a92469099b90d446fafe67b064` |
| Base branch | `agent/independent-holdout-validation` |
| Implementation branch | `agent/holdout-generalization-fixes` |
| Historical matcher-v3 implementation | `29ea23e0e9b0b85269d3eaaa52ccf3c7a91da30b` |
| Historical matcher-v3 source-tree SHA-256 | `4a6b69ed50a96334fbcf949eda7a044d14f4d9c7405e7641567ff84d604f6486` |
| Evaluated matcher-v3.1 implementation | `863210dfda02690b0d9ee579f5d7fd7a45545b1e` |
| Matcher-v3.1 source-tree SHA-256 | `fa14cb54282345aa2cc16e4a931d79ba651282f4b3355dc09df51fa05212694f` |
| Matcher-v3.2 branch | `agent/nightly-release-hardening` |
| Matcher-v3.2 evidence state | Normal exact-head verification succeeded |
| Authenticated sparse-evidence source head | `4cc6faf0167d7da385c1d204cba97d1f34ccb479` |
| Stage-two promotion source head | `ac081e70ab2911c02bafffce5661eaec76a871fa` |
| Normal verification source head | `d880bd0a0495650a34ae2faa8521f170af80d7a9` |
| Composite-evidence support head | `4838532f5e808f97bf8804b772d153d294181aee` |
| Matcher | `sarifregress/matcher/v3.2` |
| Product output/configuration schemas | `1` / `1` |
| Holdout manifest SHA-256 | `b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379` |

The holdout labels, source transformations, difficult cases, Microsoft SARIF Multitool pin, and
quality thresholds are byte-unchanged. Matcher v2's first run is the independent baseline. Once
those labels informed implementation, v3, v3.1, and v3.2 became exposed-holdout regression evidence, not
new independent validation. The original v2 reports remain under
`validation/history/matcher-v2/`; matcher-v3 and v3.1 records are preserved separately with
deterministic deltas. The
[machine-readable interpretation erratum](../validation/holdout/interpretation-erratum.json)
hash-binds those legacy labels to this corrected interpretation without rewriting either report.

## Original matcher-v2 failures

The frozen MVP accepted none of the 75 known identity relationships:

| Producer | TP | FP | FN | Precision | Recall | F1 | Primary failure |
|---|---:|---:|---:|---:|---:|---:|---|
| Gitleaks 8.30.1 | 0 | 0 | 25 | 1.000000 | 0.000000 | 0.000000 | Repeated context formed one oversized component |
| PMD 7.26.0 | 0 | 0 | 25 | 1.000000 | 0.000000 | No admissible fingerprint or context evidence |
| Semgrep 1.172.0 | 0 | 0 | 25 | 1.000000 | 0.000000 | Two inputs failed on an undefined external URI base |
| **Aggregate** | **0** | **0** | **75** | **1.000000** | **0.000000** | **0.000000** | Release blocked |

Precision was vacuously 1.0 because v2 accepted zero matches. Gitleaks produced
60 ambiguous endpoint classifications, Semgrep produced 58 `CANON0032`
diagnostics, and PMD produced 30 new plus 30 resolved classifications. These
facts remain reproducible at the exact PR #8 head and are not rewritten by v3.

## Phase 1: explicit external URI bases

### Design

`uriBaseMappings` is an explicit, bounded configuration overlay for a
logical base referenced by SARIF but absent from `run.originalUriBaseIds`.
For example:

```json
{
  "schemaVersion": "1",
  "uriBaseMappings": [
    {
      "id": "WORKSPACE_ROOT",
      "uri": "repo:/"
    }
  ]
}
```

A SARIF-defined base always wins. Configuration fills only a missing
definition; it cannot silently replace producer data. Unknown bases remain an
error. Configured definitions may chain through `uriBaseId`, with the same
cycle detection and maximum depth of 32 used for SARIF definitions.

Targets are limited to directory-form repository roots, local POSIX or
drive-absolute roots, hostless local `file:` roots, or safe relative children
of another configured base. Network/UNC roots, authorities, queries,
fragments, traversal, control characters, and non-directory targets fail
closed. Resolution is lexical and never performs a network fetch. Optional
source reads still pass through the independent repository-containment and
symlink/junction checks.

Successful use records a `configured-uri-base` transformation with
`sarifregress/configured-uri-base/v1`. It records the logical identifier but
not the raw configured target, keeping equivalent local-root reports
platform-neutral. The mechanism contains no producer name or well-known
identifier.

### Result

Both authentic Semgrep inputs ingest. `CANON0032` falls from 58 to 0, all 25
known relationships match, both deliberate ambiguity units are refused, and
the three new and three resolved labels remain correct. An unrelated logical
identifier exercises the same path in tests.

## Phase 2: collision-aware contextual evidence

### Alternatives considered

1. **Occurrence-aware reliability — selected.** Context and derived
   fingerprint values are counted independently on each input side within the
   automatic producer-identity and canonical-rule bucket. A value is reliable
   only when it occurs once on both sides. Counts are based on distinct
   findings, not repeated fields within one finding.
2. **Indisputable-edge peeling — not used as the primary rule.** Resolving
   exact-path edges before building the complete graph would recover some
   diagonals, but by itself it leaves the invalid dense weak graph in place
   and risks making the result depend on the order in which edges are peeled.
   The existing global one-to-one solver therefore remains authoritative.
3. **Graph decomposition by evidence tier — combined with occurrence
   reliability.** Collision-only context is degraded before graph union.
   Cross-path collision-only edges are refused, so weak shared values cannot
   merge components that stronger identity and path evidence keep separate.
   This fixes graph quality without raising the exact-assignment size limit.

### Evidence policy

- A unique derived fingerprint or unique exact context retains its existing
  strong tier.
- A duplicated derived fingerprint is admissible only with an exact or
  explicitly aliased path.
- Duplicated raw context requires an explicit path alias, or an exact path
  plus a compatible canonical message.
- Region proximity cannot manufacture a preferred pairing inside a collision
  set.
- Collision evidence is emitted with
  `sarifregress/evidence-occurrence/v1`; context comparison is
  `sarifregress/context-evidence/v2`.
- Candidate-pair, retained-edge, assignment-component, and explanation limits
  are unchanged and still enforced.

No literal snippet, producer, scanner category, rule ID, or component size is
special-cased.

### Result

The authentic Gitleaks case now preserves all 25 identity pairs with no false
matches. Its two 2×2 ambiguity units remain ambiguous, and the six labelled
lifecycle findings are correct. The original repeated context is visible as
degraded collision evidence rather than being treated as a unique identity.
The exact 13×13 reproduction and a 30×30 repeated-context test remain bounded
and input-order invariant.

In the matcher-v3 result, five accepted Gitleaks pairs still have a classification mismatch
(`gitleaks-match-014` through `-018`). Their identity is correct, so they
are true-positive correspondence edges, but the complete label graph gate
remains failed and the mismatches stay visible in that frozen report. Matcher v3.1's later general
classification correction resolves all five without changing correspondence or labels.

## Phase 3: sparse SARIF safe stop

Three producer-agnostic options were evaluated before changing matching code.
The full evidence is in
[ADR 0002](decisions/0002-sparse-sarif-continuity.md).

### Option A: unique exact-location signature

The proposed signature combined producer family, canonical rule, canonical
repository-relative path, exact region, and canonical message, requiring
uniqueness on both sides. On the authentic PMD case it admitted ten
intersections: five true pairs, three false cross-pairs, and two intersection
pairs covering all four deliberate ambiguity endpoints.

The hypothetical result was `5 TP / 5 FP / 20 FN`, precision `0.5`,
recall `0.2`, with labelled ambiguity silently paired. Whole-bucket
uniqueness avoided false matches but recovered zero relationships. Both
variants fail the selection rule.

### Option B: separate baseline and candidate repositories

At the time of this historical experiment, side-specific read-only source roots were only a
plausible future design, and
the current holdout snapshots contain adjacent semantic identity markers used
to construct ground truth. Deriving source context from those files would
leak labels into the matcher. Removing those markers or changing labels would
invalidate the holdout. No CLI or configuration option was added in that experiment.

Any future implementation must preserve shared-`--repo` compatibility,
bind every source read to its correct side, and independently enforce
containment, regular-file, symlink/junction, size, and encoding rules.

### Option C: combination

The combination inherits Option A's false matches and Option B's validation
leakage. It was rejected.

### Decision

No sparse-continuity tier was added at this historical stage. PMD remained unmatched. This was the
required stop condition: a safe partial improvement
is preferable to a rule below 0.95 precision or one that silently resolves
ambiguity.

### Clean side-specific repository-context experiment

ADR 0003 subsequently evaluated Option B without using the marker-bearing legacy PMD sources. Two
separately designed clean PMD families were frozen before their first scored run. They contain 19
relationships, three new findings, three resolved findings, and three ambiguity groups covering
nine endpoints. This is controlled research designed after the legacy failure was known, not a
second independent holdout.

| Variant | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| SARIF-only control | 0 | 0 | 19 | `1.0` by empty-acceptance convention | `0` | `0` |
| Exact-region snippet | 2 | 0 | 17 | `1.0` | `0.105263` | `0.190476` |
| Token window | 4 | 0 | 15 | `1.0` | `0.210526` | `0.347826` |
| Relative context | 9 | 0 | 10 | `1.0` | `0.473684` | `0.642857` |
| Agreement-only combination | 9 | 0 | 10 | `1.0` | `0.473684` | `0.642857` |

All labelled ambiguity remained refused, and ingestion and structural failures were zero. However,
all source-backed variants failed all three no-trusted-hash wrong-root scenarios. The tied best
variants also failed family B's no-trusted-hash mismatched-snapshot scenario. Source preflight and
later reads did not share one immutable snapshot handle, physical-root identity was not proved, and
source projection was not benchmarked.

The clean 19-relationship universe cannot replace the frozen 75-relationship holdout. Historical
aggregate recall therefore remains `0.666667`, and best clean-PMD recall is `0.473684`; both miss
their fixed gates. At that evidence head, separate repository roots remained validation-only
research and no matcher-v4 implementation or product option was added. The later preview adapter
and ADR 0004 supersede only that product-implementation conclusion, not these frozen measurements.

## Matcher-v3 evidence hierarchy and versions

The global one-to-one assignment policy and deterministic tie refusal remain
unchanged. Candidate edges are ranked through these explainable tiers:

1. explicit override with real path and reliable context;
2. unique, version-compatible producer fingerprint;
3. exact path plus unique derived fingerprint;
4. unique reliable context, including moved-path continuity;
5. compatible supporting evidence for a path problem;
6. collision-degraded context constrained by exact or explicit alias paths;
7. optional weak message evidence only when explicitly enabled;
8. refusal when no admissible tier exists or equal optima remain.

Version changes are:

| Contract | Matcher v2 | Matcher v3 |
|---|---|---|
| Matcher | `sarifregress/matcher/v2` | `sarifregress/matcher/v3` |
| Derived fingerprint generator | `rule-path-context/v2` | unchanged |
| Derived comparison | `sarifregress/derived-fingerprint-compare/v1` | `sarifregress/derived-fingerprint-compare/v2` |
| Context evidence | prior matcher semantics | `sarifregress/context-evidence/v2` |
| Occurrence explanation | absent | `sarifregress/evidence-occurrence/v1` |
| Configured URI-base provenance | absent | `sarifregress/configured-uri-base/v1` |

Product configuration and output schemas remain version 1 because their
readers remain backward compatible and no existing output field changed
meaning. The validation-only SarifRegress report and comparison summary
advance to schema 2; the deterministic delta and attestation use schemas 1
and 2 respectively.

## Matcher-v3 results

| Producer | TP | FP | FN | Precision | Recall | F1 | Other result |
|---|---:|---:|---:|---:|---:|---:|---|
| Gitleaks 8.30.1 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 2 correct ambiguity refusals; 5 classification mismatches |
| PMD 7.26.0 | 0 | 0 | 25 | 1.000000 | 0.000000 | 0.000000 | No sparse tier; 2 ambiguity units remain unmatched |
| Semgrep 1.172.0 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 ingestion failures; 2 correct ambiguity refusals |
| **Aggregate** | **50** | **0** | **25** | **1.000000** | **0.666667** | **0.800000** | Release blocked |

Additional gates:

| Measure | Matcher v2 | Matcher v3 |
|---|---:|---:|
| Correct new labels | 3 / 9 | 9 / 9 |
| Correct resolved labels | 3 / 9 | 9 / 9 |
| Correct ambiguity refusals | 2 | 4 |
| Unexpected ambiguity refusals | 25 | 0 |
| Incorrect ambiguity auto-matches | 0 | 0 |
| Ingestion failures | 2 | 0 |
| Structural failures | 0 | 0 |
| Classification mismatches | 0 accepted pairs | 5 |

The delta records 59 fixed ground-truth relationships, 0 regressed
relationships, 32 still failing relationships, and 0 newly introduced false
matches. All 64 changed decisions have bounded explanation traces.

## Matcher-v3.1 classification correction

The frozen matcher-v3 record above remains unchanged. A subsequent
post-correspondence audit proved that `gitleaks-match-014` through `-018` are
unchanged one-finding files moved through the configured
`src/renamed-old/` to `src/renamed-new/` alias: each baseline/candidate source
pair is byte-identical, while Gitleaks embeds the changed repository-relative
path in its otherwise identical canonical message.

Matcher v3.1 corrects only that general classification boundary. It requires an
already accepted, explicitly aliased edge; one unique, delimited occurrence of
each side's own full repository-relative path; and byte-identical canonical
message prefix and suffix. Extra message text, repeated tokens, embedded path
prefixes, path continuations, context changes, and code-flow changes remain
`modified`. The classifier cannot affect candidate admission, scoring,
assignment, or ambiguity.

Each use adds a bounded hashed
`classification-message-location-template` transformation under
`sarifregress/message-location-template/v1`. Matcher v3.1 therefore preserves
the correspondence metrics (`50 TP / 0 FP / 25 FN`) while reducing the five
known Gitleaks classification mismatches to zero. The exact case-level evidence
is in
[`validation/research/gitleaks-classification/analysis.json`](../validation/research/gitleaks-classification/analysis.json).
The later clean sparse-SARIF experiment failed its fixed gates, so matcher v4 was not created.

## Matcher-v3.2 admission safety correction

The adversarial review found two independent precision risks after v3.1 evidence was frozen.
Collided snippet or token context could still admit an edge even when another available context
representation contradicted it, and a shared code-flow anchor could act as primary identity. Matcher
v3.2 applies general, producer-neutral corrections without changing holdout labels, thresholds, or
resource limits:

- any context conflict vetoes collision-only and weak-message admission;
- code-flow evidence cannot admit an edge;
- a shared code-flow anchor can rank an already admissible edge only when the same path/context
  anchor occurs in exactly one finding on each input side within its automatic-producer/rule bucket;
- repeated anchors produce one bounded finding-local degradation record under
  `sarifregress/code-flow-occurrence/v1`; and
- equal-optimum ambiguity remains refused by the unchanged assignment layer.

The active comparison summary advances to schema version `4` because v3.2 replaces the v3 report
hash fields with v3.1 and v3.1-to-v3.2 delta hashes. Frozen v3.1 schema-3 bytes remain under
`validation/history/matcher-v3.1/`. The interpretation erratum now hash-binds the exact v3.2 report
generated on source head `4cc6faf0167d7da385c1d204cba97d1f34ccb479`. Stage-two run `30762486314`
on `ac081e70ab2911c02bafffce5661eaec76a871fa` reproduced seven normalized files byte-identically
across Ubuntu and Windows, promoted only the resulting comparison and checksum binding, and then
stopped at the deliberate final-promotion refusal. Neither bootstrap artifact is release evidence.

## External baseline

Microsoft SARIF Multitool remains pinned at 5.5.0 and is not ground truth.
Across 72 comparable identity relationships it remains
`47 TP / 17 FP / 25 FN`, precision `0.734375`, recall `0.652778`,
and F1 `0.691177`.

Across all 99 units, the v3 comparison classifies 48 as both correct, 18 as
SarifRegress-only correct, 11 as Multitool-only correct, 13 as both
incorrect, and 9 as non-comparable. The external baseline was not retuned or
used to select matcher behavior.

## Determinism, resources, and security

The first hosted run produced identical unattested report bytes on Ubuntu and
Windows. Its fixed attestation is
[run 30698849989](https://github.com/ppcdaniel/sarif-regress/actions/runs/30698849989).
An attested regeneration then reproduced the same base reports and identical
final project-owned bytes on both systems in
[run 30699075579](https://github.com/ppcdaniel/sarif-regress/actions/runs/30699075579).
The attestation from the first run is retained to avoid a self-referential
hash cycle.

Matcher-v3 checkpoint benchmarks passed the 10,000 and 100,000 unique and
pathological datasets on hosted Ubuntu and Windows, including deterministic
byte comparison, in
[run 30698849978](https://github.com/ppcdaniel/sarif-regress/actions/runs/30698849978).
The 1,000-finding resource smoke remains part of normal CI. No assignment,
candidate-pair, retained-edge, repository-containment, or source-read ceiling
was increased.

The earlier sparse experiment role artifacts were bound to source head
`4cc6faf0167d7da385c1d204cba97d1f34ccb479`: CI run `30761620627` succeeded; holdout/sparse run
`30761620623`, determinism run `30761620626`, and resource run `30761620637` generated authenticated
promotion candidates. Their coordinators authenticated exact artifact
IDs, names, archive digests, run IDs, and heads, then reproduced the release, determinism, and
stable resource projection bytes. The candidate workflows failed only at the expected stale
committed-projection comparison or the deliberate promotion refusal. This is not the composite
cross-binding tracked by #27. The 1k/10k/100k resource matrix passed for the SARIF-only matcher, but
it did not execute source-context projection; that production gate remains unproved.

On stage-two promotion head `ac081e70ab2911c02bafffce5661eaec76a871fa`, CI run `30762486272`,
determinism run `30762486305`, and benchmark run `30762486292` succeeded. Holdout run `30762486314`
passed every product, capture, sparse, schema, and coordinator job and concluded `failure` only at
its deliberate final-refusal job. The coordinator artifact was authenticated before the two
promotable files were accepted.

On normal verification head `d880bd0a0495650a34ae2faa8521f170af80d7a9`, CI run `30763347889`,
holdout/sparse run `30763347894`, determinism run `30763347908`, and benchmark run `30763347910`
all succeeded. Each hosted OS passed 545 tests in CI; the holdout coordinator selected `normal`,
authenticated its inputs, reproduced committed reports and sparse projections byte-for-byte, and
emitted a success attestation. All twelve 1k/10k/100k benchmark cells passed without changing a
budget or product limit.

The final composite support roles share source head
`4838532f5e808f97bf8804b772d153d294181aee`: holdout run `31638319042`, determinism run
`31638319041`, and benchmark run `31638349628` all succeeded. Compositor run `31638669221`
authenticated their workflow paths, heads, conclusions, artifact identities, archive digests, and
complete coordinator manifests. Its candidate artifact `9157965667` has archive digest
`48bfb81237357c80e3d42a4913ecb256b913675a6da767a0966fecc8c50f18b5`; the promoted deterministic
bundle cross-binds the complete semantic release and determinism projections and derives its stable
resource projection from all twelve authenticated runtime cells.

Configured bases remain local, lexical, non-fetching, and fail closed.
Occurrence indexing is bounded by the already ingested findings and stores
only per-bucket evidence identities and counts. It does not execute producer
code, inspect secret values semantically, or use machine learning.

## Release decision and remaining limitations

The fixed aggregate thresholds are precision at least 0.95 and recall at
least 0.90; each producer requires precision at least 0.95 and recall at
least 0.80. The bound matcher v3.2 report passes every precision, classification, ambiguity,
ingestion, structural, trace, and determinism condition, but fails aggregate
recall, PMD recall, and the complete label graph. The recommendation therefore
remains `blocked`.

Remaining failures are exactly:

- 25 PMD missed identity relationships; and
- two PMD ambiguity units that remain unmatched rather than being silently
  paired.

The first clean experiment reached `9 TP / 0 FP / 10 FN`. A later predeclared design closes its
snapshot-safety gaps with independent raw-byte manifests, retained physical root handles,
immutable bounded caches, and comment-blind filename/lexical identity. It reaches `18 TP / 0 FP /
1 FN`, precision `1.0`, recall `0.947368`, with zero labelled ambiguity auto-matched. The remaining
relationship renames its filename and type and is deliberately refused.

That result cannot repair the frozen legacy oracle. Its repeated 2-by-2 ambiguity and five 5-by-5
relationship groups are equal-evidence complete bipartite graphs. Safe uniqueness yields 0/25;
source-order pairing yields 25 TP and 2 FP and silently matches the deliberate ambiguity. ADR 0004
records why issue #12's stable gates are unsatisfiable without a forbidden corpus-specific rule.
The authenticated compositor closes issue #27's derivation gap while preserving the
`document-limitation` decision. The exact same-head candidate is promoted and accepted by the
strict scanner; this provenance result changes neither the failed scientific gates nor the stable
channel decision.

Supported automatic evidence requires a reliable non-colliding fingerprint; reliable embedded
context or bounded token context from the current shared root; a manifest-verified non-colliding
filename/lexical atom from explicit side roots; or safe URI-base resolution combined with another
qualifying identity signal. Explicit aliases still require qualifying path/context.
The unsupported profile has no reliable fingerprint, no embedded snippet, no trusted source
snapshot, and only non-unique rule/path/message/location evidence.

The holdout is one controlled case per producer, not an ecosystem-wide
sample. Producer capture remains Linux-only, while evaluation of committed
SARIF is cross-platform. The suite measures finding continuity, not analyzer
detection quality.

## Reproduction

From any directory on Linux:

```sh
/path/to/sarif-regress/scripts/verify.sh
/path/to/sarif-regress/scripts/validate-holdout.sh
```

From hosted Windows PowerShell:

```powershell
& C:\path\to\sarif-regress\scripts\verify.ps1
& C:\path\to\sarif-regress\scripts\validate-holdout.ps1
```

The wrappers restore locked dependencies, verify the exact Multitool package,
validate provenance and schemas, regenerate reports in a temporary directory,
and byte-compare them with `validation/expected/`. They do not modify
committed fixtures.

Run the remaining commands from the repository root.

The matcher-v2, matcher-v3, and matcher-v3.1 history anchors can be checked without running
the analyzers:

```sh
sha256sum -c validation/history/matcher-v2/checksums.sha256
sha256sum -c validation/history/matcher-v3/checksums.sha256
sha256sum -c validation/history/matcher-v3.1/checksums.sha256
```

Clean sparse admission and the preserved limitation evidence can be checked with:

```sh
python3 -B validation/research/sparse-sarif/tools/test_scan_contamination.py
python3 -B validation/research/sparse-sarif/tools/scan_contamination.py \
  --research-root validation/research/sparse-sarif
(
  cd validation/research/sparse-sarif/expected
  sha256sum -c checksums.sha256
)
```

See `validation/research/sparse-sarif/README.md` for label-neutral execution and post-run scoring.
The checked-in schema-version-2 `expected/experiment-report.json` is the authenticated composite
decision record. It records `document-limitation` with no selected variant and does not authorize
matcher v4.

Extended deterministic datasets use:

```sh
sarif-regress bench --size 10000 --dataset unique --enforce-budgets
sarif-regress bench --size 10000 --dataset pathological --enforce-budgets
sarif-regress bench --size 100000 --dataset unique --enforce-budgets
sarif-regress bench --size 100000 --dataset pathological --enforce-budgets
```
