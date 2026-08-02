# Real-producer generalisation

## Outcome

Matcher v3.1 retains matcher v3's general Semgrep ingestion and repeated-context Gitleaks fixes and
corrects the five exposed-holdout Gitleaks classification mismatches. It does not add a
sparse-SARIF continuity rule for PMD. A clean side-specific source-context experiment reached only
`9 TP / 0 FP / 10 FN` and failed the fixed recall and production-safety gates, so matcher v4 was
not created.

The release recommendation remains:

```json
{
  "releaseRecommendation": "blocked"
}
```

The implementation is stacked on the still-open independent-validation PR:

| Item | Value |
|---|---|
| Validation base | `0231d6fe779203a92469099b90d446fafe67b064` |
| Base branch | `agent/independent-holdout-validation` |
| Implementation branch | `agent/holdout-generalization-fixes` |
| Historical matcher-v3 implementation | `29ea23e0e9b0b85269d3eaaa52ccf3c7a91da30b` |
| Historical matcher-v3 source-tree SHA-256 | `4a6b69ed50a96334fbcf949eda7a044d14f4d9c7405e7641567ff84d604f6486` |
| Evaluated matcher-v3.1 implementation | `863210dfda02690b0d9ee579f5d7fd7a45545b1e` |
| Matcher-v3.1 source-tree SHA-256 | `fa14cb54282345aa2cc16e4a931d79ba651282f4b3355dc09df51fa05212694f` |
| Authenticated sparse-evidence source head | `94c906d485f55bb1900f159caa1abd73d71ee56c` |
| Matcher | `sarifregress/matcher/v3.1` |
| Product output/configuration schemas | `1` / `1` |
| Holdout manifest SHA-256 | `b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379` |

The holdout labels, source transformations, difficult cases, Microsoft SARIF Multitool pin, and
quality thresholds are byte-unchanged. Matcher v2's first run is the independent baseline. Once
those labels informed implementation, v3 and v3.1 became exposed-holdout regression evidence, not
new independent validation. The original v2 reports remain under
`validation/history/matcher-v2/`; matcher-v3 and v3.1 records are preserved separately with
deterministic deltas.

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

Five accepted Gitleaks pairs still have a classification mismatch
(`gitleaks-match-014` through `-018`). Their identity is correct, so they
are true-positive correspondence edges, but the complete label graph gate
remains failed and the mismatches stay visible in the report.

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

Side-specific read-only source roots remain a plausible future design, but
the current holdout snapshots contain adjacent semantic identity markers used
to construct ground truth. Deriving source context from those files would
leak labels into the matcher. Removing those markers or changing labels would
invalidate the holdout. No CLI or configuration option was added.

Any future implementation must preserve shared-`--repo` compatibility,
bind every source read to its correct side, and independently enforce
containment, regular-file, symlink/junction, size, and encoding rules.

### Option C: combination

The combination inherits Option A's false matches and Option B's validation
leakage. It was rejected.

### Decision

No sparse-continuity tier was added. PMD remains unmatched and issue #11
remains open. This is the required stop condition: a safe partial improvement
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
their fixed gates. Separate repository roots remain validation-only research, issue #11 stays open,
and no matcher-v4 implementation or product option was added.

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

The later sparse experiment's original supporting artifacts are bound to source head
`94c906d485f55bb1900f159caa1abd73d71ee56c`: holdout/sparse run `30725861186`, determinism run
`30725861139`, and resource run `30725861161`. After removing volatile measurements from the stable
resource projection, exact-head runs `30727269210`, `30727269224`, and `30727269219` independently
reproduced the current release, determinism, and resource projection bytes. This is not the
composite cross-binding tracked by #27. The 1k/10k/100k resource matrix passed for the SARIF-only
matcher, but it did not execute source-context projection; that production gate remains unproved.

Configured bases remain local, lexical, non-fetching, and fail closed.
Occurrence indexing is bounded by the already ingested findings and stores
only per-bucket evidence identities and counts. It does not execute producer
code, inspect secret values semantically, or use machine learning.

## Release decision and remaining limitations

The fixed aggregate thresholds are precision at least 0.95 and recall at
least 0.90; each producer requires precision at least 0.95 and recall at
least 0.80. Matcher v3.1 passes every precision, classification, ambiguity,
ingestion, structural, trace, and determinism condition, but fails aggregate
recall, PMD recall, and the complete label graph. The recommendation therefore
remains `blocked`.

Remaining failures are exactly:

- 25 PMD missed identity relationships; and
- two PMD ambiguity units that remain unmatched rather than being silently
  paired.

The clean corpus does not change that universe. Its best variants reached only `9 TP / 0 FP /
10 FN`, recall `0.473684`. All source-backed variants failed the three no-trusted-hash wrong-root
scenarios; the tied best variants also failed family B's mismatched-snapshot scenario. Snapshot
preflight and later reads are not one immutable operation, and source projection lacks bounded
resource evidence. Issue #27 additionally requires an explicit full-resource-to-stable-projection
derivation and cross-binding, while issue #28 prevents the current validator from representing the
SARIF-only `0/0/19` control without falsely deriving source preflight. The typed
`sparse-experiment-limitation/v1` record and individually authenticated role projections are
preserved without changing either source or resource evidence.

Supported automatic evidence requires a reliable non-colliding fingerprint; reliable embedded
context or bounded token context from the current shared root; or safe URI-base resolution combined
with another qualifying identity signal. Explicit aliases still require qualifying path/context.
The unsupported profile has no reliable fingerprint, no embedded snippet, no trusted source
snapshot, and only non-unique rule/path/message/location evidence. Side-specific roots are not
shipped.

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

The matcher-v2 and matcher-v3 history anchors can be checked without running
the analyzers:

```sh
sha256sum -c validation/history/matcher-v2/checksums.sha256
sha256sum -c validation/history/matcher-v3/checksums.sha256
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
No composite `expected/experiment-report.json` can currently be reproduced while issues #27 and
#28 are open; the checked-in `sparse-experiment-limitation.json` is the authoritative safe-stop
record.

Extended deterministic datasets use:

```sh
sarif-regress bench --size 10000 --dataset unique --enforce-budgets
sarif-regress bench --size 10000 --dataset pathological --enforce-budgets
sarif-regress bench --size 100000 --dataset unique --enforce-budgets
sarif-regress bench --size 100000 --dataset pathological --enforce-budgets
```
