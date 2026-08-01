# Independent holdout validation: matcher v2

> [!IMPORTANT]
> This document and `validation/history/matcher-v2/` preserve the original,
> untuned MVP evaluation from PR #8. Matcher v3 is evaluated separately in
> [Real-producer generalisation](real-producer-generalisation.md); none of the
> v2 labels, thresholds, difficult cases, or reports were replaced.

## Result

The frozen SarifRegress MVP does **not** meet its release criteria on this
holdout. The release recommendation is:

```json
{
  "releaseRecommendation": "blocked"
}
```

SarifRegress made no false positive matches and never silently chose a labelled
ambiguity, but it also matched none of the 75 known same-finding relationships.
Its measured precision is therefore `1.0` only because it accepted zero
positive matches; recall and F1 are both `0.0`. Two Semgrep inputs could not
be ingested.

This is an evaluation result, not a producer-quality benchmark. It says nothing
about how well Semgrep, Gitleaks, or PMD detect vulnerabilities or other source
problems.

The immutable machine-readable evidence is committed in:

- `validation/history/matcher-v2/sarif-regress-holdout.json`
- `validation/history/matcher-v2/sarif-multitool-baseline.json`
- `validation/history/matcher-v2/comparison-summary.json`
- `validation/history/matcher-v2/checksums.sha256`
- `validation/history/matcher-v2/cross-platform-attestation.json`

## Why this suite is separate

The development corpus was available while the matcher was built. This holdout
uses three previously unused real producer families and lives under
`validation/holdout/`, outside `corpus/`. It is not part of the development
corpus for this milestone.

The evaluated application tree is frozen at commit
`df45e021bc4d2b3c2fd0155bf75ae3967ee80b0d`. This validation change does not
modify `src/`, matcher behavior, fingerprints, canonicalisation, assignment,
classification, or existing corpus labels. Failures remain in the committed
reports and are tracked separately.

## Producers and provenance

Capture occurred on 2026-08-01. Each analyzer ran only against small controlled
fixtures in this repository. Rules were local or pinned built-ins; normal
evaluation uses the committed SARIF and performs no producer downloads.

Semgrep, Gitleaks, and PMD were selected because they are mature, independent
analyzers that produce SARIF directly rather than three wrappers around one
engine. Their Python/OCaml, Go, and Java implementations and different
fingerprint, snippet, path, and metadata choices provide heterogeneous output
that was not represented by the existing ESLint fixture.

| Producer | Exact version | Source commit | Licence | Verified primary download SHA-256 |
|---|---|---|---|---|
| Gitleaks | `8.30.1` | `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` | MIT | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| PMD | `7.26.0` | `8fd38edf285a33e1164f66205ebe243441db9557` | PMD BSD-style | `9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9` |
| Semgrep Community Edition | `1.172.0` | `651f37efa397bf066e1cf627414eeabe40b07e27` | LGPL-2.1-only | `d8b94af4266a575287ad2cd844573743ab4fe58f6bfb6d9229327807937eade3` |

The exact project and release URLs, every download size and checksum, generated
help checks, installation commands, environment pins, and capture commands are
in `validation/holdout/manifest.json` and
`validation/tools/capture/capture-provenance.json`. Per-producer narrative
provenance is in each case's `notes.md`.

Gitleaks emits results from concurrent file fragments in nondeterministic
completion order. Its untouched `*.producer.sarif` captures are retained.
`normalize_gitleaks_sarif.py` creates a deterministic adjacent raw projection
by sorting complete result objects; it changes no result field. PMD and Semgrep
raw captures remain untouched.

## Ground truth and scenarios

Ground truth comes from `case-plan.json` plus controlled baseline/candidate
source transformations. The projector maps each real result to an immediately
preceding `HOLDOUT:<semantic-id>` source comment, rejects that marker if it
appears inside producer evidence, and then derives `labels.json` from the
source-authored plan. Neither SarifRegress nor Multitool contributes a label.

Each producer contributes:

- 25 known same-finding pairs: five exact, five inserted-line, five moved,
  five renamed/rebased, and five message-modified;
- three candidate-only new findings;
- three baseline-only resolved findings; and
- two deliberately ambiguous ground-truth units represented by a 2×2
  near-collision.

That is 33 ground-truth units per producer, 99 total, including 75 labelled
same-finding relationships, 9 new, 9 resolved, and 6 ambiguity units. The
projections also cover missing and duplicate fingerprints, repeated findings,
similar findings in different contexts, producer-version metadata changes,
and controlled POSIX/Windows path spellings. Every raw-SARIF change is listed
with original field hashes, projected values, mutation name, and semantic
rationale in the case's
`producer-input/projection-audit.json`.

## Frozen evaluation metadata

| Item | Frozen value |
|---|---|
| Repository commit | `df45e021bc4d2b3c2fd0155bf75ae3967ee80b0d` |
| Frozen `src/` tree SHA-256 | `317f294b9f52ea9ec78388f9bb96e219d3de4db2607d48c9e9fae1e8be21f7cf` |
| SarifRegress version | `0.1.0` |
| Matcher | `sarifregress/matcher/v2` |
| Derived fingerprint | `rule-path-context/v2` |
| Derived comparison | `sarifregress/derived-fingerprint-compare/v1` |
| Embedded snippet | `embedded-snippet/v1` |
| Producer common fingerprint | `sarifregress/producer-fingerprint-common-version/v1` |
| Output/configuration schema | `1` / `1` |
| .NET SDK | `10.0.302` |
| Holdout manifest SHA-256 | `b9cf6325e2758889449aa021b5b45b3636e17a0dcf65d3c7dba215c2964fe379` |

## SarifRegress results

| Producer | Labelled pairs | TP | FP | FN | Precision | Recall | F1 | Other outcome |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Gitleaks 8.30.1 | 25 | 0 | 0 | 25 | 1.000000 | 0.000000 | 0.000000 | All 60 finding endpoints ambiguous |
| PMD 7.26.0 | 25 | 0 | 0 | 25 | 1.000000 | 0.000000 | 0.000000 | 30 new and 30 resolved classifications |
| Semgrep 1.172.0 | 25 | 0 | 0 | 25 | 1.000000 | 0.000000 | 0.000000 | 2 input ingestion failures |
| **Aggregate** | **75** | **0** | **0** | **75** | **1.000000** | **0.000000** | **0.000000** | 0 structural failures; 0 silent ambiguity matches |

### Complete failure inventory

There are no SarifRegress false matches and no classification mismatches among
accepted matches, because no match was accepted.

- **Gitleaks:** `gitleaks-match-001` through
  `gitleaks-match-025` are all unexpected ambiguity refusals.
  `gitleaks-ambiguous-001` and `gitleaks-ambiguous-002` are the two
  intended ambiguity refusals. `gitleaks-new-001` through `-003` are
  `incorrect-new`, and `gitleaks-resolved-001` through `-003` are
  `incorrect-resolved`; all six lifecycle findings were also marked
  ambiguous instead of new or resolved. Every authentic result contains the
  same redacted snippet, which creates a 30×30 context-connected component;
  the 12-per-side exact-solver bound refuses it with `MATCH0002`. This is
  tracked in [issue #10](https://github.com/ppcdaniel/sarif-regress/issues/10).
- **PMD:** `pmd-match-001` through `pmd-match-025`, plus
  `pmd-ambiguous-001` and `pmd-ambiguous-002`, are reported
  `not-reported`/missed. PMD emits no fingerprints or snippets, and this
  statement applies to the untouched producer output; the controlled
  ambiguity projection adds duplicate partial fingerprints. This SARIF-only
  evaluation supplies no repository context, so the conservative default
  admits no edge. Only `pmd-new-001` through `-003` and
  `pmd-resolved-001` through `-003` have the expected lifecycle. This
  evidence limitation, including the shared-repository-context caveat, is
  tracked in [issue #11](https://github.com/ppcdaniel/sarif-regress/issues/11).
- **Semgrep:** both `baseline.sarif` and `candidate.sarif` fail ingestion.
  The 29 preserved `%SRCROOT%` references per projected side have no
  `originalUriBaseIds` mapping, producing 58 `CANON0032` diagnostics. All
  33 Semgrep ground-truth units are therefore unevaluable by SarifRegress.
  This external URI-base mapping gap is tracked in
  [issue #9](https://github.com/ppcdaniel/sarif-regress/issues/9).

Diagnostic counts are preserved rather than collapsed:

| Code | Count | Meaning in this evaluation |
|---|---:|---|
| `CANON0020` | 270 | Empty producer fingerprint values ignored |
| `CANON0032` | 58 | Unresolved Semgrep `%SRCROOT%` URI base |
| `GHCS0013` | 4 | Advisory GitHub compatibility diagnostic |
| `GHCS0017` | 4 | Advisory GitHub compatibility diagnostic |
| `GHCS0023` | 2 | Advisory GitHub compatibility diagnostic |
| `MATCH0002` | 61 | Oversized Gitleaks component refused |
| `MATCH0005` | 4 | Duplicate producer fingerprint value |

## Microsoft SARIF Multitool comparison

The external baseline is Microsoft `Sarif.Multitool` `5.5.0`, source commit
`e68c02f86ac02bb9acb3b9da6c3de2291d5b0e2a`, MIT licensed. The exact
33,705,414-byte NuGet package has SHA-256
`2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149`.
Generated help was checked before the invocation was implemented.

The evaluated command is the generated
`sarif match-results-forward <candidate> --previous <baseline>
--output-file-path <output>` form. The adapter runs it once on the committed
deterministic projections and once on copies with deterministic result GUIDs.
It proves that the state multiset is unchanged by instrumentation for all
three producers, then uses the GUID-bearing output only to map external states
back to ground-truth keys. Raw outputs remain workflow artifacts; only the
bounded deterministic external report is committed.

Multitool is a comparison baseline, not an oracle.

The following TP/FP/FN metrics measure result correspondence only. They do not
measure agreement with the project's `unchanged`, `moved`, or `modified`
classification: a correct pairing can be a TP even when Multitool's
`unchanged` or `updated` state does not equal the ground-truth class.

| Producer | Comparable pairs | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Gitleaks 8.30.1 | 24 | 17 | 0 | 7 | 1.000000 | 0.708333 | 0.829268 |
| PMD 7.26.0 | 24 | 11 | 14 | 13 | 0.440000 | 0.458333 | 0.448979 |
| Semgrep 1.172.0 | 24 | 19 | 3 | 5 | 0.863636 | 0.791667 | 0.826087 |
| **Aggregate** | **72** | **47** | **17** | **25** | **0.734375** | **0.652778** | **0.691177** |

Across all 99 units, including lifecycle and ambiguity records, Multitool alone
is correct on 59, SarifRegress alone is correct on 6, both are incorrect on 25,
and 9 are non-comparable; neither tool is correct on the same comparable unit.
The six SarifRegress-only units are PMD's three expected-new and three
expected-resolved findings.

The 31 comparable ground-truth units on which Multitool is incorrect are:

- Gitleaks `match-010`, `match-014` through `match-018`, and
  `match-025`;
- PMD `match-006` through `match-013`, `match-016` through
  `match-020`, `new-001` through `new-003`, and `resolved-001`
  through `resolved-003`; and
- Semgrep `match-012` through `match-016`.

The complete external pair/state mapping is in
`sarif-multitool-baseline.json`; its FP/FN counts measure correspondence
edges and therefore do not equal the number of incorrect ground-truth units.

### Non-comparable semantics

- Multitool's run-to-run states do not express SarifRegress's ambiguity
  refusal. The six `*-ambiguous-001/002` units are non-comparable.
- Multitool has no equivalent for the project path-rebase configuration used by
  `gitleaks-match-002`, `pmd-match-015`, and
  `semgrep-match-021`; those relationships are non-comparable.
- Multitool `updated` can establish continuity but does not distinguish the
  project's `moved` from `modified`; Multitool `unchanged` can likewise
  preserve the right pair while disagreeing with a controlled `modified`
  label. Those identity results may be comparable while their taxonomy differs
  or is explicitly unmapped.

## Release decision

Thresholds were fixed before results were observed.

| Release condition | Required | Observed | Pass |
|---|---:|---:|---|
| Precision | ≥ 0.95 | 1.00 with zero accepted matches | Yes, but vacuous |
| Recall | ≥ 0.90 | 0.00 | **No** |
| Incorrectly auto-matched ambiguity | 0 | 0 | Yes |
| Unexplained ingestion failures | 0 | 2 | **No** |
| Structural failures | 0 | 0 | Yes |
| Complete label graph | Required | Incomplete | **No** |
| Cross-platform deterministic bytes | Required | Linux/Windows identical | Yes |
| Evaluation completed | Required | Completed | Yes |

The committed recommendation is `blocked` for
`recall-below-threshold`, `unexplained-ingestion-failure`, and
`complete-label-graph-failed`. No threshold or label was changed after seeing
the result.

## Reproduction and cross-platform evidence

To reproduce matcher v2, materialise the exact validation head instead of
running the active matcher-v3.1 branch:

```sh
git worktree add ../sarif-regress-matcher-v2 0231d6fe779203a92469099b90d446fafe67b064
../sarif-regress-matcher-v2/scripts/verify.sh
../sarif-regress-matcher-v2/scripts/validate-holdout.sh
```

The equivalent hosted Windows commands at that commit are:

```powershell
& C:\path\to\sarif-regress-matcher-v2\scripts\verify.ps1
& C:\path\to\sarif-regress-matcher-v2\scripts\validate-holdout.ps1
```

The wrappers restore locked dependencies, verify the pinned Multitool package,
validate structure/provenance/schemas/checksums, regenerate into a private
temporary directory, preserve raw Multitool files only under the artifact
directory, and byte-compare the project-owned outputs with the committed
files. They snapshot committed fixtures before and after evaluation.

The fixed attestation comes from
[workflow run 30665972957](https://github.com/ppcdaniel/sarif-regress/actions/runs/30665972957).
Linux artifact `8806996929` and Windows artifact `8807028980` produced
identical SarifRegress and Multitool report bytes. Attested regeneration then
passed on both operating systems in
[workflow run 30666574940](https://github.com/ppcdaniel/sarif-regress/actions/runs/30666574940).

To verify source transformations without downloading producers:

```sh
python3 -B validation/tools/capture/verify_capture_provenance.py --repository-root .
python3 -B validation/tools/capture/verify_source_transformations.py --repository-root .
python3 -B validation/tools/capture/verify_projected_holdout.py \
  --repository-root . \
  --output-root ../holdout-projection-check
```

Optional Linux-only recapture is deliberately separate:

```sh
./validation/tools/capture/capture-holdout.sh \
  --output-root ../holdout-recapture
```

## Limitations

- This is one controlled case and one selected/configured rule per producer,
  not a broad sample of each ecosystem.
- The suite measures finding identity preservation, not analyzer detection
  quality, severity, or security coverage.
- PMD emits neither fingerprints nor snippets here. The SARIF-only result must
  not be generalized to a comparison supplied with faithful side-specific
  source context; the current product exposes only one shared repository root.
- Semgrep's unresolved `%SRCROOT%` shape prevents matching from being tested
  at all until ingestion succeeds.
- Multitool's taxonomy and project configuration semantics only partially
  overlap with SarifRegress. Instrumentation is audited against an untouched
  run, but it is still an adapter-owned measurement.
- Producer recapture is Linux-only. Evaluation of the committed SARIF is the
  cross-platform contract.
- The labels and transformations are reproducible and source-controlled, but
  this milestone does not claim independent human review.
