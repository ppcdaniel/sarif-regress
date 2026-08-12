# ADR 0002: Safe stop for sparse SARIF continuity

- **Status:** Superseded in part by ADRs 0003 and 0004; exact-location rejection retained
- **Date:** 2026-08-01
- **Scope:** [Issue #11](https://github.com/ppcdaniel/sarif-regress/issues/11)

## Context

Some SARIF producers emit neither usable fingerprints nor embedded snippets. The PMD 7.26.0
holdout has this shape for its ordinary findings. The matcher therefore has no admissible identity
edge even when automatic producer identity, rule, canonical path, exact region, and canonical
message happen to be equal.

This is the highest-risk generalisation defect because location and message can coincide after
unrelated edits. The already-exposed holdout can falsify an unsafe proposed rule, but it cannot
provide new independent positive validation or supply hidden identity labels to that rule. A future
independent claim requires a new untouched or blinded corpus. Precision must remain at least 0.95,
and labelled ambiguity must never be silently auto-matched.

The [interpretation erratum](../../validation/holdout/interpretation-erratum.json) is the
machine-readable authority for the distinction between matcher-v2's independent first evaluation
and the exposed-holdout matcher-v3/v3.1 results used in this decision.

## Audited evidence

The audit ingested both committed PMD inputs through the active case configuration, then joined the
canonical findings on the complete proposed exact signature: automatic producer identity,
canonical rule, canonical repository-relative URI, exact region, and canonical message.

| Scope | Exact intersections | Safe identity result |
|---|---:|---|
| All PMD endpoints | 10 | 5 correct labelled pairs, 3 false cross-pairs, and 2 intersection pairs covering 4 deliberately ambiguous endpoints |
| Endpoints participating in the 25 labelled identity pairs | 8 | Scoped diagnostic: 5 correct and 3 false cross-pairs; `5 / 8 = 0.625` |
| Deliberately ambiguous set | 2 intersection pairs | Covers 4 endpoints that must remain refused; these are outside the scoped `5 / 8` diagnostic |

The three false exact intersections are:

| Baseline | Candidate | Shared line | Why it is false |
|---|---|---:|---|
| `baseline:0:17` | `candidate:0:15` | 34 | Distinct controlled identities aligned after inserted lines |
| `baseline:0:18` | `candidate:0:16` | 36 | Distinct controlled identities aligned after inserted lines |
| `baseline:0:19` | `candidate:0:17` | 38 | Distinct controlled identities aligned after inserted lines |

Requiring the entire producer/rule bucket to contain exactly one sparse finding on each side
recovers zero PMD relationships. It is safe but does not materially improve recall.

If Option A accepted all ten locally unique signature intersections, its complete hypothetical
matcher result against the holdout would be:

| TP | FP | FN | Precision | Recall | Silently matched ambiguous endpoints |
|---:|---:|---:|---:|---:|---:|
| 5 | 5 | 20 | `0.5` | `0.2` | 4 |

The `0.625` figure above diagnoses the eight intersections within the match-labelled endpoint
pools. It is not the precision of the full hypothetical matcher because it excludes the two
ambiguity intersection pairs.

## Options considered

### Option A: unique exact-location signature

This would add a named tier for a signature that is unique on both sides. All ten direct
intersections are locally unique. The full experiment fails the precision gate at `0.5`: three
intersections join the wrong controlled identities, and two more intersection pairs silently pair
all four endpoints in the deliberately ambiguous set. Stronger whole-bucket uniqueness avoids
those errors but recovers nothing.

**Decision:** reject for this milestone. Exact location and message are observations, not a safe
identity proof in a bucket containing repeated sparse findings.

### Option B: separate baseline and candidate repository contexts

Separate read-only roots remain a plausible general design. A future implementation would need:

- backward-compatible shared `--repo` behavior;
- distinct CLI and configuration fields for the two snapshots;
- side-bound lookup so baseline findings never read the candidate root or vice versa;
- independent containment, regular-file, symlink, junction, size, and encoding checks;
- deterministic path canonicalisation and evidence provenance proving which root was read.

The current PMD source snapshots cannot independently validate this option. They contain adjacent
`HOLDOUT:pmd-*` semantic identity markers used to construct and audit ground truth. Deriving source
context from those files would expose the answer to the matcher. Removing the markers, changing the
labels, or pretending the resulting recall were independent would violate the holdout protocol.

**Decision:** do not implement or score Option B with this holdout. This is a validation-data
limitation, not a conclusion that separate repository roots are inherently unsafe.

### Option C: combine exact-location continuity and separate roots

The combination inherits both blockers: Option A produces false matches and Option B cannot be
measured without semantic-ID leakage from the current snapshots.

**Decision:** reject for this milestone.

## Decision

Stop Phase 3 without changing product matching behavior. Matcher v3 contains URI-base and
collision-aware context work that improved the exposed-holdout regression result, but it emits no
sparse-continuity tier.
Fingerprint-free, snippet-free findings without another admissible evidence mechanism remain
unmatched. Duplicate signatures are never resolved by input order, and the deliberate PMD
ambiguity is not silently auto-matched.

At this decision point, issue #11 remained open. The stop conditions were demonstrably met:

- the proposed exact-signature rule produces five false positives: three false cross-pairs and two
  ambiguity intersection pairs;
- full hypothetical precision is `0.5`, below the fixed `0.95` gate;
- it would auto-match two ambiguity intersection pairs covering four deliberately ambiguous
  endpoints;
- testing separate roots on the current snapshots would leak holdout semantic IDs.

No holdout label, source snapshot, quality threshold, or matcher constant is changed by this
decision.

## Consequences and reopening criteria

- PMD recall remains zero in matcher-v3's exposed-holdout regression result; safety takes priority
  over recall.
- Reports continue to distinguish unmatched endpoints from an explicitly solved ambiguity
  component. With no admissible sparse edge, current PMD ambiguity endpoints are one-sided
  unmatched decisions, but they are not silently paired.
- Tests freeze the audit counts, unsafe-refusal behavior, input-order invariance, and absence of a
  sparse evidence tier.

At this decision point, reconsidering #11 required producer-agnostic development evidence that was
not derived from this holdout, plus source snapshots without semantic identity markers. The later
trusted filename/lexical design met those criteria on the separately designed clean corpus and
closed #11; ADR 0004 records that result and the remaining duplicate-symmetry boundary. That later
result does not reverse this ADR's rejection of exact location and message as identity evidence.
