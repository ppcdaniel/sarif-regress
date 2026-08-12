# ADR 0004: Duplicate symmetry is an identity boundary

- **Status:** Accepted; bounded filename/lexical preview candidate implemented, duplicate boundary retained
- **Date:** 2026-08-13
- **Scope:** [Issues #11 and #12](https://github.com/ppcdaniel/sarif-regress/issues/12)
- **Executable evidence:**
  [`analyze_duplicate_symmetry.py`](../../validation/research/sparse-sarif/tools/analyze_duplicate_symmetry.py)

## Context

The predeclared, separately designed controlled sparse-PMD corpus demonstrates that side-bound
source snapshots can supply useful,
producer-neutral evidence when PMD SARIF contains no fingerprints or snippets. That result does not
by itself establish that every older labelled relationship is observable. In particular, the frozen
legacy PMD holdout contains repeated findings whose comment-free code, lexical scope, rule, message,
and source transformation do not distinguish one occurrence from another.

This distinction is normative for the project. The architecture requires maximum-cardinality,
lexicographic, deterministic one-to-one assignment, but it also says that a stable identity key may
order work and output and **may not resolve semantic equality**. Equal semantic assignments must be
reported as ambiguous rather than selected by result or source order.

SARIF 2.1.0 has the same underlying identity intent. Section 3.27.16 requires a fingerprint to be,
as far as feasible, stable for logically identical results and different for logically distinct
results. Appendix B further says that a result-management system should not include an absolute line
number in its fingerprint because harmless inserted lines would change it. Therefore, equal rule and
line observations are not an occurrence-identity proof.

## Method

The bounded analyzer performs these phases in a fixed order:

1. Strictly read SARIF and side-bound source files with duplicate-key rejection and explicit byte,
   file, JSON-depth, JSON-node, result, line, token, and duplicate-component limits.
2. Strip line and block comments while preserving every source line.
3. Extract exact statement tokens and the smallest method-like lexical brace scope. No producer name,
   PMD-specific rule, marker text, label ID, or relationship label participates in extraction.
4. Freeze predictions from three predeclared variants:
   - **filename-bound uniqueness** models the implemented preview-candidate contract: ordinal final filename,
     method-like scope header, and exact statement, with equal rivals refused;
   - **safe uniqueness** accepts a semantic signature only when it is unique on both sides and refuses
     every equal rival;
   - **source-order control** pairs equal duplicate occurrences by their source coordinates. It is an
     intentionally unsafe diagnostic, not a proposed matcher tier.
5. Only after both predictions exist, load the existing labels and score exact pairs, ambiguity
   endpoints, new findings, and resolved findings.
6. Emit sorted canonical JSON as UTF-8 without BOM and with an LF terminator. Fail if any frozen
   observation differs from the predeclared counts.

The executable tests additionally mutate every `HOLDOUT:` prefix in memory to the same-length
`MUTATED:` prefix. All comment-free feature digests remain identical across 8 source snapshots and
60 marker occurrences. Marker text therefore cannot explain any measured match.

## Results

### Predeclared controlled clean sparse corpus

Across `pmd-clean-a` and `pmd-clean-b`, unrestricted safe uniqueness establishes the scientific
upper bound while the filename-bound product contract deliberately refuses a file-and-type rename:

| Observation | Filename-bound TP | FP | FN | Unrestricted-safe TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Labelled relationships | 18 | 0 | 1 | 19 | 0 | 0 |
| Ambiguity endpoints | 6 | 0 | 3 | 9 | 0 | 0 |
| New endpoints | 3 | 3 | 0 | 3 | 0 | 0 |
| Resolved endpoints | 3 | 2 | 0 | 3 | 0 | 0 |

The implemented relationship result is precision `1.0`, recall `18 / 19 = 0.947368`, and F1
`0.972973`. It exceeds issue #11's PMD precision and recall gates, recovers every labelled new and
resolved endpoint, and auto-matches zero labelled ambiguity. Six repeated endpoints become explicit
ambiguity. Three endpoints whose method names diverge have no equal identity atom and remain
new/resolved; this is a conservative classification limitation, not a false correspondence.

### Frozen legacy PMD holdout

| Control | Relationship TP | FP | FN | Precision | Ambiguity endpoint TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| Safe uniqueness | 0 | 0 | 25 | no accepted pairs | 4 | 50 | 0 |
| Source-order control | 25 | 2 | 0 | `25 / 27 = 0.925926` | 0 | 0 | 4 |

Safe uniqueness refuses all 54 endpoints in repeated legacy components: the 4 endpoints labelled
ambiguous and the 50 endpoints belonging to the 25 expected pairs. Source-order alignment recovers
all 25 expected pairs, but its 2 false-positive pairs are exactly the 2 pairs covering all 4 labelled
ambiguous endpoints. It both violates zero-silent-ambiguity and falls below the fixed `0.95`
precision gate.

The lifecycle sets remain independently observable under either control: 3 new and 3 resolved
endpoints are exact, with no false positives or false negatives.

## Formal counterexample

For a repeated group with `n` indistinguishable baseline occurrences and `n` indistinguishable
candidate occurrences, every baseline-to-candidate edge has the same semantic evidence. The
component is the complete bipartite graph `K(n,n)`. It has `n²` equal-weight edges and `n!`
maximum-cardinality perfect assignments.

The legacy holdout requires different policies for components with this same symmetry:

| Lexical scope | Cardinality | Equal semantic edges | Equal perfect assignments | Frozen oracle |
|---|---:|---:|---:|---|
| `ambiguousCases` | 2-by-2 | 4 | 2 | Refuse all 4 endpoints |
| `exactCases` | 5-by-5 | 25 | 120 | Select the coordinate diagonal |
| `messageCases` | 5-by-5 | 25 | 120 | Select the coordinate diagonal |
| `movedCases` | 5-by-5 | 25 | 120 | Select the coordinate diagonal |
| `lineShiftCases` | 5-by-5 | 25 | 120 | Select the source-order continuation |
| `renamedCases` | 5-by-5 | 25 | 120 | Select the coordinate diagonal |

Within each component, permuting result order or permuting equal source occurrences preserves every
admissible semantic observation. A permutation-invariant matcher must therefore either refuse the
component or return an equivalence class of assignments. It cannot choose the labelled diagonal.

The legacy oracle can be reproduced only by adding one of the following non-semantic distinguishers:

- marker comments that encode ground-truth identity;
- result, coordinate, or source order as a semantic tie-breaker;
- a rule keyed to duplicate cardinality, such as pairing 5-by-5 but refusing 2-by-2;
- opaque class or method names whose meaning comes from this corpus.

Marker use leaks labels. Order contradicts the architecture and SARIF fingerprint guidance.
Cardinality and opaque-name rules are corpus special cases, not producer-neutral identity evidence.
Consequently, issue #12's current fixed legacy oracle and its zero-silent-ambiguity/precision gates
are jointly unsatisfiable by a label-blind, order-invariant matcher.

## Research basis and limits

Myers models sequence differencing as a shortest-edit-script/longest-common-subsequence problem and
provides an `O(ND)` algorithm when the edit distance is `D`. It explains how a deterministic source
alignment can be computed; it does not turn repeated equal sequence elements into distinct semantic
identities. An implementation still has to choose among equal alignments.

GumTree demonstrates that richer AST mappings can improve fine-grained source-code differencing by
using structural context. That is a credible direction for a later, independently evaluated source
adapter. It is not evidence that two structurally indistinguishable repeated nodes have a unique
correspondence, and language-specific AST extraction remains outside the first-MVP architecture.

The analyzer intentionally does not implement Myers or GumTree. Its source-order control isolates
the exact disputed assumption with less machinery: once equal duplicates are ordered, the legacy
diagonal appears and the labelled ambiguity is silently consumed.

## Decision

Ship `trusted-filename-lexical-context/v1` as an opt-in adapter identity. Each SARIF side has an
independent physical repository root and independently supplied raw-byte SHA-256 manifest. Only
verified UTF-8 bytes enter a comment-blind, bounded method-header/exact-statement atom; the final
filename is bound with ordinal case-sensitive semantics. Same-filename directory moves are
supported. File renames, missing/mutated bytes, and equal rivals are refused.

The generic matcher and existing callers retain `sarifregress/matcher/v3.2`; the new evidence
contract is versioned independently and is available only through the complete side-specific CLI
option set. Do not use the frozen legacy 25-pair oracle to claim those unobservable duplicates are
recovered, and do not create a matcher-v4 identity for them.

Issue #12's requested implementation is therefore resolved as not planned: its simultaneous legacy
oracle, precision, and zero-silent-ambiguity requirements cannot all be satisfied without violating
its own stop rules and the architecture. Reopening that implementation requires one explicit
owner-reviewed change:

1. correct the legacy labels so every equal duplicate component is ambiguity; or
2. replace the legacy duplicate cases with a new independent corpus containing genuine,
   non-label-derived per-occurrence evidence; or
3. change the product contract to permit a named order/cardinality rule and accept the resulting
   ambiguity and precision consequences.

Thresholds and labels are unchanged. Existing shared-root product behavior is unchanged; only the
explicit trusted-snapshot mode can emit the new fingerprint.

## Consequences

- The safe design boundary is reproducible with exact confusion counts and permutation counts.
- The clean sparse corpus supplies a fixed regression contract for the preview adapter, including
  the single deliberate filename-rename refusal and exact lifecycle limitations.
- Any future source-diff proposal must enumerate all equal optimal mappings and refuse the affected
  component unless additional admissible evidence breaks the symmetry.
- Evaluation reports must keep controlled clean evidence separate from the exposed legacy oracle.

## References

- OASIS, [Static Analysis Results Interchange Format (SARIF) Version 2.1.0 Plus Errata 01,
  sections 3.27.16 and Appendix B](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
- Eugene W. Myers, [“An O(ND) Difference Algorithm and Its Variations,” *Algorithmica* 1,
  251–266 (1986)](https://doi.org/10.1007/BF01840446).
- Jean-Rémy Falleri, Floréal Morandat, Xavier Blanc, Matias Martinez, and Martin Monperrus,
  [“Fine-grained and Accurate Source Code Differencing,” ASE 2014,
  313–324](https://doi.org/10.1145/2642937.2642982).
