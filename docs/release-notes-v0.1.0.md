# SarifRegress 0.1.0 release notes

Status: **draft, unreleased, and blocked**

No package, executable, Git tag, or GitHub release has been published. These notes describe the
current candidate so its claims can be reviewed before any release decision.

## What the candidate does

SarifRegress compares baseline and candidate SARIF 2.1.0 runs, produces deterministic one-to-one
correspondence, classifies continued/new/resolved findings, refuses equal or unsafe ambiguity, and
emits stable JSON with optional offline HTML and canonical SARIF projections. Matching is bounded,
explainable, local, and intended for the same producer family unless an explicit rule alias is
provided.

The candidate is product version `0.1.0`, matcher `sarifregress/matcher/v3.2`, configuration schema
`1`, output schema `1`, and derived fingerprint `rule-path-context/v2`. The SDK is pinned to
`10.0.302`.

## What was independently validated

Matcher v2's first evaluation occurred before the holdout was exposed to implementation and was
then frozen. It recorded `0 TP / 0 FP / 75 FN`, recall `0`, F1 `0`, two Semgrep ingestion
failures, an oversized Gitleaks ambiguity component, and no PMD sparse-continuity path. This frozen
failure is the independent baseline.

The same labels were then exposed to diagnose and implement matcher v3, v3.1, and v3.2. Their metrics are
useful regression evidence because labels and thresholds remained frozen, but they are not a new
out-of-sample or independent generalisation result. A clean two-family PMD research corpus was
authored separately and contamination-scanned for source-context research; its experiment still
failed the fixed recall and production-safety gates. The
[machine-readable interpretation erratum](../validation/holdout/interpretation-erratum.json)
hash-binds the exact legacy reports to this qualification and changes no metric.

## Exposed-holdout results

| Producer | TP | FP | FN | Precision | Recall | F1 | Other result |
|---|---:|---:|---:|---:|---:|---:|---|
| Semgrep 1.172.0 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | Zero ingestion/structural failures; two ambiguity units correctly refused |
| Gitleaks 8.30.1 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | Five v3 classification mismatches corrected; two ambiguity units correctly refused |
| PMD 7.26.0 | 0 | 0 | 25 | 1.000000* | 0.000000 | 0.000000 | No pairs accepted; precision is undefined in ordinary statistical terms |
| **Aggregate** | **50** | **0** | **25** | **1.000000** | **0.666667** | **0.800000** | 0 classification mismatches, 0 ambiguity auto-matches, 0 ingestion or structural failures |

All nine labelled new and all nine labelled resolved units are found. The report's current
“accuracy” fields should be read as labelled-unit recall, not full lifecycle accuracy, because they
do not penalise unexpected new/resolved output.

Matcher v3.1 changes classification only: after correspondence on an aliased path, a bounded,
producer-neutral location-token rule proves when the canonical message delta is exactly one unique,
delimited old/new repository-relative path substitution. The five evaluated source files were
byte-identical moves, but source-byte identity is not a classifier precondition. Correspondence
remains `50 TP / 0 FP / 25 FN`.

Matcher v3.2 is a precision-preserving safety revision. Conflicting context vetoes collided or weak
context admission, and code-flow anchors can rank an already admissible edge only when the anchor is
unique on both input sides; they cannot create an edge. Frozen v2, v3, and v3.1 bytes remain
unchanged. The v3.2 report is promoted through two fail-closed hosted stages before it can be used as
release evidence.

## Sparse PMD result and unsupported profile

The clean PMD corpus contains 19 relationships, five unchanged and 14 moved, plus three new, three
resolved, and three deliberate ambiguity groups. The tied `relative-context` and
`agreement-only-combination` variants each produced `9 TP / 0 FP / 10 FN`, precision `1.000000`,
recall `0.473684`, and F1 `0.642857`.

That misses the fixed PMD recall gate of `0.80`; the original holdout remains below aggregate
recall `0.90`; source snapshot lifetime, physical-root identity, and source-projection resource
evidence are incomplete. Matcher v4 was therefore not implemented. There are no
`--baseline-repo` or `--candidate-repo` options.

The role projections were individually authenticated on the exact evidence head, and the typed
`sparse-experiment-limitation/v1` safe-stop record is preserved. They are not a composite
cross-binding. A composite `experiment-report.json` was not promoted because issue #27 still needs
an explicit full-resource-to-stable-projection derivation/cross-binding. Issue #28's invalid source
preflight derivation for the SARIF-only `0/0/19` control was corrected without changing the
control. The limitation record names `blockedCompositeValidationIssue: 27`; no source or resource
evidence was changed.

Automatic matching is not supported when all of the following are true: no reliable fingerprint,
no embedded snippet, no trusted source snapshot, and non-unique rule/path/message/location
evidence. Those cases are deliberately left new/resolved or ambiguous instead of being guessed.

## Microsoft SARIF Multitool comparison

Microsoft SARIF Multitool `5.5.0` is retained as an external reference, not ground truth. Across 72
comparable relationships it records `47 TP / 17 FP / 25 FN`, precision `0.734375`, recall
`0.652778`, and F1 `0.691177`. Across complete comparison units, 48 are correct for both tools, 18
for SarifRegress only, 11 for Multitool only, 13 for neither, and 9 are non-comparable.

SarifRegress was not tuned to reproduce Multitool behavior.

## Determinism and security

Project-owned normalized reports have been byte-compared across hosted Ubuntu and Windows on exact
product heads. Inputs, algorithms, ordering, line endings, and hashes are versioned; stable output
omits timestamps, hostnames, and checkout-specific absolute paths. The product performs no network
requests, repository-code execution, package restore, or telemetry. Repository reads are bounded,
regular-file-only, UTF-8 checked, and handle-relative beneath an approved root. HTML is escaped and
offline under a restrictive Content Security Policy.

These are report-determinism and bounded-input guarantees, not a claim that independent builds
produce byte-identical packages. Local Windows execution was not performed by the agent. The owner
must complete the separate clean-Windows checklist.

Open release-blocking security findings include global edge-object materialisation,
repository-root lifetime, corpus output/input aliasing, package cleanup through filesystem links,
and an output-directory TOCTOU boundary. Matcher v3.2 closes the conflicting-context and
code-flow-admission gaps without raising graph limits. See `docs/release-readiness.md` and
`SECURITY.md`.

## Packaging

The source can build:

- `SarifRegress.Tool.0.1.0.nupkg`, requiring a compatible .NET 10 runtime;
- a self-contained `linux-x64` single-file executable; and
- a self-contained `win-x64` single-file executable.

Package scripts generate SHA-256 manifests. Hosted smoke tests checked checksum verification,
standalone startup, local-feed tool installation, installed package byte identity, and installed
tool startup on Linux and Windows at exact matcher-v3.2 source head
`d880bd0a0495650a34ae2faa8521f170af80d7a9` in CI run `30763347889`. Normal holdout run
`30763347894`, determinism run `30763347908`, and extended benchmark run `30763347910` also
succeeded on that exact head. Real comparison through each distribution form, an independent
package-byte reproducibility check, and verified licence/notice
inclusion remain outstanding. No asset is available for installation from a public feed or release
page.

## Compatibility

- Existing `compare`, `validate`, `canonicalise`, `corpus run`, and `bench` commands remain.
- Exit codes `0`, `1`, `3`, and `4` remain stable; `2` is reserved.
- The existing shared `--repo` and configuration `repoRoot` remain the only repository-root
  interface.
- Configuration and output schemas remain version `1`. `uriBaseMappings` was added during the
  pre-release period; older schema-v1 binaries can behave differently and should not be assumed
  behavior-compatible.

## Release recommendation

**Do not release 0.1.0.** Aggregate recall is below `0.90`, PMD recall is below `0.80`, and open
security, licence, notice, distribution-comparison, release-gating, reproducibility, and
evidence-claim findings remain. A preview also remains blocked until the preview criteria in
`docs/release-readiness.md` pass.
