# Changelog

All notable changes to SarifRegress will be recorded here. The project follows Semantic
Versioning after publication; nothing in this file means that a package or release exists.

## [Unreleased]

Release status: **blocked**.

### Added

- Deterministic SARIF comparison with one-to-one bounded assignment, explicit ambiguity refusal,
  stable JSON, offline HTML, and canonical SARIF projections.
- Labelled development corpus plus frozen real-producer evidence for Semgrep `1.172.0`, Gitleaks
  `8.30.1`, and PMD `7.26.0`.
- General, bounded `uriBaseMappings` for missing external URI bases, with SARIF-defined bases taking
  precedence and unknown bases failing closed.
- Collision-aware context occurrence evidence and deterministic matcher-v2-to-v3 and
  matcher-v3-to-v3.1 history, plus a frozen v3.1-to-v3.2 comparison path.
- A contamination-resistant, authentic PMD `7.26.0` sparse-SARIF research corpus with two fixture
  families and explicit one-to-many/many-to-one ambiguity.
- Pre-release adversarial review, release decision record, security policy, release checklist, and
  incomplete third-party inventory.

### Changed

- Matcher identity advanced from `sarifregress/matcher/v2` to v3 for URI-base and context-collision
  behavior, then to `sarifregress/matcher/v3.1` for classification-only path-template handling, and
  to `sarifregress/matcher/v3.2` for precision-preserving context-conflict and code-flow admission
  safety.
- Current reports retain configuration schema `1`, output schema `1`, and derived fingerprint
  `rule-path-context/v2`.
- Pull-request workflows select and verify the exact pull-request head; all external Actions remain
  pinned to full commit SHAs.

### Fixed

- Both Semgrep inputs with external URI bases now ingest without `CANON0032`; Semgrep records
  `25 TP / 0 FP / 0 FN` on the exposed holdout.
- Repeated low-information context no longer hides 25 safe Gitleaks identities; deliberate
  ambiguity remains refused.
- Five Gitleaks pure moves whose messages echoed the changed path are classified as moved under a
  bounded producer-neutral post-correspondence rule. Gitleaks remains
  `25 TP / 0 FP / 0 FN`, and classification mismatches fall from five to zero.
- Conflicting context now vetoes collision-only/weak admission, and code-flow anchors can only rank
  already admissible edges when unique on both input sides; neither change adds a producer-specific
  rule or raises a graph/resource limit.

### Security

- Hardened URI-base mapping against network roots, encoded traversal, cycles, excessive depth, and
  ambient absolute-path disclosure.
- Added fail-closed sparse-corpus contamination scanning, bounded authentic PMD capture, safe
  extraction, exact artifact provenance, and cross-platform research admission.
- No matcher v4 or side-specific repository-root API was shipped after the source-context design
  failed fixed recall and production-safety gates.
- Stable resource projections exclude volatile timing/peak-memory values while retaining fixed
  budget enforcement and structural observations in authenticated workflow artifacts.

### Known limitations

- Exposed-holdout aggregate result: `50 TP / 0 FP / 25 FN`, precision `1.000000`, recall
  `0.666667`, F1 `0.800000`.
- Legacy PMD sparse SARIF remains `0 TP / 0 FP / 25 FN`; the clean research corpus's best result is
  `9 TP / 0 FP / 10 FN`, recall `0.473684`.
- Sparse SARIF without reliable fingerprints, snippets, trusted source snapshots, or unique
  evidence is unsupported and deliberately left unmatched.
- Several matcher-security, memory, release-gating, validation-terms, and notice-distribution
  blockers remain open. See `docs/release-readiness.md`.
- The typed sparse limitation record is preserved, but composite experiment-report promotion is
  blocked by issues #27 and #28; no composite report is claimed.
- Deterministic reports are verified; reproducible package bytes are not yet claimed.

## [0.1.0] — Unreleased

Reserved for the first release. Do not add a date or tag until the release checklist passes.
