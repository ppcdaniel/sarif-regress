# Pre-release adversarial review

Review date: 2026-08-01  
Repository: `ppcdaniel/sarif-regress`  
PR #8 head: `0231d6fe779203a92469099b90d446fafe67b064`  
PR #13 head and reviewed tree: `733e383858fa940faca5b6f8f087832e9ee582cf`  
PR #13 base: PR #8 head  
Reviewer: Codex, using three parallel read-only review tracks; this was not an external or human
review.

## Scope and method

The review treated PR #8 as the experimental-infrastructure change and PR #13 as the exposed-
holdout generalisation change. It read both pull requests and their conversations, issues #9–#12,
the repository contracts, every ADR, every workflow, every verification or capture script, the
matching and repository-context implementations, the immutable evaluation histories, and the
package/release surface. The working tree was clean before review. Holdout labels and both history
checksum manifests were hashed and verified before any edit.

Locally available static checks passed: JSON parsing with duplicate-key rejection, Python syntax,
workflow YAML parsing, shell syntax, checksum verification, and `git diff --check`. The pinned
.NET SDK `10.0.302` was present but CoreCLR could not start (`0x8007000E`, exit 137), so this review
does not claim local executable or Windows evidence. Successful historical Actions runs were useful
integration evidence, but at the time of review B-01 limited what they proved about an exact
pull-request head. That boundary was subsequently resolved on
`9debc7d4007b5ea1448fcec07e0ad781512298c7`; see the B-01 disposition.

Severity means:

- **Blocker:** the claimed review or evidence boundary is invalid until corrected.
- **High:** a correctness, scientific-validity, licensing, or release failure that needs a focused
  disposition before the affected merge or release.
- **Medium:** material risk or misleading contract that is bounded by another control.
- **Low:** maintainability or hygiene debt with limited immediate effect.
- **Observation:** a verified positive control or a limitation that is already represented safely.

## Summary

Counts include every recorded finding, including findings later remediated. The original review,
research-infrastructure addendum, and matcher-v3.2 promotion addendum remain separately visible so
historical severity is not rewritten by disposition.

| Severity | Original review | Research addendum | Promotion addendum | Total | Current effect |
|---|---:|---:|---:|---:|---|
| Blocker | 1 | 0 | 2 | 3 | Historical and pre-push promotion defects remain counted after remediation |
| High | 9 | 7 | 3 | 19 | Mixed resolved and open findings; licensing, release, and composite-evidence blockers plus a manifest-refresh follow-up remain |
| Medium | 14 | 8 | 2 | 24 | Metric semantics, context/output/package hardening, compatibility, test isolation, and research-evidence durability |
| Low | 3 | 0 | 0 | 3 | Version authority, public constructor compatibility, and unused restore path |

Total recorded findings: 49.

## Blocker findings

### B-01 — Pull-request workflows test a synthetic merge commit, not the exact head

- **Evidence and code area:** `.github/workflows/ci.yml` checkout step; equivalent checkout steps in
  `holdout-validation.yml`, `determinism.yml`, and `benchmarks.yml`. They trigger on
  `pull_request` but do not set `actions/checkout`'s `ref`. GitHub therefore checks out the
  pull-request merge ref. The holdout attestation checks only the shape of `GITHUB_SHA`; it does not
  compare the checked-out commit with `github.event.pull_request.head.sha`. The committed v3
  attestation binds product commit `29ea23e0e9b0b85269d3eaaa52ccf3c7a91da30b` and
  generation-workflow commit `cc1016e71d5c31acf73c4dbed3cb7b59c5dc1e74`, not final PR #13
  head `733e383858fa940faca5b6f8f087832e9ee582cf`.
- **Why it matters:** successful run metadata names the PR head, but the compiled and tested tree may
  include the current base through a generated merge commit. That is valuable integration evidence,
  not the required exact-head evidence. Claims that PR #8 or PR #13 passed on its exact head are not
  established by the current workflow implementation.
- **Smallest safe remediation:** explicitly check out
  `${{ github.event.pull_request.head.sha || github.sha }}`, fail unless `git rev-parse HEAD` equals
  that selected SHA, and bind it into generated evidence. A separate merge-ref integration job may
  remain, but cannot replace the exact-head job.
- **Blocks merging PR #8:** yes, for its hosted-evidence claim.
- **Blocks merging PR #13:** yes.
- **Blocks release:** yes.
- **Tracking:** [#14](https://github.com/ppcdaniel/sarif-regress/issues/14).
- **Disposition:** resolved on exact head
  `9debc7d4007b5ea1448fcec07e0ad781512298c7`; issue #14 is closed. All four pull-request
  workflows explicitly selected the PR head and asserted `git rev-parse HEAD` equality before
  evidence generation. CI run `30727269212`, holdout/sparse run `30727269210`, determinism run
  `30727269224`, and benchmark run `30727269219` all completed successfully on that SHA, including
  Ubuntu/Windows verification, both package jobs, sparse authentication, cross-platform byte
  comparison, and all 1k/10k/100k benchmark cells. This does not retroactively convert older
  merge-ref runs or the standalone PR #8/#13 heads into exact-head evidence.

## High findings

### H-01 — Path-templated messages turn pure Gitleaks moves into modifications

- **Evidence and code area:** `validation/holdout/cases/gitleaks/labels.json` relationships
  `gitleaks-match-014` through `-018`; `validation/holdout/cases/gitleaks/notes.md`;
  source-transformation checks in
  `validation/tools/capture/verify_source_transformations.py`; message comparison in
  `src/SarifRegress.Match/CandidateEdgeFactory.cs`; classification ordering in
  `src/SarifRegress.Match/FindingMatcher.cs` (`Classify`).
- **Why it matters:** all five accepted correspondences are correct, but each byte-identical file
  rename is reported as `modified` because Gitleaks mechanically echoes the changed path in its
  message. This is a general classification defect, not a label defect, and it fails the complete
  label graph.
- **Smallest safe remediation:** after correspondence only, recognize an exact, bounded,
  producer-neutral location-token substitution when the old and new repository-relative path each
  occur exactly once at token boundaries and replacing them with one sentinel makes the canonical
  messages identical. Any additional message delta remains material. Emit a versioned structured
  explanation; do not alter edge admission or scoring.
- **Blocks merging PR #8:** no.
- **Blocks merging PR #13:** yes under its complete-label acceptance contract.
- **Blocks release:** yes.
- **Tracking:** [#15](https://github.com/ppcdaniel/sarif-regress/issues/15); #12 reports the
  aggregate count.
- **Disposition:** resolved by matcher v3.1; issue #15 is closed. Exact-head holdout run
  `30727269210` preserved `50 TP / 0 FP / 25 FN`, reduced the five Gitleaks classification
  mismatches to zero, and preserved deliberate ambiguity refusal.

### H-02 — Matcher-v3 is post-hoc regression evidence but is labelled independent

- **Evidence and code area:** `docs/real-producer-generalisation.md` diagnoses v2 failures and
  selects changes using the same holdout later scored as v3.
  `validation/history/matcher-v3/metadata.json` calls the record
  `frozen-independent-holdout-evaluation`, and the report kind repeats the independent claim.
- **Why it matters:** frozen labels prevent metric manipulation, but they do not restore
  out-of-sample status after the corpus has guided implementation. `50 TP / 0 FP / 25 FN` is valid
  exposed-holdout regression evidence, not independent v3 generalisation evidence. Unqualified use
  would overstate scientific and portfolio claims.
- **Smallest safe remediation:** preserve historical bytes, add a machine-readable erratum, call v3
  an exposed-holdout regression everywhere current claims are made, and reserve independent claims
  for a new untouched or blinded corpus.
- **Blocks merging PR #8:** no; its v2 baseline was measured before product changes.
- **Blocks merging PR #13:** yes for evidence wording, not necessarily its code after correction.
- **Blocks release:** yes for a generalisation claim.
- **Tracking:** [#16](https://github.com/ppcdaniel/sarif-regress/issues/16); #12 remains the
  umbrella.
- **Disposition:** addressed in the hardening work by a strict
  [hash-bound interpretation erratum](../../validation/holdout/interpretation-erratum.json) and
  corrected current prose. The frozen matcher-v2 and matcher-v3 histories are unchanged; issue
  #16 was closed after normal-mode holdout run `30763347894` reproduced the bound reports and
  interpretation on hosted Ubuntu and Windows at exact head
  `d880bd0a0495650a34ae2faa8521f170af80d7a9`.

### H-03 — Required validation previously used binaries with unresolved maintenance terms

- **Current evidence and code area:** the validation dependency chain tracked by issue #17 is
  absent from `Directory.Packages.props`, the validation project, and all current lock files.
  Required schema checks now use a repository-owned bounded evaluator that supports only the
  committed schema vocabulary and fails closed on unsupported constructs or resource-limit
  violations.
- **Why it mattered:** required CI and owner verification had executed upstream precompiled
  validation binaries whose applicability depended on owner-specific facts that cannot be inferred
  from this repository.
- **Disposition:** resolved technically by removing that binary dependency chain. This records the
  owner's implementation disposition without making or requiring a legal applicability conclusion
  about packages that are no longer used.
- **Blocks merging PR #8/#13 or release:** no after direct verification of the locked dependency
  graph and bounded evaluator tests.
- **Tracking:** [#17](https://github.com/ppcdaniel/sarif-regress/issues/17).

### H-04 — Release artifacts omit project and third-party notice material

- **Evidence and code area:** `scripts/package.sh`, `scripts/package.ps1`,
  `.github/workflows/release.yml`, and `docs/releasing.md` put only the nupkg, two self-contained
  executables, and checksums in the release bundle. The nupkg embeds the project `LICENSE`, but not a
  third-party notice. The standalone executables redistribute .NET runtime components and
  `System.CommandLine 2.0.10`.
- **Why it matters:** the project MIT notice must accompany copies/substantial portions, and the
  self-contained runtime carries third-party notices with binary-redistribution conditions. The
  current top-level release bundle does not carry those materials or checksum them.
- **Smallest safe remediation:** create a verified third-party notice, include the project licence
  and applicable runtime/dependency notices in the release bundle and nupkg as appropriate, checksum
  them, and assert their contents during package smoke tests.
- **Blocks merging PR #8:** no.
- **Blocks merging PR #13:** no.
- **Blocks release:** yes.
- **Tracking:** [#18](https://github.com/ppcdaniel/sarif-regress/issues/18).
- **Disposition:** resolved in the release-hardening completion. The audited product graph and
  verbatim upstream material are retained in `THIRD_PARTY_NOTICES.md` and `notices/`; packaging
  embeds the applicable project/dependency material in the nupkg, places the project/runtime/
  dependency files beside the standalone executables, checks exact source bytes on both operating
  systems, and binds every release file in `checksums.sha256`.

### H-05 — Tagged release drafts ignore the blocked holdout recommendation

- **Evidence and code area:** `.github/workflows/release.yml` runs development-corpus and small
  benchmark gates but does not run `validate-holdout`, authenticate the committed comparison
  summary, or check `releaseRecommendation`. Current committed evidence says `blocked`, yet a
  matching `v*.*.*` tag can still create a draft release.
- **Why it matters:** a draft is not publication, but the automated release control contradicts the
  repository's authoritative readiness record and makes an unqualified stable release too easy to
  stage.
- **Smallest safe remediation:** bind the exact-head holdout report/attestation into the release
  job, fail according to documented preview/stable criteria, and prohibit an unqualified stable tag
  while the stable gate is blocked.
- **Blocks merging PR #8:** no.
- **Blocks merging PR #13:** no.
- **Blocks release:** yes.
- **Tracking:** [#19](https://github.com/ppcdaniel/sarif-regress/issues/19).
- **Disposition:** implementation and behavioral coverage are present. CI run `30763347889` and
  normal holdout run `30763347894` passed on exact head
  `d880bd0a0495650a34ae2faa8521f170af80d7a9`. Issue #19 remains open because its acceptance
  criteria require a real tagged-commit run; this mission forbids creating a tag or release, so no
  tag-triggered execution is claimed.

### H-06 — Collided context can be admitted even when other context conflicts

- **Evidence and code area:** context comparison and weak-context edge admission in
  `src/SarifRegress.Match/CandidateEdgeFactory.cs`; positive collision tests in
  `tests/SarifRegress.UnitTests/ContextCollisionTests.cs`. One repeated snippet or token hash can
  produce compatible/collided context while another available context hash conflicts. The weak
  tier can then admit the edge using path/message support.
- **Why it matters:** an unrelated new finding can replace a resolved finding at the same path while
  generic or redacted context repeats. Stronger contradictory context is currently unable to veto
  that collision-only correspondence.
- **Smallest safe remediation:** carry an explicit context-conflict flag and refuse collision-only
  edge admission whenever any available context conflicts. Add asymmetric snippet/token and
  resolved/new same-path tests; keep all graph and assignment limits unchanged.
- **Blocks merging PR #8:** no; v3 collision logic is in PR #13.
- **Blocks merging PR #13:** yes.
- **Blocks release:** yes.
- **Tracking:** [#20](https://github.com/ppcdaniel/sarif-regress/issues/20).
- **Disposition:** matcher v3.2 carries an explicit conflict bit into admission and vetoes collided
  derived/context and weak-message edges when another available context representation conflicts.
  Exact-head Ubuntu and Windows product suites passed in both bootstrap stages and normal-mode run
  `30763347894`; issue #20 is closed.

### H-07 — Code-flow anchors can act as unbounded primary identity

- **Evidence and code area:** code-flow comparison and `PathProblem` admission in
  `src/SarifRegress.Match/CandidateEdgeFactory.cs`; code-flow tests in
  `tests/SarifRegress.UnitTests/MatchingEngineTests.cs`. A single shared anchor can admit a match
  despite unrelated primary path/message evidence, and anchor occurrences are not collision-counted.
- **Why it matters:** common helpers or sinks can pair resolved and new findings; message or region
  can then select among anchor collisions. This conflicts with documentation that presents code flow
  as supporting evidence.
- **Smallest safe remediation:** occurrence-count anchors by side and producer/rule bucket, require
  uniqueness plus independent compatible identity evidence, or make code flow scoring-only after
  another tier admits the edge.
- **Blocks merging PR #8:** no; this predates PR #8.
- **Blocks merging PR #13:** no if tracked independently.
- **Blocks release:** yes.
- **Tracking:** [#21](https://github.com/ppcdaniel/sarif-regress/issues/21).
- **Disposition:** matcher v3.2 removes code flow from edge admission and occurrence-counts anchor
  identities independently on both input sides; only a one-per-side anchor can rank an edge already
  admitted by independent evidence. Repeated anchors retain one bounded degradation trace.
  Exact-head Ubuntu and Windows product suites passed in both bootstrap stages and normal-mode run
  `30763347894`; issue #21 is closed.

### H-08 — Candidate-edge bounds are applied after full edge materialisation

- **Evidence and code area:** `BuildCandidateGraph` in
  `src/SarifRegress.Match/FindingMatcher.cs` creates every admissible `MatchEdge` in
  `allAdmissibleEdges`; `RetainBoundedEdges` sorts and applies the per-finding retained cap only
  afterwards. Defaults permit up to 1,000,000 evaluated pairs.
- **Why it matters:** many individually legal small buckets can allocate and sort close to one
  million full edge/evidence objects. Existing oversized-single-bucket benchmarks do not exercise
  that shape, so documented memory budgets are not proved at the global cap.
- **Smallest safe remediation:** use a two-pass or compact streamed score representation and only
  materialize bounded retained edges while preserving complete-graph ambiguity accounting and stable
  ordering. Add a many-small-buckets global-cap stress test; do not raise limits.
- **Blocks merging PR #8:** no; this predates PR #8.
- **Blocks merging PR #13:** no if tracked independently, although v3 can admit more edges.
- **Blocks release:** yes.
- **Tracking:** [#22](https://github.com/ppcdaniel/sarif-regress/issues/22).
- **Disposition:** candidate scoring now records only fixed-size 16-byte descriptors while it
  preserves complete-graph union/count accounting, sorts those descriptors in the former exact
  full-edge order, and materialises evidence only for capacity-retained pairs. The focused Release
  stress test covered 244 independent 64-by-64 buckets plus one 24-by-24 bucket (exactly 1,000,000
  admissible pairs), retained and fully materialised exactly 15,640 edges, preserved all 245
  ambiguous components, and observed a 153,182,208-byte process peak working set on the recorded
  Windows run. A second regression test proves compact-descriptor ordering parity with the former
  full-edge preference order across both retained and discarded candidates. Final exact-head
  cross-platform verification is still required before closing the tracking issue.

### H-09 — Sparse-experiment supporting projections can self-attest semantics

- **Evidence and code area:** the initial Phase 4 research contract in
  `validation/research/sparse-sarif/schemas/experiment-supporting-evidence.schema.json` makes the
  release `reportPath`, determinism `artifactPath`, and resource `evidencePath`/cell
  `artifactPath` references optional. `_optional_experiment_reference_is_valid` in
  `validation/research/sparse-sarif/tools/scan_contamination.py` accepts a missing path/hash pair.
- **Why it matters:** a report and its typed supporting JSON can agree on invented semantic values
  while citing unrelated, structurally valid workflow artifact IDs and digests. The deliberate
  absence of a product-implementation evidence role prevents this from authorising matcher v4, but
  it would weaken the scientific integrity of the limitation record.
- **Smallest safe remediation:** require one hash-bound typed projection per supporting role whose
  complete ordered variant payload equals the claimed values. Generate that projection inside the
  authenticated workflow coordinator and require final strict CI to compare its bytes with the
  committed projection. Connector verification remains the external artifact-service trust check.
- **Blocks merging PR #8:** no.
- **Blocks merging PR #13:** no.
- **Blocks release:** yes, until the Phase 4 limitation evidence is bound and reproduced.
- **Tracking:** [#27](https://github.com/ppcdaniel/sarif-regress/issues/27).
- **Disposition:** partially remediated, still open. Release and determinism projections are
  authenticated and byte-compared. The stable resource projection correctly omits volatile timing
  and peak-memory values, and the scanner now derives that stable subset. Issue #27 remains open
  until the full authenticated supporting bytes and structural digest are cross-bound in one
  composite report. Issue #28 no longer blocks the safe-stop evidence.

## Medium findings

### M-01 — Controlled fixtures limit ecosystem and source-context validity

- **Evidence and code area:** holdout source snapshots contain adjacent `HOLDOUT:<semantic-id>`
  markers, and Semgrep/Gitleaks evidence contains scenario-like identifiers. Current configs omit
  `repositoryRoot`, so current v2/v3 runs do not read marker-bearing source. The projection tool also
  rejects markers from SARIF snippets.
- **Why it matters:** current SARIF-only metrics are not directly contaminated by source markers,
  but the same trees cannot test source-context matching, and scenario-coded evidence limits broad
  ecosystem claims.
- **Smallest safe remediation:** build a neutral contamination-scanned corpus with ground truth only
  in labels. Preserve and qualify the historical controlled-fixture metrics.
- **Blocks PR #8/#13:** no if claims are qualified. **Blocks release:** broad ecosystem claims only.
- **Tracking:** #11 and #12 cover the source-context limitation.

### M-02 — Lifecycle “accuracy” omits false new/resolved outputs

- **Evidence and code area:** `HoldoutMetricsCalculator` in
  `validation/tools/SarifRegress.Validation/HoldoutEvaluation.cs` computes accuracy as
  correct/expected while separately counting observed outputs. PMD emits 30 new and 30 resolved,
  only three of each are expected, yet both accuracy fields are `1.0`.
- **Why it matters:** the quantity is label recall, not accuracy. The complete-label-graph gate still
  blocks release, but individual metrics can mislead readers.
- **Smallest safe remediation:** preserve history; in a versioned current contract add unexpected
  counts, lifecycle precision/recall/F1, or rename the existing value to label recall.
- **Blocks PR #8/#13:** no if qualified. **Blocks release:** yes for metric claims.

### M-03 — Vacuous precision is machine-reported as a passing value

- **Evidence and code area:** zero-denominator division returns `1` in corpus and holdout metric
  calculators; the comparison gate therefore records PMD `precisionMet: true` for zero accepted
  pairs.
- **Why it matters:** recall and accepted-count fields keep the release blocked, but precision has
  not been demonstrated.
- **Smallest safe remediation:** add `precisionDefined` or a nullable precision state and treat an
  undefined producer value as not demonstrated/inconclusive.
- **Blocks PR #8/#13:** no. **Blocks release:** yes for metric interpretation.

### M-04 — Accepted explanations omit the selected decision vector

- **Evidence and code area:** `DecisionTraceProjection.cs`, `StableJsonWireModels.cs`, and
  `StableJsonWireMapper.cs` serialize vectors for rejected alternatives only. Accepted Gitleaks
  traces therefore do not independently expose the vector used by classification.
- **Why it matters:** “trace present” is weaker than reproducing the decision; the five mismatches
  require code-based reconstruction.
- **Smallest safe remediation:** add a bounded selected vector and versioned classification reason,
  or commit an independently checked secret-safe analysis record.
- **Blocks PR #8:** no. **Blocks PR #13:** its explanation-completeness claim. **Blocks release:**
  auditability only.

### M-05 — Repository roots are reopened by pathname and ancestor links are not rejected

- **Evidence and code area:** `FileSystemRepositoryContext` stores a root string and calls
  `RepositoryFileHandleOpener.Open` for each read. Linux and Windows validate the final root handle,
  but do not component-walk every ancestor or retain a root handle across reads.
- **Why it matters:** an intermediate symlink/junction or root replacement can change the snapshot
  between reads, weakening the promised fixed-root model and any future two-root experiment.
- **Smallest safe remediation:** validate/open the root component-by-component once, retain the safe
  directory handle for the context lifetime, and open all files relative to it. Test ancestor links
  and root replacement independently for both sides.
- **Blocks PR #8/#13:** no. **Blocks release:** repository-context guarantee; **blocks v4:** yes.
- **Disposition:** resolved in the release-hardening completion. Linux and Windows component-walk
  the root without following links, retain the physical directory handle for the context lifetime,
  open repository files relative to that handle, and cover ancestor-link, root-replacement,
  disposal, remote/device, and known unsafe-filesystem cases. Hosted Linux runtime confirmation is
  still required for the exact completion head.

### M-06 — Corpus JSON output may overwrite a corpus input

- **Evidence and code area:** `CorpusCommandHandler` writes `--json-out` without the physical
  input/output identity checks present in compare and validate handlers.
- **Why it matters:** a labels, config, or SARIF file can be selected as output and destroyed.
- **Smallest safe remediation:** conservatively forbid output under the physical corpus root or
  reject every consumed input identity, including symlink aliases.
- **Blocks PR #8/#13:** no. **Blocks release:** yes.
- **Disposition:** resolved in the release-hardening completion. `corpus run --json-out` rejects
  both lexical descendants and destinations whose existing parent resolves beneath the physical
  corpus tree; focused tests cover direct and aliased-parent destinations.

### M-07 — Package cleanup follows an `artifacts` symlink/junction

- **Evidence and code area:** `scripts/package.sh` recursively removes artifact children and
  `scripts/package.ps1` does the same without the real-directory/reparse guards used by holdout
  scripts.
- **Why it matters:** a malicious or accidental artifacts link can make packaging delete files
  outside the repository.
- **Smallest safe remediation:** reuse the existing real-directory/reparse checks before recursive
  cleanup and test a Linux symlink and Windows junction.
- **Blocks PR #8/#13:** no. **Blocks release:** yes.
- **Disposition:** resolved in the release-hardening completion by verifying that `artifacts` and
  each managed direct child are the expected physical non-link directories, rejecting nested
  links/reparse points before recursive cleanup, and exercising Linux symlink and Windows junction
  canaries in package CI.

### M-08 — Atomic outputs rely on pathname checks across a TOCTOU window

- **Evidence and code area:** `AtomicOutputWriter` checks for a random sibling name before creating
  it, then stages, backs up, and renames by pathname after identity checks. A writable shared parent
  can replace an ancestor or staging name.
- **Why it matters:** this is narrower than untrusted SARIF—it requires a hostile local filesystem
  peer—but it exceeds the unconditional atomic-output wording in `docs/security.md`.
- **Smallest safe remediation:** reserve staging files with `CreateNew` and no-follow handles,
  retain/revalidate the parent identity, and use platform-safe rename/replace; otherwise narrow the
  documented output-directory threat model.
- **Blocks PR #8/#13:** no. **Blocks release:** security claim.
- **Disposition:** partially remediated and the claim narrowed. Staging names are exclusively
  reserved with `CreateNew`, the handle remains held through write and flush, and ordinary failures
  preserve the destination. A hostile local peer that can replace the parent during pathname-based
  commit remains outside the guarantee and is documented in `SECURITY.md`.

### M-09 — Vulnerability reporting is not concretely discoverable

- **Evidence and code area:** no top-level `SECURITY.md`; `docs/security.md` refers generically to
  GitHub's security-reporting mechanism without supported versions, a direct route, or response
  expectations.
- **Why it matters:** reporters may disclose sensitive SARIF publicly or be unable to reach the
  owner.
- **Smallest safe remediation:** confirm GitHub Private Vulnerability Reporting and document the
  exact route plus supported versions; otherwise provide an owner-approved private channel.
- **Blocks PR #8/#13:** no. **Blocks release:** yes.
- **Disposition:** resolved in the release-hardening completion. Top-level `SECURITY.md` documents
  supported versions, response expectations, and the exact private-reporting route; GitHub Private
  Vulnerability Reporting is enabled for the repository.

### M-10 — Deterministic reports do not prove reproducible package bytes

- **Evidence and code area:** deterministic compilation and locked dependencies are enabled, but
  `.github/workflows/determinism.yml` compares reports only. No same-commit independent builds
  compare nupkg or executable bytes.
- **Why it matters:** current claims support deterministic normalized output, not reproducible
  binaries.
- **Smallest safe remediation:** either add repeated-build byte/provenance evidence or state the
  narrower guarantee explicitly. Do not call current package builds reproducible.
- **Blocks PR #8/#13:** no. **Blocks release:** a reproducible-build claim only.

### M-11 — Configuration schema v1 now names two behavioral languages

- **Evidence and code area:** PR #13 adds `uriBaseMappings` while retaining configuration schema
  version `1`; older v1 implementations ignore the unsupported property and may resolve the same
  configuration differently.
- **Why it matters:** strict shape validation and behavior compatibility are no longer aligned.
- **Smallest safe remediation:** define the evolution contract and prefer a v2 configuration schema
  with v1 reading/migration where practical.
- **Blocks PR #8:** no. **Blocks PR #13:** compatibility disposition. **Blocks release:** no before
  the first public release if documented.

### M-12 — Required release and handoff documents are absent

- **Evidence and code area:** no `CHANGELOG.md`, top-level `SECURITY.md`,
  `THIRD_PARTY_NOTICES.md`, release-readiness/notes/checklist, Windows owner checklist, or engineering
  case study exists at the reviewed head.
- **Why it matters:** release status, security intake, attribution, rollback, unsupported evidence,
  and owner-only verification are not collected into auditable handoff documents.
- **Smallest safe remediation:** create the requested documents from verified evidence, clearly
  separating performed checks from owner actions.
- **Blocks PR #8/#13:** no. **Blocks release:** yes.

### M-13 — Validation evidence code is monolithic and shell orchestration is duplicated

- **Evidence and code area:** the validation tool exceeds 10,000 lines; several individual files
  exceed 1,000 lines, while Linux and Windows wrappers separately encode the evaluation sequence.
- **Why it matters:** the byte coordinator catches output drift, but structural changes remain hard
  to review and platform orchestration can diverge before output comparison.
- **Smallest safe remediation:** after evidence is frozen, split contract/runner/projection concerns
  and derive both wrappers from one declarative sequence. Do not refactor during metric repair.
- **Blocks PR #8/#13/release:** no.

### M-14 — Package smoke tests do not execute a real comparison

- **Evidence and code area:** CI/release smoke verifies checksums, exact nupkg installation, and
  startup/help, but not a JSON/HTML-producing comparison through installed and standalone forms.
- **Why it matters:** dependency bundling or runtime-only compare failures can survive packaging.
- **Smallest safe remediation:** execute one tiny checked fixture comparison on Linux and Windows
  with the tool package and standalone executable; validate JSON and inspect the HTML contract.
- **Blocks PR #8/#13:** no. **Blocks release:** yes.
- **Disposition:** resolved in the release-hardening completion. CI and release smoke run the
  checked `github-supported-subset` fixture through both distribution forms, assert the exact JSON
  schema/version/summary contract and offline HTML CSP, and require byte-identical reports.

## Low findings

### L-01 — Matcher version has multiple authorities

`MatchingAlgorithms.MatcherVersion` and `ProductInformation.MatcherAlgorithmVersion` duplicate the
same literal for different output paths. Consolidate them or enforce an invariant test before the
next version change. This does not block either PR or release by itself.

### L-02 — Public configuration constructor changed CLR signature

PR #13 adds an optional constructor parameter, which is source-compatible but not binary-compatible
for callers compiled against the previous signature. No library package has been released, so the
safe minimum is to document the tool-only public API boundary or retain a forwarding overload. This
does not block release if resolved before the first stable API promise.

### L-03 — An unused tool manifest bypasses audited Multitool acquisition

`.config/dotnet-tools.json` permits ordinary `dotnet tool restore` of Multitool `5.5.0`, while the
accepted validation scripts download, hash, verify, and install the exact nupkg offline. Remove the
unused manifest or clearly mark it as non-authoritative. It does not affect the audited scripts.

## Positive observations

- Holdout ground truth is derived from source transformations and case plans, not matcher output.
  Label hashes are unchanged from PR #8. No difficult case or threshold was removed.
- Current v3 does not read marker-bearing source snapshots. The marker scanner excludes those
  strings from projected snippets. The limitation is prospective source-context research, not a
  hidden contaminant in current SARIF-only runs.
- Correspondence, classification mismatch, ambiguity, ingestion, and structural-failure counts are
  distinct. Arithmetic for `50 TP / 0 FP / 25 FN` is internally coherent, and no labelled ambiguity
  is silently matched.
- Assignment is exact and non-greedy within the bounded component. Equal semantic optima are refused
  before stable keys are used, and all dictionary-derived outputs are explicitly ordered.
- URI-base mappings reject network roots, encoded traversal, cycles, and excessive depth. SARIF
  definitions take precedence over configuration. Stable provenance omits ambient absolute roots.
- Repository source reads use handle-anchored beneath/no-link primitives for files under an opened
  root, reject non-regular files, bound bytes/encoding/token work, and fail closed when required OS
  primitives are unavailable. M-05 identifies the remaining root-lifetime boundary.
- HTML values are escaped under a restrictive offline CSP. Capture extractors reject traversal,
  links, encryption, unsupported entries, and oversized expansion.
- Producer and baseline acquisitions pin exact versions, sizes, hashes, and provenance. No producer
  binaries or archives are committed or released. All external GitHub Actions use full commit SHAs,
  workflows default to `contents: read`, and checkout credentials are not persisted.
- Historical v2/v3 checksum manifests verify. Earlier successful Ubuntu/Windows runs remain valid
  merge-ref integration evidence. The current workflows additionally produced successful
  exact-head evidence on `9debc7d4007b5ea1448fcec07e0ad781512298c7`; B-01 and issue #14
  are resolved.

## Required disposition before release

At minimum, every unresolved High finding requires either a verified fix or a focused open issue
with a release-blocking disposition. B-01 and H-01 are resolved and remain counted historically.
Medium findings that are not fixed must appear in release-readiness, security, and
supported-evidence documentation. A safe preview remains blocked until preview criteria are
defined. A stable release remains blocked by exposed-holdout recall, the PMD evidence gap,
licensing disposition, release notices/gates, unresolved matcher-safety findings, and composite
research-evidence issue #27. Issue #28's source-free control derivation is resolved; that fix did
not change the failed sparse metrics or authorize matcher v4.

## Nightly research-infrastructure addendum

This addendum records findings made on 2026-08-02 while the clean sparse-SARIF corpus and its
pre-experiment controls were still uncommitted. The split summary above preserves the original
review counts and reports the addendum and whole-document totals separately. Findings remain
counted after remediation; each disposition records current status. These findings concern the new
research evidence, not the frozen v2/v3/v3.1 records.

### H-10 — The initial contamination scanner failed open on boundedness and label admission

- **Evidence and code area:** the first versions of
  `validation/research/sparse-sarif/tools/scan_contamination.py`, especially tree enumeration, JSON
  parsing, label-token scanning, selector admission, and Windows filesystem checks. Separator-
  normalized label IDs could evade detection; JSON depth was checked only after materialisation;
  the aggregate byte limit diagnosed but continued admission; directory count/depth were
  unbounded; embedded absolute paths and Windows reparse points could escape checks; SARIF keys and
  values were not scanned for label IDs; equal/overlapping side roots were accepted; and labels
  were not proved to uniquely and exhaustively partition the SARIF results. The original test
  fixture itself assigned some endpoints more than once.
- **Why it matters:** a scanner with these gaps can report that a corpus is clean while it contains
  a direct label channel, an unlabelled or multiply labelled result, a swapped side, or an
  input capable of exhausting the scanner before its limits take effect. Any PMD metric produced
  after such admission would be scientifically unauditable.
- **Smallest safe remediation:** fail before materialising over-depth JSON or admitting files past
  any resource bound; use no-follow/reparse-aware enumeration and reads; scan normalized IDs and
  marker text in source and SARIF; require distinct side roots and inputs; and resolve every natural
  selector exactly once into a disjoint, exhaustive relationship/new/resolved/ambiguity partition.
  Add a negative test for every former bypass and run the Windows junction test on hosted Windows.
- **Blocks merging PR #8:** no. **Blocks merging PR #13:** no. **Blocks the nightly hardening PR:**
  yes until fixed. **Blocks release or matcher v4:** yes.
- **Tracking:** [#24](https://github.com/ppcdaniel/sarif-regress/issues/24).
- **Disposition:** remediated. Seventy-seven scanner mutation/contract tests and the real corpus
  passed on exact head `2f4499a51f621ee8c1fb3816752205d7e5b224bf` on hosted Ubuntu and
  Windows. Windows executed the junction test;
  the one local skip remains an operating-system boundary, not an untested hosted path.

### H-11 — An `implement-v4` decision was not bound to every fixed gate

- **Evidence and code area:** the initial
  `validation/research/sparse-sarif/schemas/experiment-report.schema.json` conditional and
  `_scan_experiment_report`/`_scan_variant_projection` in the contamination scanner. A report only
  needed some variant-shaped object with passing projection values. The selected variant was not
  originally tied to that object, and aggregate-holdout precision/recall, development-corpus
  status, and Semgrep/Gitleaks non-regression remained self-asserted projection fields rather than
  values derived from structured evidence. A later draft distinguished the ten scenarios but
  treated a mismatch or root swap caught only by the corpus-specific trusted source-tree hash as a
  production-safe pass, even though ADR 0003 explicitly says that preflight is unavailable to an
  ordinary caller and cannot by itself authorize a shipped design.
- **Why it matters:** a schema-valid report could authorize matcher v4 even though the selected
  variant failed or the original 75-pair holdout, development corpus, or existing producer results
  were never demonstrated. This defeats the predeclared stop rule while making the report look
  machine-enforced.
- **Smallest safe remediation:** represent clean-PMD metrics, original-holdout metrics,
  producer-regression results, development-corpus status, ambiguity/security outcomes,
  determinism, and resource evidence separately. Bind every projected gate to those values, require
  exactly one selected variant, and permit `implement-v4` only when that same variant passes all
  thresholds with zero unexplained ingestion or structural failure. Record whether a scenario's
  safety depends on corpus-only attestation and reject `implement-v4` when it does. Add negative
  tests that forge each projected value independently.
- **Blocks merging PR #8:** no. **Blocks merging PR #13:** no. **Blocks the nightly hardening PR:**
  yes until fixed. **Blocks release or matcher v4:** yes.
- **Tracking:** [#25](https://github.com/ppcdaniel/sarif-regress/issues/25).
- **Pre-capture disposition:** fail-closed. The policy now rejects every `implement-v4` decision
  until role-specific parsers and cross-reference validators exist; a forged report that reuses one
  hash-valid irrelevant file for every evidence role is rejected. This restriction is not a
  substitute for the Phase 4 experiment.

### H-12 — The initial sparse-capture pipeline could attest unauthentic or ambient PMD output

- **Evidence and code area:** the first uncommitted versions of
  `.github/workflows/sparse-sarif-research.yml`, `tools/capture_pmd.sh`,
  `tools/project_pmd_sarif.py`, and `tools/verify_pmd_capture.py` under the research corpus. The
  workflow ran scanner tests without scanning the actual corpus; the verifier accepted a PMD
  driver name/version even when its invocation failed or emitted error notifications; and the URI
  projector rejected only the selected source-root prefix, allowing other POSIX/Windows paths,
  file URIs, runner hostnames, and timestamps to survive. The shell execution constants and Python
  evidence constants were not bound to one canonical command, and the archive download had no
  transfer-time byte ceiling before its exact size/hash check.
- **Why it matters:** contamination-free source is insufficient if a failed producer run, ambient
  checkout data, or execution/evidence drift can be promoted as authentic SARIF. Retrying an
  unbounded redirected download also exposes a hosted runner to avoidable disk exhaustion.
- **Smallest safe remediation:** execute the actual source-only admission on both hosted systems;
  require exactly one successful invocation and no execution/configuration errors; reject ambient
  machine data outside explicitly typed portable values; derive execution and environment evidence
  from one command/provenance contract; and impose a transfer-time ceiling while retaining the
  exact post-download size, SHA-256, and safe-extraction checks. After first capture, replace the
  upload-only bootstrap with strict comparison of deterministic projections, projection audits,
  and raw hashes.
- **Blocks merging PR #8/#13:** no. **Blocks the nightly hardening PR:** yes until corrected and
  recaptured. **Blocks release or matcher v4:** yes, because the clean-PMD evidence would otherwise
  be unauditable.
- **Tracking:** [#26](https://github.com/ppcdaniel/sarif-regress/issues/26).
- **Disposition:** remediated. Thirty-four capture/projector mutation tests pass. On exact head
  `2f4499a51f621ee8c1fb3816752205d7e5b224bf`, hosted PMD capture verified the canonical PMD/curl
  arrays, environment evidence,
  projection mutations, raw hashes, and promoted bytes; the retained artifact was then downloaded
  by ID and independently reverified.

### M-15 — The initial PMD URI projector did not establish its no-link input boundary

- **Evidence and code area:** the first uncommitted
  `validation/research/sparse-sarif/tools/project_pmd_sarif.py`, in `read_strict_json`,
  `project_document`, and `_assert_source_file`. It resolved the supplied source root before asking
  whether it was a link, walked source components by pathname, and checked JSON depth only after
  parsing.
- **Why it matters:** the intended workflow uses controlled fixtures and a pinned PMD binary, so
  this is not a remote product exploit. It nevertheless fails the experiment's independent-root
  security contract and could project through a symlink/junction or materialise an adversarially
  deep capture before rejecting it.
- **Smallest safe remediation:** preflight JSON nesting before parsing; reject symlink, junction,
  reparse, and non-directory roots before canonical resolution; open files through anchored
  no-follow handles (or an equivalently safe checked mechanism); and test link roots, linked parent
  components, non-regular files, and deep JSON. The projection verifier must also prove that only
  the enumerated URI JSON values changed and that result order is identical.
- **Blocks merging PR #8/#13:** no. **Blocks the nightly hardening PR:** until the capture tool is
  corrected or removed. **Blocks release:** no independently; **blocks sparse-corpus evidence:**
  yes.
- **Disposition:** remediated with anchored no-follow handles, lexical JSON depth rejection, a
  complete URI-only mutation audit, and ambient-data refusal. Hosted capture and strict replay
  passed on exact head `2f4499a51f621ee8c1fb3816752205d7e5b224bf`.

### M-16 — Whole-artifact capture checksums are not stable promotion targets

- **Evidence and code area:** the bootstrap capture artifact includes `capture-environment.json` in
  `checksums.sha256`. The environment document intentionally records the current source SHA and
  GitHub-hosted image version. Both can differ on the commit that promotes the captured files or a
  later exact-head recapture, even when raw PMD and projected SARIF bytes remain identical.
- **Why it matters:** comparing that complete checksum set after promotion creates a self-invalidating
  bootstrap loop and can encourage repeated regeneration until a workflow appears green.
- **Smallest safe remediation:** preserve the first capture's environment and artifact identity as
  provenance, but compare only deterministic projected SARIF, projection audits, and expected raw
  hashes in strict mode. Verify each new run's HEAD/image evidence structurally and attest it
  separately.
- **Blocks merging PR #8/#13:** no. **Blocks the nightly hardening PR:** conversion from bootstrap to
  strict mode. **Blocks release:** no independently; **blocks a deterministic research claim:** yes.
- **Disposition:** the strict workflow compares only stable projected/audit/raw identities and
  independently authenticates each newly uploaded artifact. Exact-head run `30719295884` passed.

### H-13 — Promoted capture provenance was structurally recorded but not authenticated

- **Evidence and code area:** the first promotion draft in
  `.github/workflows/holdout-validation.yml`, `validation/research/sparse-sarif/manifest.json`, and
  `tools/verify_pmd_capture.py` recorded the historical workflow run, artifact ID/name/digest,
  source SHA, and runner image, but the routine workflow verified only the manifest shape and
  artifact content contract. It never retrieved artifact `8823830998` from run `30717611507`,
  compared GitHub's authoritative metadata, or proved that the current sources, labels, and
  rulesets were unchanged from capture source `3a398396213cac416f1b1237c605dd2d119d572f`.
- **Why it matters:** a locally edited provenance object could remain shape-valid and internally
  cross-consistent without proving that the asserted GitHub run or artifact supplied the promoted
  raw bytes. That weakens independent auditability even when every committed projection hash is
  correct.
- **Smallest safe remediation:** grant only `actions: read`, download the historical artifact by
  immutable run and artifact ID with digest mismatch configured to fail, compare the GitHub REST
  artifact ID/name/digest/run/head metadata to a separate workflow authority and the manifest,
  rerun strict promotion verification over the downloaded content, and byte-compare the frozen
  corpus inputs against the recorded source commit.
- **Blocks merging PR #8/#13:** no. **Blocks the nightly hardening PR:** yes until authenticated on
  the exact head. **Blocks release or matcher v4:** yes because the clean-PMD evidence would be
  unauthenticated.
- **Tracking:** [#26](https://github.com/ppcdaniel/sarif-regress/issues/26).
- **Disposition:** resolved by exact-head run `30719295884`, job `91420311128`. GitHub authenticated
  the historical artifact ID/name/digest/run/head; the downloaded content and frozen source inputs
  were reverified. The canonical manifest now records the subsequently attested exact-head capture.

### H-14 — Exact-head recapture was verified before upload but not after upload

- **Evidence and code area:** the first strict form of
  `.github/workflows/holdout-validation.yml` compared the runner staging directory with the promoted
  projections and then uploaded it. The upload step exposed `artifact-id` and `artifact-digest`, but
  no downstream job consumed either value or re-downloaded the stored artifact.
- **Why it matters:** the verified staging directory and the retained GitHub artifact were adjacent
  evidence objects, not one authenticated chain. A corrupt, misidentified, or differently named
  retained artifact would not fail the workflow that claimed to preserve exact-head evidence.
- **Smallest safe remediation:** after the upload job completes, download by its immutable artifact
  ID, require the action's archive-digest verification to succeed, compare GitHub's artifact
  metadata with the upload outputs/current run/head, and rerun the strict promotion verifier over
  the downloaded content.
- **Blocks merging PR #8/#13:** no. **Blocks the nightly hardening PR:** yes until hosted on the exact
  head. **Blocks release or matcher v4:** yes for reliance on the recapture evidence.
- **Tracking:** [#26](https://github.com/ppcdaniel/sarif-regress/issues/26).
- **Disposition:** resolved by exact-head run `30719295884`, job `91420356347`. It downloaded newly
  uploaded artifact `8824342390` by ID, matched GitHub metadata to the upload outputs/run/head, and
  reran strict promotion verification over the downloaded content.

### M-17 — Cross-platform corpus admission lacked a post-execution clean-tree guard

- **Evidence and code area:** the initial `sparse-admission` matrix checked the exact clean checkout
  before installing Python and running scanner tests/admission, but did not repeat that assertion
  afterwards.
- **Why it matters:** a platform-specific scanner/test side effect could modify or add a repository
  file without invalidating the otherwise successful admission cell.
- **Smallest safe remediation:** repeat both the exact-HEAD comparison and full tracked/untracked
  clean-worktree assertion after admission on Ubuntu and Windows.
- **Blocks PR #8/#13/release:** no independently. **Blocks accepting the corpus:** until corrected.
- **Disposition:** remediated and passed on hosted Windows and Ubuntu in exact-head run
  `30719295884`.

### M-18 — Sparse-corpus status text contradicted the promoted capture record

- **Evidence and code area:** the opening of
  `validation/research/sparse-sarif/README.md` said hosted PMD capture was still pending, while its
  provenance section recorded the successful first capture, promoted projections, artifact ID, and
  workflow run.
- **Why it matters:** mutually inconsistent status text makes it unclear whether the SARIF is
  authentic producer output or an unexecuted fixture plan.
- **Smallest safe remediation:** distinguish the already promoted authentic capture, the pending
  strict exact-head recapture, and the still-pending repository-context experiment.
- **Blocks PR #8/#13/release:** no independently. **Blocks accepting the corpus documentation:** yes.
- **Disposition:** preserved as a historical pre-experiment artifact. `README.md` is itself
  integrity-bound by the frozen corpus manifest; changing its bytes without regenerating the
  observation, gate, projection, provenance, and limitation chain makes corpus admission fail.
  Current results are therefore recorded in ADR 0003, the root status documentation, and
  `expected/sparse-experiment-limitation.json`. A future corpus-manifest advance must update the
  README and regenerate every dependent evidence byte together.

### M-19 — A permanent CI gate cannot depend on the 30-day promotion artifact

- **Evidence and code area:** the first provenance-remediation draft added an unconditional
  `promoted-capture-provenance` job to `.github/workflows/holdout-validation.yml`. It downloads
  historical artifact `8823830998`, whose producing bootstrap step retained it for 30 days.
- **Why it matters:** after expiration, every otherwise unchanged pull-request and `main` holdout
  run would fail before reaching the repeatable PMD recapture. A temporary GitHub evidence object
  must not become a hidden permanent availability dependency.
- **Smallest safe remediation:** execute the historical download/authentication once on the exact
  promotion head, preserve that successful run and its checked metadata in the corpus provenance
  record, then remove the unconditional historical download. Keep the reproducible exact-head PMD
  recapture and post-upload verification as the long-lived gate.
- **Blocks PR #8/#13/release:** no independently. **Blocks accepting the final hardening workflow:**
  until the one-time gate is retired after successful execution.
- **Disposition:** the one-time provenance job passed in run `30719295884` and was then removed.
  Routine CI retains reproducible PMD recapture plus post-upload authentication without depending
  on the 30-day historical artifact.

### H-15 — The evidence scanner made source preflight depend on SARIF-only recall

- **Evidence and code area:** on exact head `94c906d485f55bb1900f159caa1abd73d71ee56c`, all four hosted
  evidence workflows passed,
  but promotion of their authenticated projections failed in
  `validation/research/sparse-sarif/tools/scan_contamination.py`,
  `_computed_gate_bindings`. The `sarif-only-control` correctly recorded no repository preflight;
  the scanner derived that preflight was required solely because the control's PMD recall was
  `0/19`. All four source-backed variants produced internally consistent bindings.
- **Why it matters:** the typed limitation report could not represent the scientifically correct
  negative control. Changing the control evidence to satisfy that derivation would falsely imply
  that SARIF-only matching reads or authenticates a source tree.
- **Smallest safe remediation:** exempt only the predeclared SARIF-only control from the
  source-context preflight derivation, retain all metric gates, and add a real-shape regression test
  with `0 TP / 0 FP / 19 FN`. Because the scanner is corpus-integrity-bound, update the scanner and
  manifest hashes and regenerate every exact-head projection.
- **Blocks PR #8/#13:** no. **Blocks the nightly hardening PR:** until corrected and regenerated.
  **Blocks release or matcher v4:** yes for reliance on the sparse experiment report.
- **Tracking:** [#28](https://github.com/ppcdaniel/sarif-regress/issues/28).
- **Disposition:** resolved without changing the control. The source-preflight requirement is now
  derived from whether the predeclared variant consumes source context, and the real `0/0/19`
  regression test remains source-free. Exact-head holdout/sparse run `30761620623` admitted the
  refreshed manifests, reproduced the control and four source-backed variants on Ubuntu and
  Windows, authenticated their artifacts, and uploaded the candidate before the expected stale
  committed-evidence comparison. Normal-mode run `30763347894` then reproduced the promoted bytes;
  issue #28 is closed. The limitation records #27 as its remaining composite blocker.

### H-16 — The stable resource projection embedded volatile benchmark measurements

- **Evidence and code area:** exact-head extended benchmark run `30726918341` passed all twelve
  Linux/Windows 1k, 10k, and 100k unique/pathological measurement jobs and byte-compared every
  application-emitted deterministic report. Its coordinator then failed in
  `.github/workflows/benchmarks.yml` because
  `validation/research/sparse-sarif/expected/projections/sparse-experiment-resource-projection.json`
  copied per-run `elapsedMilliseconds` and `peakWorkingSetBytes` values. A second valid hosted run
  necessarily observed different timing and memory values.
- **Why it matters:** an artifact described and enforced as a stable byte projection cannot include
  scheduler- and runner-dependent observations. After the first evidence promotion, all later
  successful resource runs would fail exact reproduction even when limits, bounded refusals, and
  deterministic application bytes were unchanged.
- **Smallest safe remediation:** retain exact time and peak-memory measurements in the per-run
  artifact and continue enforcing fixed hosted budgets, but make the committed projection reference
  only the stable structural observations record and its digest. Add a regression check proving that
  different passing measurements yield the same stable projection.
- **Blocks PR #8/#13:** no. **Blocks the nightly hardening PR:** yes until a fresh exact-head run
  reproduces the corrected projection. **Blocks release:** yes because resource evidence is not yet
  repeatable.
- **Tracking:** [#29](https://github.com/ppcdaniel/sarif-regress/issues/29).
- **Disposition:** resolved on exact head `9debc7d4007b5ea1448fcec07e0ad781512298c7` by run
  `30727269219`; issue #29 is closed. Full per-run artifacts retain exact timing and
  peak-memory values; the committed projection now carries only stable pass/fail facts plus the
  path and digest of the structural observation record. Replaying the corrected coordinator over
  run `30726918341` and then executing the hosted exact-head matrix reproduced the committed
  projection despite different measurements. All twelve benchmark cells and cross-platform byte
  comparison passed without changing thresholds or product limits.

### M-20 — The composite scanner expects the stable resource projection to equal volatile evidence

- **Evidence and code area:** `.github/workflows/benchmarks.yml` now correctly separates the full
  `sparse-experiment-resource-values.json` artifact from the stable committed projection. However,
  `_scan_supporting_evidence_projection` in
  `validation/research/sparse-sarif/tools/scan_contamination.py` still requires the projection's
  ordered variants to equal the full resource-evidence variants, whose schema requires timing and
  peak-memory cells.
- **Why it matters:** after issue #28 is fixed, a scientifically correct full resource artifact and
  stable projection would still be rejected by composite promotion.
- **Smallest safe remediation:** version an explicit stable resource subset, derive it from the full
  authenticated evidence, cross-bind the structural observation digest, and test the exact
  transformation. Update the integrity-bound scanner/manifest and regenerate all projections.
- **Blocks PR #8/#13:** no. **Blocks the nightly hardening PR:** no because no composite report is
  claimed. **Blocks composite promotion/release evidence:** yes; tracked in #27.
- **Disposition:** the scanner now derives a versioned stable subset from the full resource shape,
  validates its structural-observation digest, and has focused transformation tests. Exact-head
  benchmark run `30761620637` generated the stable candidate after all twelve matrix jobs passed.
  Issue #27 remains open because no single composite report yet cross-binds every authenticated
  supporting byte.

### M-21 — The resource-projection schema and unit guard are under-constrained

- **Evidence and code area:** `schemas/sparse-experiment-projection.schema.json` permits any non-empty
  variant value. `DeterminismAndSafetyTests.cs` rejects the two current volatile field names and the
  exact former deep-copy expression, but does not execute a reusable projection function over two
  distinct measurement matrices or cross-check the evidence digest.
- **Why it matters:** a renamed volatile field or another construction route could pass the static
  guard. The hosted coordinator would catch the current regression, but the local contract is less
  precise than its documentation.
- **Smallest safe remediation:** extract and version projection construction, schema the stable
  value shape, and test byte equality for different passing measurements plus digest binding.
- **Blocks PR #8/#13:** no. **Blocks release:** no independently; it must be dispositioned with #27.

### M-22 — Full runtime measurements expire with 30-day workflow artifacts

- **Evidence and code area:** both per-cell and coordinator benchmark artifacts use
  `retention-days: 30`; the committed structural record intentionally excludes exact timing and
  peak-memory values.
- **Why it matters:** the current run proves fixed budgets, but after artifact expiry a future
  reviewer can verify only the stable pass/structure record, not recompute the historical runtime
  conclusion from raw measurements.
- **Smallest safe remediation:** preserve one immutable, head/run-bound historical full-values
  record outside the future byte-reproduction gate, or explicitly limit the duration of the raw
  performance-audit claim.
- **Blocks PR #8/#13:** no. **Blocks release:** only a durable historical-performance claim.

## Matcher-v3.2 promotion addendum

This addendum records an independent pre-push review of the matcher-v3.2 safety revision and its
two-stage evidence bootstrap. None of these defects reached a release, tag, package publication, or
merged pull request.

### B-02 — Stage-2 finalization omitted a required evaluation identity

- **Evidence and code area:** `.github/workflows/holdout-validation.yml`, stage-2 finalization file
  inventory. The verified producer bundle always included `evaluation-metadata.json`, but the
  coordinator's exact expected-name set omitted it.
- **Why it matters:** every stage-2 coordinator would fail before producing promotable bound
  comparison/checksum bytes, so the fail-closed protocol could never reach normal verification.
- **Smallest safe remediation:** include `evaluation-metadata.json` in the exact stage-2 set and add
  an executable workflow invariant test.
- **Blocks merging PR #8:** no. **Blocks merging PR #13:** no. **Blocks the hardening PR and
  release:** yes.
- **Tracking:** existing release-gate issue #19.
- **Disposition:** fixed and exercised in stage-two run `30762486314`. Its mode detector selected
  `stage2` for both operating systems, the coordinator accepted the complete exact file set, and the
  workflow reached only the deliberate final-refusal job. Normal run `30763347894` subsequently
  selected `normal` and succeeded. Issue #19 remains open solely for tag-triggered evidence.

### B-03 — Candidate-unbound CI validated frozen bytes against future schemas

- **Evidence and code area:** `tests/SarifRegress.ValidationTests/TrackedOutputTests.cs` and active
  schemas under `validation/schemas/`. The candidate-unbound tree still contained frozen matcher
  v3.1 expected outputs, while the test unconditionally selected active matcher-v3.2 schemas.
- **Why it matters:** ordinary CI would fail before stage 1 even though the deliberate bootstrap
  state was internally valid. Weakening the active schema would instead make incompatible evidence
  appear valid.
- **Smallest safe remediation:** make tracked-output validation branch only on the typed erratum
  status: archived v3.1 schemas/checksums for `candidate-unbound`, active v3.2 contracts after a
  bound promotion.
- **Blocks merging PR #8:** no. **Blocks merging PR #13:** no. **Blocks the hardening PR and
  release:** yes.
- **Tracking:** [#30](https://github.com/ppcdaniel/sarif-regress/issues/30).
- **Disposition:** fixed without changing frozen v3.1 bytes. Hosted CI runs `30761620627` and
  `30762486272` passed the stage-aware validation tests on Ubuntu and Windows; both bootstrap
  stages reached their intended coordinators, and normal CI/holdout runs `30763347889` and
  `30763347894` succeeded. Issue #30 is closed.

### H-17 — Attestation-bearing artifacts were uploaded before a later fallible step

- **Evidence and code area:** `.github/workflows/holdout-validation.yml`, bootstrap coordinator.
  The cross-platform artifact asserted `coordinatorJobConclusion: success`, then a later sparse
  projection upload could still fail the same job. Normal compare also did not depend on the sparse
  comparison job.
- **Why it matters:** an artifact could contain a success claim even though its coordinator or the
  standalone holdout graph later concluded failure. The release verifier added another control, but
  the document itself would be misleading.
- **Smallest safe remediation:** upload the sparse projection first, make the attestation-bearing
  upload the final stage-specific step, and make normal compare depend on sparse comparison while
  leaving bootstrap dependencies able to generate candidates.
- **Blocks merging PR #8/#13:** no. **Blocks the hardening PR and release:** yes.
- **Tracking:** existing release-gate issue #19.
- **Disposition:** fixed and covered by workflow-order/dependency assertions. Stage-one run
  `30761620623` and stage-two run `30762486314` both uploaded their attestation-bearing artifact
  only from a successful coordinator after sparse comparison. Normal run `30763347894` succeeded
  and emitted a workflow/coordinator-success attestation. Issue #19 remains open only because no
  tag-triggered workflow was permitted.

### H-18 — Comparison field renames reused schema version 3

- **Evidence and code area:** `StableReportSerializer.Serialize(ComparisonSummaryReport)` and
  `validation/schemas/comparison-summary.schema.json`. The v3.2 summary replaced v3/v3.1 hash keys
  with v3.1/v3.2 keys while still emitting schema version `3` under a closed object contract.
- **Why it matters:** consumers cannot distinguish two incompatible schema-3 meanings, violating
  the documented rule that field removal or rename requires a version change.
- **Smallest safe remediation:** emit/require comparison schema `4`, retain the archived v3.1
  schema-3 bytes, and make bootstrap/release verifiers reject the wrong envelope.
- **Blocks merging PR #8/#13:** no. **Blocks the hardening PR and release:** yes.
- **Tracking:** [#30](https://github.com/ppcdaniel/sarif-regress/issues/30).
- **Disposition:** fixed. Schema 4, archived v3.1 schema 3, and wrong-envelope refusals passed hosted
  Ubuntu and Windows tests in CI runs `30761620627` and `30762486272` and in both bootstrap product
  jobs. Normal CI/holdout runs `30763347889` and `30763347894` succeeded; issue #30 is closed.

### H-19 — Sparse implementation inventories had no supported deterministic refresh path

- **Evidence and code area:** exact-head holdout run `30760917264` on
  `be00cf6ad4acc8b9c408f8afdba22631f1fd8b81`; both `sparse-admission` cells failed
  `EXPERIMENT022` because `CodeFlowAnchorOccurrenceIndex.cs` changed after
  `experiment-implementation-manifest.json` was last refreshed. All candidate, recapture, compare,
  and deliberate-refusal jobs were skipped. The repository has strict readers in
  `SparseResearchManifestReader` and `scan_contamination.py`, but no production refresh command;
  `_refresh` in the scanner test suite is synthetic-fixture-only.
- **Why it matters:** a two-line production import fix invalidated the exact implementation
  inventory and prevented any replacement sparse evidence from being generated. Ad hoc refreshes
  are easy to make incomplete. The old expected evidence correctly remains bound to its original
  implementation/corpus hashes and must not be rewritten by hand.
- **Smallest safe remediation:** deterministically refresh the current implementation manifest and
  corpus integrity entry from the closed file-set contract, verify them with the strict scanner,
  then generate the complete exact-head evidence/provenance/limitation/checksum cascade from hosted
  artifacts. Track a reusable bounded refresh command separately.
- **Blocks merging PR #8/#13:** no. **Blocks the hardening PR:** until the manifest is refreshed and
  hosted candidates are produced. **Blocks release:** yes for any current sparse-evidence claim.
- **Tracking:** [#31](https://github.com/ppcdaniel/sarif-regress/issues/31).
- **Disposition:** the original evidence blocker was resolved. The exact 131-file implementation
  inventory and 67-file corpus inventory were deterministically refreshed, the strict scanner
  passed, and exact-head runs `30761620623`, `30761620626`, and `30761620637` produced authenticated
  replacement candidates bound to those manifest hashes. The release-hardening completion adds a
  reusable bounded deterministic `--check`/`--write` refresh command, focused mutation tests, and a
  required workflow freshness check. Its new inventory must still pass the strict scanner and the
  hosted evidence cascade before issue #31 closes; historical metric evidence is not rebound by a
  manifest-only refresh.

### M-24 — The assignment-solver regression test depended on code-flow edge admission

- **Evidence and code area:** exact-head holdout run `30761477309`, Linux job `91532730149`;
  `AssignmentSolverTests.Maximum_cardinality_solver_avoids_the_greedy_high_edge_trap` expected two
  matched decisions but observed three refused/new/resolved decisions. Its second assignment edge
  existed only because a shared code-flow anchor previously admitted correspondence. Matcher v3.2
  intentionally removes code-flow anchors from edge admission, so the pure assignment regression
  no longer constructed the graph it claimed to test.
- **Why it matters:** an assignment-objective test was coupled to an unrelated, now-rejected
  evidence heuristic. That obscured whether the failure was in bounded assignment or in the
  intended admission hardening and stopped all hosted candidate generation.
- **Smallest safe remediation:** construct the second edge with unique independent context evidence,
  retain the high-edge trap and the exact two-pair assertions, and leave the separate code-flow
  admission-refusal tests responsible for the new safety contract.
- **Blocks PR #8/#13/release:** no product defect independently. **Blocks the hardening PR:** until
  the test again isolates assignment behaviour and passes on both hosted operating systems.
- **Disposition:** resolved by replacing only the trap's code-flow-only leg with a unique raw
  context edge. The product matcher and expected two-pair assignment remain unchanged. Exact-head
  CI run `30761620627` passed all 545 tests on each operating system, and holdout run
  `30761620623` independently passed the bootstrap product suites on Ubuntu and Windows.

### M-23 — Pre-push checksum and research manifests became stale during integration

- **Evidence and code area:** `validation/expected/checksums.sha256`,
  `validation/research/sparse-sarif/experiment-implementation-manifest.json`, and the corpus
  integrity list. Concurrent safety/schema edits changed bound files before their mechanical
  manifests were refreshed.
- **Why it matters:** tracked-output and sparse admission jobs would fail before executable evidence;
  blindly staging the tree would also obscure whether frozen history changed.
- **Smallest safe remediation:** regenerate only the affected manifests, verify every referenced
  byte, re-run the contamination scanner, and separately prove v2/v3 histories and label hashes are
  unchanged.
- **Blocks merging PR #8/#13:** no. **Blocks the hardening PR:** yes until refreshed. **Blocks
  release:** no independently.
- **Disposition:** resolved locally; all active/history/research checksum graphs, exact
  implementation inventory, contamination admission, and frozen label hashes pass.
