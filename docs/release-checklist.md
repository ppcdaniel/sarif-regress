# Release checklist

This checklist applies to preview `0.1.0-rc.1`. The repository owner has authorized publication
after the exact-head gates and draft inspection.
Unchecked items are blockers unless the repository owner records an explicit, safe disposition.
Do not lower benchmark thresholds or relabel holdout cases to complete the checklist.

## Current decision

- [x] Product version is `0.1.0-rc.1`; matcher is `sarifregress/matcher/v3.2`.
- [x] Matcher v4 was not created; trusted source identity is independently versioned as
  `trusted-filename-lexical-context/v1`.
- [x] Preview is ready in channel policy; stable remains blocked.
- [ ] All release-blocking issues and Medium dispositions in `docs/release-readiness.md` are closed
  or explicitly owner-accepted.
- [ ] Final exact-head preview criteria are met.

## Source and version control

- [ ] Select one exact commit and record its full 40-character SHA.
- [ ] Confirm the worktree is clean and contains no build output, capture staging, private input,
  credentials, or local configuration.
- [ ] Confirm merged PR #32 and the current release PR/head match the intended branch strategy;
  historical draft stacks remain closed and unmerged.
- [ ] Confirm no holdout label or fixed quality threshold changed.
- [ ] Confirm `VersionPrefix`, `ProductInformation.Version`, release-note version, package filename,
  and intended tag agree.
- [ ] Confirm matcher/fingerprint/schema versions changed only when their contracts require it.
- [ ] Review the complete diff and `git diff --check`.

## Scientific and product evidence

- [x] Frozen matcher-v2 result remains `0 TP / 0 FP / 75 FN`.
- [x] Bound v3.2 exposed-holdout result is `50 TP / 0 FP / 25 FN`, precision `1.0`, recall
  `0.666667`, F1 `0.8`; it adds no false match relative to v3.1.
- [x] Semgrep and Gitleaks each remain `25 TP / 0 FP / 0 FN`; Gitleaks classification mismatches
  are zero.
- [x] Legacy PMD safe uniqueness remains `0 TP / 0 FP / 25 FN`; the trusted filename/lexical clean
  result is `18 TP / 0 FP / 1 FN`, precision `1.0`, recall `0.947368`.
- [x] Zero labelled ambiguity is silently matched in the recorded reports.
- [x] Exact normal verification head `d880bd0a0495650a34ae2faa8521f170af80d7a9` development corpus passes.
- [x] Its holdout report and comparison summary reproduce byte-for-byte.
- [x] Its sparse observations, gate evidence, limitation record, and every supporting
  projection authenticate and reproduce byte-for-byte.
- [ ] Promote issue #27's exact-head authenticated composite candidate and independently validate
  its full-resource-to-stable derivation before claiming `experiment-report.json`.
- [x] Any “independent” claim refers only to the original matcher-v2 holdout or a genuinely new
  blinded corpus; v3/v3.1/v3.2 is labelled exposed/post-hoc regression evidence.

## Security and dependency disposition

- [x] Matcher issues #20 and #21 are closed with exact normal-mode Ubuntu/Windows evidence.
- [ ] Complete final exact-head cross-platform verification for compact candidate-edge retention;
  the exact 1,000,000-pair local stress case is implemented and recorded (#22).
- [x] Retain a physical repository-root handle, reject linked ancestors and known remote/device
  roots, and cover root replacement and disposal.
- [x] Refuse lexical and physical `corpus run --json-out` destinations under the corpus input tree.
- [ ] Close the remaining hostile-parent atomic-output boundary or retain the documented
  private-output-directory requirement.
- [x] Reject linked/reparseable package cleanup roots and descendants, with Linux symlink and
  Windows junction canary coverage.
- [x] Enable GitHub Private Vulnerability Reporting and link the direct private-advisory route from
  `SECURITY.md` without publishing private contact data.
- [x] Record the owner implementation disposition for #17: remove the validation-only package
  chain and use the bounded, fail-closed repository evaluator without making a legal conclusion.
- [x] Produce an exact final distribution inventory and verify upstream primary licence/notice
  texts.
- [x] Replace the incomplete status in `THIRD_PARTY_NOTICES.md` with the verified applicable
  notices; do not paraphrase licence terms.
- [x] Include project `LICENSE` and all required notices in the release bundle and package, include
  them in `checksums.sha256`, and assert exact contents on both operating systems (#18).
- [x] Confirm every external Action uses a full immutable commit SHA.
- [x] Confirm workflow defaults are least privilege and checkout credentials are not persisted.

## Local static checks

Run on a clean clone without changing frozen evidence:

```bash
git diff --check
bash -n scripts/*.sh validation/tools/capture/*.sh validation/research/sparse-sarif/tools/*.sh
python3 -B validation/tools/capture/test_capture_tools.py
python3 -B validation/research/sparse-sarif/tools/test_scan_contamination.py
python3 -B validation/research/sparse-sarif/tools/test_pmd_capture_tools.py
python3 -B validation/research/sparse-sarif/tools/test_project_release_evidence.py
python3 -B validation/research/sparse-sarif/tools/test_analyze_duplicate_symmetry.py
python3 -B validation/tools/test_compose_sparse_experiment_evidence.py
python3 -B validation/tools/test_bootstrap_matcher_v32_metadata.py
python3 -B validation/tools/release/test_create_release_draft.py
python3 -B validation/research/sparse-sarif/tools/scan_contamination.py \
  --research-root validation/research/sparse-sarif
git status --short
```

- [x] All JSON parses reject duplicate keys and validate against governing schemas.
- [ ] All workflow YAML parses.
- [x] All shell scripts pass syntax checks.
- [x] Checksum manifests verify.
- [x] Static scans introduce no bytecode/build/generated output.

## Linux verification

```bash
./scripts/verify.sh
./scripts/validate-holdout.sh
./scripts/package.sh
(
  cd artifacts/release
  sha256sum --check checksums.sha256
)
```

- [ ] `verify.sh` passes with locked dependencies and warnings as errors.
- [ ] Holdout validation reproduces all expected reports and recommendation.
- [ ] Package script creates exactly one `.nupkg`, one Linux executable, one Windows executable,
  the project licence, verified notices, and one complete checksum manifest.
- [ ] Linux self-contained executable starts and performs a real fixture comparison producing
  schema-valid JSON and escaped offline HTML.
- [ ] The exact local `.nupkg` installs from the local-only source; the installed package bytes
  match; the installed command performs the same real comparison.

## Windows owner and hosted verification

The release-hardening completion ran locally on Windows x64 with SDK `10.0.302`: the locked
verification pipeline passed 581 tests, package checksums verified, the local-only package install
was byte-identical, and the standalone and installed commands produced identical JSON/HTML from a
real fixture. Holdout validation reached the intentional frozen-source refusal and therefore still
requires the authenticated hosted evidence-refresh cascade. On a clean owner clone, also follow
`docs/windows-owner-verification.md` and run:

```powershell
.\scripts\verify.ps1
.\scripts\validate-holdout.ps1
.\scripts\package.ps1
```

- [ ] Owner records Windows version, architecture, .NET SDK `10.0.302`, exact commit, and each exit
  result.
- [x] Windows package checksum verification succeeds.
- [x] Windows standalone and locally installed tool both run a real fixture comparison and produce
  expected JSON/HTML.
- [x] Hosted Ubuntu and Windows full CI succeeded on exact head
  `d880bd0a0495650a34ae2faa8521f170af80d7a9` in run `30763347889`.
- [x] Hosted Ubuntu and Windows holdout and sparse research jobs succeeded on that head in run
  `30763347894`.
- [ ] Hosted package smoke succeeds on both operating systems for the exact same release bundle.

## Determinism and resources

- [x] Linux and Windows normalized reports are byte-identical, including holdout, delta, sparse
  experiment, and deterministic benchmark projections.
- [x] 1k, 10k, and 100k unique and pathological benchmark gates passed in run `30763347910`
  without raising limits.
- [x] Trusted source context is bounded by repository-file, manifest, token/scope, and aggregate
  immutable-cache ceilings, with focused overflow refusal tests.
- [ ] Repeated independent package builds either compare byte-identical or release wording clearly
  says binary reproducibility is not established.

## Release workflow controls

- [x] `.github/workflows/release.yml` authenticates the exact tagged commit's holdout evidence and
  refuses a blocked selected channel (#19).
- [x] Repository rules restrict release-tag creation to the owner and prohibit update/deletion.
- [ ] A manual release-workflow run produces a reviewable bundle without creating a release.
- [ ] The bundle's `source-commit.txt` and every checksum match the selected commit and files.
- [ ] Package/release notes contain exact metrics, unsupported profile, security limitations, and
  verified notices.

## Preview decision

- [ ] Every security, dependency-terms, attribution, package, exact-head, and workflow blocker is
  closed.
- [ ] Zero labelled ambiguity is auto-matched and no unexplained ingestion/structural failure
  remains.
- [ ] A SemVer prerelease identifier is used.
- [x] Notes distinguish exposed-holdout evidence, the supported trusted-snapshot subset, and the
  formally unobservable legacy duplicate profile.

## Stable decision

- [ ] Aggregate precision `>= 0.95` and recall `>= 0.90`.
- [ ] Every producer has precision `>= 0.95` and recall `>= 0.80`, with a non-vacuous accepted-pair
  denominator or an explicit statistically undefined state.
- [ ] Complete classification/new/resolved/ambiguity label graph passes.
- [ ] All preview criteria pass.

## Publication and rollback

Do not create or push a tag until every applicable item above passes. A tag-triggered workflow can
create a draft release, so even “just tagging” is a release action.

If a future draft or publication must be rolled back:

- [ ] Freeze promotion and record tag, commit, asset hashes, workflow run, and failure.
- [ ] Do not replace assets behind an existing checksum or move the old tag.
- [ ] Deprecate/unlist the affected package or mark the release affected using a reversible host
  control.
- [ ] Publish an advisory and workaround without exposing private reporter data.
- [ ] Fix forward under a new version and repeat this checklist from a clean clone.

No publication or rollback action is part of this checklist's current execution.
