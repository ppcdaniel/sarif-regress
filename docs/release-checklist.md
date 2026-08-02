# Release checklist

This checklist applies to the first `0.1.0` release candidate. It does not authorize a release.
Unchecked items are blockers unless the repository owner records an explicit, safe disposition.
Do not lower benchmark thresholds or relabel holdout cases to complete the checklist.

## Current decision

- [x] Product version is `0.1.0`; matcher is `sarifregress/matcher/v3.2`.
- [x] Matcher v4 was not created after the sparse experiment failed fixed gates.
- [x] Release recommendation is documented as **blocked**.
- [ ] All release-blocking issues and Medium dispositions in `docs/release-readiness.md` are closed
  or explicitly owner-accepted.
- [ ] Preview or stable criteria are met.

## Source and version control

- [ ] Select one exact commit and record its full 40-character SHA.
- [ ] Confirm the worktree is clean and contains no build output, capture staging, private input,
  credentials, or local configuration.
- [ ] Confirm PR #8, PR #13, and the hardening PR state matches the intended branch strategy.
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
- [x] Legacy PMD remains `0 TP / 0 FP / 25 FN`; the clean sparse best result is
  `9 TP / 0 FP / 10 FN`.
- [x] Zero labelled ambiguity is silently matched in the recorded reports.
- [ ] Exact final-head development corpus passes.
- [ ] Exact final-head holdout report and comparison summary reproduce byte-for-byte.
- [ ] Exact final-head sparse observations, gate evidence, limitation record, and every supporting
  projection authenticate and reproduce byte-for-byte.
- [ ] Resolve issue #27's full-resource-to-stable-projection derivation/cross-binding before
  claiming a composite `experiment-report.json`; issue #28's SARIF-only preflight derivation is
  corrected without changing source evidence, resource measurements, or gates.
- [ ] Any “independent” claim refers only to the original matcher-v2 holdout or a genuinely new
  blinded corpus; v3/v3.1/v3.2 is labelled exposed/post-hoc regression evidence.

## Security and dependency disposition

- [ ] Close or safely disposition matcher issues #20 and #21.
- [ ] Prove bounded candidate-edge memory at the documented global cap or narrow the release
  guarantee (#22).
- [ ] Resolve repository-root lifetime, corpus output/input aliasing, package cleanup, and atomic
  output threat-model findings.
- [ ] Confirm GitHub Private Vulnerability Reporting or approve another private reporting route;
  update `SECURITY.md` without publishing private contact data accidentally.
- [ ] Record the owner-specific decision for JsonSchema/JsonPointer/Json.More maintenance terms
  (#17).
- [ ] Produce an exact final distribution inventory and verify upstream primary licence/notice
  texts.
- [ ] Replace the incomplete status in `THIRD_PARTY_NOTICES.md` with the verified applicable
  notices; do not paraphrase licence terms.
- [ ] Include project `LICENSE` and all required notices in the release bundle and package, include
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
python3 -B validation/research/sparse-sarif/tools/scan_contamination.py \
  --research-root validation/research/sparse-sarif
git status --short
```

- [ ] All JSON parses with duplicate-key rejection and validates against its governing schema.
- [ ] All workflow YAML parses.
- [ ] All shell scripts pass syntax checks.
- [ ] Checksum manifests verify.
- [ ] Static scans introduce no bytecode/build/generated output.

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

On a clean owner clone, follow `docs/windows-owner-verification.md`; this agent does not claim local
Windows execution. At minimum run:

```powershell
.\scripts\verify.ps1
.\scripts\validate-holdout.ps1
.\scripts\package.ps1
```

- [ ] Owner records Windows version, architecture, .NET SDK `10.0.302`, exact commit, and each exit
  result.
- [ ] Windows package checksum verification succeeds.
- [ ] Windows standalone and locally installed tool both run a real fixture comparison and produce
  expected JSON/HTML.
- [ ] Hosted Ubuntu and Windows full CI succeed on the exact final head.
- [ ] Hosted Ubuntu and Windows holdout and sparse research jobs succeed on the exact final head.
- [ ] Hosted package smoke succeeds on both operating systems for the exact same release bundle.

## Determinism and resources

- [ ] Linux and Windows normalized reports are byte-identical, including holdout, delta, sparse
  experiment, and deterministic benchmark projections.
- [ ] 1k, 10k, and 100k unique and pathological benchmark gates pass without raising limits.
- [ ] Source-context projection has a bounded resource result before any future side-specific root
  design is reconsidered.
- [ ] Repeated independent package builds either compare byte-identical or release wording clearly
  says binary reproducibility is not established.

## Release workflow controls

- [ ] `.github/workflows/release.yml` authenticates the exact tagged commit's holdout evidence and
  refuses `releaseRecommendation: blocked` (#19).
- [ ] Repository rules protect release tags from unauthorized creation, update, or deletion.
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
- [ ] Notes explicitly call v3/v3.1/v3.2 exposed-holdout evidence and sparse SARIF unsupported.

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
