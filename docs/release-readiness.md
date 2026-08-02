# Release readiness

Audit date: 2026-08-02

Planned version: `0.1.0`

Product matcher: `sarifregress/matcher/v3.1`

Recommendation: **blocked; do not tag, publish, or create a release**

This document is the release decision record, not a claim that the current branch has been
released. It distinguishes the frozen independent matcher-v2 baseline from matcher-v3/v3.1 results
obtained after that holdout had informed implementation. The latter are valid exposed-holdout
regression evidence, but are not a second independent validation.

## Evidence snapshot

The current product and checked-in reports use .NET SDK `10.0.302`, configuration schema `1`,
output schema `1`, derived fingerprint `rule-path-context/v2`, and matcher
`sarifregress/matcher/v3.1`. The 75-relationship holdout labels and quality thresholds were not
changed.

| Dataset | TP | FP | FN | Precision | Recall | F1 | Interpretation |
|---|---:|---:|---:|---:|---:|---:|---|
| Semgrep 1.172.0 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | Exposed-holdout regression result |
| Gitleaks 8.30.1 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | Exposed-holdout regression result; five v3 classification defects corrected in v3.1 |
| Legacy PMD 7.26.0 holdout | 0 | 0 | 25 | 1.000000* | 0.000000 | 0.000000 | No accepted pairs; precision is the repository's zero-denominator convention, not demonstrated precision |
| Aggregate holdout | 50 | 0 | 25 | 1.000000 | 0.666667 | 0.800000 | Fails aggregate recall `>= 0.90` and PMD recall `>= 0.80` |
| Clean sparse-PMD research, best variant | 9 | 0 | 10 | 1.000000 | 0.473684 | 0.642857 | Fails the fixed PMD recall gate; research only |

The current holdout also reports zero classification mismatches, zero ingestion failures, zero
structural failures, four correct ambiguity refusals, and zero labelled ambiguity auto-matches.
The lifecycle fields report all nine labelled new and nine labelled resolved units found, but their
current name, “accuracy”, does not penalise unexpected new/resolved outputs; PMD emits 30 of each.
Those values must not be presented as full lifecycle accuracy.

Microsoft SARIF Multitool `5.5.0` is an external baseline, not ground truth. Across 72 comparable
relationships it records `47 TP / 17 FP / 25 FN`, precision `0.734375`, recall `0.652778`, and F1
`0.691177`. The comparison summary records 48 units both correct, 18 SarifRegress-only correct,
11 Multitool-only correct, 13 both incorrect, and 9 non-comparable.

## Sparse-SARIF decision

Matcher v4 was not created. The clean corpus has two separately designed fixture families,
19 labelled relationships, three new findings, three resolved findings, and three refused ambiguity
groups covering nine endpoints. Its best source-context experiment result was
`9 TP / 0 FP / 10 FN`; recall `0.473684` is below the fixed `0.80` PMD threshold. The original
75-relationship universe also remains at recall `0.666667`; the clean corpus cannot be substituted
for the contaminated legacy PMD snapshots to manufacture aggregate recall.

This corpus is controlled research designed after the legacy PMD failure was known and frozen
before its first scored run. It is not a second independent holdout. All four source-backed variants
failed all three no-trusted-hash wrong-root scenarios; the tied `relative-context` and
`agreement-only-combination` variants also failed family B's no-hash mismatched-snapshot scenario.

The experiment additionally leaves production blockers: the tree preflight and later context reads
do not share one immutable snapshot handle, one-sided source mutation is not fully isolated by the
current scenario matrix, physical root aliases are not proved, and the normal matcher benchmarks do
not execute source projection. Separate `--baseline-repo` and `--candidate-repo` options therefore
remain a design experiment and are not part of the CLI or configuration contract.

Authenticated workflow artifacts and individually reproduced role projections are bound to source
head `94c906d485f55bb1900f159caa1abd73d71ee56c`. The checked-in
`sparse-experiment-limitation/v1` record names decision `document-limitation`, confirms that matcher
v4 was not implemented, and records `blockedCompositeValidationIssue: 28`. Those artifacts are not
the still-missing composite cross-binding. Issue #27 requires an explicit derivation from full
resource evidence to the stable projection; issue #28 incorrectly demands source preflight for the
SARIF-only `0/0/19` control. No composite `experiment-report.json` was promoted, and neither source
nor resource evidence was falsified.

## Supported evidence profile

The endorsed v3.1 evidence profile is conservative and intended for same-producer-family
comparisons. A correspondence is supported as a release claim when the input supplies enough
independently bounded evidence to admit an edge, such as:

- a reliable producer fingerprint that is not degraded by a collision;
- reliable embedded source context, or optional token context read under the existing single,
  shared approved repository root;
- explicit, safe URI-base configuration that makes repository-relative path evidence resolvable,
  combined with another qualifying identity signal; or
- an explicit rule alias for cross-producer rule identity, still combined with qualifying path and
  context evidence.

This profile is not yet a complete implementation invariant. Open issues #20 and #21 show that
collided context can survive conflicting context and that a code-flow anchor can admit an edge
without independent identity. Those cases fall outside the endorsed profile and are a reason the
pre-release build remains blocked.

`--repo` and configuration `repoRoot` bind both inputs to one shared root. Independently supplied
baseline and candidate roots could become a supported evidence source only after a future design
passes the fixed security, determinism, resource, precision, and recall gates. They are not shipped
in v3.1.

The unsupported SARIF-only profile has all of these properties:

- no reliable fingerprints;
- no embedded snippets;
- no independently trusted source snapshots; and
- non-unique rule, path, message, and location evidence.

SarifRegress refuses that profile rather than guessing. In particular, PMD-style sparse SARIF with
repeated evidence is not automatically paired, and exact old coordinates alone are not a safe
continuity proof.

## Compatibility and version history

| Contract | Current value | Release assessment |
|---|---|---|
| CLI commands | `compare`, `validate`, `canonicalise`, `corpus run`, `bench` | No command removed; exit codes `0`, `1`, `3`, and `4` retained; `2` reserved |
| Repository option | shared `--repo` only | Backward compatible; no side-specific options shipped |
| Configuration | schema `1` | Reader/schema remain version 1, but `uriBaseMappings` added behavior to the existing version; document this pre-release compatibility limitation |
| Stable comparison JSON | output schema `1` | No field removal or reinterpretation claimed |
| Product version | `0.1.0` | Unreleased |
| Matcher v2 | `sarifregress/matcher/v2` | Frozen independent baseline: `0/0/75` |
| Matcher v3 | `sarifregress/matcher/v3` | Exposed-holdout regression: `50/0/25`, five Gitleaks classification mismatches |
| Matcher v3.1 | `sarifregress/matcher/v3.1` | Same correspondence metrics; zero classification mismatches |
| Matcher v4 | absent | Correct outcome of failed fixed gates |

Current matching evidence identifiers include `sarifregress/rule-identity/v2`,
`sarifregress/rule-alias/v2`, `sarifregress/derived-fingerprint-compare/v2`,
`sarifregress/context-evidence/v2`, `sarifregress/evidence-occurrence/v1`, and the v3.1
classification explanation `sarifregress/message-location-template/v1`. Historical reports retain
the identifiers that were current when their bytes were frozen.

## Build, package, and reproducibility audit

`scripts/package.sh` and `scripts/package.ps1` build one framework-dependent .NET tool package,
one self-contained `linux-x64` single-file executable, and one self-contained `win-x64` single-file
executable. Trimming, ReadyToRun, and Native AOT are disabled. The scripts create lowercase SHA-256
entries with deterministic LF text for the generated assets.

Exact implementation/evidence head `9debc7d4007b5ea1448fcec07e0ad781512298c7` passed hosted
Ubuntu/Windows CI and package smoke in run `30727269212`, holdout/sparse validation in
`30727269210`, determinism in `30727269224`, and every extended benchmark cell in `30727269219`.
Package checks covered checksum verification, self-contained `--help` startup, local-feed tool
installation, installed-package byte identity, and installed-tool `--help` on both operating
systems. This agent did not perform local Windows execution. A later documentation-only final head
still requires its own connector-confirmed workflow disposition.

Issues #14 (exact-head workflow execution) and #29 (volatile resource projection) were closed on
that exact head and those runs. Issues #27 and #28 remain open for composite evidence promotion;
their status does not invalidate the individually authenticated role evidence described above.

After running a package script, the intended source-tree installation check is:

```bash
smoke_root="$(mktemp -d)"
trap 'rm -rf -- "${smoke_root}"' EXIT
mkdir -p -- "${smoke_root}/release"
cp -- \
  ./artifacts/release/SarifRegress.Tool.0.1.0.nupkg \
  "${smoke_root}/release/"
cp -- ./NuGet.ReleaseSmoke.config "${smoke_root}/"
NUGET_PACKAGES="${smoke_root}/packages" \
dotnet tool install \
  --tool-path "${smoke_root}/tool" \
  --configfile "${smoke_root}/NuGet.ReleaseSmoke.config" \
  --no-cache \
  SarifRegress.Tool \
  --version 0.1.0
"${smoke_root}/tool/sarif-regress" --help
installed_package="$(find "${smoke_root}/tool/.store" \
  -type f -iname 'sarifregress.tool.*.nupkg' -print -quit)"
test -n "${installed_package}"
cmp --silent -- \
  ./artifacts/release/SarifRegress.Tool.0.1.0.nupkg \
  "${installed_package}"
```

`NuGet.ReleaseSmoke.config` clears every configured package source and names only the copied local
feed, so this check cannot fall back to a public source. This is a local package check, not evidence
of publication. The checksum manifest detects changed assets only when the manifest itself comes
from a trusted channel; assets, packages, and manifests are not currently signed and have no
publisher provenance attestation.

Current evidence proves deterministic project-owned reports, not reproducible package bytes.
Independent same-commit builds do not compare `.nupkg` or executable bytes. Package smoke also stops
at startup/help and does not run a real JSON/HTML-producing comparison through every installed and
self-contained form. No release should claim reproducible binaries.

The release bundle is not distribution-ready because it omits the top-level project licence and
verified third-party notice material. Packaging cleanup also recursively removes children below
`artifacts` without first proving that `artifacts` is a real directory rather than a symlink or
junction. Both are release blockers.

## Supply-chain and licence audit

- The project is MIT licensed and the `.nupkg` includes the repository `LICENSE`.
- The sole direct product package is `System.CommandLine 2.0.10`, pinned by the central package
  file and lock file. The self-contained builds also redistribute .NET runtime components.
- The repository does not contain the upstream licence/notice texts needed to assemble and verify
  the complete binary redistribution notice set. `THIRD_PARTY_NOTICES.md` therefore records an
  incomplete, release-blocking inventory rather than inventing text.
- `JsonSchema.Net 9.4.0`, `JsonPointer.Net 7.0.2`, and `Json.More.Net 3.0.1` are validation-only and
  are not product artifacts. Their named maintenance terms require an owner-specific applicability
  decision; issue #17 remains open. `Humanizer.Core 3.0.10` is another locked validation transitive
  whose licence/notice disposition remains part of the incomplete inventory, not issue #17's named
  maintenance-terms question.
- Semgrep `1.172.0` (LGPL-2.1-only), Gitleaks `8.30.1` (MIT), and PMD `7.26.0`
  (`LicenseRef-PMD-BSD-Style`; its archive includes Apache-2.0-licensed components) are capture
  tools only. Their versions, source commits, download sizes, and SHA-256 values are recorded; no
  producer binary or archive is committed or released.
- Microsoft SARIF Multitool `5.5.0` is downloaded only for validation from the exact package URL,
  size `33,705,414`, and SHA-256
  `2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149`.
  It is MIT licensed according to the committed normalized baseline and governing schema, and it
  is not redistributed.
- All external GitHub Actions are pinned to full commit SHAs. Workflows default to
  `contents: read`, checkout credentials are not persisted, and only the tag-only draft-release
  job requests `contents: write`.
- The tag-only draft-release job invokes the runner-provided `gh` executable without pinning its
  binary version or hash. This agent did not invoke it. Replace it with a pinned/reviewed mechanism
  or record and verify its exact provenance before calling the release workflow reproducible.

## Security audit

Positive controls include bounded streaming SARIF/configuration parsing, network URI refusal,
explicit URI-base validation, repository-relative no-link file opens, regular-file and UTF-8
checks, bounded explanations, escaped JSON/HTML, an offline Content Security Policy, transactional
multi-output writes, safe capture archive extraction, immutable Action pins, and least-privilege
workflow defaults.

The security claims must remain qualified by these unresolved findings:

- collided context can be admitted despite another context conflict (#20);
- a shared code-flow anchor can act as primary identity without independent evidence (#21);
- candidate edges are fully materialised before the retained-edge cap (#22);
- repository roots are reopened by path rather than held as one immutable directory identity;
- `corpus run --json-out` can target an input under the corpus root;
- package cleanup can follow an `artifacts` symlink or junction;
- transactional output still has a hostile-parent TOCTOU window; and
- the sparse experiment's release/determinism/resource projections are exact-head authenticated,
  but the composite scanner does not yet derive and cross-bind the stable resource subset from the
  full volatile evidence (#27), and the SARIF-only control remains unrepresentable (#28).

See the top-level `SECURITY.md` for safe reporting. Do not attach private SARIF, source, secrets, or
exploit payloads to a public issue.

## Open release blockers

GitHub issue state was checked on 2026-08-02. A code change that appears to address an open issue is
not treated as closed evidence until its acceptance criteria and final exact-head run are recorded.

| Tracking | Blocker |
|---|---|
| #7 / PR #8 | Independent holdout infrastructure remains an open, unmerged draft stack dependency |
| #11 / #12 / PR #13 | Sparse SARIF remains unsupported; aggregate and PMD recall miss fixed gates; the matcher work remains draft and unmerged |
| PR #23 | Nightly hardening, release audit, and limitation evidence remain draft and unmerged |
| #16 | Current claims must distinguish independent v2 from exposed v3/v3.1 evidence |
| #17 | Owner-specific disposition for validation dependency maintenance terms is absent |
| #18 | Release bundle and package do not contain verified project/runtime/dependency notices |
| #19 | Tagged release workflow does not enforce authenticated holdout `releaseRecommendation` |
| #20 | Conflicting context does not veto collision-only admission |
| #21 | Code-flow anchors can admit identity without an independent signal |
| #22 | Global candidate-edge memory behavior is not bounded before object materialisation |
| #25 | Sparse decision/evidence gate tracking remains open; no v4 may be authorised |
| #27 | Composite evidence needs an explicit full-resource-to-stable-projection derivation and cross-binding |
| #28 | Composite validation incorrectly requires source preflight for the SARIF-only control |

The untracked Medium findings listed in the adversarial review also require release disposition:
lifecycle metric naming, vacuous precision, repository-root lifetime, corpus output/input aliasing,
package cleanup, atomic-output threat-model wording, binary reproducibility wording, configuration
schema-v1 evolution, runner-provided release tooling, real comparison smoke through distribution
artifacts, durable retention of raw runtime measurements, and a stricter stable-projection schema
and behavioral test.

## Preview and stable criteria

A **preview** may be considered only after every security, licensing, attribution, workflow, and
package blocker above is closed or explicitly owner-accepted with a documented safe limitation;
fresh exact-head Ubuntu and Windows verification, holdout, determinism, extended benchmarks, and
package smoke all pass; zero labelled ambiguity is auto-matched; and the prerelease notes clearly
state the unsupported sparse profile. A preview version must use a SemVer prerelease identifier and
must not be described as broadly validated or stable.

A **stable** release additionally requires aggregate holdout precision `>= 0.95`, aggregate recall
`>= 0.90`, per-producer precision `>= 0.95`, per-producer recall `>= 0.80`, zero unexplained
ingestion/structural failures, the complete label graph, verified notice inclusion, and a release
workflow that refuses a blocked recommendation.

Neither threshold set is currently met. The correct action is to keep the work in draft pull
requests and publish nothing.

## Rollback procedure

Before publication, abandon the draft release and retain the failed workflow/report evidence; do
not move or reuse a version tag. After publication of a future version:

1. stop further promotion and record the affected tag, commit, asset hashes, and failure;
2. mark the GitHub release and package/feed entry as affected using the host's reversible
   deprecation or unlisting mechanism rather than silently replacing immutable bytes;
3. remove compromised downloadable assets from active distribution only when necessary for user
   safety, while retaining hashes and an incident record;
4. publish an advisory with the supported workaround and verification instructions;
5. fix forward with a new Semantic Version, rerun every exact-head gate, and never retarget the old
   tag; and
6. confirm consumers can verify the replacement assets against the new checksum manifest.

No rollback action has been performed because no release has been created.
