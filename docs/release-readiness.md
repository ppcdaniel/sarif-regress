# Release readiness

Audit date: 2026-08-13

Planned version: `0.1.0-rc.1`

Product matcher: `sarifregress/matcher/v3.2`

Recommendation: **preview channel ready after the exact-head gates below pass; stable blocked**

This document is the release decision record, not a claim that the current branch has been
released. It distinguishes the frozen independent matcher-v2 baseline from matcher-v3/v3.1/v3.2 results
obtained after that holdout had informed implementation. The latter are valid exposed-holdout
regression evidence, but are not a second independent validation. The
[machine-readable interpretation erratum](../validation/holdout/interpretation-erratum.json)
binds that qualification to the exact v2, v3, v3.1, and active v3.2 report bytes. The two hosted
bootstrap stages remain promotion evidence, not release evidence.

## Evidence snapshot

The current product uses .NET SDK `10.0.302`, configuration schema `1`, output schema `1`, derived
fingerprint `rule-path-context/v2`, and matcher `sarifregress/matcher/v3.2`. The interpretation
erratum hash-binds the active v3.2 exposed-holdout report generated on exact source head
`4cc6faf0167d7da385c1d204cba97d1f34ccb479`. The 75-relationship holdout labels and quality
thresholds were not changed.

| Dataset | TP | FP | FN | Precision | Recall | F1 | Interpretation |
|---|---:|---:|---:|---:|---:|---:|---|
| Semgrep 1.172.0 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | Exposed-holdout regression result |
| Gitleaks 8.30.1 | 25 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | Exposed-holdout regression result; five v3 classification defects corrected in v3.1 |
| Legacy PMD 7.26.0 holdout | 0 | 0 | 25 | 1.000000* | 0.000000 | 0.000000 | No accepted pairs; precision is the repository's zero-denominator convention, not demonstrated precision |
| Aggregate holdout | 50 | 0 | 25 | 1.000000 | 0.666667 | 0.800000 | Fails aggregate recall `>= 0.90` and PMD recall `>= 0.80` |
| Clean sparse PMD, trusted filename/lexical product profile | 18 | 0 | 1 | 1.000000 | 0.947368 | 0.972973 | Meets issue #11 identity gates; one filename-and-type rename deliberately refused |

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

Matcher v4 was not created. Instead, the adapter exposes
`trusted-filename-lexical-context/v1` only when the caller supplies two physical repository roots
and two independent raw-byte SHA-256 manifests. The source bytes are opened through retained root
handles, verified before decoding, cached under aggregate bounds, stripped of comments, and reduced
to a bounded method-header/exact-statement atom bound to the ordinal final filename.

The clean corpus has 19 labelled relationships, three new, three resolved, and nine ambiguity
endpoints. The product profile yields `18 TP / 0 FP / 1 FN`, precision `1.0`, recall `0.947368`, and
F1 `0.972973`; it auto-matches zero labelled ambiguity. Six repeated endpoints are explicit
ambiguity. Three method-renamed ambiguity endpoints and the one filename-and-type rename remain
new/resolved because no equal identity atom exists.

The original legacy PMD labels remain unchanged. Five labelled 5-by-5 relationship groups and one
2-by-2 ambiguity group are observationally symmetric after comment removal. Safe uniqueness
returns 0/25; source-order pairing returns 25 TP and 2 FP, precision 0.925926, and silently consumes
the deliberate ambiguity. The stable aggregate/PMD thresholds are therefore jointly unattainable
without violating the repository's no-order/no-cardinality/no-label-leakage rules. ADR 0004 records
the counterexample and owner-accepted preview limitation.

Issue #27 is addressed by a dedicated compositor. It authenticates three exact-head successful
workflow runs, exact artifact IDs/names/digests, complete coordinator manifests and referenced raw
bytes, and the full-resource-to-stable derivation before emitting one atomic deterministic v2
bundle. The experiment decision remains `document-limitation`; provenance completion does not
change failed gates or authorise matcher v4.

## Supported evidence profile

The endorsed v3.2 evidence profile is conservative and intended for same-producer-family
comparisons. A correspondence is supported as a release claim when the input supplies enough
independently bounded evidence to admit an edge, such as:

- a reliable producer fingerprint that is not degraded by a collision;
- reliable embedded source context, or optional token context read under the existing single,
  shared approved repository root;
- a manifest-verified, non-colliding filename/lexical atom from explicit independent baseline and
  candidate roots;
- explicit, safe URI-base configuration that makes repository-relative path evidence resolvable,
  combined with another qualifying identity signal; or
- an explicit rule alias for cross-producer rule identity, still combined with qualifying path and
  context evidence.

Matcher v3.2 makes this profile an implementation invariant for the two reviewed gaps:
conflicting context vetoes collided or weak admission, and code-flow anchors cannot admit edges and
rank only when unique on both sides. Exact-head product suites on hosted Ubuntu and Windows covered
both revisions during each bootstrap stage and normal-mode run `30763347894`.

`--repo` and configuration `repoRoot` retain their shared-root behavior. The four side-specific
CLI inputs are all-or-nothing and cannot be mixed with either shared-root mechanism. Configuration
schema 1 intentionally gains no implicit side-root precedence.

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
| Repository option | shared `--repo`, or four explicit side-root/manifest options | Shared behavior is backward compatible; trusted mode is opt-in and all-or-nothing |
| Configuration | schema `1` | Reader/schema remain version 1, but `uriBaseMappings` added behavior to the existing version; document this pre-release compatibility limitation |
| Product comparison JSON | output schema `1` | No field removal or reinterpretation claimed |
| Holdout validation report | evidence schema `3` | Exposed-holdout report kind; historical v2/v3/v3.1 schema-2 bytes are frozen |
| External comparison summary | evidence schema `4` | v3.1 and v3.1-to-v3.2 hashes replace schema-3 fields; historical schema-3 bytes are frozen |
| Cross-platform attestation | evidence schema `4` | Workflow and coordinator conclusions are recorded separately |
| Product version | `0.1.0-rc.1` | Preview candidate; stable remains blocked |
| Matcher v2 | `sarifregress/matcher/v2` | Frozen independent baseline: `0/0/75` |
| Matcher v3 | `sarifregress/matcher/v3` | Exposed-holdout regression: `50/0/25`, five Gitleaks classification mismatches |
| Matcher v3.1 | `sarifregress/matcher/v3.1` | Same correspondence metrics; zero classification mismatches |
| Matcher v3.2 | `sarifregress/matcher/v3.2` | Precision-preserving context-conflict and code-flow admission safety revision; promotion is fail-closed |
| Matcher v4 | absent | Correct outcome of failed fixed gates |

Current matching evidence identifiers include `sarifregress/rule-identity/v2`,
`sarifregress/rule-alias/v2`, `sarifregress/derived-fingerprint-compare/v2`,
`sarifregress/context-evidence/v2`, `sarifregress/evidence-occurrence/v1`, the v3.1
classification explanation `sarifregress/message-location-template/v1`, and the v3.2
`sarifregress/code-flow-occurrence/v1` degradation record. Opt-in trusted snapshots add
`sarifregress/trusted-filename-lexical-context/v1`. Historical reports retain
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
systems. This agent did not perform local Windows execution.

Issues #14 (exact-head workflow execution) and #29 (volatile resource projection) were closed on
that earlier exact head and those runs. Current matcher-v3.2 head
`4cc6faf0167d7da385c1d204cba97d1f34ccb479` then passed hosted Ubuntu/Windows CI and package smoke
in run `30761620627`. Holdout/sparse run `30761620623`, determinism run `30761620626`, and resource
run `30761620637` authenticated and uploaded exact-head candidates before their expected stale-byte
comparison or deliberate promotion refusal. Issue #28's implementation is covered by the exact-head
sparse admission path and is now closed. Those runs are historical; the current candidate requires
fresh exact-head evidence and a composite promotion before publication.

On the stage-two promotion head `ac081e70ab2911c02bafffce5661eaec76a871fa`, CI run `30762486272`,
determinism run `30762486305`, and benchmark run `30762486292` succeeded. Holdout run `30762486314`
passed every product, PMD capture, sparse, schema, and coordinator job; its overall conclusion was
`failure` solely because the final-promotion refusal ran as designed. Coordinator artifact
`8837926338` (ZIP SHA-256
`60994dadd6c7395bbe451b869ccf86714d9aa741bcd97392b25f6793815c0ea3`) reproduced all seven
normalized files byte-identically across Ubuntu and Windows. Only `comparison-summary.json` and
its checksum binding changed; the report, metrics, delta, metadata, and truthful stage-one
attestation remained byte-identical.

Normal verification head `d880bd0a0495650a34ae2faa8521f170af80d7a9` then completed the protocol:
CI run `30763347889`, holdout/sparse run `30763347894`, determinism run `30763347908`, and extended
benchmark run `30763347910` all succeeded. CI passed 545 tests on each hosted operating system,
both package-smoke jobs and the 1k resource smoke passed, the holdout detector selected `normal`,
and artifact `8838184822` attested workflow/coordinator success plus cross-platform byte identity.
All twelve extended benchmark cells passed. Issues #16, #20, #21, #28, and #30 were closed with
this evidence. Issue #19 remains open because its acceptance criteria require a real tagged-commit
run, which this no-tag mission intentionally did not create.

Matcher-v3.2 promotion used a deliberate two-stage protocol. The first failed workflow authenticated
the unbound report bytes and recorded the failed workflow separately from its successful
coordinator. After those bytes were hash-bound, the second failed workflow regenerated the real
attested comparison/checksum bytes on Ubuntu and Windows. A subsequent strict run with the promoted
stage-two bytes is the normal reusable-workflow evidence consumed by the release gate. Every
download was selected by upload output ID and checked against its expected name, archive digest,
current run, and exact head through the Actions artifact API. Neither bootstrap stage is release
evidence.

After running a package script, the intended source-tree installation check is:

```bash
smoke_root="$(mktemp -d)"
trap 'rm -rf -- "${smoke_root}"' EXIT
mkdir -p -- "${smoke_root}/release"
cp -- \
  ./artifacts/release/SarifRegress.Tool.0.1.0-rc.1.nupkg \
  "${smoke_root}/release/"
cp -- ./NuGet.ReleaseSmoke.config "${smoke_root}/"
NUGET_PACKAGES="${smoke_root}/packages" \
dotnet tool install \
  --tool-path "${smoke_root}/tool" \
  --configfile "${smoke_root}/NuGet.ReleaseSmoke.config" \
  --no-cache \
  SarifRegress.Tool \
  --version 0.1.0-rc.1
"${smoke_root}/tool/sarif-regress" --help
installed_package="$(find "${smoke_root}/tool/.store" \
  -type f -iname 'sarifregress.tool.*.nupkg' -print -quit)"
test -n "${installed_package}"
cmp --silent -- \
  ./artifacts/release/SarifRegress.Tool.0.1.0-rc.1.nupkg \
  "${installed_package}"
```

`NuGet.ReleaseSmoke.config` clears every configured package source and names only the copied local
feed, so this check cannot fall back to a public source. This is a local package check, not evidence
of publication. The checksum manifest detects changed assets only when the manifest itself comes
from a trusted channel; assets, packages, and manifests are not currently signed and have no
publisher provenance attestation.

Current evidence proves deterministic project-owned reports, not reproducible package bytes.
Independent same-commit builds do not compare `.nupkg` or executable bytes, so no release should
claim reproducible binaries. Package smoke now runs one checked JSON/HTML-producing comparison
through every installed and self-contained form on Windows and Linux, verifies the exact report
contract, and requires the two distribution forms to emit identical bytes.

The release bundle now includes the top-level project licence and the exact audited dependency and
runtime notice material, all bound by the release checksum manifest. Packaging verifies physical
non-link artifact targets and rejects linked descendants before recursive cleanup; package CI
exercises a Linux symlink and a Windows junction against external canaries.

## Supply-chain and licence audit

- The project is MIT licensed and the `.nupkg` includes the repository `LICENSE`.
- The sole direct product package is `System.CommandLine 2.0.10`, pinned by the central package
  file and lock file. The self-contained builds also redistribute .NET runtime components.
- `THIRD_PARTY_NOTICES.md` records the exact product distribution graph, audited package/source
  identities, and primary upstream records. Verbatim retained files cover `System.CommandLine` and
  the .NET runtime/host packs; source and release manifests bind their exact bytes.
- The validation-only dependency chain tracked by #17 was removed from the central package file,
  validation project, and current lock files. Required schema validation now uses the
  repository-owned bounded evaluator and fails closed on unsupported vocabulary or resource-limit
  violations. This is the owner implementation disposition and makes no legal conclusion about
  packages that are no longer used.
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
- The tag-only job uses the repository-owned bounded Python REST client rather than a runner-provided
  release CLI. Tests run without the write token; only the invocation receives `contents: write`.
  Redirects are refused, asset names/digests are exact, and any authenticated partial draft is
  retained for explicit owner review rather than deleted automatically.

## Security audit

Positive controls include bounded streaming SARIF/configuration parsing, network URI refusal,
explicit URI-base validation, repository-relative no-link file opens, regular-file and UTF-8
checks, bounded explanations, escaped JSON/HTML, an offline Content Security Policy, transactional
multi-output writes, guarded non-link packaging cleanup, safe capture archive extraction, immutable
Action pins, and least-privilege workflow defaults.

The security claims must remain qualified by these unresolved or not-yet-verified findings:

- candidate scoring now applies the retained-edge cap to fixed-size descriptors before full
  explanation materialisation, and the exact-global-cap stress test passes locally, but final
  exact-head cross-platform verification remains for #22;
- repository contexts now retain a component-walked physical root capability, reject linked
  ancestors plus known remote/device roots, and keep later reads anchored across root replacement;
- `corpus run --json-out` now refuses lexical and physical destinations under its input tree;
- transactional output still has a hostile-parent TOCTOU window; and
- trusted side-specific source reads add independent digest manifests, immutable verified-byte
  caches, comment-blind bounded lexical extraction, wrong-root/mutation refusal, and filename-bound
  identity; renamed files remain unsupported;
- the dedicated sparse compositor independently authenticates and cross-binds every role artifact
  and derives the stable resource subset from the full volatile shape; final exact-head promotion
  remains an operational prerequisite.

See the top-level `SECURITY.md` for safe reporting. Do not attach private SARIF, source, secrets, or
exploit payloads to a public issue.

## Release issue disposition

GitHub issue state was checked on 2026-08-13. Code is not treated as release evidence until its
acceptance criteria and final exact-head run are recorded.

| Tracking | Blocker |
|---|---|
| #7 | Owner accepts hosted Ubuntu verification instead of the historical local-Linux checkbox |
| #11 | Filename-bound trusted snapshot design meets clean PMD identity gates; close after exact-head hosted verification |
| #12 | Stable legacy gate is formally unsatisfiable without forbidden order/cardinality leakage; close as not planned with ADR 0004, while retaining stable-channel block |
| #19 | Code, tests, draft-only client, and tag rules are complete; close only after the real tag-triggered run succeeds |
| #27 | Composite generator/workflow are complete; close after authenticated candidate promotion and strict rerun |

The remaining Medium findings listed in the adversarial review require release disposition:
lifecycle metric naming, vacuous precision, the hostile-parent atomic-output boundary, binary
reproducibility wording, configuration schema-v1 evolution, and durable retention of raw runtime
measurements. The owner accepts these documented limitations for a preview, not for a stable claim.

Issue #31 now has a reusable bounded deterministic `--check`/`--write` refresh command plus focused
tests and a required workflow freshness check. The current implementation and corpus inventories
must still be refreshed and exercised through the exact-head hosted evidence cascade before the
issue can close; historical metric bytes are not rebound by the inventory refresh.

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

The source tree is eligible only for the preview channel. Stable remains blocked by aggregate and
legacy-PMD recall plus the incomplete legacy label graph. Preview publication additionally waits
for the final exact-head gates, authenticated composite promotion, tag run, and draft inspection.

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
