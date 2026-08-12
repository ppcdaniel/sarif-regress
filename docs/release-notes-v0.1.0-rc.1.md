# SarifRegress 0.1.0-rc.1 release notes

Status: **preview release; stable channel blocked**

This preview is intended for evaluation in CI and local developer workflows. It is not described as
a stable or broadly validated release.

## What is included

SarifRegress compares baseline and candidate SARIF 2.1.0, produces deterministic one-to-one
correspondence, classifies continued/new/resolved findings, refuses equal semantic assignments,
and emits stable JSON with optional offline HTML and canonical SARIF projections.

The preview contains:

- product version `0.1.0-rc.1`;
- matcher `sarifregress/matcher/v3.2`;
- trusted source identity `trusted-filename-lexical-context/v1`;
- configuration and output schema version `1`; and
- .NET SDK `10.0.302`, with self-contained .NET runtime `10.0.10` distributions.

## Fingerprint-free SARIF continuity

`compare` can now bind the baseline and candidate to separate read-only source snapshots:

```text
sarif-regress compare \
  --baseline baseline.sarif \
  --candidate candidate.sarif \
  --baseline-repo baseline-source \
  --baseline-snapshot-manifest baseline-manifest.json \
  --candidate-repo candidate-source \
  --candidate-snapshot-manifest candidate-manifest.json
```

All four side-specific options are required together. Each manifest maps canonical relative paths
to lowercase SHA-256 digests of the exact raw source bytes. Reads are handle-relative beneath a
retained physical root, digest-checked before UTF-8 decoding, immutable for the comparison, and
bounded in file and aggregate memory.

The derived atom strips comments and combines the method-like scope header, exact single-line
statement, and case-sensitive final filename. It supports directory moves that retain the filename.
It deliberately refuses file renames, digest drift, missing files, repeated equal atoms, unsafe
roots, and over-budget input.

On the separately designed clean PMD 7.26.0 corpus, the fixed filename-bound result is:

| Metric | Result |
|---|---:|
| Relationships | 18 TP / 0 FP / 1 FN |
| Precision | 1.000000 |
| Recall | 0.947368 |
| F1 | 0.972973 |
| Labelled ambiguity auto-matched | 0 |
| Expected new / resolved recovered | 3 / 3 and 3 / 3 |

The single missed relationship renames both its file and enclosing type. Six repeated ambiguity
endpoints are explicitly ambiguous; three method-renamed ambiguity endpoints remain new/resolved
because no equal identity atom exists.

## Scientific limitation

The frozen legacy PMD holdout contains five 5-by-5 repeated groups labelled as 25 distinct
relationships and one observationally equivalent 2-by-2 group labelled ambiguous. Without marker,
source-order, input-order, cardinality, or corpus-name leakage, each group is a complete equal-edge
bipartite graph. Safe uniqueness therefore recovers 0/25 legacy PMD pairs; ordering them recovers
25/25 but also creates the two forbidden false pairs and drops precision to 0.925926.

The project preserves those labels and thresholds. It does not claim the unobservable legacy
diagonal is solved, does not create matcher v4, and does not weaken ambiguity policy. See
`docs/decisions/0004-duplicate-symmetry-boundary.md`.

The existing exposed holdout remains 50 TP / 0 FP / 25 FN: Semgrep and Gitleaks are each 25/25;
legacy PMD is 0/25. Aggregate precision is 1.0 and recall is 0.666667. This is post-hoc regression
evidence, not a new independent generalisation claim.

## Authenticated experiment evidence

A dedicated manual compositor now cross-binds the exact successful holdout, determinism, and
12-cell resource runs. It authenticates the source SHA, workflow path, run status, artifact
ID/name/digest, complete coordinator manifests, raw report hashes, Windows/Linux comparisons, and
the full-resource-to-stable projection derivation. The authenticated roles share source head
`4838532f5e808f97bf8804b772d153d294181aee`: holdout run `31638319042`, determinism run
`31638319041`, and benchmark run `31638349628`. Compositor run `31638669221` emitted promoted
candidate artifact `9157965667` with archive digest
`48bfb81237357c80e3d42a4913ecb256b913675a6da767a0966fecc8c50f18b5`. The promoted output is
deterministic, atomic, and independently checked by the existing contamination scanner.

The resulting experiment decision remains `document-limitation`. Stronger provenance does not
change failed metrics or authorise matcher v4.

## Release integrity and security

- Release tags are protected from update and deletion; tag creation is restricted to the owner.
- The tag workflow binds the exact tagged commit to exact-head holdout evidence and channel policy.
- Release creation is draft-only inside the workflow. The repository-owned client refuses HTTP
  redirects, streams a fixed asset allowlist, checks every GitHub-reported SHA-256 digest, and
  retains any authenticated partial draft for explicit owner review rather than racing publication
  with an automatic delete.
- The NuGet package and release bundle contain the project licence and audited dependency/runtime
  notices. `checksums.sha256` covers every other distributed file; the manifest is authenticated
  by the immutable release asset set and tag workflow.
- Product comparison is local: it makes no network request, executes no repository code, restores
  no analysed-repository package, and sends no telemetry.

The checksum manifest is not a signature. Executables are not code-signed, and independent build
byte reproducibility has not been established. Obtain assets only from the GitHub release page and
verify `checksums.sha256` plus `source-commit.txt` against the immutable tag.

## Assets

The release bundle contains exactly:

- `SarifRegress.Tool.0.1.0-rc.1.nupkg`;
- self-contained `sarif-regress-linux-x64` and `sarif-regress-win-x64.exe`;
- four deterministic benchmark JSON files and `corpus-report.json`;
- project, System.CommandLine, and .NET runtime licence/notice files;
- `source-commit.txt`; and
- `checksums.sha256`.

The .NET tool requires a compatible .NET 10 runtime. The standalone executables do not.

## Compatibility

Existing commands and shared `--repo`/configured `repoRoot` behavior remain unchanged. The new
side-specific options cannot be mixed with those shared-root inputs. Stable exit codes remain `0`,
`1`, `3`, and `4`; code `2` remains reserved.
