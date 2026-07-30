# Command-line contract

The executable and .NET tool command is `sarif-regress`. Commands are local-only: they do not make
network requests, execute repository code, or infer a repository root from the current directory.

Use `sarif-regress <command> --help` for generated parser help.

## Streams and paths

Unless a command-specific output path is supplied, its primary JSON or SARIF document is written
to standard output. Supplying that output path makes standard output silent. Deterministically
formatted diagnostics are written to standard error.

Relative command-line paths are resolved from the invocation directory. A relative `repoRoot`
inside a configuration file is instead resolved from that file's directory. An explicit `--repo`
overrides `repoRoot`. Resolved ambient absolute paths are adapter state and are not copied into
stable reports.

An output cannot overwrite an input, and two output options cannot select the same file. Existing
parent-directory symbolic links and junctions are resolved for these identity checks. Compare and
multi-file benchmark outputs are staged and committed as one transaction so an I/O failure does
not leave a partial new report set.

## `compare`

```text
sarif-regress compare
  --baseline <path>
  --candidate <path>
  [--config <path>]
  [--repo <path>]
  [--json-out <path>]
  [--html-out <path>]
  [--sarif-out <path>]
```

`--baseline` and `--candidate` are required SARIF paths.

`--config` selects schema-versioned matching, policy, aliases, and resource limits. `--repo`
selects the only root from which bounded source context may be read. Repository reads still obey
`matching.enableRepoContext`.

Stable JSON is always the source comparison contract. Without `--json-out`, those bytes are
written to standard output. `--html-out` writes a static offline rendering produced only from the
JSON contract. `--sarif-out` writes canonical SARIF with SarifRegress-derived fingerprints in their
own namespace. Neither optional projection changes matching.

Exit `0` means comparison and configured policy passed. Exit `3` means comparison completed but a
classification named by `policy.failOn`, or an enabled GitHub-compatibility policy, failed. The
requested report is still available on exit `3`.

## `validate`

```text
sarif-regress validate
  --input <path>
  [--config <path>]
  [--repo <path>]
  [--json-out <path>]
```

`--input` is required. Validation covers the supported SARIF subset, bounded reference
resolution, deterministic project diagnostics, and the pinned advisory GitHub compatibility
profile. It does not claim to emulate GitHub ingestion.

The deterministic validation result is written to standard output unless `--json-out` is
supplied. A warning can describe unsupported or GitHub-ignored data without making an otherwise
safe input invalid. When `policy.treatGithubIncompatibilityAsError` is enabled, a GitHub-profile
warning makes `policyPassed` false and the command returns `1`. Malformed input, an unresolved
required reference, a security-boundary failure, or inaccessible I/O also returns `1`.

For a raw file, `compressedUploadSizeEvaluation` is `not-evaluated` and
`compressedUploadBytes` is `null`. SarifRegress does not recompress untrusted input merely to
predict GitHub's upload size. An embedding caller may supply an already measured gzip payload size.

## `canonicalise`

```text
sarif-regress canonicalise
  --input <path>
  [--config <path>]
  [--repo <path>]
  [--sarif-out <path>]
```

`--input` is required. The command parses and canonicalises the supported finding subset, then
emits deterministic SARIF. Derived values are written only under SarifRegress-namespaced
fingerprint names and never overwrite a producer-owned name. The projection identifies
SarifRegress as its driver and retains original producer family/name/version as run properties. It
does not add a comparison classification or `baselineState`, because no baseline/candidate match
has occurred.

Canonical SARIF is written to standard output unless `--sarif-out` is supplied.

## `corpus run`

```text
sarif-regress corpus run
  [--corpus <path>]
  [--json-out <path>]
```

`--corpus` defaults to `corpus` relative to the invocation directory. Cases are visited in stable
ordinal order. The stable LF/no-BOM JSON report is written to standard output unless `--json-out`
is supplied.

Exit `0` requires all of:

- precision at least `0.95`;
- recall at least `0.90`;
- exact expected matched classifications, new, resolved, and ambiguous sets;
- no unexpected invalid input;
- every selected exact diagnostic and explanation expectation;
- zero silently matched labelled ambiguity.

A completed evaluation below a quality gate returns `3`. Invalid corpus structure or I/O returns
`1`.

## `bench`

```text
sarif-regress bench
  [--size <1000|10000|100000>]
  [--dataset <unique|pathological>]
  [--enforce-budgets]
  [--json-out <path>]
  [--deterministic-out <path>]
```

Defaults are `--size 1000 --dataset unique`. Other size or dataset values are invalid usage and
return `1`.

`unique` measures scaling when findings have distinct coarse identities. `pathological` places
many findings in the same producer/rule/file bucket to exercise pair and assignment limits. A
budget excess is recorded as a bounded refusal; the harness never scores a truncated prefix or
changes matching policy based on elapsed time.

The report contains measured candidate-bucket and component-size distributions, classification
counts, explanation bytes, comparison-output bytes and SHA-256, diagnostic codes, throughput,
allocation, and process working-set observations. Deterministic operation/hash fields are suitable
for cross-platform gates. Runtime observations remain explicit because shared runners and local
machines vary.

`--deterministic-out` writes a separate, versioned JSON projection containing only dataset
identity, limits, deterministic operation counts, comparison-output identity, and fixed budget
ceilings. It excludes runtime observations and observation-derived pass/failure fields. The
projection is emitted directly by SarifRegress as UTF-8 without BOM with a final LF, so
cross-platform checks compare its raw bytes without parsing or reserializing it.

When `--json-out` and `--deterministic-out` are both supplied, the paths must be distinct and the
files are staged together before either destination is replaced. If `--json-out` is omitted, the
full benchmark report is still written to standard output.

`--enforce-budgets` applies the published ceiling for the selected size and returns `3` after
writing the report when latency, peak working set, or the pathological bounded-refusal condition
fails. CI uses this flag for the 1,000-finding smoke datasets.

## Stable exit codes

| Code | Contract |
|---:|---|
| `0` | Processing completed and policy or quality gates passed |
| `1` | Invalid command, input, configuration, validation, security boundary, or I/O |
| `2` | Reserved bootstrap placeholder code |
| `3` | Completed comparison policy, corpus quality, or enforced benchmark-budget failure |
| `4` | Internal invariant failure |

Parser errors are actionable and non-zero. Internal exception details are not emitted into stable
diagnostics.
