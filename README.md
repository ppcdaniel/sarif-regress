# SarifRegress

SarifRegress is a CLI-first, local-first engine for explaining whether findings in two SARIF 2.1.0
runs represent the same underlying issue after paths, line numbers, messages, source context, tool
versions, or producer metadata change.

Its thesis is deliberately falsifiable: conservative, deterministic one-to-one matching should
preserve identity across non-semantic changes, refuse unsafe ambiguity, explain every decision,
and produce byte-stable JSON on Windows and Linux.

The architectural source of truth is [docs/architecture.md](docs/architecture.md). The stable JSON
and configuration contracts are independently versioned at schema version `1`.

## MVP capabilities

The MVP surface:

- streams and validates the comparison-relevant SARIF 2.1.0 subset;
- canonicalises POSIX, URI, Windows drive, drive-relative, UNC, and device-path forms;
- resolves artifact indexes and bounded URI-base chains;
- preserves producer fingerprints and derives separately versioned SarifRegress fingerprints;
- optionally reads bounded, read-only source context from an explicitly approved repository root;
- performs deterministic maximum-cardinality, lexicographic one-to-one assignment;
- classifies findings as `new`, `unchanged`, `moved`, `modified`, `resolved`, or `ambiguous`;
- emits structured evidence, transformations, rejected alternatives, and diagnostics;
- uses stable JSON as the source of truth, with optional static HTML and canonical SARIF projections;
- checks the documented GitHub code-scanning subset as an advisory compatibility profile;
- evaluates a labelled corpus against precision, recall, classification, and ambiguity gates;
- provides bounded synthetic benchmark datasets and checksummed release packaging.

Automatic matching uses a collision-resistant producer identity and permits tool-version changes;
the readable producer family is display metadata, not the match key. Cross-producer rule
equivalence requires an explicit `ruleAliases` entry and still needs both a qualifying path and
exact context evidence. Equal semantic alternatives are never resolved by array order.

## Non-goals

SarifRegress does not:

- provide a hosted service, account system, database, collaborative triage product, or IDE extension;
- replace analysers or act as a general-purpose SARIF viewer;
- emulate GitHub code-scanning ingestion completely;
- infer cross-producer equivalence without explicit mappings;
- use an LLM, opaque machine-learning score, or a greedy order-dependent matcher;
- execute repository code, restore its packages, invoke language servers, or fetch network URIs;
- perform automatic source fixes or provide a universal severity taxonomy;
- support every optional SARIF feature in the MVP;
- use Native AOT.

## Prerequisites

The repository pins .NET SDK `10.0.302` in `global.json` with roll-forward disabled.

Windows contributors need:

- a Windows version supported by the pinned SDK;
- the pinned .NET 10 SDK;
- PowerShell 5.1 or later;
- Git.

Linux and CI contributors need:

- a Linux distribution supported by .NET 10;
- the pinned .NET 10 SDK;
- Bash, `sha256sum`, and Git;
- PowerShell only when explicitly validating the PowerShell scripts on Linux.

The framework-dependent .NET tool also needs a compatible .NET 10 runtime. The Windows and Linux
self-contained release binaries do not.

## Quick start

Compare two files and write stable JSON to standard output:

```bash
sarif-regress compare \
  --baseline baseline.sarif \
  --candidate candidate.sarif
```

On PowerShell, select repository context and all report projections explicitly:

```powershell
sarif-regress compare `
  --baseline baseline.sarif `
  --candidate candidate.sarif `
  --repo C:\work\project `
  --config config\regress.json `
  --json-out artifacts\report.json `
  --html-out artifacts\report.html `
  --sarif-out artifacts\canonical.sarif
```

When `--json-out` is omitted, JSON is written to standard output. When it is supplied, standard
output is silent. Diagnostics use deterministic lines on standard error. Multi-file report output
is transactional: an output failure does not leave a partial set of new reports or overwrite an
input.

Existing parent-directory links and junctions are resolved for output identity checks, so two
lexically different options cannot silently select one physical destination.

## Commands

| Command | Purpose |
|---|---|
| `compare` | Compare baseline and candidate SARIF and apply regression policy |
| `validate` | Validate one SARIF input and report supported-subset and GitHub-profile diagnostics |
| `canonicalise` | Project one input into deterministic canonical SARIF |
| `corpus run` | Evaluate labelled cases and enforce the published quality gates |
| `bench` | Run a bounded synthetic benchmark dataset |

The complete option and output contract is in [docs/cli.md](docs/cli.md). The concise forms are:

```text
sarif-regress compare --baseline <path> --candidate <path>
  [--config <path>] [--repo <path>]
  [--json-out <path>] [--html-out <path>] [--sarif-out <path>]

sarif-regress validate --input <path>
  [--config <path>] [--repo <path>] [--json-out <path>]

sarif-regress canonicalise --input <path>
  [--config <path>] [--repo <path>] [--sarif-out <path>]

sarif-regress corpus run [--corpus <path>] [--json-out <path>]

sarif-regress bench
  [--size <1000|10000|100000>]
  [--dataset <unique|pathological>]
  [--enforce-budgets]
  [--json-out <path>]
  [--deterministic-out <path>]
```

`corpus run` defaults to `corpus` relative to the invocation directory. `bench` defaults to
`--size 1000 --dataset unique`. The pathological benchmark records bounded refusal when a work
budget is exceeded; it never changes matching policy to improve a timing result.
`--enforce-budgets` returns `3` when the published latency, working-set, or bounded-refusal gate
fails after writing the benchmark report. `--deterministic-out` writes the first-class stable
benchmark projection used for raw Windows/Linux byte comparison.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Command completed and its configured policy or quality gates passed |
| `1` | Command syntax, input, configuration, validation, or I/O error |
| `2` | Reserved for the historical bootstrap placeholder; completed MVP commands do not use it |
| `3` | Comparison policy, corpus quality, or enforced benchmark budget failed |
| `4` | Internal invariant failure |

A `compare` invocation still writes its requested report before returning `3`, so CI can inspect
the exact regressions that failed policy.

## Configuration and path resolution

Configuration is JSON validated against [schemas/config.schema.json](schemas/config.schema.json).
See [docs/configuration.md](docs/configuration.md) for every section and bound.

Path resolution is explicit:

- command-line relative paths are resolved from the invocation directory;
- a relative `repoRoot` inside a configuration file is resolved from that configuration file's
  directory;
- `--repo` overrides `repoRoot`;
- the current directory is never selected as repository context merely because it exists;
- aliases and rebases match complete path-segment prefixes, with the longest match winning;
- equal conflicting prefixes are invalid configuration.

Repository context is optional, bounded, read-only, and contained beneath the approved root.

## Determinism and matching

Stable reports use UTF-8 without a byte-order mark, LF line endings, explicit property order,
ordinal sorting, invariant formatting, and versioned algorithms. They contain no generated
timestamp, process identifier, machine name, random value, or ambient absolute path.

The matcher commits reliable, unique exact evidence first, splits remaining candidate edges into
bipartite components, and chooses the lexicographically best maximum-cardinality one-to-one
assignment. Stable finding keys order work and output only. If equal semantic assignments remain,
the affected component is `ambiguous`; it is not silently matched.

See [docs/output-contract.md](docs/output-contract.md) and
[ADR 0001](docs/decisions/0001-mvp-determinism-security-and-matching-policy.md).

## Corpus and quality gates

Corpus labels record expected pairs, classifications, ambiguity, new findings, resolved findings,
intentionally invalid inputs, exact diagnostic sets where selected, and structured explanation
goldens. Passing the MVP gate requires:

- precision of at least `0.95`;
- recall of at least `0.90`;
- exact expected matched classifications, new, resolved, and ambiguous sets;
- no unexpected invalid inputs;
- every selected diagnostic and explanation golden to match exactly;
- zero silently matched labelled ambiguity.

The corpus report is stable LF/no-BOM JSON. The cross-platform workflow produces it independently
on Windows and Linux, then compares the report bytes and SHA-256 hashes in a separate coordinator
job. Each case embeds its complete comparison or invalid-diagnostic artifact. The workflow also
compares the deterministic benchmark projection, including the generated comparison-report hash.
See [docs/corpus.md](docs/corpus.md).

## Build, test, lint, verify, and package

Scripts locate the repository relative to their own file, so they work from any current directory.
The examples below assume the repository root; from elsewhere, invoke the script through its
checkout path.

Windows:

```powershell
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\verify.ps1
.\scripts\package.ps1
```

Linux:

```bash
./scripts/build.sh
./scripts/test.sh
./scripts/verify.sh
./scripts/package.sh
```

The reproducible lint/format check on either platform is:

```bash
dotnet restore SarifRegress.slnx --locked-mode
dotnet format SarifRegress.slnx --no-restore --verify-no-changes
```

`verify` restores locked dependencies, checks formatting, performs a deterministic Release build
with warnings as errors, and runs the complete solution. `package` performs a locked Release pack
and produces:

- `SarifRegress.Tool.<version>.nupkg`;
- `sarif-regress-linux-x64`;
- `sarif-regress-win-x64.exe`;
- `checksums.sha256`.

The release bundle is under `artifacts/release/`. Packaging uses normal .NET tool and self-contained
single-file publish modes, not trimming, ReadyToRun, or Native AOT. See
[docs/releasing.md](docs/releasing.md).

## Installation

After the tool package is available from a configured NuGet feed:

```bash
dotnet tool install --global SarifRegress.Tool --version 0.1.0
```

To test a locally built package:

```bash
dotnet tool install \
  --tool-path ./artifacts/tool \
  --add-source ./artifacts/release \
  SarifRegress.Tool \
  --version 0.1.0
```

Alternatively, download the matching self-contained binary and `checksums.sha256` from a tagged
GitHub release, verify its SHA-256 digest, and on Linux mark the downloaded binary executable if
the transfer did not preserve its mode.

## Current status

The MVP implementation is tracked under Issue #3 and remains pre-release until its draft pull
request is reviewed and a release is tagged. Verification state belongs to the corresponding
GitHub Actions runs; this README does not claim a particular unpublished run or release succeeded.

## Licence

SarifRegress is available under the [MIT License](LICENSE).
