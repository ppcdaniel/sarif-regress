# SarifRegress

[![CI](https://github.com/ppcdaniel/sarif-regress/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ppcdaniel/sarif-regress/actions/workflows/ci.yml)
[![Cross-platform determinism](https://github.com/ppcdaniel/sarif-regress/actions/workflows/determinism.yml/badge.svg?branch=main)](https://github.com/ppcdaniel/sarif-regress/actions/workflows/determinism.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](https://github.com/ppcdaniel/sarif-regress/blob/main/LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512bd4.svg)](https://github.com/ppcdaniel/sarif-regress/blob/main/global.json)

**Explainable, deterministic regression matching for SARIF 2.1.0.**

SarifRegress compares a baseline analysis run with a candidate run and answers the useful question:
is this the same finding after code, paths, line numbers, messages, or tool metadata changed? It
produces deterministic one-to-one decisions, refuses unsafe ambiguity, and explains the evidence
behind every result.

> [!NOTE]
> SarifRegress is pre-release. Build from source until the first tagged release is published. The
> supported fingerprint/context profile is ready for evaluation; sparse fingerprint-free SARIF is
> intentionally conservative and remains a documented limitation.

| What you get | Contract |
|---|---|
| Regression lifecycle | `new`, `unchanged`, `moved`, `modified`, `resolved`, or explicitly `ambiguous` |
| Auditable evidence | Stable JSON decision traces plus offline HTML and canonical-SARIF projections |
| Repeatability | Ordinal ordering, versioned hashes, transactional outputs, and Windows/Linux byte checks |
| Bounded execution | 1k, 10k, and 100k gates; no repository-code execution, package restore, telemetry, or network fetches |

## Same finding, different line

This controlled fixture uses real ESLint 8.57.1 output produced through Microsoft's SARIF
formatter. The candidate adds one comment; the analysed code is otherwise unchanged.

**Before** ([source](https://github.com/ppcdaniel/sarif-regress/blob/main/corpus/cases/eslint-real-mutation/producer-input/baseline.js))

```javascript
function compare(userInput, expected) {
  if (userInput == expected) {
    return eval(userInput);
  }

  return null;
}

compare("1", "1");
```

**After** ([source](https://github.com/ppcdaniel/sarif-regress/blob/main/corpus/cases/eslint-real-mutation/producer-input/candidate.js))

```javascript
// Controlled mutation: insert one source line.
function compare(userInput, expected) {
  if (userInput == expected) {
    return eval(userInput);
  }

  return null;
}

compare("1", "1");
```

SarifRegress preserves both identities: `eqeqeq` moves from line 2 to 3, and `no-eval` moves from
line 3 to 4. Neither is misreported as new or resolved.

![Terminal demo showing two real ESLint findings classified as moved](https://raw.githubusercontent.com/ppcdaniel/sarif-regress/main/docs/assets/readme/eslint-line-shift-terminal.gif)

The single-pass animation replays an authentic CLI run. `jq` only condenses the generated stable
JSON for display; it does not perform matching. The [capture recipe](https://github.com/ppcdaniel/sarif-regress/tree/main/docs/assets/readme)
asserts the exact result before rendering the asset; the table below is its static equivalent.

| Rule | Baseline | Candidate | Result | Decision |
|---|---:|---:|---|---|
| `eslint/eqeqeq` | 2 | 3 | `moved` | high-confidence `exact-canonical` |
| `eslint/no-eval` | 3 | 4 | `moved` | high-confidence `exact-canonical` |

![Generated SarifRegress HTML report showing the comparison summary](https://raw.githubusercontent.com/ppcdaniel/sarif-regress/main/docs/assets/readme/eslint-line-shift-report.png)

![Generated report showing the first moved finding and its decision](https://raw.githubusercontent.com/ppcdaniel/sarif-regress/main/docs/assets/readme/eslint-line-shift-evidence.png)

The summary is an unmodified browser capture of the offline HTML emitted by `--html-out`; the
finding image is a deterministic crop from the same generated report. It confirms a high-confidence
`exact-canonical` decision with ambiguity explicitly false.

## Quick start

The repository pins .NET SDK `10.0.302` in `global.json`.

```bash
git clone https://github.com/ppcdaniel/sarif-regress.git
cd sarif-regress
./scripts/build.sh

dotnet run \
  --project src/SarifRegress.Cli/SarifRegress.Cli.csproj \
  --configuration Release \
  --no-build \
  --no-restore \
  -- \
  compare \
  --baseline corpus/cases/eslint-real-mutation/baseline.sarif \
  --candidate corpus/cases/eslint-real-mutation/candidate.sarif \
  --json-out artifacts/demo/report.json \
  --html-out artifacts/demo/report.html
```

On Windows, use `.\scripts\build.ps1` from PowerShell. When tagged releases are available, the
[release page](https://github.com/ppcdaniel/sarif-regress/releases) will provide a .NET tool package
and self-contained Linux x64 and Windows x64 binaries. The .NET tool requires a compatible .NET 10
runtime; the standalone binaries do not.

For an installed command, the normal comparison shape is:

```bash
sarif-regress compare \
  --baseline baseline.sarif \
  --candidate candidate.sarif \
  --json-out report.json \
  --html-out report.html \
  --sarif-out canonical.sarif
```

Stable JSON is the source of truth. HTML consumes that JSON contract and never calls the matcher;
canonical SARIF is a separate projection. Multi-output writes are transactional.

## Classifications

| Classification | Meaning |
|---|---|
| `new` | A candidate finding has no safe baseline match. |
| `unchanged` | Identity, logical location, and context remain materially stable. |
| `moved` | The same finding moved by path or region. |
| `modified` | Identity continues, but message, context, or flow changed materially. |
| `resolved` | A baseline finding has no safe candidate match. |
| `ambiguous` | Equal or unsafe alternatives are explicitly refused. |

## Why SarifRegress

- **Explainable:** every decision records evidence, transformations, rejected alternatives, and
  diagnostics.
- **Deterministic:** stable reports use explicit ordering, versioned hashes, LF line endings, and
  byte checks across Windows and Linux.
- **Conservative:** matching is globally one-to-one; semantic ties are never broken by array order.
- **Local and bounded:** SARIF and optional repository context are treated as untrusted input. The
  tool performs no network requests, analysed-repository package restore, repository-code
  execution, or telemetry.

Automatic matching is intended for the same producer family while allowing tool-version changes.
Cross-producer rule equivalence requires an explicit alias and still needs qualifying path and
context evidence. GitHub code-scanning compatibility checks are advisory, not an ingestion emulator.

The supported automatic-evidence profile includes a reliable non-colliding producer fingerprint;
reliable embedded context or bounded token context read from the one shared approved repository
root; a manifest-verified filename and lexical atom from separate baseline/candidate roots; or safe
URI-base resolution combined with another qualifying identity signal. URI mapping is path
interpretation, not identity proof. The side-specific mode hashes exact source bytes against an
independent manifest, ignores comments, supports same-filename directory moves, and refuses renamed
files or repeated equal atoms rather than ordering them. Findings with no reliable fingerprint, no
embedded snippet, no trusted source snapshot, and only non-unique
rule/path/message/location evidence are intentionally left unmatched.
Matcher v3.2 enforces the two previously open safety boundaries: conflicting context vetoes
collided or weak admission, and code-flow anchors cannot admit an edge. Normal-mode holdout run
`30763347894` succeeded on exact head `d880bd0a0495650a34ae2faa8521f170af80d7a9`, reproducing
the committed reports byte-for-byte on hosted Ubuntu and Windows. CI run `30763347889`, determinism
run `30763347908`, and all twelve extended benchmark cells in run `30763347910` also succeeded on
that historical head. Stable release remains blocked by the frozen legacy recall and label-graph
gates. `v0.1.0-rc.1` is preview-eligible only after its final exact-head workflows, authenticated
composite promotion, immutable tag run, and draft inspection succeed.

The public corpus gates precision at `0.95`, recall at `0.90`, exact classifications and diagnostics,
zero silently matched labelled ambiguity, and byte-identical approved Windows/Linux reports.

The [independent matcher-v2 holdout](docs/independent-validation.md)
and [v3/v3.1/v3.2 generalisation report](docs/real-producer-generalisation.md)
preserve 75 known relationships from Gitleaks 8.30.1, PMD 7.26.0, and Semgrep 1.172.0. Matcher v2's
`0 TP / 0 FP / 75 FN` run is the independent baseline. After those labels informed implementation,
v3/v3.1/v3.2 provide exposed-holdout regression evidence: Semgrep and Gitleaks each recover all 25
identities, v3.1 corrects the five classification mismatches, and v3.2 tightens context and
code-flow admission without changing the frozen labels or thresholds. The aggregate remains
`50 TP / 0 FP / 25 FN` (precision `1.0`, recall `0.666667`, F1 `0.8`). A separately designed clean
PMD research corpus originally reached `9 TP / 0 FP / 10 FN`. The subsequently predeclared,
digest-bound filename/lexical design reaches `18 TP / 0 FP / 1 FN` (precision `1.0`, recall
`0.947368`) on that clean corpus, with zero labelled ambiguity auto-matched. The one refused
relationship renames both the file and enclosing type, while the frozen legacy PMD repetition
remains formally symmetric and cannot be paired without an unsafe order/cardinality rule. The
[hash-bound interpretation erratum](validation/holdout/interpretation-erratum.json) qualifies the
legacy v3/v3.1 report labels without changing their metrics or frozen bytes and binds the exact
matcher-v3.2 exposed-holdout report. Matcher v4 was not created; the new source identity has its own
`trusted-filename-lexical-context/v1` contract and does not alter matching for existing callers.

## Commands

| Command | Purpose |
|---|---|
| `compare` | Compare baseline and candidate SARIF and apply regression policy. |
| `validate` | Validate SARIF and report supported-subset diagnostics. |
| `canonicalise` | Write deterministic canonical SARIF. |
| `corpus run` | Evaluate labelled cases and enforce quality gates. |
| `bench` | Run bounded 1k, 10k, or 100k synthetic datasets. |

The [CLI reference](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/cli.md) documents every
option. Stable exit codes are `0` for success, `1` for command/input errors, `3` for a completed run
whose policy failed, and `4` for an internal invariant failure; `2` remains reserved. A policy failure
still writes the requested comparison report.

## Develop

Run the complete platform verification command before committing:

```bash
./scripts/verify.sh
```

```powershell
.\scripts\verify.ps1
```

Both restore locked dependencies, verify formatting, build Release with warnings as errors, and run
the complete test suite. See [CONTRIBUTING.md](https://github.com/ppcdaniel/sarif-regress/blob/main/CONTRIBUTING.md)
for contributor workflow and [docs/releasing.md](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/releasing.md)
for packaging and release verification.

## Documentation

| Topic | Reference |
|---|---|
| Architecture and matching policy | [Architecture](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/architecture.md) · [ADR 0001](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/decisions/0001-mvp-determinism-security-and-matching-policy.md) |
| Configuration | [Guide](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/configuration.md) · [Schema](https://github.com/ppcdaniel/sarif-regress/blob/main/schemas/config.schema.json) |
| JSON, HTML, and SARIF output | [Output contract](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/output-contract.md) · [Schema](https://github.com/ppcdaniel/sarif-regress/blob/main/schemas/output.schema.json) |
| Security and resource limits | [Security](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/security.md) · [Budgets](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/resource-budgets.md) |
| Evaluation and interoperability | [Corpus](docs/corpus.md) · [Independent holdout](docs/independent-validation.md) · [v3/v3.1/v3.2 generalisation](docs/real-producer-generalisation.md) · [Side-specific-context ADR](docs/decisions/0003-side-specific-repository-context-experiment.md) · [Duplicate-symmetry boundary](docs/decisions/0004-duplicate-symmetry-boundary.md) · [Frozen clean-corpus protocol](validation/research/sparse-sarif/README.md) · [GitHub profile](docs/github-compatibility.md) |

The dedicated sparse composite workflow authenticates exact successful role runs and artifact
IDs/digests, independently checks every raw coordinator byte, derives the stable resource
projection, and emits one deterministic v2 evidence bundle. Its document-limitation decision does
not authorize matcher v4 or change the frozen legacy labels.

The supplied [architecture](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/architecture.md)
is the source of truth. SarifRegress is not a hosted service, general SARIF viewer, or automatic
source-fixing tool.

## License

[MIT](https://github.com/ppcdaniel/sarif-regress/blob/main/LICENSE)
