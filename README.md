# SarifRegress

[![CI](https://github.com/ppcdaniel/sarif-regress/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ppcdaniel/sarif-regress/actions/workflows/ci.yml)
[![Cross-platform determinism](https://github.com/ppcdaniel/sarif-regress/actions/workflows/determinism.yml/badge.svg?branch=main)](https://github.com/ppcdaniel/sarif-regress/actions/workflows/determinism.yml)

**Explainable, deterministic regression matching for SARIF 2.1.0.**

SarifRegress compares a baseline analysis run with a candidate run and answers the useful question:
is this the same finding after code, paths, line numbers, messages, or tool metadata changed? It
produces deterministic one-to-one decisions, refuses unsafe ambiguity, and explains the evidence
behind every result.

> [!NOTE]
> SarifRegress is pre-release. Build from source until the first tagged release is published.

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

The animation runs the real CLI. `jq` only condenses the generated stable JSON for display; it does
not perform matching. The [capture recipe](https://github.com/ppcdaniel/sarif-regress/tree/main/docs/assets/readme)
asserts the exact result before rendering the asset.

| Rule | Baseline | Candidate | Result | Decision |
|---|---:|---:|---|---|
| `eslint/eqeqeq` | 2 | 3 | `moved` | high-confidence `exact-canonical` |
| `eslint/no-eval` | 3 | 4 | `moved` | high-confidence `exact-canonical` |

![Generated SarifRegress HTML report showing the comparison summary](https://raw.githubusercontent.com/ppcdaniel/sarif-regress/main/docs/assets/readme/eslint-line-shift-report.png)

The screenshot is an unmodified browser capture of the offline HTML emitted by `--html-out`.

## Try it from source

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
and self-contained Linux and Windows binaries. The .NET tool requires a compatible .NET 10 runtime;
the standalone binaries do not.

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

The public corpus gates precision at `0.95`, recall at `0.90`, exact classifications and diagnostics,
zero silently matched labelled ambiguity, and byte-identical approved Windows/Linux reports.

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
| Evaluation and interoperability | [Corpus](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/corpus.md) · [GitHub profile](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/github-compatibility.md) |

The supplied [architecture](https://github.com/ppcdaniel/sarif-regress/blob/main/docs/architecture.md)
is the source of truth. SarifRegress is not a hosted service, general SARIF viewer, or automatic
source-fixing tool.

## License

[MIT](https://github.com/ppcdaniel/sarif-regress/blob/main/LICENSE)
