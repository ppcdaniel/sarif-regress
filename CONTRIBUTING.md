# Contributing to SarifRegress

SarifRegress welcomes focused changes that preserve the boundaries, deterministic behavior,
security model, and measurable acceptance criteria in [docs/architecture.md](docs/architecture.md).

## Setup

Install:

- Git;
- the exact stable .NET SDK pinned in `global.json`;
- PowerShell 5.1 or later on Windows, or Bash on Linux;
- `sha256sum` on Linux when creating release packages.

Confirm the SDK before changing source:

```text
dotnet --version
```

The project uses locked NuGet dependencies. Do not regenerate a lock file unless a dependency,
target framework, runtime identifier, or project graph intentionally changed.

## Branch and pull-request workflow

1. Start from the branch named by the active issue or from an up-to-date `main`.
2. Create a focused branch such as `issue-42-short-description`.
3. Implement only the issue's acceptance criteria.
4. Add deterministic tests for every observable behavior introduced or changed.
5. Run the platform verification command below.
6. Run `git diff --check` and review the complete diff for generated or unrelated files.
7. Open a pull request that links the issue and records exact commands and outcomes.

Do not broaden scope without a tracked issue. Issue #3 is the repository-owner-authorised
dependency-ordered exception for completing the architecture; its checklist may be updated only
after the corresponding acceptance criteria have been directly verified.

Do not commit `bin`, `obj`, `artifacts`, test results, coverage, benchmark output, package caches,
IDE state, generated user files, private SARIF, or secrets. Do not use `--no-verify`, force-push
`main`, or conceal a failing verification result.

## Required local verification

Windows:

```powershell
.\scripts\verify.ps1
```

Linux:

```bash
./scripts/verify.sh
```

This is the single required local gate. It restores in locked mode, checks formatting, builds the
complete solution in Release with warnings as errors, and runs every test.

To run only the reproducible lint/format check after a locked restore:

```text
dotnet format SarifRegress.slnx --no-restore --verify-no-changes
```

Changes to release packaging should additionally run the platform package script:

```powershell
.\scripts\package.ps1
```

```bash
./scripts/package.sh
```

Verify `artifacts/release/checksums.sha256` before distributing any output. A package command is not
a substitute for the required verification command.

## Deterministic changes

Observable behavior must not depend on time, randomness, locale, machine identity, current
directory, dictionary or filesystem enumeration order, or environment-specific absolute paths.
Use ordinal comparison, explicit stable ordering, invariant formatting, UTF-8 without BOM, and LF
line endings.

Tests must compare exact bytes across repeated invocations. Add Windows/Linux fixtures when an
operating-system path, newline, culture, encoding, executable, or filesystem behavior is relevant.
Stable identity keys may order work and output but must not resolve a semantic tie.

Matching changes require:

- focused one-to-one assignment and ambiguity tests;
- an incremented matcher algorithm version when classifications can change;
- a before/after labelled-corpus comparison;
- release notes describing the behavioral change.

## Corpus contributions

Each case belongs below `corpus/cases/<case-name>/` and should include baseline and candidate SARIF,
`labels.json`, notes, and only the bounded repository/config fixtures needed by that case. Labels
must describe the expected pairing graph and classifications, not summary counts alone.

Corpus additions must preserve:

- precision at least `0.95`;
- recall at least `0.90`;
- exact expected matched classifications, new, resolved, and ambiguous sets;
- zero silently matched labelled ambiguity;
- byte-identical approved Windows/Linux corpus reports.

See [docs/corpus.md](docs/corpus.md) and
[corpus/schema/labels.schema.json](corpus/schema/labels.schema.json).

## Untrusted-input and resource changes

SARIF, configuration, corpus labels, and repository source are untrusted. Parser or repository
changes need negative tests for relevant size, depth, traversal, symlink/junction, invalid UTF-8,
and malformed-index boundaries. Never add network access or repository code execution.

Do not relax a resource ceiling merely to make a fixture pass. A deliberate budget change must
update code, schema, tests, [docs/resource-budgets.md](docs/resource-budgets.md), and the accepted
decision record together.

## Project boundaries

- `SarifRegress.Core` references no application project.
- `SarifRegress.Sarif`, `SarifRegress.Match`, and `SarifRegress.Report` may reference `Core` only.
- `SarifRegress.Cli` may reference all application libraries.
- No library references `Cli`.
- `Match` must not reference `Sarif`, `Report`, or I/O adapters.

The architecture test must continue to fail with a useful message when a forbidden reference is
introduced.

## Pull-request evidence

Record:

- exact verification and focused test commands with exit outcomes;
- tests and corpus cases added;
- deterministic output or hash comparisons performed;
- assumptions, deviations, and resource-budget effects;
- CI state, without claiming success before the run is complete.
