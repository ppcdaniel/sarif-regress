# Repository instructions

## Scope and source of truth

Read `docs/architecture.md` before changing code. Implement only the active GitHub issue and do not
pull work forward from a later issue for convenience.

Issue #3 is the repository-owner-authorised exception that tracks the complete MVP architecture.
Work under it must remain dependency ordered, use focused commits, and update its checklist only
after the corresponding acceptance criteria have been directly verified.

Do not edit `docs/architecture.md`; it is the supplied architectural source of truth.

## Required commands

Run the platform-specific verification command before committing.

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

`verify` restores locked dependencies, verifies formatting, builds the complete solution in
Release with warnings as errors, and runs every test. Run `package` as an additional gate only when
packaging, runtime identifiers, release metadata, or executable startup behavior changes.

## Architectural boundaries

- `SarifRegress.Core` references no application project.
- `SarifRegress.Sarif`, `SarifRegress.Match`, and `SarifRegress.Report` may reference `Core` only.
- `SarifRegress.Cli` may reference all application libraries.
- No library may reference `Cli`.
- `SarifRegress.Match` must not reference `SarifRegress.Sarif`, `SarifRegress.Report`, or I/O
  adapters.

Keep matching pure over immutable canonical models and configuration. Parsing, repository access,
command policy, and report projection are adapters.

## Deterministic output

All observable output must be deterministic. Do not depend on current time, randomness, machine
identity, locale, process current directory, filesystem enumeration, dictionary enumeration, or
environment-specific absolute paths.

Use ordinal comparison, explicit stable ordering, invariant formatting, fixed versioned hashes,
UTF-8 without BOM, and LF line endings. Stable identity keys may order work and output but may not
resolve semantic equality. Tests for observable output must compare exact bytes across repeated
invocations and approved Windows/Linux fixtures.

JSON is the comparison source of truth. HTML must deserialize that contract and must not call the
matcher. Canonical SARIF is a separate projection and cannot change comparison decisions.

## Matching and corpus gates

Assignment is maximum-cardinality, lexicographic, deterministic, and one-to-one. Equal semantic
assignments are `ambiguous`; never select one by input order. Cross-producer bucket entry requires
an explicit rule alias and still needs qualifying evidence.

The labelled corpus must keep precision at least `0.95`, recall at least `0.90`, exact expected
classification/new/resolved/ambiguous sets, no unexpected invalid inputs, zero silently matched
labelled ambiguity, and byte-identical approved Windows/Linux reports.

## Security and budgets

Treat SARIF, configuration, corpus labels, and repository source as untrusted. Preserve streaming
and token-time input bounds, repository containment, symlink/junction rejection, invalid UTF-8
handling, HTML escaping, bounded explanations, no network access, and no code execution.

Do not truncate candidate pairs and then score the prefix. A work-budget violation fails closed;
oversized assignment components are refused as ambiguous rather than matched heuristically. Keep
the limits in code, schemas, tests, `docs/resource-budgets.md`, and ADR 0001 aligned.

## CLI contracts

The public commands are `compare`, `validate`, `canonicalise`, `corpus run`, and `bench`. Preserve
stable exit codes `0`, `1`, `3`, and `4`; code `2` is reserved for bootstrap history.

Command-line relative paths use the invocation directory. Relative configured `repoRoot` uses the
configuration file directory, and explicit `--repo` wins. Stable reports must not expose the
resulting ambient absolute paths. Outputs must not overwrite inputs, and multi-output comparison
or benchmark writes remain transactional. Resolve physical parent-directory aliases as well as
lexical path equality when enforcing those rules.

## Git hygiene

Do not commit `bin`, `obj`, `artifacts`, test results, coverage, benchmark output, IDE state, local
packages, generated user files, private fixtures, or secrets. Before committing, run `git status`,
`git diff --check`, and review the complete diff for unrelated or generated files. Never claim a
command or workflow succeeded unless its outcome was directly observed.
