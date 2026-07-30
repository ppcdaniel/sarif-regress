# Repository instructions

## Scope

Implement only the active GitHub issue. Do not pull work forward from later issues in `docs/architecture.md`, even when adjacent scaffolding would be convenient.

## Commands

Windows:

```powershell
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\verify.ps1
```

Linux:

```bash
./scripts/build.sh
./scripts/test.sh
./scripts/verify.sh
```

Run the platform-specific `verify` command before committing. It restores locked dependencies, verifies formatting, builds the complete solution in Release with no warnings, and runs every test.

## Architectural boundaries

- `SarifRegress.Core` references no application project.
- `SarifRegress.Sarif`, `SarifRegress.Match`, and `SarifRegress.Report` may reference `SarifRegress.Core` only.
- `SarifRegress.Cli` may reference all application libraries.
- No library may reference `SarifRegress.Cli`.
- `SarifRegress.Match` must not reference `SarifRegress.Sarif` or `SarifRegress.Report`.

## Determinism

All observable output must be deterministic. Do not depend on current time, randomness, machine identity, locale-sensitive behavior, filesystem enumeration order, dictionary enumeration order, or environment-specific absolute paths.

Use ordinal comparisons, explicit stable ordering, UTF-8 without a byte-order mark, and LF line endings for stable generated text.

Tests for observable output must compare exact bytes across repeated invocations. Add cross-platform fixtures when operating-system behaviour could affect the result.

## Git hygiene

Do not commit `bin`, `obj`, test results, coverage output, IDE state, local packages, generated user files, or secrets. Before committing, run `git status`, `git diff --check`, and review the complete diff for unrelated changes.
