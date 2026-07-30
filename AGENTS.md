# Repository instructions

## Scope

Implement only the active GitHub issue. Do not pull work forward from later issues in `docs/architecture.md`, even when adjacent scaffolding would be convenient.

## Verification

Run the platform-specific repository verification command before committing:

```powershell
.\scripts\verify.ps1
```

```bash
./scripts/verify.sh
```

## Architectural boundaries

- `SarifRegress.Core` references no application project.
- `SarifRegress.Sarif`, `SarifRegress.Match`, and `SarifRegress.Report` may reference `SarifRegress.Core` only.
- `SarifRegress.Cli` may reference all application libraries.
- No library may reference `SarifRegress.Cli`.
- `SarifRegress.Match` must not reference `SarifRegress.Sarif` or `SarifRegress.Report`.

## Determinism

All observable output must be deterministic. Do not depend on current time, randomness, machine identity, locale-sensitive behavior, filesystem enumeration order, dictionary enumeration order, or environment-specific absolute paths.

Use ordinal comparisons, explicit stable ordering, UTF-8 without a byte-order mark, and LF line endings for stable generated text.
