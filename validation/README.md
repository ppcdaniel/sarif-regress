# Independent holdout validation

This directory evaluates the frozen SarifRegress matcher against findings from
producer families that were not used by the development corpus. It is an
evaluation set, not a source of matching heuristics or tuned labels.

The committed SARIF files are the ordinary validation inputs. Re-running the
external analyzers is optional and Linux-only; evaluating those committed files
and normalizing the external baseline is supported on Linux and Windows.

## Layout

- `holdout/manifest.json` records producer, case, provenance, and label counts.
- `holdout/cases/` contains one controlled baseline/candidate experiment per
  producer.
- `tools/capture/` reproducibly captures and projects producer output.
- `tools/SarifRegress.Validation/` evaluates the holdout and normalizes the
  Microsoft SARIF Multitool comparison.
- `schemas/` defines the strict machine-readable contracts.
- `expected/` contains the byte-stable evaluation snapshot and its checksums.

## Evaluation

From any current directory, run the platform wrapper:

```bash
./scripts/validate-holdout.sh
```

```powershell
.\scripts\validate-holdout.ps1
```

Both wrappers verify structure, provenance, schemas, tool identity, checksums,
and expected bytes. They write regenerated evidence beneath
`artifacts/holdout-validation/` and do not modify committed fixtures.

Producer capture is deliberately separate. See `tools/capture/README.md` for
the exact Linux-only commands, versions, download hashes, and mutation steps.
The normalized external baseline is comparative evidence; Microsoft SARIF
Multitool is not treated as ground truth.
