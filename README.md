# SarifRegress

SarifRegress is a CLI-first, local-first engine for deciding whether findings in two SARIF 2.1.0 runs represent the same underlying issue after paths, line numbers, messages, source context, tool versions, or producer metadata change.

## Thesis

A conservative matcher can preserve finding identity across common non-semantic changes while refusing ambiguous matches, explaining every decision, and producing byte-stable machine-readable output on Windows and Linux.

## MVP

The planned MVP will compare one baseline SARIF run set with one candidate run set from the same producer family. It will canonicalise comparison-relevant data, perform deterministic one-to-one matching, classify findings, retain structured explanations, and emit stable JSON. Cross-producer equivalence will require explicit configuration.

## Non-goals

The MVP will not:

- provide a hosted service, collaborative triage system, or large interactive dashboard;
- replace static-analysis producers or act as a general SARIF viewer;
- emulate GitHub code-scanning ingestion completely;
- infer cross-producer equivalence without explicit mappings;
- use an LLM or opaque machine-learning matcher;
- execute repository code or fetch network resources referenced by SARIF;
- add HTML reporting, benchmarking, Native AOT, publishing, or packaging during bootstrap.

See [docs/architecture.md](docs/architecture.md) for the architectural source of truth.

## Prerequisites

The repository pins the stable .NET SDK in `global.json`; other SDK versions are intentionally rejected.

### Windows

- Windows 11;
- the .NET SDK version specified in `global.json`;
- PowerShell 5.1 or later;
- Git.

### Linux

Linux contributors who need to reproduce CI must install:

- the .NET SDK version specified in `global.json`;
- Bash;
- Git.

## Build, test, and verify

Run commands from any current directory by using the script path for your checkout.

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

`verify` restores locked dependencies, checks formatting, performs a deterministic Release build with warnings treated as errors, and runs the complete test suite.

## Current status

SarifRegress is in repository bootstrap. Implementation proceeds through narrowly scoped, tracked issues. The `compare` command currently accepts baseline and candidate inputs, prints the deterministic placeholder below, and exits with code `2`:

```text
SarifRegress comparison is not implemented yet.
```

No SARIF parsing, canonicalisation, or matching is implemented yet.

## Licence

SarifRegress is available under the [MIT License](LICENSE).
