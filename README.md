# SarifRegress

SarifRegress is an explainable, deterministic engine for deciding whether findings in two SARIF 2.1.0 runs represent the same underlying issues after non-semantic source and metadata changes.

## Status

The project is at repository bootstrap. Implementation begins through narrowly scoped, tracked GitHub issues; no comparison engine is available yet.

## Thesis

A conservative matcher can preserve finding identity across common changes while refusing ambiguous matches, explaining every decision, and producing byte-stable machine-readable output on Windows and Linux.

## Non-goals

The MVP is not a hosted service, a general SARIF viewer, a complete GitHub ingestion emulator, or an opaque machine-learning matcher. It will not infer cross-producer equivalence without explicit configuration, execute repository code, or fetch network resources referenced by SARIF.

The architectural source of truth is [docs/architecture.md](docs/architecture.md).
