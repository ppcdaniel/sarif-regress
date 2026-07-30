# Stable output contract

JSON is the source of truth for SarifRegress results. The MVP schema is
[`schemas/output.schema.json`](../schemas/output.schema.json) and has
`outputSchemaVersion: "1"`.

## Stability rules

- UTF-8 without a byte-order mark;
- LF line endings;
- explicit schema property order;
- ordinal array ordering using documented logical keys;
- invariant integer and decimal formatting;
- no generated timestamps, process identifiers, host names, ambient absolute paths, or random
  values;
- fixed, versioned matching, path-normalisation, and hashing algorithm identifiers.

Repeated invocations over identical approved inputs must produce identical bytes. Approved corpus
fixtures must also produce identical bytes on Windows and Linux.

## Versioning

Additive fields may remain in schema version 1 when old readers can safely ignore them. Removing,
renaming, or changing the meaning of a field requires a schema-version change. A matching change
that can alter classifications also changes the matcher algorithm version and requires a corpus
comparison in release notes.

## Findings

Each finding record contains:

- one project classification;
- optional baseline and candidate source references;
- comparison-relevant snapshots, not the full SARIF wire object;
- audit-only source `level`, `kind`, and `baselineState` metadata kept distinct from the project
  classification;
- explicit message-normalisation flags and accumulated lossiness identifiers;
- the selected precedence tier and display confidence;
- exact evidence values or hashes and their origin;
- rejected alternatives;
- canonicalisation transforms and lossiness;
- deterministic diagnostics.

The stable identity key can order output. It never converts an equal semantic assignment into a
match.

## HTML and canonical SARIF

HTML is rendered by deserialising this JSON contract and cannot call the matching engine. Optional
canonical SARIF is a separate projection from canonical findings. Neither projection changes the
JSON classifications or evidence.

## Other command contracts

`validate`, `corpus run`, and `bench` have separately versioned JSON summaries. They do not reuse or
silently extend comparison output schema version `1`.

- validation output contains the logical input name, bounded input/run/finding counts, validity,
  policy state, and sorted diagnostics;
- corpus output contains fixed thresholds, aggregate and case metrics, stable failure reasons, and
  each case's exact stable comparison or invalid-diagnostic artifact plus SHA-256;
- benchmark output separates deterministic operation/hash fields from explicitly advisory runtime
  observations and records the applicable published budget evaluation.

`canonicalise` emits deterministic SARIF rather than comparison JSON. See [cli.md](cli.md) for
stream and file behavior.
