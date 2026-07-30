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

The checked-in schema describes the exact fields written by the current release and rejects
unknown properties. The report reader nevertheless ignores unknown properties so an older binary
can consume a safely additive version-1 report; it still rejects every missing decision-critical
field required by its own contract.

## Findings

Each finding record contains:

- one project classification;
- optional baseline and candidate source references;
- comparison-relevant snapshots, not the full SARIF wire object;
- exact source `producerToolName`, optional `producerToolVersion`, human-readable
  `producerFamily`, and the decision-relevant `automaticProducerIdentity`;
- audit-only source `level`, `kind`, and `baselineState` metadata kept distinct from the project
  classification;
- explicit message-normalisation flags and accumulated lossiness identifiers;
- the selected precedence tier and display confidence;
- exact evidence values or hashes and their origin;
- rejected alternatives;
- canonicalisation transforms and lossiness;
- deterministic diagnostics.

The current writer always emits `sourceMetadata`, `messageNormalisationFlags`, `lossiness`, and
`derivedFingerprints`. They remain optional in schema version 1 so a reader can safely interpret
their omission as empty audit metadata. Decision-critical producer identity fields are required
and are never reconstructed from the display-only family.

The stable identity key can order output. It never converts an equal semantic assignment into a
match.

## Producer identities

Each baseline or candidate snapshot reports the exact source `producerToolName`, its optional
`producerToolVersion`, the human-readable `producerFamily`, and
`automaticProducerIdentity`. The last value is the exact collision-resistant key used by automatic
same-producer decisions; reporting all four values makes display-family collisions and intentional
allowlist collapses auditable. `producerFamily` is never the automatic same-producer key.
Automatic matching and derived fingerprints use this separate deterministic identity:

- the exact, case-insensitive names `CodeQL`, `CodeQL command-line toolchain`, and `Semgrep` use
  stable known-family identities;
- every other producer uses a `producer-tool-name/v1/<sha256>` identity over its complete UTF-8
  tool name;
- the separately reported tool version is excluded, so one producer can match across versions;
- configured producer names in rule aliases use the same resolution path.

The allowlist is closed: a name such as `CodeQL-Evil` is not CodeQL merely because it has a token
boundary after `CodeQL`. Outside that allowlist, tool names—including producer names in configured
rule aliases—are exact, ordinal, and case-sensitive. The ingested producer identity retains the
original tool name and version. Findings resolved through the known-family allowlist record
`producer-family-allowlist` in `lossiness` because that intentional semantic family mapping can
collapse multiple explicitly approved tool labels.
Using the collision-resistant automatic identity changed derived-fingerprint bytes, so the
fingerprint and algorithm identifiers are versioned as `sarifregress/rule-path-context/v2` and
`rule-path-context/v2`; v1 values are not compared as v2 evidence.
Rule-alias canonical identities and matching decisions now resolve producer names through this
same identity, so their public identifiers are likewise versioned as
`sarifregress/rule-alias/v2` and `sarifregress/matcher/v2`.

## HTML and canonical SARIF

HTML is rendered by deserialising this JSON contract and cannot call the matching engine. Its
finding detail displays the source tool name and version, display family, and automatic identity so
producer-identity decisions remain explainable offline. Optional canonical SARIF is a separate
projection from canonical findings. Neither projection changes the JSON classifications or
evidence.

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
