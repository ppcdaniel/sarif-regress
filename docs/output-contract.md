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
`sarifregress/rule-alias/v2` and `sarifregress/matcher/v3`.

Matcher v3 makes context reliability occurrence-aware. The derived fingerprint generator remains
`rule-path-context/v2` because its bytes are unchanged, while comparison semantics advance to
`sarifregress/derived-fingerprint-compare/v2`. Context evidence advances to
`sarifregress/context-evidence/v2`, and bounded collision explanations use
`sarifregress/evidence-occurrence/v1`. These version changes identify altered matching semantics;
the product JSON output schema remains version `1` because no existing field was removed, renamed,
or reinterpreted.

Matcher v3.1 corrects post-correspondence classification when an accepted edge uses an explicit
path alias and each canonical producer message differs only by one delimited occurrence of its own
full repository-relative path. The path-neutral message template is recorded as a lossy, hashed
`classification-message-location-template` transform under
`sarifregress/message-location-template/v1`. This transform cannot admit, score, or assign an edge.
Matcher v3 history remains immutable; the minor matcher revision distinguishes the observable
classification change without claiming the separately gated sparse-SARIF matcher-v4 design.

Matcher v3.2 makes two precision-preserving admission changes. Collided context cannot admit a
candidate edge when another available context representation conflicts, including when weak
message matching is enabled. A refused pair's values are not copied into a finding-level trace:
the bounded trace records the finding-local collision degradation plus `no-admissible-*`, which is
the stable public explanation for this veto. Code-flow anchors are supporting evidence only: they
cannot admit an edge, and a shared anchor contributes to ranking only when its path/context
identity occurs in exactly one finding on each input side within the same automatic-producer/rule
bucket. Repeated anchors emit one bounded lossy finding-local
`code-flow-anchor-collision` summary under
`sarifregress/code-flow-occurrence/v1`; the existing code-flow anchor and set hashes remain v1
because their bytes are unchanged.

The current product emits `sarifregress/matcher/v3.2`. No matcher-v4 or side-specific-source
evidence identifier exists, and validation-only sparse research algorithm names never enter stable
product comparison JSON.

The active matcher-v3.2 validation report uses schema version `3` and report kind
`sarif-regress-exposed-holdout-regression`. That envelope makes the erratum's interpretation
machine-readable instead of repeating the historical independent-holdout claim. Historical
matcher-v2, matcher-v3, and matcher-v3.1 bytes retain their schema-v2
`sarif-regress-independent-holdout` envelope and remain checksum-anchored; the stable serializer
selects that legacy envelope only for those exact historical matcher identifiers.

The active validation comparison summary uses schema version `4`. Matcher v3.2 replaces the
v3-to-v3.1 report-hash fields with matcher-v3.1 and v3.1-to-v3.2 bindings; because those are closed
contract renames, the frozen matcher-v3.1 comparison remains schema version `3` and is validated
only against its archived schema.

The active cross-platform attestation schema is version `4`. Its GitHub Actions identity records
`workflowConclusion` and `coordinatorJobConclusion` separately. Normal evidence requires both to be
`success`. A matcher-v3.2 stage-1 candidate records `workflowConclusion: failure` and
`coordinatorJobConclusion: success`, because a dedicated refusal job deliberately fails the workflow
after the coordinator authenticates and uploads the candidate. The generic legacy `conclusion`
property is rejected.

Matcher-v3.2 evidence uses two fail-closed promotion stages. `candidate-unbound` generates and
cross-compares the exact reports and truthful candidate attestation, then refuses final status. Once
the report digest and that candidate attestation are committed, a bound comparison whose
`crossPlatformByteIdentity` remains `false` selects stage 2. Both operating systems rerun the real
evaluator, tolerate only the expected tracked-output mismatch, and cross-compare the resulting
attested comparison and checksum bytes before another deliberate refusal. Only promotion of those
stage-2 bytes changes the mode to normal strict validation. Producer artifacts are downloaded by
their upload output IDs, and their API metadata must bind the expected archive digest, current run,
and exact workflow head before their contents are compared.

An attestation document is not, by itself, proof that its linked Actions run has finished with the
recorded workflow conclusion. Candidate failure is guaranteed by the explicit refusal job. Normal
success is accepted for release only after the reusable holdout workflow has completed successfully
and the release gate has rebound the run ID, attempt, exact head, artifact IDs, names, and digests.

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

The sparse repository-context experiment is a validation-only contract, not an extension of
product output schema `1`. Its checked-in decision uses root schema
`sparse-experiment-limitation/v1` and references separately authenticated observations, gates,
workflow provenance, resources, and coordinator projections. A composite
`expected/experiment-report.json` is intentionally absent while issue #27 tracks derivation and
cross-binding of the stable resource subset. The SARIF-only control preflight defect tracked in
issue #28 is corrected without changing its `0/0/19` result; the absent composite must not be
claimed as emitted or validated.

`canonicalise` emits deterministic SARIF rather than comparison JSON. See [cli.md](cli.md) for
stream and file behavior.
