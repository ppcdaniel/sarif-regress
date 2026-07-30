# Labelled corpus and quality gates

The corpus is the public falsification mechanism for SarifRegress. Aggregate counts are not enough:
each case records the expected pairing graph, matched classification, ambiguity, new findings,
resolved findings, intentionally invalid inputs, exact diagnostics where asserted, and selected
structured explanation/evidence goldens.

## Layout

```text
corpus/cases/rename-with-line-shift/
  baseline.sarif
  candidate.sarif
  config.json
  labels.json
  notes.md
  repo/
```

Only files required by the case should be present. `repo/` and `config.json` are optional. Paths
inside a case are resolved from the case directory so the suite does not depend on its checkout
location.

`labels.json` conforms to
[`corpus/schema/labels.schema.json`](../corpus/schema/labels.schema.json):

- `pairs` contains `baselineKey`, `candidateKey`, and `unchanged`, `moved`, or `modified`;
- `expectedAmbiguous` lists finding keys that must not be silently assigned;
- `expectedResolved` and `expectedNew` list expected unmatched keys;
- `expectedInvalidInputs` identifies deliberately malformed baseline or candidate inputs;
- an omitted `expectedDiagnostics` preserves a legacy case with no diagnostic assertion, while a
  present array is the exact expected set (including an explicitly empty set);
- each expected diagnostic fixes code, severity, stage, message, optional source coordinates,
  `standardBasis`, and `help`; omit all source fields for a source-less diagnostic, otherwise
  provide both `input` and `jsonPointer` (with optional run/result indexes);
- diagnostic source `input` accepts `baseline`, `candidate`, `configuration`, or `corpus`;
- omitted `standardBasis` or `help` asserts that the corresponding diagnostic value is absent;
- `expectedExplanations` pins selected finding sides, classification, precedence, ambiguity, and
  the complete set of evidence kinds without turning summary counts into the oracle.

Case directories and labels are visited in explicit ordinal order.

## Required strata

The public Alpha corpus should contain approximately 200–500 labelled result pairs covering:

- exact unchanged findings;
- line insertion and region movement;
- checkout-root and Windows/POSIX spelling changes;
- explicit file and rule rename mappings;
- missing and duplicate producer fingerprints;
- multiple findings on one line;
- one-to-many and many-to-one conflicts;
- message and context changes;
- cross-producer refusal and explicit aliases;
- malformed, unsupported, and security-boundary inputs;
- controlled mutations of output captured from a redistributable real producer;
- GitHub code-scanning supported-subset compatibility.

Controlled producer fixtures should be redacted and small enough to review. Do not add private
repository contents, secrets, or licensed source that cannot be redistributed. Their `notes.md`
must record the producer and version, reproducible command, source/licence links, capture date,
and every post-capture mutation. A GitHub-profile case is an offline check against the pinned
primary documentation, not evidence that an upload occurred.

## Evaluation

Run from the repository root:

```bash
sarif-regress corpus run --corpus corpus
```

or during development:

```bash
dotnet run \
  --project src/SarifRegress.Cli/SarifRegress.Cli.csproj \
  --configuration Release \
  -- \
  corpus run \
  --corpus corpus \
  --json-out artifacts/corpus-report.json
```

The report uses UTF-8 without BOM, LF line endings, stable property order, and no ambient checkout
path or timestamp.

The gate passes only when:

- precision is at least `0.95`;
- recall is at least `0.90`;
- expected matched classifications are exact;
- expected new, resolved, and ambiguous sets are exact;
- intentionally invalid inputs are exact;
- every explicitly labelled diagnostic set is exact;
- every selected explanation/evidence golden is exact;
- no ambiguous label is silently auto-matched.

A fully processed corpus below these thresholds returns exit `3`; malformed corpus structure or
I/O returns `1`.

## Cross-platform determinism

`.github/workflows/determinism.yml` builds the same revision on Windows and Linux, runs the
approved corpus and both 1,000-finding benchmark shapes independently, and uploads each report
under a distinct artifact name. A separate Linux coordinator job downloads both immutable
artifacts and compares SHA-256 hashes and exact bytes for the corpus report and application-emitted
deterministic benchmark projections. It does not parse or reserialize those projections.

Each case entry embeds either its complete stable comparison JSON or its complete invalid-input
diagnostic JSON and the SHA-256 of those exact bytes. Consequently, the cross-platform comparison
covers per-finding classifications and explanations as well as aggregate metrics.

The producing jobs do not compare their own output and do not share a writable directory. The
coordinator has read-only repository permission, uses only artifacts from the same workflow run,
and publishes the verified projections with a checksum manifest. Tagged releases call this same
workflow, so the exact tagged commit must pass the cross-platform gate before publication.

## Changing matching behavior

A change that can alter classifications must:

1. add or update focused unit/property tests;
2. update affected labels only when the ground truth changed, not merely to make metrics pass;
3. compare corpus reports before and after the algorithm change;
4. increment the matcher algorithm version;
5. describe the behavioral change in release notes.

If thresholds can be met only with an opaque heuristic or silent ambiguity, narrow or stop the
feature instead.
