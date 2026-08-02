# Clean sparse-SARIF research corpus

This directory is a pre-experiment corpus for studying source-backed continuity when a SARIF
producer supplies neither reliable fingerprints nor embedded snippets. It is deliberately separate
from the development corpus and the frozen real-producer holdout. No matcher result was consulted
when the source transformations or labels were written.

The corpus is not evidence that side-specific repository context is safe to ship. An authentic
hosted PMD capture and strict exact-head recapture have been promoted; the repository-context
experiment is still pending. The experiment must pass the fixed gates in
[ADR 0003](../../../docs/decisions/0003-side-specific-repository-context-experiment.md) before any
product behavior changes.

## Independence protocol

Ground truth exists only in each family's `labels.json`. A label selects an endpoint by the full
natural SARIF-visible descriptor: rule ID, source-root-relative artifact URI, complete region, and
canonical PMD message. Every transformation proof path is bound to the applicable side and exact
source-file SHA-256. Labels never select a result index. Relationship IDs, transformation proofs,
and ambiguity declarations are not matcher inputs.

The Java source was frozen before producer capture or matcher evaluation and has:

- no relationship, case, or semantic identity IDs;
- no comments explaining correspondence;
- no adjacent markers or deliberately identity-encoding names;
- no dependence on directory enumeration, file order, result order, or label order;
- no source copied from the old PMD holdout, whose adjacent identity markers make it unsuitable for
  repository-context experiments.

Labels are evaluated only after a candidate report has been produced. They must not be loaded by a
capture tool, URI projector, repository ingestor, evidence generator, matcher, or assignment solver.

## Frozen fixture inventory

| Family | Baseline findings | Candidate findings | Relationships | Unchanged | Moved | New | Resolved | Refused ambiguity |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `pmd-clean-a` | 10 | 11 | 8 | 2 | 6 | 1 | 1 | 1 one-to-many group |
| `pmd-clean-b` | 16 | 16 | 11 | 3 | 8 | 2 | 2 | 1 one-to-many and 1 many-to-one group |
| **Total** | **26** | **27** | **19** | **5** | **14** | **3** | **3** | **3 groups / 9 endpoints** |

The two families were designed independently. Together they cover exact unchanged findings,
blank-line and statement-induced region drift, whole-file moves, movement between and within
methods, message-stable findings, new and resolved findings, repeated rule/path/message evidence,
similar findings in different methods and files, and both ambiguity orientations. Family B also
swaps two methods across their previous regions: an exact old coordinate points at the wrong
natural method after the transformation. This prevents exact-location coincidence from acting as
hidden ground truth.

Family A contains a pure file-move control. The baseline and candidate `ArchiveWorker.java` bytes
are identical; only the source-root-relative path changes. This isolates path movement from token
or snippet changes.

## Producer provenance

The capture contract reuses the already verified PMD release provenance; it does not download an
unversioned latest release.

| Field | Frozen value |
|---|---|
| Producer | PMD `7.26.0` |
| Source commit | `8fd38edf285a33e1164f66205ebe243441db9557` |
| Release archive | `pmd-dist-7.26.0-bin.zip`, 73,646,044 bytes |
| Archive SHA-256 | `9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9` |
| `pmd check --help` SHA-256 | `babf2b1e17bddd7611cc4882b9686c207e2b73fee3e3053276b3455e6c890b91` |
| Java | Eclipse Temurin `17.0.19+10`; PMD language level `java-17` |
| Licence reference | `LicenseRef-PMD-BSD-Style` |
| Capture contract | `pmd-authentic-sparse-capture/v1`; canonical PMD and curl argv are runtime-verified |

The official release URL, archive URL, extraction procedure, and licence context are recorded in
[`validation/tools/capture/capture-provenance.json`](../../tools/capture/capture-provenance.json)
and [`validation/tools/capture/README.md`](../../tools/capture/README.md). Capture must verify the
archive size and SHA-256 before using
[`validation/tools/capture/extract_zip.py`](../../tools/capture/extract_zip.py). No PMD binary or
release archive is committed here.

## Raw capture and URI-only projection

PMD must analyse each `baseline/source` and `candidate/source` tree independently with the local
family ruleset and this help-verified command shape:

```text
pmd check --dir <side-source-root> --format sarif --no-cache --no-fail-on-violation --no-progress --relativize-paths-with <side-source-root> --report-file <raw-capture> --rulesets <family>/pmd-ruleset.xml --threads 0 --use-version java-17
```

Raw producer bytes belong in a caller-selected staging directory and are immutable capture
evidence. Their SHA-256 values must be recorded in `manifest.json`. A dedicated URI projector,
`tools/project_pmd_sarif.py`, may replace only the proven absolute source-root prefix in
`physicalLocation.artifactLocation.uri` with the portable path relative to that side's `source`
root. It must preserve result order, rule IDs, messages, regions, properties, and every other
producer field byte-for-byte at the JSON-value level. It must not add fingerprints, snippets,
symbols, source text, labels, or evidence intended to help matching.

The capture verifies and executes the same read-only PMD argument array. Its canonical contract
also binds the pinned archive, runtime, projection algorithm, curl configuration suppression,
transfer ceiling, and inherited file-size limit. The contract SHA-256 is recorded in the capture
environment and every projection audit. Hosted image version and exact source HEAD are run
provenance, not deterministic projected-output fields.

The committed `baseline.sarif` and `candidate.sarif` files are the audited URI-only projections,
not hand-authored SARIF. Each projection audit binds raw and projected hashes and lists every
changed JSON pointer. The canonical promotion record is exact-head workflow run `30719295884` on
source `2f4499a51f621ee8c1fb3816752205d7e5b224bf`. Its Ubuntu and Windows admission jobs passed; its
strict PMD recapture reproduced every promoted projection, audit, and raw hash; and a downstream
job downloaded artifact `8824342390` by ID and reverified its GitHub digest and content.
`manifest.json` records that run's runner image, artifact identity, commands, and hashes. The
untouched raw SARIF remains in the workflow artifact and is not committed. Routine exact-head
recapture continues to enforce the same byte comparisons without depending on that expiring
historical artifact.

## Expected layout

```text
validation/research/sparse-sarif/
  README.md
  manifest.json                         # capture hashes and provenance
  capture-evidence/
    projection-audits/
      pmd-clean-a/{baseline,candidate}.json
      pmd-clean-b/{baseline,candidate}.json
  cases/
    pmd-clean-a/
      baseline/source/**/*.java
      candidate/source/**/*.java
      pmd-ruleset.xml
      labels.json
      baseline.sarif                    # authentic URI-only projection
      candidate.sarif                   # authentic URI-only projection
    pmd-clean-b/
      baseline/source/**/*.java
      candidate/source/**/*.java
      pmd-ruleset.xml
      labels.json
      baseline.sarif                    # authentic URI-only projection
      candidate.sarif                   # authentic URI-only projection
  schemas/
    labels.schema.json
    manifest.schema.json
    projection-audit.schema.json
    experiment-report.schema.json
  expected/
    experiment-report.json              # pending; generated only after evaluation
    checksums.sha256
  tools/
    capture_pmd.sh                       # pinned hosted capture entry point
    project_pmd_sarif.py                 # URI-only projector
    scan_contamination.py
    test_scan_contamination.py
    test_pmd_capture_tools.py
    verify_pmd_capture.py
```

## Reproduction and admission workflow

The workflow is intentionally ordered so labels cannot be changed in response to matcher output:

1. Verify the frozen Java and `labels.json` hashes, recompute every side-bound transformation proof
   hash, and validate labels against `schemas/labels.schema.json`.
2. Run `python3 -B tools/test_scan_contamination.py`.
3. Before producer output or `manifest.json` exists, run `python3 -B
   tools/scan_contamination.py --research-root validation/research/sparse-sarif --source-only`;
   any diagnostic rejects the source/label topology. Normal mode remains fail-closed when the
   manifest is absent.
4. Verify and safely extract the pinned PMD archive with
   `validation/tools/capture/extract_zip.py`; verify `pmd --version` and the pinned help hash.
5. Capture each side independently with its own source root and local `pmd-ruleset.xml`.
6. Hash and retain the untouched raw captures in staging.
7. Run the reviewed `tools/project_pmd_sarif.py` URI-only projection and verify its complete audit.
8. Commit the audited projections and manifest, then run normal scanner mode without
   `--source-only`; re-run schema, integrity, selector-exhaustiveness, and deterministic-byte
   checks.
9. Only then run the research experiment described by ADR 0003. The experiment receives SARIF and
   side-specific source roots, never labels; a separate evaluator scores its output afterward.

The contamination policy is `sparse-sarif-contamination/v1`. Its scanner must reject label IDs or
normalized label keys in source, known marker prefixes, correspondence comments adjacent to an
analysed call, result-index ground truth, fingerprints or snippets in the sparse SARIF, source/SARIF
selector gaps, order leakage, absolute local paths, hostnames, timestamps, unsafe filesystem
entries, checksum drift, and resource-limit violations. Passing the scanner is an admission check,
not evidence that hosted capture or matching succeeded.
