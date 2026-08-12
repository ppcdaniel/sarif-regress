# Clean sparse-SARIF research corpus

This directory is a pre-experiment corpus for studying source-backed continuity when a SARIF
producer supplies neither reliable fingerprints nor embedded snippets. It is deliberately separate
from the development corpus and the frozen real-producer holdout. No matcher result was consulted
when the source transformations or labels were written.

The first repository-context experiment correctly stopped at its safety gates. A later bounded
analysis proved both a useful safe subset and a duplicate-symmetry boundary. The shipped opt-in
adapter therefore requires separate physical roots and independent raw-byte digest manifests,
derives a comment-blind filename/method/statement identity, and refuses renamed files or equal
rivals. See [ADR 0004](../../../docs/decisions/0004-duplicate-symmetry-boundary.md). The frozen
labels and thresholds remain unchanged.

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
  experiment-implementation-manifest.json # canonical-LF admitted implementation hashes
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
  expected/                         # post-promotion layout; absent entries are never implied
    experiment-report.json              # present only after authenticated promotion
    supporting/{release,determinism,resources}/** # present only after promotion
    supporting/github/**                # promoted exact REST run/artifact metadata bytes
    checksums.sha256
  tools/
    analyze_duplicate_symmetry.py        # fixed safe/product/order boundary
    capture_pmd.sh                       # pinned hosted capture entry point
    project_pmd_sarif.py                 # URI-only projector
    refresh_sparse_manifests.py          # bounded deterministic inventory refresh
    scan_contamination.py
    test_refresh_sparse_manifests.py
    test_scan_contamination.py
    test_pmd_capture_tools.py
    verify_pmd_capture.py
```

## Reproduction and admission workflow

The workflow is intentionally ordered so labels cannot be changed in response to matcher output:

1. Verify the frozen Java and `labels.json` hashes, recompute every side-bound transformation proof
   hash, and validate labels against `schemas/labels.schema.json`.
2. Run `python3 -B tools/test_scan_contamination.py`, `python3 -B
   tools/test_refresh_sparse_manifests.py`, and `python3 -B
   tools/refresh_sparse_manifests.py --check`.
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
10. Run the three authenticated coordinator roles on one exact source SHA, then dispatch
    `sparse-experiment-composite.yml` with their run IDs. The offline compositor verifies each
    successful workflow, artifact ID/name/digest, coordinator checksum manifest, raw referenced
    byte, and resource full-to-stable derivation before atomically emitting the v2 candidate tree.
    Promote only the exact candidate bytes and rerun the independent contamination scanner.

The contamination policy is `sparse-sarif-contamination/v1`. Its scanner must reject label IDs or
normalized label keys in source, known marker prefixes, correspondence comments adjacent to an
analysed call, result-index ground truth, fingerprints or snippets in the sparse SARIF, source/SARIF
selector gaps, order leakage, absolute local paths, hostnames, timestamps, unsafe filesystem
entries, checksum drift, and resource-limit violations. Passing the scanner is an admission check,
not evidence that hosted capture or matching succeeded.

## Refreshing deterministic inventories

Any admitted matcher, ingestion, reporting, CLI, or validation-harness byte change makes
`experiment-implementation-manifest.json` stale. Any non-`expected/` file change in this research
directory also makes `manifest.json` stale. Refresh both inventories from the repository root with:

```text
python -B validation/research/sparse-sarif/tools/refresh_sparse_manifests.py --write
python -B validation/research/sparse-sarif/tools/refresh_sparse_manifests.py --check
python -B validation/research/sparse-sarif/tools/scan_contamination.py --research-root validation/research/sparse-sarif
```

The refresh command enumerates the same implementation roots, file kinds, ordinal ordering,
256 admitted-file limit, 4 MiB per-file limit, and per-root 4,096-file/4,096-directory traversal
limits enforced independently by the .NET evaluator and contamination scanner. It rejects links,
junctions, special files, oversized inputs, unstable reads, lone carriage returns, and over-limit
trees. Implementation entries hash the Git-canonical LF representation so a locked Windows restore
and an LF checkout authenticate the same committed text. Corpus integrity remains raw-byte exact
and covers every physical file except `manifest.json` itself and the historical `expected/`
evidence tree, keeping the corpus manifest deliberately non-self-hashing.

Refreshing inventories authenticates current source bytes only. It never edits labels, gates,
thresholds, metrics, or expected evidence, and it does not rebind historical observations to the
current implementation. Promote a new evidence cascade only from authenticated exact-head hosted
artifacts.

## Duplicate boundary and product profile

`tools/analyze_duplicate_symmetry.py` constructs all source features before opening labels and
freezes three comparisons. Unrestricted safe uniqueness observes 19/19 clean relationships; the
implemented preview-candidate filename-bound profile observes 18 TP, 0 FP, and 1 FN (precision 1.0, recall 0.947368), with
zero labelled ambiguity auto-matched. Source-order alignment recovers all 25 legacy relationships
but also creates the two forbidden ambiguity pairs, demonstrating why order is not identity.

The legacy 2-by-2 ambiguity component and five labelled 5-by-5 relationship components are
otherwise complete equal-evidence bipartite graphs. A permutation-invariant matcher cannot safely
choose the labelled diagonal in the 5-by-5 groups while refusing the 2-by-2 group. The composite
report therefore retains `decision: document-limitation`; authenticated evidence closes the
provenance gap without rewriting that scientific result or authorising matcher v4.
