# Semgrep 1.172.0 holdout notes

This case uses Semgrep Community Edition `1.172.0` from the official
[`v1.172.0` release](https://github.com/semgrep/semgrep/releases/tag/v1.172.0)
and PyPI wheel. The project is licensed under LGPL-2.1. Capture occurred on
2026-08-01 against only the small Python files in `producer-input/`; the local
`semgrep-rules.yml` contains one `holdout-sink` rule and performs no network
rule retrieval.

The exact wheel URL, 69,575,334-byte size, SHA-256, hash-locked Python 3.12
dependency set, and commands are recorded in
`validation/tools/capture/capture-provenance.json`. Capture installs with
`pip --require-hashes`, then runs:

```text
semgrep scan --config <case>/producer-input/semgrep-rules.yml --disable-version-check --metrics=off --no-git-ignore --no-rewrite-rule-ids --oss-only --quiet --sarif --strict --output <raw-capture> .
```

`producer-input/captures/*.raw.sarif` are the unmodified producer output.
`project_holdout.py` maps each result to the immediately preceding
`HOLDOUT:<semantic-id>` source comment. That comment is audit metadata outside
the finding line and is rejected if it appears in a SARIF snippet. Labels are
derived from `case-plan.json`, never from SarifRegress output.

## Known paired relationships

Each row explains why the two findings are the same source-authored issue.

| Semantic ID | Expected class | Controlled proof |
|---|---|---|
| `semgrep-exact-01` | unchanged | The same `holdout_sink("SEMGREP_EXACT_01")` call remains at the same path and line. |
| `semgrep-exact-02` | unchanged | The same `holdout_sink("SEMGREP_EXACT_02")` call remains at the same path and line. |
| `semgrep-exact-03` | unchanged | The same `holdout_sink("SEMGREP_EXACT_03")` call remains at the same path and line; producer fingerprints are removed from both projections to test missing fingerprints. |
| `semgrep-exact-04` | unchanged | The same `holdout_sink("SEMGREP_EXACT_04")` call remains at the same path and line. |
| `semgrep-exact-05` | unchanged | The same `holdout_sink("SEMGREP_EXACT_05")` call remains at the same path and line. |
| `semgrep-line-shift-01` | moved | A local block of one inert comment is inserted; its cumulative line delta is 1. |
| `semgrep-line-shift-02` | moved | A local block of two comments follows the earlier block in the shared file; its cumulative line delta is 3. |
| `semgrep-line-shift-03` | moved | A local block of three comments produces cumulative line delta 6. |
| `semgrep-line-shift-04` | moved | A local block of four comments produces cumulative line delta 10. |
| `semgrep-line-shift-05` | moved | A local block of five comments produces cumulative line delta 15; this relationship also carries the documented POSIX/Windows URI projection and matching rebase. |
| `semgrep-moved-01` | moved | The unchanged `SEMGREP_MOVED_01` call moves below the inert `neutral_padding` function in the same file. |
| `semgrep-moved-02` | moved | The unchanged `SEMGREP_MOVED_02` call moves with its source group below `neutral_padding`. |
| `semgrep-moved-03` | moved | The unchanged `SEMGREP_MOVED_03` call moves with its source group below `neutral_padding`. |
| `semgrep-moved-04` | moved | The unchanged `SEMGREP_MOVED_04` call moves with its source group below `neutral_padding`. |
| `semgrep-moved-05` | moved | The unchanged `SEMGREP_MOVED_05` call moves with its source group below `neutral_padding`. |
| `semgrep-renamed-01` | moved | The unchanged `SEMGREP_RENAMED_01` call moves from `src/renamed-old/renamed.py` to `src/renamed-new/renamed.py`. |
| `semgrep-renamed-02` | moved | The unchanged `SEMGREP_RENAMED_02` call moves in the same controlled directory rename. |
| `semgrep-renamed-03` | moved | The unchanged `SEMGREP_RENAMED_03` call moves in the same controlled directory rename. |
| `semgrep-renamed-04` | moved | The unchanged `SEMGREP_RENAMED_04` call moves in the same controlled directory rename. |
| `semgrep-renamed-05` | moved | The unchanged `SEMGREP_RENAMED_05` call moves in the same controlled directory rename. |
| `semgrep-message-modified-01` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled wording suffix. |
| `semgrep-message-modified-02` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled wording suffix. |
| `semgrep-message-modified-03` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled wording suffix. |
| `semgrep-message-modified-04` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled wording suffix. |
| `semgrep-message-modified-05` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled wording suffix. |

## New, resolved, and ambiguous findings

- `semgrep-resolved-01`, `semgrep-resolved-02`, and `semgrep-resolved-03`
  are three calls in baseline-only `src/resolved.py`; removing that controlled
  file removes each finding.
- `semgrep-new-01`, `semgrep-new-02`, and `semgrep-new-03` are three calls in
  candidate-only `src/new.py`; adding that controlled file creates each finding.
- `semgrep-ambiguous-01` and `semgrep-ambiguous-02` are identical calls in the
  same function on both sides. Their projected `partialFingerprints` deliberately
  share one value, creating a 2×2 near-collision. Ground truth declares all four
  finding keys ambiguous and does not invent a pairing.

## Reproducible SARIF projections

The original captures are retained. The deterministic projection changes only:

- candidate driver version fields from `1.172.0` to
  `1.172.0+holdout-candidate-projection`;
- the five candidate message strings, by appending
  `[controlled candidate wording change]`;
- both fingerprint objects for `semgrep-exact-03`, ensuring a missing-fingerprint
  case on both sides;
- ambiguity fingerprints, assigning the same controlled partial fingerprint to
  both ambiguity members on both sides; and
- the `semgrep-line-shift-05` artifact URI: a POSIX absolute baseline projection
  and Windows-style candidate projection that `config.json` rebases to `repo:/`.

No semantic IDs or labels are inserted into projected SARIF. Original URI,
message, and fingerprint hashes plus every mutation name live only in
`producer-input/projection-audit.json`. Producer-emitted result order is
preserved, and labels use those raw indices. Run the read-only source proof and
full capture with:

```sh
python3 -B validation/tools/capture/verify_source_transformations.py --repository-root .
./validation/tools/capture/capture-holdout.sh --output-root ../semgrep-holdout-capture --producer semgrep
```
