# Gitleaks 8.30.1 holdout notes

This case uses the free Gitleaks CLI `8.30.1` from the official
[`v8.30.1` release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
under the MIT license. Capture occurred on 2026-08-01. Every apparent token is
synthetic fixture text; no real secret, repository history, or private source is
present. The one local rule in `producer-input/gitleaks.toml` matches only the
`HOLDOUT_TOKEN_...` namespace and needs no network access.

The exact release archive and official checksum-manifest URLs, byte sizes,
SHA-256 values, help-output hash, and commands are recorded in
`validation/tools/capture/capture-provenance.json`. The capture script extracts
only the verified regular `gitleaks` member, checks `gitleaks version`, and runs:

```text
gitleaks dir . --config <case>/producer-input/gitleaks.toml --exit-code 0 --log-level error --no-banner --no-color --redact=100 --report-format sarif --report-path <producer-capture>
```

`producer-input/captures/*.producer.sarif` are the untouched Gitleaks output.
Gitleaks scans directory fragments concurrently and emits results in completion
order, which varied in the hosted recapture even though all 30 result objects
were identical as a multiset. This behavior follows from the pinned
[`Files.Fragments`](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/sources/files.go)
dispatch and
[`Detector.AddFinding`](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/detect/detect.go)
append path. `normalize_gitleaks_sarif.py` therefore creates
the adjacent `*.raw.sarif` projection input by sorting complete result objects
by canonical JSON. No result field changes, and the original bytes remain for
review. Its exact invocation is:

```text
python3 -B validation/tools/capture/normalize_gitleaks_sarif.py --input <producer-capture> --output <normalized-projection-input>
```

Full redaction prevents synthetic token text from becoming a matching shortcut.
Each result is mapped to the immediately preceding `HOLDOUT:<semantic-id>`
comment in controlled source; that comment is not part of the matched text or
SARIF snippet. `case-plan.json`, not either matcher's output, supplies labels.

## Known paired relationships

Each row explains why the two findings represent the same synthetic-token
occurrence.

| Semantic ID | Expected class | Controlled proof |
|---|---|---|
| `gitleaks-exact-01` | unchanged | The same synthetic token assignment remains at the same path and line. |
| `gitleaks-exact-02` | unchanged | The same synthetic token assignment remains at the same path and line. |
| `gitleaks-exact-03` | unchanged | The same assignment remains at the same path and line; both projections explicitly lack producer fingerprints. |
| `gitleaks-exact-04` | unchanged | The same synthetic token assignment remains at the same path and line. |
| `gitleaks-exact-05` | unchanged | The same synthetic token assignment remains at the same path and line. |
| `gitleaks-line-shift-01` | moved | One neutral comment is inserted before the marker and unchanged token line. |
| `gitleaks-line-shift-02` | moved | Two neutral comments are inserted before the marker and unchanged token line. |
| `gitleaks-line-shift-03` | moved | Three neutral comments are inserted before the marker and unchanged token line. |
| `gitleaks-line-shift-04` | moved | Four neutral comments are inserted before the marker and unchanged token line. |
| `gitleaks-line-shift-05` | moved | Five neutral comments are inserted before the marker and unchanged token line; this pair also carries the documented POSIX/Windows URI projection and rebase. |
| `gitleaks-moved-01` | moved | The unchanged token line moves below three neutral assignments in its file. |
| `gitleaks-moved-02` | moved | The unchanged token line moves below four neutral assignments in its file. |
| `gitleaks-moved-03` | moved | The unchanged token line moves below five neutral assignments in its file. |
| `gitleaks-moved-04` | moved | The unchanged token line moves below six neutral assignments in its file. |
| `gitleaks-moved-05` | moved | The unchanged token line moves below seven neutral assignments in its file. |
| `gitleaks-renamed-01` | moved | The unchanged one-finding file moves from `src/renamed-old/` to `src/renamed-new/`. |
| `gitleaks-renamed-02` | moved | The unchanged one-finding file moves in the same controlled directory rename. |
| `gitleaks-renamed-03` | moved | The unchanged one-finding file moves in the same controlled directory rename. |
| `gitleaks-renamed-04` | moved | The unchanged one-finding file moves in the same controlled directory rename. |
| `gitleaks-renamed-05` | moved | The unchanged one-finding file moves in the same controlled directory rename. |
| `gitleaks-message-modified-01` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `gitleaks-message-modified-02` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `gitleaks-message-modified-03` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `gitleaks-message-modified-04` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `gitleaks-message-modified-05` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |

## New, resolved, and ambiguous findings

- `gitleaks-resolved-01`, `gitleaks-resolved-02`, and
  `gitleaks-resolved-03` each occupy a separate baseline-only file; removing
  those files removes the three findings.
- `gitleaks-new-01`, `gitleaks-new-02`, and `gitleaks-new-03` each occupy a
  separate candidate-only file; adding those files creates the three findings.
- `gitleaks-ambiguous-01` and `gitleaks-ambiguous-02` use the same synthetic
  token value twice in one file on each side. Full redaction makes their
  producer-visible finding content the same, and the projection gives them one
  duplicated partial fingerprint. The 2×2 group is labelled ambiguous without
  asserting either arbitrary pairing.

## Reproducible SARIF projections

Gitleaks `8.30.1` reports a stale driver `semanticVersion` of `v8.0.0` in its
own SARIF. The CLI version is independently asserted as `8.30.1`; the raw
metadata is retained rather than silently corrected. The candidate projection
changes that field to `v8.0.0+holdout-candidate-projection` only to exercise a
controlled producer-metadata difference.

Other deterministic changes are limited to the five candidate message suffixes,
missing fingerprints for `gitleaks-exact-03`, one shared ambiguity partial
fingerprint, and the `gitleaks-line-shift-05` POSIX/Windows URI pair. The two
URI prefixes are explicitly rebased in `config.json`. No semantic ID or label
field is added by the projection; producer-emitted source paths remain. The
sidecar `projection-audit.json` records original URI/message/fingerprint hashes
and mutation names. Labels use indices from the documented canonical result
ordering; that ordering exists solely to make the projection reproducible and
is not evidence about finding identity.

Reproduce the source proof and capture with:

```sh
python3 -B validation/tools/capture/verify_source_transformations.py --repository-root .
./validation/tools/capture/capture-holdout.sh --output-root ../gitleaks-holdout-capture --producer gitleaks
```
