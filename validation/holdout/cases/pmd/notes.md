# PMD 7.26.0 holdout notes

This case uses PMD `7.26.0` from the official
[`pmd_releases/7.26.0` release](https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.26.0)
under PMD's BSD-style license. Capture occurred on 2026-08-01 against only the
small Java fixtures in `producer-input/`. The local ruleset references PMD's
bundled `AvoidPrintStackTrace` rule; it has no remote schema declaration and
normal capture performs no network rule retrieval.

The verified ZIP URL, 73,646,044-byte size, SHA-256, generated-help hash, and
installation details are recorded in
`validation/tools/capture/capture-provenance.json`. The safe extractor rejects
links, traversal, duplicate members, unsupported file types, and expansion over
the configured bound. After asserting `PMD 7.26.0`, capture runs the help-verified
command:

```text
pmd check --dir . --format sarif --no-cache --no-fail-on-violation --no-progress --relativize-paths-with <controlled-source-root> --report-file <raw-capture> --rulesets <case>/producer-input/pmd-ruleset.xml --threads 0 --use-version java-17
```

`producer-input/captures/*.raw.sarif` remain untouched producer output. The
projector maps each result to an immediately preceding
`HOLDOUT:<semantic-id>` comment in controlled source. The comment is not the
finding line and is rejected if a producer includes it in a SARIF snippet.
Ground truth comes from `case-plan.json`, not from SarifRegress or Multitool.

## Known paired relationships

Each row explains why the two PMD violations are the same source-authored issue.

| Semantic ID | Expected class | Controlled proof |
|---|---|---|
| `pmd-exact-01` | unchanged | The same `exception.printStackTrace()` call remains at the same path and line. |
| `pmd-exact-02` | unchanged | The same `exception.printStackTrace()` call remains at the same path and line. |
| `pmd-exact-03` | unchanged | The same call remains at the same path and line; producer fingerprints are absent in both projections. |
| `pmd-exact-04` | unchanged | The same `exception.printStackTrace()` call remains at the same path and line. |
| `pmd-exact-05` | unchanged | The same `exception.printStackTrace()` call remains at the same path and line. |
| `pmd-line-shift-01` | moved | One inert Java comment is inserted above the unchanged call. |
| `pmd-line-shift-02` | moved | Two inert Java comments are inserted above the unchanged call. |
| `pmd-line-shift-03` | moved | Three inert Java comments are inserted above the unchanged call. |
| `pmd-line-shift-04` | moved | Four inert Java comments are inserted above the unchanged call. |
| `pmd-line-shift-05` | moved | Five inert Java comments are inserted above the unchanged call; this pair also carries the documented POSIX/Windows URI projection and rebase. |
| `pmd-moved-01` | moved | The unchanged call moves below the inert `neutralPadding` method in the same class. |
| `pmd-moved-02` | moved | The unchanged call moves with its method group below `neutralPadding`. |
| `pmd-moved-03` | moved | The unchanged call moves with its method group below `neutralPadding`. |
| `pmd-moved-04` | moved | The unchanged call moves with its method group below `neutralPadding`. |
| `pmd-moved-05` | moved | The unchanged call moves with its method group below `neutralPadding`. |
| `pmd-renamed-01` | moved | The unchanged call moves from `src/renamed-old/RenamedCases.java` to `src/renamed-new/RenamedCases.java`. |
| `pmd-renamed-02` | moved | The unchanged call moves in the same controlled directory rename. |
| `pmd-renamed-03` | moved | The unchanged call moves in the same controlled directory rename. |
| `pmd-renamed-04` | moved | The unchanged call moves in the same controlled directory rename. |
| `pmd-renamed-05` | moved | The unchanged call moves in the same controlled directory rename. |
| `pmd-message-modified-01` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `pmd-message-modified-02` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `pmd-message-modified-03` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `pmd-message-modified-04` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |
| `pmd-message-modified-05` | modified | Source identity and location are unchanged; only the candidate SARIF message gets the controlled suffix. |

## New, resolved, and ambiguous findings

- `pmd-resolved-01`, `pmd-resolved-02`, and `pmd-resolved-03` are the three
  violations in baseline-only `ResolvedCases.java`; removing that controlled
  file removes the findings.
- `pmd-new-01`, `pmd-new-02`, and `pmd-new-03` are the three violations in
  candidate-only `NewCases.java`; adding that controlled file creates them.
- `pmd-ambiguous-01` and `pmd-ambiguous-02` are identical adjacent
  `printStackTrace` calls in the same method on both sides. The projection gives
  both one duplicated partial fingerprint. All four finding keys are labelled
  ambiguous, with no arbitrary pair asserted.

## Reproducible SARIF projections

PMD's SARIF formatter emits absolute `file:` URIs even when
`--relativize-paths-with` is supplied. The raw files preserve those authentic
URIs. After the source resolver proves that each path is a regular controlled
fixture beneath its side root, the deterministic evaluation projection removes
only the ambient checkout prefix and writes the relative `src/...` path. This
sanitization is applied uniformly and is recorded in the sidecar audit; it is
not a producer-specific matching exception.

The scenario-specific changes are limited to candidate version metadata
(`7.26.0+holdout-candidate-projection`), five candidate message suffixes,
missing fingerprints for `pmd-exact-03`, one shared ambiguity partial
fingerprint, and the `pmd-line-shift-05` POSIX/Windows URI pair. `config.json`
rebases only that explicit URI pair and aliases only the controlled renamed
directory. No semantic IDs or labels enter projected SARIF. Original field
hashes and every mutation name live in `projection-audit.json`; results are
ordered by semantic ID for deterministic finding keys.

Reproduce the source proof and Linux-only capture with:

```sh
python3 -B validation/tools/capture/verify_source_transformations.py --repository-root .
./validation/tools/capture/capture-holdout.sh --output-root ../pmd-holdout-capture --producer pmd
```
