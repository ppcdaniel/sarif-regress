# Holdout capture and projection

This directory reproduces the independent holdout inputs. Producer capture is
Linux-only and writes to a new staging directory; ordinary evaluation consumes
the committed SARIF and works on Linux and Windows.

## Frozen producer inputs

| Producer | CLI version | Release source commit | License | Verified artifact SHA-256 |
|---|---:|---|---|---|
| Gitleaks | 8.30.1 | `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` | MIT | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| PMD | 7.26.0 | `8fd38edf285a33e1164f66205ebe243441db9557` | PMD BSD-style; bundled components include Apache-2.0 software | `9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9` |
| Semgrep Community Edition | 1.172.0 | `651f37efa397bf066e1cf627414eeabe40b07e27` | LGPL-2.1-only | `d8b94af4266a575287ad2cd844573743ab4fe58f6bfb6d9229327807937eade3` |

The capture date was 2026-08-01 on Linux x86-64 with Python 3.12.13
and Eclipse Temurin 17.0.19+10. The script rejects any other Python version,
Java vendor, or Java runtime. The hosted byte-recapture check additionally
fails closed unless it uses runner image `ubuntu24/20260720.247.2`, glibc
`2.39`, and dynamic-loader SHA-256
`1cd555ac46b7887edeaf3c42aac5408c8135e52f6b37870da2cf82d5fe14e829`.
Those are verified reproduction-environment pins, not a claim that the first
capture was made on a GitHub runner. Exact immutable URLs, byte sizes, dependency
hashes, generated-help hashes, install commands, and execution commands are in
[`capture-provenance.json`](capture-provenance.json) and the holdout
[`manifest.json`](../../holdout/manifest.json).

Semgrep dependencies are hash-locked for Python 3.12/Linux x86-64. Gitleaks and
PMD archives are size- and SHA-256-verified before safe extraction. The capture
uses only repository-created source and local rules; it does not execute fixture
source, download rules, follow SARIF network URIs, or contain real secrets.
Semgrep is started through `run_semgrep.py` in its explicit `--legacy` mode.
After the wheel's native core is verified as
`8a7c27e6286381fdb6235eb91bd0fed40b919496a242c72f1e55d2b5caa10cb2`,
it is retained as `semgrep-core.native` and the reviewed
`semgrep-core-loader.sh` is installed at the package's core path. The loader
uses the Linux x86-64 dynamic loader's per-invocation `--library-path`, so only
the native core sees the complete wheel library directory. The already-started
Python parent scrubs and later restores hosted-runtime `LD_LIBRARY_PATH` and
`LD_PRELOAD` values; they are never passed to Semgrep or its Python children.
Metrics and network version checks are disabled as well.

## Reproduce source transformations

From the repository root:

```sh
python3 -B validation/tools/capture/verify_source_transformations.py \
  --repository-root .
```

The verifier checks byte snapshots, additions, removals, renames, unchanged
finding lines, local insertion blocks, cumulative line deltas, and ambiguity
construction without consulting either matcher.

## Reproduce a full producer capture

The output path must not exist:

```sh
./validation/tools/capture/capture-holdout.sh \
  --output-root ../holdout-capture \
  --producer all
```

Use `semgrep`, `gitleaks`, or `pmd` instead of `all` to capture one
family. Raw producer output is retained under each staged
`producer-input/captures/` directory. PMD and Semgrep project directly from
their untouched `*.raw.sarif` files. Gitleaks additionally retains untouched
`*.producer.sarif` bytes, then uses `normalize_gitleaks_sarif.py` to create an
ordering-only `*.raw.sarif` copy because its concurrent directory scan emits
the same findings in nondeterministic completion order. Projection writes
deterministic SARIF, labels, and a field-level audit.
Each producer's `commands.reproduction` manifest entry is the authoritative
end-to-end invocation. The adjacent `install` and `capture` arrays expose the
security-relevant subprocess arguments for review; the script itself is the
complete shell transcript, including downloads, size/hash checks, extraction,
runtime checks, version/help checks, capture, and projection.

## Reproduce committed projections without external analyzers

```sh
python3 -B validation/tools/capture/verify_projected_holdout.py \
  --repository-root . \
  --output-root ../holdout-projection-check
```

This first reproduces each Gitleaks ordering-only input from the untouched
capture, then regenerates all projected SARIF, labels, and projection audits
from committed inputs and compares exact bytes. It is also run by both hosted
evaluation jobs.
