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
Java vendor, or Java runtime. Exact immutable URLs, byte sizes, dependency
hashes, generated-help hashes, install commands, and execution commands are in
[`capture-provenance.json`](capture-provenance.json) and the holdout
[`manifest.json`](../../holdout/manifest.json).

Semgrep dependencies are hash-locked for Python 3.12/Linux x86-64. Gitleaks and
PMD archives are size- and SHA-256-verified before safe extraction. The capture
uses only repository-created source and local rules; it does not execute fixture
source, download rules, follow SARIF network URIs, or contain real secrets.
Semgrep is started through `run_semgrep.py`: Python initializes against the
host runtime first, then only the verified Semgrep native child sees the full
wheel-bundled library directory. The runner also disables metrics and network
version checks and rejects ambient `LD_PRELOAD` inheritance.

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
`producer-input/captures/` directory. Projection preserves producer-emitted
result order and writes deterministic SARIF, labels, and a field-level audit.
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

This regenerates all projected SARIF, labels, and projection audits from the
committed raw captures and compares exact bytes. It is also run by both hosted
evaluation jobs.
