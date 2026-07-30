# Resource budgets

SarifRegress publishes deterministic operation counts alongside advisory latency and memory
measurements. The pull-request smoke job enforces the published 1,000-finding latency and
working-set ceiling on a standard Ubuntu runner and requires deterministic bounded refusal for the
pathological bucket. The scheduled and manually dispatchable extended workflow enforces the
10,000- and 100,000-finding targets outside pull requests and retains the resulting evidence.

## MVP targets

| Dataset | Target |
|---|---:|
| Pull-request smoke, 1,000 findings per side | 10 seconds and 512 MiB |
| Standard, 10,000 findings per side | 20 seconds and 768 MiB |
| Scale, 100,000 findings per side | 60 seconds and 1 GiB |
| Oversized pathological identity bucket | bounded refusal without heuristic matching |

Targets use a standard GitHub-hosted Ubuntu runner and a Release build. They are engineering
budgets, not guaranteed performance on every machine.

## Complexity controls

- Candidate generation uses producer-family and canonical-rule buckets rather than a global
  Cartesian product.
- Coarse pairs are preflighted before scoring, with limits of 256 pairs on either side of a finding
  and 1,000,000 pairs for one comparison.
- Retained candidate edges are capped per finding.
- The assignment graph is split into connected components.
- Components within the exact bound use a maximum-cardinality lexicographic solver.
- Larger components are classified as ambiguous and produce a bounded explanation.
- Report alternatives and source reads are capped independently.
- Optional repository token-window evidence uses algorithm `token-window/v1`. It is disabled by
  default, ignores whitespace and blank-line-only movement, and is bounded by repository-file,
  string, and term-count ceilings.

Token-window evidence is omitted rather than partially compared when a bound is exceeded.
`CANON0011` identifies a region exceeding `maximumTokenWindowTerms`; `CANON0012` identifies a term
exceeding `maximumStringCharacters`. The source read remains independently capped by
`maximumRepositoryFileBytes`.

The benchmark harness records finding count, candidate-edge count, component-size distribution,
classification counts, and process measurements. It never changes matching policy based on
timing.

Run the deterministic synthetic datasets with:

```bash
sarif-regress bench --size 1000 --dataset unique
sarif-regress bench --size 1000 --dataset pathological
sarif-regress bench \
  --size 1000 \
  --dataset unique \
  --enforce-budgets \
  --json-out report.json \
  --deterministic-out deterministic.json
```

Supported sizes are 1,000, 10,000, and 100,000 findings per side. Deterministic dataset identity,
operation counts, comparison-output bytes, diagnostic codes, and comparison-output SHA-256 are
separate from advisory latency, throughput, allocation, and working-set observations. Shared-runner
wall-clock values are not cross-platform byte-stability gates. The CLI emits a versioned
deterministic projection that excludes observations and their derived pass/failure fields. The
determinism workflow compares those application-emitted bytes directly on Windows and Linux; the
embedded comparison-output SHA-256 must agree.

`.github/workflows/benchmarks.yml` runs weekly and on manual dispatch. Its matrix measures both
dataset shapes at 10,000 and 100,000 findings on standard Ubuntu and Windows runners. Ubuntu
enforces the published latency, memory, and refusal budgets; Windows records the same deterministic
operation projection without applying Ubuntu-calibrated runtime ceilings. Every matrix cell
uploads the full observation report, deterministic projection, and checksums. A coordinator
compares the application-emitted Windows/Linux projection bytes and publishes their hashes. In
particular, the 100,000 pathological case must refuse the oversized component without retained
candidate edges or heuristic matching. These measurements are evidence and scheduled gates, not
pull-request gates.
