# Resource budgets

SarifRegress publishes deterministic operation counts alongside advisory latency and memory
measurements. Operation and allocation bounds are CI gates; wall-clock results are reported because
shared runner timing is inherently variable.

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
- Retained candidate edges are capped per finding.
- The assignment graph is split into connected components.
- Components within the exact bound use a maximum-cardinality lexicographic solver.
- Larger components are classified as ambiguous and produce a bounded explanation.
- Report alternatives and source reads are capped independently.

The benchmark harness records finding count, candidate-edge count, component-size distribution,
classification counts, and process measurements. It never changes matching policy based on
timing.
