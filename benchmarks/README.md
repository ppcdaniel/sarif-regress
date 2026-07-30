# Functional benchmarks

The dependency-free benchmark harness is implemented by `sarif-regress bench` so it exercises the
same parser, canonicaliser, matcher, and stable writer as the product.

Run the pull-request smoke shapes with:

```bash
sarif-regress bench --size 1000 --dataset unique --enforce-budgets
sarif-regress bench --size 1000 --dataset pathological --enforce-budgets
```

Supported sizes are 1,000, 10,000, and 100,000 findings per side. Dataset `unique` measures normal
bucket scaling; `pathological` proves bounded refusal when many findings share one identity
bucket. Use `--json-out` for observations and `--deterministic-out` for the cross-platform byte
contract.

Do not commit generated reports. The pull-request smoke, weekly extended matrix, published limits,
and interpretation rules are documented in
[resource-budgets.md](../docs/resource-budgets.md).
