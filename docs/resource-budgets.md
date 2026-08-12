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

- Candidate generation uses collision-resistant automatic-producer-identity and canonical-rule
  buckets rather than a global Cartesian product.
- Path rebases are compiled once into an immutable compressed complete-prefix index.
  Canonicalising one path visits only its own prefix characters; it does not scan every configured
  rebase, and structural nodes scale with configured entries rather than prefix characters.
- Path aliases are compiled once into paired immutable compressed complete-prefix indexes. Each
  candidate edge traverses the two path representations, compares their suffix once, and directly
  probes matched terminal pairs; unrelated aliases do not multiply pair-scoring work.
- Coarse pairs are preflighted before scoring, with limits of 256 pairs on either side of a finding
  and 1,000,000 pairs for one comparison.
- Admissible pairs are first retained as fixed-size 16-byte descriptors containing only the two
  finding indexes and byte-sized decision bands. This explanation-free pass still unions every
  complete-graph component and counts every admissible and exact-producer edge.
- Compact descriptors are sorted by the same indisputable-exact, semantic-vector, and ordinal
  stable-identity order as full edges, then capacity-filtered in place. Full `MatchEdge`, evidence,
  and transformation objects are materialized only for the retained descriptors.
- A comparison-wide preflight refusal emits one source-less top-level diagnostic; every affected
  finding retains a minimal structured `refuse` trace without copying that global diagnostic.
- Retained candidate edges are capped per finding.
- Context evidence is counted within each input-side producer/rule bucket. Unique context retains
  its normal tier; duplicated context is explicitly degraded, and collision-only cross-path edges
  are refused before they can merge otherwise separable components. Occurrence evidence is bounded
  and reported with `sarifregress/evidence-occurrence/v1`.
- The assignment graph is split into connected components.
- Components within the exact bound use a maximum-cardinality lexicographic solver.
- Larger components are classified as ambiguous and produce a bounded explanation.
- Report alternatives and source reads are capped independently.
- Each result independently caps both the total thread-flow objects across all code flows and the
  total thread-flow locations at `maximumThreadFlowLocationsPerResult`. Both counters are enforced
  while their JSON array items are read, before an oversized nested graph can be materialized.
- Optional repository token-window evidence uses algorithm `token-window/v1`. It is disabled by
  default, ignores whitespace and blank-line-only movement, and is bounded by repository-file,
  string, and term-count ceilings.

Token-window evidence is omitted rather than partially compared when a bound is exceeded.
`CANON0011` identifies a region exceeding `maximumTokenWindowTerms`; `CANON0012` identifies a term
exceeding `maximumStringCharacters`. The source read remains independently capped by
`maximumRepositoryFileBytes`.

Trusted snapshot manifests are capped by `maximumInputBytes`, `maximumJsonDepth`,
`maximumStringCharacters`, and `maximumRunCollectionItems`. Each verified source file remains
subject to `maximumRepositoryFileBytes`; each successful file is decoded and lexically indexed
once per side into an immutable normalized string, line-offset array, and per-line result array.
Subsequent findings use constant-time line and lexical lookups plus work proportional only to the
returned snippet. The retained string, indexes, and conservative per-hash allowance are charged to
the side's `maximumInputBytes` aggregate ceiling. Failed verification and budget results are cached
as well, so an adversarial repeated path cannot force repeated file reads. After one uncached file
cannot fit, the side refuses every later uncached path without opening it; this bounds aggregate
verification work to the admitted cache plus one file-size-limited refusal. One indexing pass is
linear in verified source characters and retains at most `maximumJsonDepth` scope entries and
`maximumTokenWindowTerms` tokens for a header or statement. Overflow omits the identity or fails
the affected trusted read; no prefix is treated as a complete fingerprint.

## Candidate-edge global-cap stress evidence

`CandidateEdgeMemoryTests.Many_small_buckets_at_the_global_cap_remain_bounded_and_complete`
constructs 244 independent 64-by-64 buckets plus one 24-by-24 bucket: 15,640 findings per side and
exactly 1,000,000 admissible pairs, the default comparison-wide cap. It lowers the retained-edge
limit to one without raising any other limit, then verifies all 245 complete components and all
31,280 findings are refused as ambiguous. A test-only observer also proves that exactly 15,640
retained edges—not all 1,000,000 admissible pairs—receive full evidence materialization. A separate
parity test orders retained and non-retained candidates through both the compact descriptor and
former full-edge comparers. The stress test records elapsed time, total-allocation proxy, and
process peak working set on every run.

The focused Release run on Windows 10.0.26200, .NET SDK 10.0.302/runtime 10.0.10, observed
4,057.035 ms and a 153,182,208-byte process peak working set (about 146.1 MiB). Process peak is an
advisory whole-test-host observation, not a deterministic threshold; the deterministic assertions
are the descriptor/full-edge ordering parity plus pair, materialization, component, ambiguity, and
diagnostic counts. Re-run them with:

```powershell
dotnet test tests/SarifRegress.UnitTests/SarifRegress.UnitTests.csproj `
  --configuration Release `
  --filter FullyQualifiedName~CandidateEdgeMemoryTests `
  --logger "console;verbosity=detailed"
```

The benchmark harness records finding count, configured per-finding/global candidate limits,
candidate-edge count, component-size distribution, classification counts, and process
measurements. Hosted resource evidence pairs that report with a stable limit record emitted by the
validation executable from `ResourceLimits.Default`, including the configured assignment-side
limit. It never changes matching policy based on timing. Resource evidence distinguishes the
largest component observed before refusal from the largest component admitted to bounded
assignment; an oversized component is reported at its real size and an admitted size of zero
rather than being rewritten to the configured limit.

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

`.github/workflows/benchmarks.yml` runs for matcher-affecting pull requests, weekly, and on manual
dispatch. Its matrix measures both
dataset shapes at 1,000, 10,000, and 100,000 findings on standard Ubuntu and Windows runners. Ubuntu
enforces the published latency, memory, and refusal budgets; Windows records the same deterministic
operation projection without applying Ubuntu-calibrated runtime ceilings. Every matrix cell
uploads the full observation report, deterministic projection, and checksums. A coordinator
compares the application-emitted Windows/Linux projection bytes and publishes their hashes. In
particular, the 100,000 pathological case must refuse the oversized component without retained
candidate edges or heuristic matching. These measurements are evidence and scheduled gates, not
pull-request gates.
